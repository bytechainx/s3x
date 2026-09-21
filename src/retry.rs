//! 重试策略：指数退避 + 抖动 + 整体 deadline。
//!
//! 全部在本 crate 内独立实现，不依赖任何外部重试框架：
//!
//! - 可重试判定委托给 [`S3Error::is_retryable`]（网络、IO、超时、408/429/5xx、
//!   `SlowDown` / `RequestTimeout` 等瞬时错误）；
//! - 退避上界由 [`backoff_delay`] 给出（`base * 2^(attempt-1)`，封顶 `max_delay_ms`）；
//! - 抖动在 `[1 - jitter_ratio, 1 + jitter_ratio]` 区间内随机缩放；
//! - [`with_retry_deadline`] 为整个重试过程设置总时限，避免每次尝试各自耗尽超时。

use std::future::Future;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::error::{S3Error, S3Result};

/// 最大尝试次数硬上界（含首次请求），防止错误配置制造无界放大。
pub const MAX_RETRY_ATTEMPTS: u32 = 10;
/// 默认最大尝试次数（含首次请求）。
pub const DEFAULT_MAX_ATTEMPTS: u32 = 3;
/// 默认首次退避时长（毫秒）。
pub const DEFAULT_BASE_DELAY_MS: u64 = 100;
/// 默认退避上限（毫秒）。
pub const DEFAULT_MAX_DELAY_MS: u64 = 5_000;
/// 默认抖动比例（±20%）。
pub const DEFAULT_JITTER_RATIO: f64 = 0.2;
/// 单次退避时长硬上限（毫秒）：更长的退避没有实际收益，同时杜绝时长运算溢出。
pub const HARD_MAX_DELAY_MS: u64 = 60_000;

/// 重试配置。
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RetryConfig {
    /// 最大尝试次数（含首次请求）；`1` 表示不重试，硬上界 [`MAX_RETRY_ATTEMPTS`]。
    pub max_attempts: u32,
    /// 首次退避时长（毫秒）。
    pub base_delay_ms: u64,
    /// 单次退避上限（毫秒）。
    pub max_delay_ms: u64,
    /// 抖动比例，会被收敛到 `0.0..=1.0`；`0.0` 表示无抖动。
    pub jitter_ratio: f64,
}

impl Default for RetryConfig {
    fn default() -> Self {
        default_retry_config()
    }
}

impl RetryConfig {
    /// 以尝试次数与首次退避时长构造，其余取默认值。
    #[must_use]
    pub const fn new(max_attempts: u32, base_delay_ms: u64) -> Self {
        Self {
            max_attempts,
            base_delay_ms,
            max_delay_ms: DEFAULT_MAX_DELAY_MS,
            jitter_ratio: DEFAULT_JITTER_RATIO,
        }
    }

    /// 设置单次退避上限（毫秒）。
    #[must_use]
    pub const fn with_max_delay_ms(mut self, max_delay_ms: u64) -> Self {
        self.max_delay_ms = max_delay_ms;
        self
    }

    /// 设置抖动比例（构造时会被收敛到 `0.0..=1.0`）。
    #[must_use]
    pub const fn with_jitter_ratio(mut self, jitter_ratio: f64) -> Self {
        self.jitter_ratio = jitter_ratio;
        self
    }

    /// 校验配置是否可用。
    ///
    /// # 错误
    ///
    /// `max_attempts` 必须落在 `1..=`[`MAX_RETRY_ATTEMPTS`]，`base_delay_ms`
    /// 不得超过 `max_delay_ms`，且两者都不得超过 [`HARD_MAX_DELAY_MS`]。
    pub fn validate(&self) -> S3Result<()> {
        if self.max_attempts == 0 || self.max_attempts > MAX_RETRY_ATTEMPTS {
            return Err(S3Error::Config(format!(
                "重试 max_attempts 必须落在 1..={MAX_RETRY_ATTEMPTS} 范围内"
            )));
        }
        if self.base_delay_ms > self.max_delay_ms {
            return Err(S3Error::Config(
                "重试 base_delay_ms 不得超过 max_delay_ms".to_owned(),
            ));
        }
        if self.max_delay_ms > HARD_MAX_DELAY_MS {
            return Err(S3Error::Config(format!(
                "重试 max_delay_ms 不得超过硬上限 {HARD_MAX_DELAY_MS}ms"
            )));
        }
        Ok(())
    }
}

/// 默认重试配置：3 次尝试（含首次）、100ms 起退避、封顶 5s、抖动 ±20%。
#[must_use]
pub fn default_retry_config() -> RetryConfig {
    RetryConfig {
        max_attempts: DEFAULT_MAX_ATTEMPTS,
        base_delay_ms: DEFAULT_BASE_DELAY_MS,
        max_delay_ms: DEFAULT_MAX_DELAY_MS,
        jitter_ratio: DEFAULT_JITTER_RATIO,
    }
}

/// 判断 S3 错误是否值得重试。
///
/// 等价于 [`S3Error::is_retryable`]：网络 / IO / 超时 / HTTP 408 / 429 / 5xx /
/// `SlowDown` 可重试；其余 4xx（含 401 / 403 / 404）与配置、序列化、对象键
/// 非法等永久错误不可重试。
#[must_use]
pub fn is_s3_retryable(error: &S3Error) -> bool {
    error.is_retryable()
}

/// 第 `attempt` 次失败后的退避上界（不含抖动）。
///
/// `attempt` 为 1 起算的**失败次数**：`base * 2^(attempt - 1)`，封顶
/// `max_delay_ms`。溢出按饱和处理。
#[must_use]
pub fn backoff_delay(config: &RetryConfig, attempt: u32) -> Duration {
    let shift = attempt.saturating_sub(1).min(63);
    let factor = 1_u64.checked_shl(shift).unwrap_or(u64::MAX);
    let delay_ms = config.base_delay_ms.saturating_mul(factor);
    Duration::from_millis(delay_ms.min(config.max_delay_ms))
}

/// 带抖动的实际退避时长；`rand_unit` 取 `[0.0, 1.0]`，便于测试确定性地驱动。
fn jittered_delay(config: &RetryConfig, attempt: u32, rand_unit: f64) -> Duration {
    let base = backoff_delay(config, attempt);
    let ratio = config.jitter_ratio.clamp(0.0, 1.0);
    let unit = rand_unit.clamp(0.0, 1.0);
    let factor = (1.0 - ratio + 2.0 * ratio * unit).max(0.0);
    let jittered = base.mul_f64(factor);
    jittered.min(Duration::from_millis(config.max_delay_ms))
}

/// 由纳秒时间戳与参数派生的伪随机数（xorshift64*），避免引入 `rand` 依赖。
fn random_unit(seed: u64) -> f64 {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    let mut state = nanos ^ seed.rotate_left(17) ^ 0x9e37_79b9_7f4a_7c15;
    if state == 0 {
        state = 0x2545_f491_4f6c_dd1d;
    }
    state ^= state >> 12;
    state ^= state << 25;
    state ^= state >> 27;
    let value = state.wrapping_mul(0x2545_f491_4f6c_dd1d);
    // 取高 53 位映射到 [0, 1)。
    (value >> 11) as f64 / (1_u64 << 53) as f64
}

/// 以指数退避 + 抖动执行 `f`，直到成功、判定为不可重试或尝试次数耗尽。
///
/// # 错误
///
/// 返回最后一次失败的错误；配置非法时立即返回 [`S3Error::Config`]。
pub async fn with_retry<F, Fut, T>(config: &RetryConfig, op: &str, mut f: F) -> S3Result<T>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = S3Result<T>>,
{
    config.validate()?;
    let mut attempt: u32 = 0;
    loop {
        attempt += 1;
        match f().await {
            Ok(value) => return Ok(value),
            Err(error) => {
                if attempt >= config.max_attempts || !is_s3_retryable(&error) {
                    return Err(error);
                }
                let delay = jittered_delay(config, attempt, random_unit(u64::from(attempt)));
                tracing::debug!(
                    op,
                    attempt,
                    delay_ms = u64::try_from(delay.as_millis()).unwrap_or(u64::MAX),
                    "s3 请求失败，按配置退避后重试"
                );
                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
            }
        }
    }
}

/// 在总 deadline 内执行完整的重试过程。
///
/// # 错误
///
/// deadline 到期返回 [`S3Error::Timeout`]（不再继续重试）；`deadline` 为零时返回
/// [`S3Error::Config`]。
pub async fn with_retry_deadline<F, Fut, T>(
    config: &RetryConfig,
    op: &str,
    deadline: Duration,
    f: F,
) -> S3Result<T>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = S3Result<T>>,
{
    if deadline.is_zero() {
        return Err(S3Error::Config("s3 重试 deadline 必须大于零".to_owned()));
    }
    match tokio::time::timeout(deadline, with_retry(config, op, f)).await {
        Ok(result) => result,
        Err(_) => Err(S3Error::Timeout(format!(
            "s3 {op} 超过总 deadline {}ms",
            deadline.as_millis()
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    fn no_jitter(max_attempts: u32, base_delay_ms: u64) -> RetryConfig {
        RetryConfig::new(max_attempts, base_delay_ms)
            .with_max_delay_ms(1_000)
            .with_jitter_ratio(0.0)
    }

    #[test]
    fn default_config_is_bounded() {
        let config = default_retry_config();
        assert_eq!(config.max_attempts, DEFAULT_MAX_ATTEMPTS);
        assert!(config.validate().is_ok());
        assert!(RetryConfig::new(0, 0).validate().is_err());
        assert!(RetryConfig::new(MAX_RETRY_ATTEMPTS, 0).validate().is_ok());
        assert!(RetryConfig::new(MAX_RETRY_ATTEMPTS + 1, 0)
            .validate()
            .is_err());
        assert!(RetryConfig::new(3, 2_000)
            .with_max_delay_ms(100)
            .validate()
            .is_err());
        assert!(RetryConfig::new(3, 100)
            .with_max_delay_ms(HARD_MAX_DELAY_MS + 1)
            .validate()
            .is_err());
    }

    #[test]
    fn backoff_sequence_is_monotonic_and_capped() {
        let config = no_jitter(10, 100);
        let delays: Vec<u64> = (1..=10)
            .map(|attempt| backoff_delay(&config, attempt).as_millis() as u64)
            .collect();
        assert_eq!(delays[0], 100, "首次退避等于 base_delay_ms");
        assert_eq!(delays[1], 200);
        assert_eq!(delays[2], 400);
        for pair in delays.windows(2) {
            assert!(pair[1] >= pair[0], "退避必须单调不减: {delays:?}");
            assert!(pair[1] <= 1_000, "退避必须封顶: {delays:?}");
        }
        assert_eq!(*delays.last().expect("非空"), 1_000);
        // attempt = 0 与极端 attempt 不得 panic 或溢出。
        assert_eq!(backoff_delay(&config, 0), Duration::from_millis(100));
        assert!(backoff_delay(&config, u32::MAX) <= Duration::from_millis(1_000));
        assert!(
            backoff_delay(&RetryConfig::new(3, u64::MAX), 1)
                <= Duration::from_millis(DEFAULT_MAX_DELAY_MS)
        );
    }

    #[test]
    fn jitter_stays_within_configured_ratio() {
        let config = RetryConfig::new(4, 100)
            .with_max_delay_ms(10_000)
            .with_jitter_ratio(0.2);
        let low = jittered_delay(&config, 1, 0.0);
        let high = jittered_delay(&config, 1, 1.0);
        let mid = jittered_delay(&config, 1, 0.5);
        assert_eq!(low, Duration::from_millis(80));
        assert_eq!(high, Duration::from_millis(120));
        assert_eq!(mid, Duration::from_millis(100));

        // 抖动比例超过 1.0 时收敛，不产生负时长。
        let clamped = RetryConfig::new(2, 100).with_jitter_ratio(5.0);
        assert!(jittered_delay(&clamped, 1, 1.0) <= Duration::from_millis(DEFAULT_MAX_DELAY_MS));

        // 随机源始终落在 [0, 1) 区间。
        for seed in 0..64_u64 {
            let unit = random_unit(seed);
            assert!((0.0..1.0).contains(&unit), "seed={seed} unit={unit}");
        }
    }

    #[test]
    fn retryable_classification_matches_error_type() {
        assert!(is_s3_retryable(&S3Error::Connection("x".into())));
        assert!(is_s3_retryable(&S3Error::Timeout("x".into())));
        assert!(is_s3_retryable(&S3Error::Backend {
            status: 503,
            code: None,
            message: "x".into()
        }));
        // 状态码优先：非 4xx/5xx 时才看错误码。
        assert!(is_s3_retryable(&S3Error::Backend {
            status: 300,
            code: Some("SlowDown".into()),
            message: "x".into()
        }));
        assert!(!is_s3_retryable(&S3Error::Backend {
            status: 400,
            code: Some("SlowDown".into()),
            message: "x".into()
        }));
        assert!(!is_s3_retryable(&S3Error::Backend {
            status: 403,
            code: Some("SignatureDoesNotMatch".into()),
            message: "x".into()
        }));
        assert!(!is_s3_retryable(&S3Error::Config("x".into())));
        assert!(!is_s3_retryable(&S3Error::InvalidObjectKey("x".into())));
    }

    #[tokio::test]
    async fn retries_transient_then_succeeds() {
        let attempts = AtomicU32::new(0);
        let config = no_jitter(5, 1);
        let value = with_retry(&config, "test_op", || {
            let n = attempts.fetch_add(1, Ordering::SeqCst) + 1;
            async move {
                if n < 3 {
                    Err(S3Error::Connection(format!("blip-{n}")))
                } else {
                    Ok(42_u32)
                }
            }
        })
        .await
        .expect("应在重试后成功");
        assert_eq!(value, 42);
        assert_eq!(attempts.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn permanent_error_is_not_retried() {
        let attempts = AtomicU32::new(0);
        let config = no_jitter(5, 1);
        let error = with_retry(&config, "bad_op", || {
            attempts.fetch_add(1, Ordering::SeqCst);
            async move {
                Err::<(), _>(S3Error::Backend {
                    status: 404,
                    code: Some("NoSuchKey".into()),
                    message: "missing".into(),
                })
            }
        })
        .await
        .expect_err("404 必须立即失败");
        assert!(matches!(error, S3Error::Backend { status: 404, .. }));
        assert_eq!(attempts.load(Ordering::SeqCst), 1, "不可重试错误只尝试一次");
    }

    #[tokio::test]
    async fn transient_budget_is_exhausted() {
        let attempts = AtomicU32::new(0);
        let config = no_jitter(3, 1);
        let error = with_retry(&config, "always_fail", || {
            attempts.fetch_add(1, Ordering::SeqCst);
            async move { Err::<(), _>(S3Error::Timeout("still bad".into())) }
        })
        .await
        .expect_err("必须耗尽尝试次数");
        assert!(error.is_retryable());
        assert_eq!(attempts.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn invalid_config_fails_closed_without_calling_op() {
        let attempts = AtomicU32::new(0);
        let config = RetryConfig::new(MAX_RETRY_ATTEMPTS + 1, 1);
        let error = with_retry(&config, "too_many", || {
            attempts.fetch_add(1, Ordering::SeqCst);
            async { Ok::<_, S3Error>(()) }
        })
        .await
        .expect_err("非法重试配置必须拒绝");
        assert!(matches!(error, S3Error::Config(_)));
        assert_eq!(attempts.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn deadline_bounds_the_whole_retry_loop() {
        let attempts = AtomicU32::new(0);
        let config = no_jitter(5, 1_000).with_max_delay_ms(1_000);
        let error = with_retry_deadline(&config, "slow_op", Duration::from_millis(30), || {
            attempts.fetch_add(1, Ordering::SeqCst);
            async {
                tokio::time::sleep(Duration::from_millis(200)).await;
                Err::<(), _>(S3Error::Timeout("slow".into()))
            }
        })
        .await
        .expect_err("deadline 必须终止整个重试过程");
        assert!(matches!(error, S3Error::Timeout(_)));
        assert_eq!(attempts.load(Ordering::SeqCst), 1);

        let zero = with_retry_deadline(&config, "op", Duration::ZERO, || async {
            Ok::<_, S3Error>(())
        })
        .await
        .expect_err("零 deadline 必须拒绝");
        assert!(matches!(zero, S3Error::Config(_)));
    }

    #[tokio::test]
    async fn deadline_allows_fast_success() {
        let config = no_jitter(3, 1);
        let value = with_retry_deadline(&config, "fast_op", Duration::from_secs(1), || async {
            Ok::<_, S3Error>(7_u8)
        })
        .await
        .expect("未超时");
        assert_eq!(value, 7);
    }
}
