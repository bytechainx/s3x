//! `S3ConfigBuilder`：`S3Config` 的链式构建器。
//!
//! 自 `src/config.rs` 下沉而来。公开类型经门面 `pub use` 导出，路径不变；
//! 构建器只持有并逐步覆盖 `S3Config` 的各 `pub` 字段，非法组合在 `build()` 里
//! 由 `S3Config::validate` 统一 fail-closed。

use std::time::Duration;

use crate::error::S3Result;

use super::S3Config;

/// [`S3Config`] 的链式构建器。
#[derive(Clone, Debug, Default)]
pub struct S3ConfigBuilder {
    inner: S3Config,
}

impl S3ConfigBuilder {
    /// 从默认值开始。
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: S3Config::default(),
        }
    }

    /// 从已有配置开始（便于在既有配置上覆盖少量字段）。
    #[must_use]
    pub fn from_config(config: S3Config) -> Self {
        Self { inner: config }
    }

    /// 设置自定义 endpoint（`None` 表示 AWS 官方端点）。
    #[must_use]
    pub fn endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.inner.endpoint = Some(endpoint.into());
        self
    }

    /// 清除自定义 endpoint，回退到 AWS 官方端点。
    #[must_use]
    pub fn aws_endpoint(mut self) -> Self {
        self.inner.endpoint = None;
        self
    }

    /// 设置区域。
    #[must_use]
    pub fn region(mut self, region: impl Into<String>) -> Self {
        self.inner.region = region.into();
        self
    }

    /// 设置存储桶名。
    #[must_use]
    pub fn bucket(mut self, bucket: impl Into<String>) -> Self {
        self.inner.bucket = bucket.into();
        self
    }

    /// 设置 Access Key ID。
    #[must_use]
    pub fn access_key_id(mut self, access_key_id: impl Into<String>) -> Self {
        self.inner.access_key_id = access_key_id.into();
        self
    }

    /// 设置 Secret Access Key（不会出现在 `Debug` 输出中）。
    #[must_use]
    pub fn access_key_secret(mut self, access_key_secret: impl Into<String>) -> Self {
        self.inner.access_key_secret = access_key_secret.into();
        self
    }

    /// 设置 session token（不会出现在 `Debug` 输出中）。
    #[must_use]
    pub fn session_token(mut self, session_token: impl Into<String>) -> Self {
        self.inner.session_token = Some(session_token.into());
        self
    }

    /// 设置是否强制 path-style 寻址。
    #[must_use]
    pub fn force_path_style(mut self, force_path_style: bool) -> Self {
        self.inner.force_path_style = force_path_style;
        self
    }

    /// 允许在明文 HTTP endpoint 上使用 `UNSIGNED-PAYLOAD`（默认拒绝）。
    ///
    /// 仅在确认「请求体完整性不受保护」可接受时开启（例如本地 MinIO 调试）。
    pub fn allow_unsigned_payload_over_http(mut self, allow: bool) -> Self {
        self.inner.allow_unsigned_payload_over_http = allow;
        self
    }

    /// 设置请求超时。
    #[must_use]
    pub fn request_timeout(mut self, timeout: Duration) -> Self {
        self.inner.request_timeout_ms = u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX);
        self
    }

    /// 设置连接超时（`None` 表示不单独限制）。
    #[must_use]
    pub fn connect_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.inner.connect_timeout_ms = timeout
            .map(|timeout| u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX))
            .unwrap_or(0);
        self
    }

    /// 设置最大尝试次数（含首次请求）。
    #[must_use]
    pub fn max_retries(mut self, max_retries: u32) -> Self {
        self.inner.max_retries = max_retries;
        self
    }

    /// 设置全局并发上限。
    #[must_use]
    pub fn max_in_flight(mut self, max_in_flight: usize) -> Self {
        self.inner.max_in_flight = max_in_flight;
        self
    }

    /// 设置 `User-Agent`。
    #[must_use]
    pub fn user_agent(mut self, user_agent: impl Into<String>) -> Self {
        self.inner.user_agent = user_agent.into();
        self
    }

    /// 校验并产出配置。
    pub fn build(self) -> S3Result<S3Config> {
        self.inner.validate()?;
        Ok(self.inner)
    }
}
