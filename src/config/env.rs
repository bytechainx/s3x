//! 环境变量读取辅助。
//!
//! 自 `src/config.rs` 下沉而来；三个函数由门面的 `S3Config::apply_env_overrides`
//! 调用，故提为 `pub(super)`。

use crate::error::{S3Error, S3Result};

/// 读取 trim 后非空的环境变量。
pub(super) fn env_trimmed(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

/// 读取并解析环境变量；解析失败只报告变量名，不回显取值。
pub(super) fn env_parsed<T>(name: &str) -> S3Result<Option<T>>
where
    T: std::str::FromStr,
{
    match std::env::var(name) {
        Ok(value) => value
            .trim()
            .parse::<T>()
            .map(Some)
            .map_err(|_| S3Error::Config(format!("环境变量 {name} 取值非法"))),
        Err(_) => Ok(None),
    }
}

/// 读取布尔型环境变量，兼容 `1/0`、`true/false`、`yes/no`、`on/off`。
pub(super) fn env_bool(name: &str) -> S3Result<Option<bool>> {
    let Some(value) = env_trimmed(name) else {
        return Ok(None);
    };
    match value.to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(Some(true)),
        "0" | "false" | "no" | "off" => Ok(Some(false)),
        _ => Err(S3Error::Config(format!("环境变量 {name} 取值非法"))),
    }
}
