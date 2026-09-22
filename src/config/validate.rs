//! 配置字段校验：endpoint 拆分、region 与 bucket 规则。
//!
//! 自 `src/config.rs` 下沉而来；三个函数由门面的 `S3Config::validate_shape` /
//! `validate_endpoint` 调用，故提为 `pub(super)`。

use crate::error::{S3Error, S3Result};

use super::{MAX_BUCKET_NAME_LEN, MIN_BUCKET_NAME_LEN};

/// 拆分 `scheme://authority`；无协议前缀时兜底为 `https`（`validate` 已拒绝该形态）。
pub(super) fn split_endpoint(endpoint: &str) -> (String, String) {
    match url::Url::parse(endpoint) {
        Ok(parsed) => {
            let scheme = parsed.scheme().to_owned();
            let host = parsed.host_str().unwrap_or_default().to_owned();
            let authority = match parsed.port() {
                Some(port) => format!("{host}:{port}"),
                None => host,
            };
            (scheme, authority)
        }
        Err(_) => match endpoint.split_once("://") {
            Some((scheme, rest)) => (scheme.to_owned(), rest.trim_end_matches('/').to_owned()),
            None => ("https".to_owned(), endpoint.to_owned()),
        },
    }
}

/// 校验区域名：小写字母/数字/连字符，不以连字符开头或结尾，长度 `1..=64`。
pub(super) fn validate_region(region: &str) -> S3Result<()> {
    let region = region.trim();
    let valid = !region.is_empty()
        && region.len() <= 64
        && !region.starts_with('-')
        && !region.ends_with('-')
        && region
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
    if valid {
        Ok(())
    } else {
        Err(S3Error::Config(
            "region 只允许小写字母、数字与连字符（不以连字符开头/结尾，长度 1..=64）".to_owned(),
        ))
    }
}

/// 校验存储桶名（AWS 通用存储桶命名规则）。
pub(super) fn validate_bucket(bucket: &str) -> S3Result<()> {
    let len = bucket.len();
    if !(MIN_BUCKET_NAME_LEN..=MAX_BUCKET_NAME_LEN).contains(&len) {
        return Err(S3Error::Config(format!(
            "bucket 长度必须落在 {MIN_BUCKET_NAME_LEN}..={MAX_BUCKET_NAME_LEN} 之间"
        )));
    }
    let first = bucket.chars().next().unwrap_or_default();
    let last = bucket.chars().next_back().unwrap_or_default();
    if !(first.is_ascii_lowercase() || first.is_ascii_digit())
        || !(last.is_ascii_lowercase() || last.is_ascii_digit())
    {
        return Err(S3Error::Config(
            "bucket 必须以小写字母或数字开头与结尾".to_owned(),
        ));
    }
    if !bucket
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '-' | '.'))
    {
        return Err(S3Error::Config(
            "bucket 只允许小写字母、数字、连字符与点号".to_owned(),
        ));
    }
    if bucket.contains("..") {
        return Err(S3Error::Config("bucket 不能包含连续的 `.`".to_owned()));
    }
    if bucket.parse::<std::net::Ipv4Addr>().is_ok() {
        return Err(S3Error::Config("bucket 不能是 IPv4 地址形式".to_owned()));
    }
    Ok(())
}
