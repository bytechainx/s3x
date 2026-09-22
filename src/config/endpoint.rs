//! `S3Config` 的端点与寻址。
//!
//! 自 `src/config.rs` 下沉而来：`effective_endpoint` / `endpoint_is_plain_http` /
//! `bucket_url` / `object_url` / `service` / `endpoint_parts` 六个方法、寻址三元组
//! `EndpointParts`，以及公开的 `aws_endpoint_for_region`（经门面 `pub use` 导出）。

use crate::sign::{self, S3_SERVICE};
use crate::types::ObjectKey;

use super::validate::split_endpoint;
use super::S3Config;

impl S3Config {
    /// 实际使用的 endpoint。
    ///
    /// - 未配置 `endpoint` 时返回 AWS 官方端点
    ///   `https://s3.{region}.amazonaws.com`；
    /// - 否则返回自定义 endpoint（去掉尾部 `/`）。
    #[must_use]
    pub fn effective_endpoint(&self) -> String {
        match self.endpoint.as_deref().map(str::trim) {
            Some(endpoint) if !endpoint.is_empty() => endpoint.trim_end_matches('/').to_owned(),
            _ => format!("https://s3.{}.amazonaws.com", self.region),
        }
    }

    /// 当前生效的 endpoint 是否为**明文 HTTP**（非 TLS）。
    ///
    /// 用于判定「未签名载荷」是否处于**无任何完整性保护**的状态：`UNSIGNED-PAYLOAD`
    /// 本身就不覆盖请求体，若再叠加明文传输，请求体在链路上可被篡改而签名依然有效。
    /// endpoint 无法解析时返回 `false`（交由 [`S3Config::validate`] 报错）。
    #[must_use]
    pub fn endpoint_is_plain_http(&self) -> bool {
        url::Url::parse(&self.effective_endpoint()).is_ok_and(|parsed| parsed.scheme() == "http")
    }

    /// 桶级请求的完整 URL（无查询串）。
    #[must_use]
    pub fn bucket_url(&self) -> String {
        self.endpoint_parts(None).url
    }

    /// 对象级请求的完整 URL（无查询串）。
    #[must_use]
    pub fn object_url(&self, key: &ObjectKey) -> String {
        self.endpoint_parts(Some(key.as_str())).url
    }

    /// SigV4 服务名（S3 固定为 [`S3_SERVICE`]）。
    #[must_use]
    pub fn service(&self) -> &'static str {
        S3_SERVICE
    }

    /// 一次请求的寻址三元组：完整 URL、`Host` 头、规范化 URI。
    pub(crate) fn endpoint_parts(&self, key: Option<&str>) -> EndpointParts {
        let (scheme, authority) = split_endpoint(&self.effective_endpoint());
        let encoded_key = key.map(|key| sign::percent_encode(key, false));
        if self.force_path_style {
            let mut canonical_uri = format!("/{}", self.bucket);
            if let Some(key) = &encoded_key {
                canonical_uri.push('/');
                canonical_uri.push_str(key);
            }
            EndpointParts {
                url: format!("{scheme}://{authority}{canonical_uri}"),
                host: authority,
                canonical_uri,
            }
        } else {
            let host = format!("{}.{authority}", self.bucket);
            let canonical_uri = match &encoded_key {
                Some(key) => format!("/{key}"),
                None => "/".to_owned(),
            };
            EndpointParts {
                url: format!("{scheme}://{host}{canonical_uri}"),
                host,
                canonical_uri,
            }
        }
    }
}

/// 寻址三元组（crate 内部使用）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EndpointParts {
    /// 完整 URL（不含查询串）。
    pub(crate) url: String,
    /// `Host` 头取值（virtual-hosted 时含桶名前缀）。
    pub(crate) host: String,
    /// 参与签名的规范化 URI（已 URI 编码，S3 规则不做二次编码）。
    pub(crate) canonical_uri: String,
}

/// 缺省 endpoint 的 AWS 官方形态（供文档与测试引用）。
///
/// # Examples
///
/// ```
/// use s3x::aws_endpoint_for_region;
///
/// assert_eq!(
///     aws_endpoint_for_region("ap-east-1"),
///     "https://s3.ap-east-1.amazonaws.com"
/// );
/// ```
#[must_use]
pub fn aws_endpoint_for_region(region: &str) -> String {
    format!("https://s3.{region}.amazonaws.com")
}
