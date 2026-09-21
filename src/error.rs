//! `s3x` 错误类型。
//!
//! 错误消息只保留 HTTP 状态码、S3 错误码（如 `SlowDown`）与服务端返回的错误
//! 消息（有界截断）。**secret access key / session token 永远不会进入错误消息**，
//! 服务端也不会回显它们；对象键与请求体内容同样不进入消息，避免随日志放大。

/// `s3x` 统一错误类型。
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum S3Error {
    /// 配置非法（构造或校验阶段即可判定）。
    #[error("配置无效: {0}")]
    Config(String),
    /// 连接建立或维护失败（远端不可达、被拒绝、连接被中断）。
    #[error("连接失败: {0}")]
    Connection(String),
    /// 远端返回 HTTP 错误或 S3 协议错误。
    ///
    /// `status` 为 HTTP 状态码，`code` 为 S3 错误码（如 `NoSuchKey`、
    /// `SlowDown`），`message` 为服务端错误消息（已按上限截断）。
    #[error("远端返回错误: HTTP {status}{} {message}", code.as_deref().map(|code| format!(" code={code}")).unwrap_or_default())]
    Backend {
        /// HTTP 状态码。
        status: u16,
        /// S3 错误码（响应体不含或无法解析时为 `None`）。
        code: Option<String>,
        /// 服务端错误消息（已截断；不含任何凭据）。
        message: String,
    },
    /// XML 序列化或解析失败。
    #[error("序列化失败: {0}")]
    Serialization(String),
    /// 网络或底层 I/O 失败。
    #[error("I/O 失败: {0}")]
    Io(#[from] std::io::Error),
    /// 操作超时（请求超时、等待并发额度超时或整体 deadline 到期）。
    #[error("操作超时: {0}")]
    Timeout(String),
    /// 当前能力不支持。
    #[error("不支持的操作: {0}")]
    Unsupported(String),
    /// 对象键非法（空、含前导 `/`、含 `..`、含控制字符或超长）。
    #[error("对象键非法: {0}")]
    InvalidObjectKey(String),
}

impl S3Error {
    /// 是否属于可以安全重试的瞬时错误。
    ///
    /// - 可重试：[`S3Error::Connection`]、[`S3Error::Io`]、[`S3Error::Timeout`]，
    ///   以及 HTTP `408` / `429` / `5xx`，或（非 4xx 状态下）S3 错误码
    ///   `SlowDown` / `RequestTimeout` / `InternalError` / `ServiceUnavailable`。
    /// - 不可重试：配置、序列化、对象键非法、不支持的操作，以及**其余全部 4xx**
    ///   （含 401 / 403 / 404）——状态码优先，即使响应体携带 `SlowDown` 也不重试；
    ///   重试只会放大失败。
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Connection(_) | Self::Io(_) | Self::Timeout(_) => true,
            Self::Backend { status, code, .. } => {
                if (400..500).contains(status) {
                    return *status == 408 || *status == 429;
                }
                if *status >= 500 {
                    return true;
                }
                matches!(
                    code.as_deref(),
                    Some("SlowDown" | "RequestTimeout" | "InternalError" | "ServiceUnavailable")
                )
            }
            Self::Config(_)
            | Self::Serialization(_)
            | Self::Unsupported(_)
            | Self::InvalidObjectKey(_) => false,
        }
    }
}

/// crate 专用 `Result` 别名。
pub type S3Result<T> = Result<T, S3Error>;

#[cfg(test)]
mod tests {
    use super::*;

    fn backend(status: u16, code: Option<&str>) -> S3Error {
        S3Error::Backend {
            status,
            code: code.map(str::to_owned),
            message: "m".to_owned(),
        }
    }

    #[test]
    fn retryable_matrix_is_exhaustive() {
        let retryable = [
            S3Error::Connection("x".into()),
            S3Error::Io(std::io::Error::other("x")),
            S3Error::Timeout("x".into()),
            backend(500, None),
            backend(503, Some("ServiceUnavailable")),
            backend(429, None),
            backend(408, None),
            backend(300, Some("SlowDown")),
            backend(300, Some("RequestTimeout")),
        ];
        for error in retryable {
            assert!(error.is_retryable(), "{error:?} 应可重试");
        }

        let permanent = [
            S3Error::Config("x".into()),
            S3Error::Serialization("x".into()),
            S3Error::Unsupported("x".into()),
            S3Error::InvalidObjectKey("x".into()),
            backend(400, Some("InvalidBucketName")),
            backend(400, Some("SlowDown")),
            backend(401, None),
            backend(403, Some("SignatureDoesNotMatch")),
            backend(403, Some("SlowDown")),
            backend(404, Some("NoSuchKey")),
            backend(409, None),
        ];
        for error in permanent {
            assert!(!error.is_retryable(), "{error:?} 不应可重试");
        }
    }

    #[test]
    fn io_error_converts_via_from() {
        fn read() -> S3Result<()> {
            Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "eof").into())
        }
        assert!(matches!(read(), Err(S3Error::Io(_))));
    }

    #[test]
    fn backend_display_carries_status_and_code() {
        let rendered = backend(503, Some("SlowDown")).to_string();
        assert!(rendered.contains("503"), "{rendered}");
        assert!(rendered.contains("SlowDown"), "{rendered}");
        let rendered = backend(404, None).to_string();
        assert!(rendered.contains("404"), "{rendered}");
        assert!(!rendered.contains("code="), "{rendered}");
    }
}
