//! 对象存储数据面类型：对象键、元数据、上传/下载选项与字节流别名。

use std::fmt;

use bytes::Bytes;

use crate::error::{S3Error, S3Result};

/// 对象键最大 UTF-8 字节数（与服务端上限一致）。
pub const MAX_OBJECT_KEY_BYTES: usize = 1024;

/// 已校验的对象键。
///
/// 构造时即完成校验，因此后续所有 API 都可以安全地把它拼进 URL 与查询参数：
/// 非空、无前导 `/`、无 `..`（阻断路径穿越）、无控制字符、UTF-8 字节数
/// `<= `[`MAX_OBJECT_KEY_BYTES`]。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ObjectKey(String);

impl ObjectKey {
    /// 校验并构造对象键。
    ///
    /// # 错误
    ///
    /// 任一校验失败返回 [`S3Error::InvalidObjectKey`]；错误消息只描述违规原因，
    /// 不回显完整键内容。
    pub fn new(key: impl Into<String>) -> S3Result<Self> {
        let key = key.into();
        if key.is_empty() {
            return Err(S3Error::InvalidObjectKey("对象键不能为空".to_owned()));
        }
        if key.starts_with('/') {
            return Err(S3Error::InvalidObjectKey(
                "对象键不能以 `/` 开头".to_owned(),
            ));
        }
        if key.contains("..") {
            return Err(S3Error::InvalidObjectKey(
                "对象键不能包含 `..` 路径片段".to_owned(),
            ));
        }
        if key.chars().any(char::is_control) {
            return Err(S3Error::InvalidObjectKey(
                "对象键不能包含控制字符".to_owned(),
            ));
        }
        if key.len() > MAX_OBJECT_KEY_BYTES {
            return Err(S3Error::InvalidObjectKey(format!(
                "对象键长度 {} 字节超过上限 {MAX_OBJECT_KEY_BYTES} 字节",
                key.len()
            )));
        }
        Ok(Self(key))
    }

    /// 以 `&str` 形式返回对象键。
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ObjectKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for ObjectKey {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl TryFrom<&str> for ObjectKey {
    type Error = S3Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

/// 对象元数据。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ObjectMeta {
    /// 对象键。
    pub key: String,
    /// 对象字节数。
    pub size: u64,
    /// ETag（通常为 MD5，多段上传时带 `-<part>` 后缀）。
    pub etag: Option<String>,
    /// 最后修改时间，保留服务端原始字符串（XML 为 ISO8601，响应头为 HTTP 日期）。
    pub last_modified: Option<String>,
    /// `Content-Type`。
    pub content_type: Option<String>,
}

impl ObjectMeta {
    /// 以键构造空元数据（其余字段为 `None` / `0`）。
    #[must_use]
    pub fn new(key: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            ..Self::default()
        }
    }

    /// 设置对象字节数。
    #[must_use]
    pub fn with_size(mut self, size: u64) -> Self {
        self.size = size;
        self
    }

    /// 设置 ETag。
    #[must_use]
    pub fn with_etag(mut self, etag: impl Into<String>) -> Self {
        self.etag = Some(etag.into());
        self
    }

    /// 设置最后修改时间（原样保存）。
    #[must_use]
    pub fn with_last_modified(mut self, last_modified: impl Into<String>) -> Self {
        self.last_modified = Some(last_modified.into());
        self
    }

    /// 设置 `Content-Type`。
    #[must_use]
    pub fn with_content_type(mut self, content_type: impl Into<String>) -> Self {
        self.content_type = Some(content_type.into());
        self
    }
}

/// 上传选项。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UploadOptions {
    /// `Content-Type`；`None` 时由 `reqwest` 决定（通常为 `application/octet-stream`）。
    pub content_type: Option<String>,
    /// 自定义元数据，写入 `x-amz-meta-*` 头。
    pub metadata: Option<Vec<(String, String)>>,
    /// 存储类别，写入 `x-amz-storage-class` 头（如 `STANDARD`、`STANDARD_IA`）。
    pub storage_class: Option<String>,
}

impl UploadOptions {
    /// 设置 `Content-Type`。
    #[must_use]
    pub fn with_content_type(mut self, content_type: impl Into<String>) -> Self {
        self.content_type = Some(content_type.into());
        self
    }

    /// 设置自定义元数据（整体覆盖）。
    #[must_use]
    pub fn with_metadata(mut self, metadata: Vec<(String, String)>) -> Self {
        self.metadata = Some(metadata);
        self
    }

    /// 追加一条自定义元数据。
    #[must_use]
    pub fn push_metadata(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata
            .get_or_insert_with(Vec::new)
            .push((name.into(), value.into()));
        self
    }

    /// 设置存储类别。
    #[must_use]
    pub fn with_storage_class(mut self, storage_class: impl Into<String>) -> Self {
        self.storage_class = Some(storage_class.into());
        self
    }

    /// 归一化为 `x-amz-meta-*` 之外的显式请求头。
    ///
    /// 元数据键名只允许 ASCII 字母、数字与 `-`，值不允许控制字符：两个位置都
    /// 直接进入 HTTP 头，非法取值必须 fail-closed。
    pub(crate) fn additional_headers(&self) -> S3Result<Vec<(String, String)>> {
        let mut headers = Vec::new();
        if let Some(content_type) = &self.content_type {
            headers.push(("content-type".to_owned(), content_type.clone()));
        }
        if let Some(storage_class) = &self.storage_class {
            headers.push(("x-amz-storage-class".to_owned(), storage_class.clone()));
        }
        for (name, value) in self.metadata.iter().flatten() {
            if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
                return Err(S3Error::Config(
                    "自定义元数据键名只允许 ASCII 字母、数字与 `-`".to_owned(),
                ));
            }
            if value.chars().any(char::is_control) {
                return Err(S3Error::Config(
                    "自定义元数据取值不能包含控制字符".to_owned(),
                ));
            }
            headers.push((format!("x-amz-meta-{name}"), value.clone()));
        }
        Ok(headers)
    }
}

/// 下载选项。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DownloadOptions {
    /// 闭区间字节范围 `(start, end)`，映射为 `Range: bytes=start-end`。
    pub range: Option<(u64, u64)>,
}

impl DownloadOptions {
    /// 构造带范围下载的选项。
    #[must_use]
    pub fn with_range(start: u64, end: u64) -> Self {
        Self {
            range: Some((start, end)),
        }
    }

    /// 转换为 `Range` 头取值；起点大于终点时返回 `None`（由调用方拒绝）。
    #[must_use]
    pub fn range_header(&self) -> Option<String> {
        self.range
            .filter(|(start, end)| start <= end)
            .map(|(start, end)| format!("bytes={start}-{end}"))
    }
}

/// 下载流：字节块流，单项错误为 [`std::io::Error`]。
pub type ByteStream = futures_util::stream::BoxStream<'static, Result<Bytes, std::io::Error>>;

/// 把一段内存数据包装成单元素字节流。
#[must_use]
pub fn byte_stream_from_bytes(data: Bytes) -> ByteStream {
    Box::pin(futures_util::stream::once(async move { Ok(data) }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::StreamExt;

    #[test]
    fn object_key_accepts_valid_keys() {
        for key in ["a", "a/b", "dir/sub/file.txt", "k/", "a b", "a$b.txt", "键"] {
            let parsed =
                ObjectKey::new(key).unwrap_or_else(|error| panic!("{key} 应合法: {error}"));
            assert_eq!(parsed.as_str(), key);
            assert_eq!(parsed.to_string(), key);
            assert_eq!(parsed.as_ref(), key);
        }
    }

    #[test]
    fn object_key_rejects_invalid_keys() {
        let cases = [
            ("", "空"),
            ("/leading", "前导斜杠"),
            ("../escape", "路径穿越"),
            ("a/../b", "路径穿越"),
            ("a..b", "含 `..`"),
            ("a\nb", "控制字符"),
            ("a\0b", "控制字符"),
        ];
        for (key, reason) in cases {
            let error = ObjectKey::new(key).expect_err(reason);
            assert!(matches!(error, S3Error::InvalidObjectKey(_)), "{error:?}");
            assert!(!error.is_retryable());
        }

        // 边界：1024 字节通过，1025 字节拒绝。
        assert!(ObjectKey::new("x".repeat(MAX_OBJECT_KEY_BYTES)).is_ok());
        assert!(ObjectKey::new("x".repeat(MAX_OBJECT_KEY_BYTES + 1)).is_err());
        // 多字节字符按字节数计算。
        assert!(ObjectKey::new("键".repeat(341)).is_ok());
        assert!(ObjectKey::new("键".repeat(342)).is_err());
    }

    #[test]
    fn object_meta_builders() {
        let meta = ObjectMeta::new("a/b")
            .with_size(7)
            .with_etag("etag")
            .with_last_modified("2024-01-01T00:00:00.000Z")
            .with_content_type("text/plain");
        assert_eq!(meta.key, "a/b");
        assert_eq!(meta.size, 7);
        assert_eq!(meta.etag.as_deref(), Some("etag"));
        assert_eq!(meta.content_type.as_deref(), Some("text/plain"));
        assert!(meta.last_modified.is_some());
        assert_eq!(ObjectMeta::default(), ObjectMeta::new(String::new()));
    }

    #[test]
    fn upload_options_normalize_headers() {
        let options = UploadOptions::default()
            .with_content_type("text/plain")
            .with_storage_class("STANDARD_IA")
            .push_metadata("owner", "team-a");
        let headers = options.additional_headers().expect("合法选项");
        assert_eq!(
            headers,
            vec![
                ("content-type".to_owned(), "text/plain".to_owned()),
                ("x-amz-storage-class".to_owned(), "STANDARD_IA".to_owned()),
                ("x-amz-meta-owner".to_owned(), "team-a".to_owned()),
            ]
        );

        let bad_key = UploadOptions::default().push_metadata("bad key", "v");
        assert!(bad_key.additional_headers().is_err());
        let bad_value = UploadOptions::default().push_metadata("ok", "a\r\nb");
        assert!(bad_value.additional_headers().is_err());
    }

    #[test]
    fn download_options_range_header() {
        assert_eq!(
            DownloadOptions::with_range(0, 9).range_header().as_deref(),
            Some("bytes=0-9")
        );
        assert!(DownloadOptions::default().range_header().is_none());
        // 起点大于终点：拒绝生成（而非构造一个非法 Range 头）。
        assert!(DownloadOptions::with_range(9, 0).range_header().is_none());
    }

    #[tokio::test]
    async fn byte_stream_yields_exactly_once() {
        let mut stream = byte_stream_from_bytes(Bytes::from_static(b"payload"));
        let first = stream.next().await.expect("应有元素").expect("无错误");
        assert_eq!(first, Bytes::from_static(b"payload"));
        assert!(stream.next().await.is_none());
    }
}
