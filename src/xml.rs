//! S3 XML 响应解析与请求体构造（`quick-xml`）。
//!
//! 只覆盖本 crate 用到的三种文档：
//!
//! - `ListObjectsV2` 响应（[`parse_list_objects_v2`]）；
//! - 批量删除请求体与响应（[`build_delete_objects_body`] / [`parse_delete_objects`]）；
//! - 通用 `<Error><Code>/<Message>` 错误体（[`parse_error_code_message`]）。
//!
//! 解析失败统一落到 [`S3Error::Serialization`]，且错误消息中的响应片段由调用方
//! 负责截断（见 [`MAX_ERROR_BODY_BYTES`](crate::MAX_ERROR_BODY_BYTES)）。

use percent_encoding::percent_decode_str;
use quick_xml::events::Event;
use quick_xml::{Reader, XmlVersion};

use crate::error::{S3Error, S3Result};
use crate::types::{ObjectKey, ObjectMeta};

/// 解析 XML 文本时使用的版本（S3 响应均为 XML 1.0）。
const XML_VERSION: XmlVersion = XmlVersion::Implicit1_0;

/// `ListObjectsV2` 结果。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ListObjectsResult {
    /// 是否还有后续页。
    pub is_truncated: bool,
    /// 下一页的 `ContinuationToken`。
    pub next_continuation_token: Option<String>,
    /// 本页对象元数据。
    pub keys: Vec<ObjectMeta>,
    /// 本页公共前缀（`Delimiter` 折叠出的“目录”）。
    pub common_prefixes: Vec<String>,
}

/// 批量删除的单条失败记录。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeleteError {
    /// 失败的对象键。
    pub key: String,
    /// S3 错误码。
    pub code: String,
    /// S3 错误消息。
    pub message: String,
}

/// 批量删除结果。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeleteObjectsResult {
    /// 已删除的对象键。
    pub deleted: Vec<String>,
    /// 删除失败的记录。
    pub errors: Vec<DeleteError>,
}

/// 解析 `ListObjectsV2` 响应。
///
/// 响应中携带 `<EncodingType>url</EncodingType>` 时，对象键与公共前缀会被
/// 百分号解码（本 crate 的请求固定带 `encoding-type=url`）。
pub fn parse_list_objects_v2(xml: &str) -> S3Result<ListObjectsResult> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);

    let mut path: Vec<String> = Vec::with_capacity(4);
    let mut text = String::new();
    let mut result = ListObjectsResult::default();
    let mut current: Option<ObjectMeta> = None;
    let mut encoding_url = false;
    let mut root_seen = false;

    loop {
        match reader.read_event() {
            Ok(Event::Start(start)) => {
                let name = local_name(start.local_name().as_ref());
                if path.is_empty() && name == "ListBucketResult" {
                    root_seen = true;
                }
                path.push(name);
                text.clear();
            }
            Ok(Event::Text(chunk)) => {
                let decoded = chunk
                    .xml_content(XML_VERSION)
                    .map_err(|error| serialization("ListObjectsV2 文本节点解码失败", &error))?;
                text.push_str(&decoded);
            }
            Ok(Event::End(_)) => {
                apply_list_element(
                    &path,
                    text.trim(),
                    &mut result,
                    &mut current,
                    &mut encoding_url,
                )?;
                path.pop();
                text.clear();
            }
            Ok(Event::Eof) => break,
            Ok(_) => {}
            Err(error) => {
                return Err(serialization("ListObjectsV2 XML 解析失败", &error));
            }
        }
    }

    if !path.is_empty() {
        return Err(S3Error::Serialization(
            "ListObjectsV2 响应 XML 未闭合（可能被截断）".to_owned(),
        ));
    }
    if !root_seen {
        return Err(S3Error::Serialization(
            "ListObjectsV2 响应缺少 ListBucketResult 根元素".to_owned(),
        ));
    }
    if encoding_url {
        for meta in &mut result.keys {
            meta.key = percent_decode(&meta.key);
        }
        for prefix in &mut result.common_prefixes {
            *prefix = percent_decode(prefix);
        }
    }
    Ok(result)
}

/// 把当前闭合元素的文本归入解析结果。
fn apply_list_element(
    path: &[String],
    value: &str,
    result: &mut ListObjectsResult,
    current: &mut Option<ObjectMeta>,
    encoding_url: &mut bool,
) -> S3Result<()> {
    let path: Vec<&str> = path.iter().map(String::as_str).collect();
    match path.as_slice() {
        ["ListBucketResult", "IsTruncated"] => result.is_truncated = value == "true",
        ["ListBucketResult", "EncodingType"] => *encoding_url = value.eq_ignore_ascii_case("url"),
        ["ListBucketResult", "NextContinuationToken"] => {
            result.next_continuation_token = Some(value.to_owned());
        }
        ["ListBucketResult", "CommonPrefixes", "Prefix"] => {
            result.common_prefixes.push(value.to_owned());
        }
        ["ListBucketResult", "Contents"] => {
            if let Some(meta) = current.take() {
                result.keys.push(meta);
            }
        }
        ["ListBucketResult", "Contents", "Key"] => {
            current.get_or_insert_with(ObjectMeta::default).key = value.to_owned();
        }
        ["ListBucketResult", "Contents", "Size"] => {
            let meta = current.get_or_insert_with(ObjectMeta::default);
            if !value.is_empty() {
                meta.size = value.parse::<u64>().map_err(|_| {
                    S3Error::Serialization("ListObjectsV2 的 Size 不是合法整数".to_owned())
                })?;
            }
        }
        ["ListBucketResult", "Contents", "ETag"] => {
            let meta = current.get_or_insert_with(ObjectMeta::default);
            // S3 会把 ETag 包在双引号里；对外统一去掉引号。
            meta.etag = Some(value.trim_matches('"').to_owned());
        }
        ["ListBucketResult", "Contents", "LastModified"] => {
            current
                .get_or_insert_with(ObjectMeta::default)
                .last_modified = Some(value.to_owned());
        }
        _ => {}
    }
    Ok(())
}

/// 构造 `DeleteObjects` 请求体（`POST /{bucket}?delete`）。
///
/// 注意：S3 要求该接口额外附带 `Content-MD5`（或等价的校验和头），本 crate
/// 不引入摘要依赖，因此只提供请求体构造与结果解析，由调用方决定如何补齐该校验头。
#[must_use]
pub fn build_delete_objects_body(keys: &[ObjectKey]) -> String {
    let mut body = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Delete>");
    for key in keys {
        body.push_str("<Object><Key>");
        body.push_str(&xml_escape(key.as_str()));
        body.push_str("</Key></Object>");
    }
    body.push_str("</Delete>");
    body
}

/// 解析 `DeleteObjects` 响应。
pub fn parse_delete_objects(xml: &str) -> S3Result<DeleteObjectsResult> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);

    let mut path: Vec<String> = Vec::with_capacity(3);
    let mut text = String::new();
    let mut result = DeleteObjectsResult::default();
    let mut pending: Option<DeleteError> = None;
    let mut root_seen = false;

    loop {
        match reader.read_event() {
            Ok(Event::Start(start)) => {
                let name = local_name(start.local_name().as_ref());
                if path.is_empty() && name == "DeleteResult" {
                    root_seen = true;
                }
                path.push(name);
                text.clear();
            }
            Ok(Event::Text(chunk)) => {
                let decoded = chunk
                    .xml_content(XML_VERSION)
                    .map_err(|error| serialization("DeleteObjects 文本节点解码失败", &error))?;
                text.push_str(&decoded);
            }
            Ok(Event::End(_)) => {
                let current: Vec<&str> = path.iter().map(String::as_str).collect();
                let value = text.trim();
                match current.as_slice() {
                    ["DeleteResult", "Deleted", "Key"] => result.deleted.push(value.to_owned()),
                    ["DeleteResult", "Error", "Key"] => {
                        pending
                            .get_or_insert_with(|| DeleteError {
                                key: String::new(),
                                code: String::new(),
                                message: String::new(),
                            })
                            .key = value.to_owned();
                    }
                    ["DeleteResult", "Error", "Code"] => {
                        if let Some(entry) = pending.as_mut() {
                            entry.code = value.to_owned();
                        }
                    }
                    ["DeleteResult", "Error", "Message"] => {
                        if let Some(entry) = pending.as_mut() {
                            entry.message = value.to_owned();
                        }
                    }
                    ["DeleteResult", "Error"] => {
                        if let Some(entry) = pending.take() {
                            result.errors.push(entry);
                        }
                    }
                    _ => {}
                }
                path.pop();
                text.clear();
            }
            Ok(Event::Eof) => break,
            Ok(_) => {}
            Err(error) => {
                return Err(serialization("DeleteObjects XML 解析失败", &error));
            }
        }
    }

    if !path.is_empty() {
        return Err(S3Error::Serialization(
            "DeleteObjects 响应 XML 未闭合（可能被截断）".to_owned(),
        ));
    }
    if !root_seen {
        return Err(S3Error::Serialization(
            "DeleteObjects 响应缺少 DeleteResult 根元素".to_owned(),
        ));
    }
    Ok(result)
}

/// 从 S3 错误响应体中提取 `(<Code>, <Message>)`。
///
/// 解析失败或缺少元素时返回 `None`（调用方仍可依赖 HTTP 状态码分类）。
#[must_use]
pub fn parse_error_code_message(xml: &str) -> Option<(String, String)> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);

    let mut path: Vec<String> = Vec::with_capacity(2);
    let mut text = String::new();
    let mut code: Option<String> = None;
    let mut message: Option<String> = None;

    loop {
        match reader.read_event() {
            Ok(Event::Start(start)) => {
                path.push(local_name(start.local_name().as_ref()));
                text.clear();
            }
            Ok(Event::Text(chunk)) => {
                if let Ok(decoded) = chunk.xml_content(XML_VERSION) {
                    text.push_str(&decoded);
                }
            }
            Ok(Event::End(_)) => {
                match path
                    .iter()
                    .map(String::as_str)
                    .collect::<Vec<_>>()
                    .as_slice()
                {
                    ["Error", "Code"] if code.is_none() => {
                        code = Some(text.trim().to_owned());
                    }
                    ["Error", "Message"] if message.is_none() => {
                        message = Some(text.trim().to_owned());
                    }
                    ["Error"] => return code.map(|code| (code, message.unwrap_or_default())),
                    _ => {}
                }
                path.pop();
                text.clear();
            }
            Ok(Event::Eof) => break,
            Ok(_) => {}
            // 截断或非法 XML：尽力而为地返回已提取到的内容。
            Err(_) => break,
        }
    }
    code.map(|code| (code, message.unwrap_or_default()))
}

/// 取限定名的本地部分（去掉命名空间前缀）。
fn local_name(raw: &[u8]) -> String {
    match raw.iter().rposition(|byte| *byte == b':') {
        Some(index) => String::from_utf8_lossy(&raw[index + 1..]).into_owned(),
        None => String::from_utf8_lossy(raw).into_owned(),
    }
}

/// 百分号解码（`encoding-type=url` 场景）。
fn percent_decode(value: &str) -> String {
    percent_decode_str(value).decode_utf8_lossy().into_owned()
}

/// 最小 XML 文本转义。
fn xml_escape(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&apos;"),
            _ => escaped.push(ch),
        }
    }
    escaped
}

/// 构造带上下文的序列化错误（不回显响应体）。
fn serialization(context: &str, error: &impl std::fmt::Display) -> S3Error {
    S3Error::Serialization(format!("{context}: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 固定响应：含 IsTruncated / NextContinuationToken / CommonPrefixes /
    /// 百分号编码键（`photos/2024 trip.jpg` -> `photos%2F2024%20trip.jpg`）。
    const LIST_XML: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>examplebucket</Name>
  <Prefix></Prefix>
  <KeyCount>3</KeyCount>
  <MaxKeys>2</MaxKeys>
  <Delimiter>/</Delimiter>
  <EncodingType>url</EncodingType>
  <IsTruncated>true</IsTruncated>
  <NextContinuationToken>1ueGcxLPRx1Tr%2F4a</NextContinuationToken>
  <Contents>
    <Key>photos%2F2024%20trip.jpg</Key>
    <LastModified>2024-05-01T12:34:56.000Z</LastModified>
    <ETag>&quot;d41d8cd98f00b204e9800998ecf8427e&quot;</ETag>
    <Size>1024</Size>
    <StorageClass>STANDARD</StorageClass>
  </Contents>
  <Contents>
    <Key>notes.txt</Key>
    <LastModified>2024-05-02T00:00:00.000Z</LastModified>
    <ETag>&quot;abc&quot;</ETag>
    <Size>0</Size>
  </Contents>
  <CommonPrefixes>
    <Prefix>logs%2F</Prefix>
  </CommonPrefixes>
  <CommonPrefixes>
    <Prefix>archive%2F</Prefix>
  </CommonPrefixes>
</ListBucketResult>"#;

    #[test]
    fn parses_list_objects_v2_with_encoded_keys() {
        let parsed = parse_list_objects_v2(LIST_XML).expect("固定 XML 必须解析成功");
        assert!(parsed.is_truncated);
        assert_eq!(
            parsed.next_continuation_token.as_deref(),
            Some("1ueGcxLPRx1Tr%2F4a")
        );
        assert_eq!(parsed.keys.len(), 2);

        let first = &parsed.keys[0];
        assert_eq!(first.key, "photos/2024 trip.jpg", "URL 编码键必须被解码");
        assert_eq!(first.size, 1024);
        assert_eq!(
            first.etag.as_deref(),
            Some("d41d8cd98f00b204e9800998ecf8427e")
        );
        assert_eq!(
            first.last_modified.as_deref(),
            Some("2024-05-01T12:34:56.000Z")
        );
        assert!(first.content_type.is_none());

        assert_eq!(parsed.keys[1].key, "notes.txt");
        assert_eq!(parsed.keys[1].size, 0);

        assert_eq!(parsed.common_prefixes, vec!["logs/", "archive/"]);
    }

    #[test]
    fn parses_list_objects_v2_without_encoding_type() {
        let xml = r#"<ListBucketResult><IsTruncated>false</IsTruncated>
            <Contents><Key>a%2Fb</Key><Size>1</Size></Contents></ListBucketResult>"#;
        let parsed = parse_list_objects_v2(xml).expect("解析成功");
        assert!(!parsed.is_truncated);
        assert!(parsed.next_continuation_token.is_none());
        assert!(parsed.common_prefixes.is_empty());
        // 未声明 encoding-type 时不做解码。
        assert_eq!(parsed.keys[0].key, "a%2Fb");
    }

    #[test]
    fn rejects_non_list_document_and_malformed_xml() {
        let error = parse_list_objects_v2("<Error><Code>x</Code></Error>").expect_err("根元素不符");
        assert!(matches!(error, S3Error::Serialization(_)), "{error:?}");
        assert!(!error.is_retryable());

        assert!(matches!(
            parse_list_objects_v2("<ListBucketResult><Contents>"),
            Err(S3Error::Serialization(_))
        ));
    }

    #[test]
    fn builds_delete_body_with_escaping() {
        let keys = [
            ObjectKey::new("a&b").expect("合法"),
            ObjectKey::new("dir/<x>.txt").expect("合法"),
        ];
        let body = build_delete_objects_body(&keys);
        assert!(body.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"));
        assert!(
            body.contains("<Object><Key>a&amp;b</Key></Object>"),
            "{body}"
        );
        assert!(
            body.contains("<Object><Key>dir/&lt;x&gt;.txt</Key></Object>"),
            "{body}"
        );
        assert!(body.ends_with("</Delete>"));
        assert!(build_delete_objects_body(&[]).contains("<Delete></Delete>"));
    }

    #[test]
    fn parses_delete_objects_result() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Deleted><Key>a.txt</Key></Deleted>
  <Deleted><Key>b.txt</Key></Deleted>
  <Error><Key>c.txt</Key><Code>AccessDenied</Code><Message>Access Denied</Message></Error>
</DeleteResult>"#;
        let parsed = parse_delete_objects(xml).expect("解析成功");
        assert_eq!(parsed.deleted, vec!["a.txt", "b.txt"]);
        assert_eq!(parsed.errors.len(), 1);
        assert_eq!(parsed.errors[0].key, "c.txt");
        assert_eq!(parsed.errors[0].code, "AccessDenied");
        assert_eq!(parsed.errors[0].message, "Access Denied");

        assert!(parse_delete_objects("<nope/>").is_err());
    }

    #[test]
    fn parses_error_code_and_message() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<Error><Code>SlowDown</Code><Message>Please reduce your request rate.</Message>
<RequestId>REQ1</RequestId><HostId>HOST1</HostId></Error>"#;
        let (code, message) = parse_error_code_message(xml).expect("应提取成功");
        assert_eq!(code, "SlowDown");
        assert_eq!(message, "Please reduce your request rate.");

        let no_message = parse_error_code_message("<Error><Code>NoSuchKey</Code></Error>")
            .expect("缺少 Message 也要给出 Code");
        assert_eq!(no_message.0, "NoSuchKey");
        assert!(no_message.1.is_empty());

        assert!(parse_error_code_message("not xml at all").is_none());
        assert!(parse_error_code_message("<Error><Code>unclosed").is_none());
    }
}
