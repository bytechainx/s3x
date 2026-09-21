#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::unreachable
)]
//! 纯函数行为：XML 解析/构造、重试策略与字节流构造（全部离线）。

use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use futures_util::StreamExt;
use s3x::{
    backoff_delay, build_delete_objects_body, byte_stream_from_bytes, default_retry_config,
    is_s3_retryable, parse_delete_objects, parse_error_code_message, parse_list_objects_v2,
    with_retry, with_retry_deadline, ObjectKey, RetryConfig, S3Error, MAX_RETRY_ATTEMPTS,
};

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
    assert_eq!(
        parsed.keys[0].key, "photos/2024 trip.jpg",
        "URL 编码键必须被解码"
    );
    assert_eq!(parsed.keys[0].size, 1024);
    assert_eq!(
        parsed.keys[0].etag.as_deref(),
        Some("d41d8cd98f00b204e9800998ecf8427e"),
        "ETag 引号必须被去掉"
    );
    assert_eq!(
        parsed.keys[0].last_modified.as_deref(),
        Some("2024-05-01T12:34:56.000Z")
    );
    assert_eq!(parsed.keys[1].key, "notes.txt");
    assert_eq!(parsed.keys[1].size, 0);
    assert_eq!(parsed.common_prefixes, vec!["logs/", "archive/"]);
}

#[test]
fn list_objects_parsing_is_fail_closed() {
    for xml in [
        "<Error><Code>x</Code></Error>",
        "<ListBucketResult><Contents>",
        "not xml",
        "",
    ] {
        let error = parse_list_objects_v2(xml).expect_err("非法文档必须拒绝");
        assert!(matches!(error, S3Error::Serialization(_)), "{error:?}");
        assert!(!error.is_retryable());
    }
}

#[test]
fn builds_and_parses_delete_objects_documents() {
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

    let xml = r#"<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
      <Deleted><Key>a.txt</Key></Deleted>
      <Deleted><Key>b.txt</Key></Deleted>
      <Error><Key>c.txt</Key><Code>AccessDenied</Code><Message>Access Denied</Message></Error>
    </DeleteResult>"#;
    let parsed = parse_delete_objects(xml).expect("解析成功");
    assert_eq!(parsed.deleted, vec!["a.txt", "b.txt"]);
    assert_eq!(parsed.errors.len(), 1);
    assert_eq!(parsed.errors[0].code, "AccessDenied");
    assert_eq!(parsed.errors[0].message, "Access Denied");
}

#[test]
fn parses_error_code_and_message_leniently() {
    let (code, message) = parse_error_code_message(
        "<Error><Code>SlowDown</Code><Message>Please reduce your request rate.</Message></Error>",
    )
    .expect("应提取成功");
    assert_eq!(code, "SlowDown");
    assert!(message.starts_with("Please reduce"));

    let without_message =
        parse_error_code_message("<Error><Code>NoSuchKey</Code></Error>").expect("应给出 Code");
    assert_eq!(without_message.0, "NoSuchKey");
    assert!(without_message.1.is_empty());

    assert!(parse_error_code_message("not xml").is_none());
    assert!(parse_error_code_message("<Error><Code>truncated").is_none());
    // 截断的错误体仍能尽力提取 Code。
    assert_eq!(
        parse_error_code_message("<Error><Code>AccessDenied</Code>").map(|pair| pair.0),
        Some("AccessDenied".to_owned())
    );
}

#[test]
fn retryable_classification_covers_documented_branches() {
    assert!(is_s3_retryable(&S3Error::Connection("x".into())));
    assert!(is_s3_retryable(&S3Error::Timeout("x".into())));
    assert!(is_s3_retryable(&S3Error::Io(std::io::Error::other("x"))));
    for status in [408, 429, 500, 502, 503, 504] {
        assert!(
            is_s3_retryable(&S3Error::Backend {
                status,
                code: None,
                message: "x".into()
            }),
            "HTTP {status} 应可重试"
        );
    }
    // 错误码优先于状态码：瞬时错误码挂在任意状态码上都可重试。
    for code in [
        "SlowDown",
        "RequestTimeout",
        "InternalError",
        "ServiceUnavailable",
    ] {
        assert!(is_s3_retryable(&S3Error::Backend {
            status: 300,
            code: Some(code.into()),
            message: "x".into()
        }));
        assert!(
            is_s3_retryable(&S3Error::Backend {
                status: 400,
                code: Some(code.into()),
                message: "x".into()
            }),
            "HTTP 400 + {code} 应可重试"
        );
    }
    // 无瞬时错误码时按状态码判定：其余 4xx 一律不可重试。
    for status in [400, 401, 403, 404, 405, 409, 412, 416] {
        assert!(
            !is_s3_retryable(&S3Error::Backend {
                status,
                code: None,
                message: "x".into()
            }),
            "HTTP {status} 不应可重试"
        );
    }
    // 非瞬时错误码的 4xx 依然不可重试（避免把鉴权失败当成限流）。
    assert!(!is_s3_retryable(&S3Error::Backend {
        status: 403,
        code: Some("SignatureDoesNotMatch".into()),
        message: "鉴权失败".into()
    }));
    assert!(!is_s3_retryable(&S3Error::Config("x".into())));
    assert!(!is_s3_retryable(&S3Error::Serialization("x".into())));
    assert!(!is_s3_retryable(&S3Error::InvalidObjectKey("x".into())));
    assert!(!is_s3_retryable(&S3Error::Unsupported("x".into())));
}

/// 固定「错误码优先于状态码」策略的**关键收益**：AWS 的 `RequestTimeout` 使用
/// HTTP `400`，只按状态码判定会漏掉它，因此必须先看响应体错误码。
///
/// 该策略由 `S3Error::is_retryable` 的文档注释与 README「安全约定」一节描述。
/// 若将来要改回「状态码优先」，必须同时修改本用例、`src/retry.rs` 的
/// `retryable_classification_matches_error_type` 与 README。
#[test]
fn request_timeout_on_http_400_is_retryable() {
    assert!(
        is_s3_retryable(&S3Error::Backend {
            status: 400,
            code: Some("RequestTimeout".into()),
            message: "Your socket connection to the server was not read from or written to \
                      within the timeout period."
                .into()
        }),
        "AWS 的 RequestTimeout 是 HTTP 400，必须按错误码判定为可重试"
    );
    // 对照：同一状态码若没有瞬时错误码，依然不可重试（不会把 400 一律当限流）。
    assert!(!is_s3_retryable(&S3Error::Backend {
        status: 400,
        code: Some("InvalidRequest".into()),
        message: "x".into()
    }));
    // 对照：同为瞬时语义的错误码挂在 5xx 上同样可重试。
    assert!(is_s3_retryable(&S3Error::Backend {
        status: 503,
        code: Some("SlowDown".into()),
        message: "x".into()
    }));
}

#[test]
fn backoff_sequence_is_bounded_and_monotonic() {
    let config = RetryConfig::new(10, 100)
        .with_max_delay_ms(1_000)
        .with_jitter_ratio(0.0);
    assert!(config.validate().is_ok());

    let delays: Vec<u64> = (1..=10)
        .map(|attempt| backoff_delay(&config, attempt).as_millis() as u64)
        .collect();
    assert_eq!(&delays[..4], &[100, 200, 400, 800]);
    assert_eq!(*delays.last().expect("非空"), 1_000);
    for pair in delays.windows(2) {
        assert!(pair[1] >= pair[0], "退避必须单调不减: {delays:?}");
        assert!(pair[1] <= 1_000, "退避必须封顶: {delays:?}");
    }

    // 极端输入不得 panic 或溢出。
    assert_eq!(backoff_delay(&config, 0), Duration::from_millis(100));
    assert!(backoff_delay(&config, u32::MAX) <= Duration::from_millis(1_000));
    assert!(backoff_delay(&default_retry_config(), 64).as_millis() > 0);
}

#[test]
fn retry_config_validation_rejects_unsafe_values() {
    for max_attempts in [0, MAX_RETRY_ATTEMPTS + 1] {
        let error = RetryConfig::new(max_attempts, 10)
            .validate()
            .expect_err("尝试次数越界必须拒绝");
        assert!(matches!(error, S3Error::Config(_)));
    }
    assert!(RetryConfig::new(1, 10).validate().is_ok());
    assert!(RetryConfig::new(MAX_RETRY_ATTEMPTS, 10).validate().is_ok());
    assert!(RetryConfig::new(3, 5_000)
        .with_max_delay_ms(100)
        .validate()
        .is_err());
    assert_eq!(default_retry_config().max_attempts, 3);
}

#[tokio::test]
async fn with_retry_retries_transient_and_stops_on_permanent() {
    let attempts = AtomicU32::new(0);
    let config = RetryConfig::new(4, 1).with_jitter_ratio(0.0);
    let value = with_retry(&config, "op", || {
        let attempt = attempts.fetch_add(1, Ordering::SeqCst) + 1;
        async move {
            if attempt < 3 {
                Err(S3Error::Connection(format!("blip-{attempt}")))
            } else {
                Ok(attempt)
            }
        }
    })
    .await
    .expect("应在重试后成功");
    assert_eq!(value, 3);
    assert_eq!(attempts.load(Ordering::SeqCst), 3);

    let permanent_attempts = AtomicU32::new(0);
    let error = with_retry(&config, "op", || {
        permanent_attempts.fetch_add(1, Ordering::SeqCst);
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
    assert_eq!(permanent_attempts.load(Ordering::SeqCst), 1);

    let exhausted = AtomicU32::new(0);
    let error = with_retry(&RetryConfig::new(2, 1).with_jitter_ratio(0.0), "op", || {
        exhausted.fetch_add(1, Ordering::SeqCst);
        async move { Err::<(), _>(S3Error::Timeout("still bad".into())) }
    })
    .await
    .expect_err("必须耗尽尝试次数");
    assert!(error.is_retryable());
    assert_eq!(exhausted.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn with_retry_deadline_bounds_the_whole_operation() {
    let attempts = AtomicU32::new(0);
    let config = RetryConfig::new(5, 1_000)
        .with_max_delay_ms(1_000)
        .with_jitter_ratio(0.0);
    let error = with_retry_deadline(&config, "slow", Duration::from_millis(30), || {
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

    let value = with_retry_deadline(&config, "fast", Duration::from_secs(1), || async {
        Ok::<_, S3Error>(9_u8)
    })
    .await
    .expect("未超时必须成功");
    assert_eq!(value, 9);
}

#[tokio::test]
async fn byte_stream_yields_data_then_ends() {
    let mut stream = byte_stream_from_bytes(bytes::Bytes::from_static(b"payload"));
    let chunk = stream.next().await.expect("应有数据").expect("无错误");
    assert_eq!(&chunk[..], b"payload");
    assert!(stream.next().await.is_none(), "流必须结束");

    let empty = byte_stream_from_bytes(bytes::Bytes::new());
    assert_eq!(empty.count().await, 1, "空数据仍产生一个空块");
}
