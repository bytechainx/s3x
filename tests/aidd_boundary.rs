#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::unreachable
)]
//! AIDD 对抗 / 边界用例（特性 002）。
//!
//! 候选由 AI 生成，逐条人工复核后仅保留「结论=保留」项；丢弃项登记于 PR 描述。
//! 全部离线（本地一次性 TCP 服务 + 纯函数），不依赖真实对象存储，也不使用 `#[ignore]`。
//!
//! // AIDD: 对象键 1024/1025 字节与 Unicode 边界 | 来源=AI | 复核=ZoneCNH/2026-09-22 | 依据=标准.md §2 键上限 | 结论=保留
//! // AIDD: 桶名 2/3/63/64 字节边界 | 来源=AI | 复核=ZoneCNH/2026-09-22 | 依据=标准.md §3 桶名约束 | 结论=保留
//! // AIDD: 预签名有效期极值 | 来源=AI | 复核=ZoneCNH/2026-09-22 | 依据=标准.md §3 有效期收敛 | 结论=保留
//! // AIDD: 凭据四出口不外泄 | 来源=AI | 复核=ZoneCNH/2026-09-22 | 依据=标准.md §4 凭据脱敏 | 结论=保留
//! // AIDD: 服务端超长错误消息 | 来源=AI | 复核=ZoneCNH/2026-09-22 | 依据=标准.md §3 错误截断 | 结论=保留
//! // AIDD: 瞬时错误码优先于状态码 | 来源=AI | 复核=ZoneCNH/2026-09-22 | 依据=标准.md §3 重试分类 | 结论=保留
//! // AIDD: 不可达端点数据面 fail-closed | 来源=AI | 复核=ZoneCNH/2026-09-22 | 依据=标准.md §4 鉴权/连通语义 | 结论=保留
//! // AIDD: 百分号编码与规范化 URI | 来源=AI | 复核=ZoneCNH/2026-09-22 | 依据=标准.md §2 编码规则 | 结论=保留

use std::io::{Read, Write};
use std::net::TcpListener;
use std::time::Duration;

use s3x::{
    canonical_query_string, canonical_uri_for_key, percent_encode, presign_get, sha256_hex,
    ObjectKey, S3Client, S3Config, S3Error, SignRequest, UploadOptions, EMPTY_PAYLOAD_SHA256,
    HARD_MAX_PRESIGN_EXPIRES_SECS, MAX_BUCKET_NAME_LEN, MAX_ERROR_MESSAGE_CHARS,
    MAX_OBJECT_KEY_BYTES, MAX_RETRY_ATTEMPTS, UNSIGNED_PAYLOAD,
};

const AK_ID: &str = "AKIAIOSFODNN7EXAMPLE";
const AK_SECRET: &str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

fn builder() -> s3x::S3ConfigBuilder {
    S3Config::builder()
        .bucket("examplebucket")
        .access_key_id(AK_ID)
        .access_key_secret(AK_SECRET)
}

fn config(endpoint: &str) -> S3Config {
    builder()
        .endpoint(endpoint)
        .force_path_style(true)
        .request_timeout(Duration::from_millis(300))
        .connect_timeout(Some(Duration::from_millis(300)))
        .max_retries(1)
        .build()
        .expect("测试配置必须有效")
}

/// 起一个本地一次性 HTTP 服务，最多处理 `connections` 个请求，返回 `http://addr`。
fn serve(status_line: &'static str, body: &'static str, connections: usize) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("绑定本地端口必须成功");
    let addr = listener.local_addr().expect("读取本地地址");
    let _server = std::thread::spawn(move || {
        for _ in 0..connections {
            let Ok((mut stream, _)) = listener.accept() else {
                break;
            };
            let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
            let mut buffer = [0_u8; 2048];
            let _ = stream.read(&mut buffer);
            let response = format!(
                "{status_line}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
        }
    });
    format!("http://{addr}")
}

/// 边界：对象键的字节上界是闭区间，且 Unicode 按字节计数。
#[test]
fn object_key_byte_boundaries() {
    let exactly_max = "k".repeat(MAX_OBJECT_KEY_BYTES);
    let key = ObjectKey::new(exactly_max.clone()).expect("1024 字节必须合法");
    assert_eq!(key.as_str().len(), MAX_OBJECT_KEY_BYTES);

    let too_long = "k".repeat(MAX_OBJECT_KEY_BYTES + 1);
    assert!(ObjectKey::new(too_long).is_err(), "1025 字节必须拒绝");

    // 多字节字符按 UTF-8 字节数计数：342 个 3 字节字符 = 1026 字节 > 1024。
    let multibyte_overflow = "中".repeat(MAX_OBJECT_KEY_BYTES / 3 + 1);
    assert!(
        ObjectKey::new(multibyte_overflow).is_err(),
        "多字节字符必须按字节数判定"
    );
    assert!(ObjectKey::new("中".repeat(300)).is_ok(), "900 字节合法");

    for bad in ["", "/a", "..", "a/../b", "a\nb", "a\u{0}b"] {
        assert!(ObjectKey::new(bad).is_err(), "{bad:?} 必须拒绝");
    }
}

/// 边界：桶名长度闭区间 3..=63，且形态受校验。
#[test]
fn bucket_name_boundaries() {
    let with_bucket = |bucket: String| {
        builder()
            .bucket(bucket)
            .build()
            .map(|config| config.bucket.len())
    };
    assert!(with_bucket("ab".to_owned()).is_err(), "2 字节过短");
    assert_eq!(with_bucket("abc".to_owned()).unwrap(), 3);
    assert_eq!(with_bucket("a".repeat(MAX_BUCKET_NAME_LEN)).unwrap(), 63);
    assert!(
        with_bucket("a".repeat(MAX_BUCKET_NAME_LEN + 1)).is_err(),
        "64 字节过长"
    );
    // 形态：不允许大写与下划线（S3 桶名规则）。
    assert!(with_bucket("Bad_Bucket".to_owned()).is_err());
}

/// 对抗：预签名有效期的两端极值必须被收敛，而不是原样透传。
#[test]
fn presign_expiry_extremes_are_converged() {
    let config = builder().build().expect("AWS 默认端点");
    let key = ObjectKey::new("k").expect("合法键");
    let expires_of = |url: String| -> u64 {
        url::Url::parse(&url)
            .expect("URL 合法")
            .query_pairs()
            .find(|(name, _)| name == "X-Amz-Expires")
            .map(|(_, value)| value.parse::<u64>().expect("数字"))
            .expect("必须含 X-Amz-Expires")
    };
    assert_eq!(expires_of(presign_get(&config, &key, 0).unwrap()), 1);
    assert_eq!(
        expires_of(presign_get(&config, &key, u64::MAX).unwrap()),
        HARD_MAX_PRESIGN_EXPIRES_SECS
    );
    assert_eq!(expires_of(presign_get(&config, &key, 1).unwrap()), 1);
    assert_eq!(
        expires_of(presign_get(&config, &key, HARD_MAX_PRESIGN_EXPIRES_SECS).unwrap()),
        HARD_MAX_PRESIGN_EXPIRES_SECS
    );
}

/// 对抗：secret / session token 不得从 Debug、TOML、URL、`SignRequest` 四条出口外泄。
#[test]
fn credentials_never_leak_from_any_surface() {
    let config = builder()
        .session_token("session-token-value")
        .build()
        .unwrap();
    let debug = format!("{config:?}");
    assert!(!debug.contains(AK_SECRET), "{debug}");
    assert!(!debug.contains("session-token-value"), "{debug}");
    // Access Key ID 非敏感，按文档保持可读（只有 secret 与 token 脱敏）。
    assert!(debug.contains(AK_ID), "{debug}");
    assert!(debug.contains("***"), "{debug}");

    for line in [
        "bucket = \"examplebucket\"\naccess_key_secret = \"leaked-secret-value\"\n",
        "bucket = \"examplebucket\"\nsession_token = \"leaked-token-value\"\n",
    ] {
        let error = S3Config::from_toml(line).expect_err("敏感键必须拒绝");
        let rendered = error.to_string();
        assert!(!rendered.contains("leaked-secret-value"), "{rendered}");
        assert!(!rendered.contains("leaked-token-value"), "{rendered}");
    }

    // 预签名 URL 携带会话令牌（这是它能被第三方使用的必要条件），但绝不携带 secret。
    let url = presign_get(&config, &key_for("k"), 60).unwrap();
    assert!(!url.contains(AK_SECRET), "{url}");
    assert!(
        url.contains("X-Amz-Security-Token=session-token-value"),
        "{url}"
    );

    // `SignRequest` 的 Debug 固定渲染 secret 为 `***`。
    let request = SignRequest {
        method: "GET",
        canonical_uri: "/k",
        query: &[],
        headers: &[("host", "examplebucket.s3.us-east-1.amazonaws.com")],
        payload_hash: UNSIGNED_PAYLOAD,
        amz_date: "20130524T000000Z",
        region: "us-east-1",
        service: s3x::S3_SERVICE,
        access_key_id: AK_ID,
        secret_access_key: AK_SECRET,
    };
    let rendered = format!("{request:?}");
    assert!(!rendered.contains(AK_SECRET), "{rendered}");
    assert!(rendered.contains("***"), "{rendered}");
}

fn key_for(value: &str) -> ObjectKey {
    ObjectKey::new(value).expect("合法键")
}

/// 对抗：服务端返回超长错误消息时必须按上限截断，不得把整段响应灌进日志。
#[tokio::test]
async fn oversized_error_message_is_truncated() {
    let body: &'static str = Box::leak(
        format!(
            "<Error><Code>AccessDenied</Code><Message>{}</Message></Error>",
            "M".repeat(MAX_ERROR_MESSAGE_CHARS * 2)
        )
        .into_boxed_str(),
    );
    let endpoint = serve("HTTP/1.1 403 Forbidden", body, 2);
    let client = S3Client::new(config(&endpoint)).expect("同步构造");
    let error = client
        .get_object_bytes(&key_for("k"))
        .await
        .expect_err("403 必须失败");
    match &error {
        S3Error::Backend {
            status, message, ..
        } => {
            assert_eq!(*status, 403);
            let length = message.chars().count();
            assert!(
                length <= MAX_ERROR_MESSAGE_CHARS + 1,
                "错误消息必须被截断，实际 {length} 字符"
            );
        }
        other => panic!("意外的错误类型: {other:?}"),
    }
}

/// 对抗：重试判定必须「错误码优先于状态码」，否则 AWS 的 `RequestTimeout`（HTTP 400）会被漏判。
#[test]
fn retry_classification_prefers_error_code() {
    let backend = |status: u16, code: Option<&str>| S3Error::Backend {
        status,
        code: code.map(str::to_owned),
        message: "m".to_owned(),
    };

    assert!(backend(400, Some("RequestTimeout")).is_retryable());
    assert!(backend(403, Some("SlowDown")).is_retryable());
    assert!(!backend(400, Some("InvalidRequest")).is_retryable());
    assert!(!backend(400, None).is_retryable());
    assert!(backend(408, None).is_retryable());
    assert!(backend(429, None).is_retryable());
    assert!(backend(503, None).is_retryable());
    assert!(!backend(404, Some("NoSuchKey")).is_retryable());
    assert!(!backend(401, None).is_retryable());

    // 重试次数有上限，携带瞬时错误码的 4xx 不会无限重试。
    assert_eq!(MAX_RETRY_ATTEMPTS, s3x::HARD_MAX_RETRIES);
    assert!(s3x::RetryConfig::new(MAX_RETRY_ATTEMPTS + 1, 10)
        .validate()
        .is_err());
    assert!(s3x::RetryConfig::new(1, 10).validate().is_ok());
}

/// 对抗：不可达端点上所有数据面操作 fail-closed（返回 Err 且可重试），
/// 而「可达但无权限」（403）必须判定为可达。
#[tokio::test]
async fn unreachable_data_plane_fails_closed() {
    let client = S3Client::new(config("http://127.0.0.1:1")).expect("同步构造");
    let key = key_for("k");

    for label in [
        "put_object",
        "get_object_bytes",
        "delete_object",
        "head_object",
    ] {
        let error = match label {
            "put_object" => client
                .put_object(
                    &key,
                    bytes::Bytes::from_static(b"x"),
                    &UploadOptions::default(),
                )
                .await
                .err(),
            "get_object_bytes" => client.get_object_bytes(&key).await.err(),
            "delete_object" => client.delete_object(&key).await.err(),
            _ => client.head_object(&key).await.err(),
        }
        .unwrap_or_else(|| panic!("{label} 对不可达端点必须返回 Err"));
        assert!(
            matches!(error, S3Error::Connection(_) | S3Error::Timeout(_)),
            "{label}: {error:?}"
        );
        assert!(error.is_retryable(), "{label} 的网络故障应可重试");
    }
    assert!(client.list_objects_v2(None, None, None).await.is_err());
    assert!(client.ping().await.is_err());

    // 403 = 端点可达但凭据无权限：ping 成功。
    let forbidden = serve("HTTP/1.1 403 Forbidden", "", 2);
    let client = S3Client::new(config(&forbidden)).expect("同步构造");
    client.ping().await.expect("403 视为可达");
    assert!(client.health_check().await.expect("结构化结果").healthy);
}

/// 对抗：百分号编码与规范化 URI 的边界——保留字符、斜杠策略、非 ASCII、查询串排序。
#[test]
fn percent_encoding_and_canonical_uri_boundaries() {
    // 非保留字符（AWS 全集）必须原样保留。
    assert_eq!(
        percent_encode("ABCDEFGHIJKLMNOPQRSTUVWXYZ", true),
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    );
    assert_eq!(
        percent_encode("abcdefghijklmnopqrstuvwxyz", true),
        "abcdefghijklmnopqrstuvwxyz"
    );
    assert_eq!(percent_encode("0123456789-_.~", true), "0123456789-_.~");

    // 保留字符按大写十六进制编码；斜杠由 flag 决定是否编码。
    assert_eq!(percent_encode(" ", true), "%20");
    assert_eq!(percent_encode("+", true), "%2B");
    assert_eq!(percent_encode("=", true), "%3D");
    assert_eq!(percent_encode("#", true), "%23");
    assert_eq!(percent_encode("?", true), "%3F");
    assert_eq!(percent_encode("/", false), "/");
    assert_eq!(percent_encode("/", true), "%2F");
    assert_eq!(percent_encode("中", true), "%E4%B8%AD");

    // 规范化 URI：S3 规则不做二次编码（编码后的 `%` 不再被编码）。
    let key = key_for("dir/a b+c#d.txt");
    assert_eq!(canonical_uri_for_key(&key), "/dir/a%20b%2Bc%23d.txt");

    // 查询串按编码后键值排序。
    assert_eq!(
        canonical_query_string(&[
            ("list-type", "2"),
            ("encoding-type", "url"),
            ("prefix", "a b")
        ]),
        "encoding-type=url&list-type=2&prefix=a%20b"
    );

    // 空载荷摘要与 AWS 已知值一致（常量不得被改写）。
    assert_eq!(
        sha256_hex(b""),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(sha256_hex(b""), EMPTY_PAYLOAD_SHA256);
}
