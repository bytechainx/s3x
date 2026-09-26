#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::unreachable
)]
//! E2E（s3x）：在**本地 HTTP 桩**上端到端执行全部公开接口。
//!
//! 对齐对象是 `cargo +nightly public-api --simplified` 导出的完整公开面：
//! `fn` / `type` / `field` / `const` / `variant` 登记在 [`E2E_MANIFEST`]，
//! 运行期由 `cover` 核对「声明 = 实际执行」。
//!
//! **这不是真 AWS 资格证据。** 不把本文件绿测写成 T3/T4 PASS 或
//! `INTERNAL_PRODUCTION_RELEASED`。真连服用 `tests/live_s3.rs`（`#[ignore]`）。
//!
//! 独立核对：`scripts/verify-e2e-coverage.mjs s3x`。
//!
//! ```text
//! CARGO_TARGET_DIR=/home/workspace/bytechainx/.cargo/wt/s3x \\
//!   cargo test --test e2e_s3 -- --test-threads=1
//! ```

use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::time::Duration;

use bytes::Bytes;
use chrono::{TimeZone, Utc};
use futures_util::StreamExt;
use s3x::{
    authorization_header, aws_endpoint_for_region, backoff_delay, build_delete_objects_body,
    byte_stream_from_bytes, canonical_headers, canonical_query_string, canonical_request,
    canonical_uri_for_key, credential_scope, date_stamp, default_retry_config, hmac_sha256,
    is_s3_retryable, parse_delete_objects, parse_error_code_message, parse_list_objects_v2,
    percent_encode, presign_get, presign_put, presign_url, sha256_hex, sign_request, signing_key,
    string_to_sign, with_retry, with_retry_deadline, DownloadOptions, ObjectKey, ObjectMeta,
    PresignOptions, RetryConfig, S3Client, S3Config, S3ConfigBuilder, S3Error, S3Health, S3Result,
    SignRequest, Signature, UploadOptions, ALGORITHM, DEFAULT_BASE_DELAY_MS,
    DEFAULT_CONNECT_TIMEOUT_MS, DEFAULT_JITTER_RATIO, DEFAULT_MAX_ATTEMPTS, DEFAULT_MAX_DELAY_MS,
    DEFAULT_MAX_IN_FLIGHT, DEFAULT_MAX_RETRIES, DEFAULT_REGION, DEFAULT_REQUEST_TIMEOUT_MS,
    DEFAULT_USER_AGENT, EMPTY_PAYLOAD_SHA256, ENV_ACCESS_KEY_ID, ENV_ACCESS_KEY_SECRET,
    ENV_ALLOW_UNSIGNED_PAYLOAD_OVER_HTTP, ENV_BUCKET, ENV_CONNECT_TIMEOUT_MS, ENV_ENDPOINT,
    ENV_FORCE_PATH_STYLE, ENV_MAX_IN_FLIGHT, ENV_MAX_RETRIES, ENV_PREFIX, ENV_REGION,
    ENV_REQUEST_TIMEOUT_MS, ENV_SESSION_TOKEN, ENV_USER_AGENT, HARD_MAX_CONNECT_TIMEOUT_MS,
    HARD_MAX_DELAY_MS, HARD_MAX_IN_FLIGHT, HARD_MAX_PRESIGN_EXPIRES_SECS,
    HARD_MAX_REQUEST_TIMEOUT_MS, HARD_MAX_RETRIES, MAX_BUCKET_NAME_LEN, MAX_ERROR_BODY_BYTES,
    MAX_ERROR_MESSAGE_CHARS, MAX_LIST_KEYS, MAX_OBJECT_KEY_BYTES, MAX_RETRY_ATTEMPTS,
    MIN_BUCKET_NAME_LEN, PRESIGN_SIGNED_HEADERS, S3_SERVICE, TERMINATOR, UNSIGNED_PAYLOAD,
};

const E2E_MANIFEST: &[(&str, &str)] = &[
    ("type", "S3Error"),
    ("variant", "S3Error::Backend"),
    ("variant", "S3Error::Config"),
    ("variant", "S3Error::Connection"),
    ("variant", "S3Error::InvalidObjectKey"),
    ("variant", "S3Error::Io"),
    ("variant", "S3Error::Serialization"),
    ("variant", "S3Error::Timeout"),
    ("variant", "S3Error::Unsupported"),
    ("fn", "S3Error::is_retryable"),
    ("type", "CanonicalRequest"),
    ("field", "CanonicalRequest::canonical_request"),
    ("field", "CanonicalRequest::signed_headers"),
    ("type", "DeleteError"),
    ("field", "DeleteError::code"),
    ("field", "DeleteError::key"),
    ("field", "DeleteError::message"),
    ("type", "DeleteObjectsResult"),
    ("field", "DeleteObjectsResult::deleted"),
    ("field", "DeleteObjectsResult::errors"),
    ("type", "DownloadOptions"),
    ("field", "DownloadOptions::range"),
    ("fn", "DownloadOptions::range_header"),
    ("fn", "DownloadOptions::with_range"),
    ("type", "ListObjectsResult"),
    ("field", "ListObjectsResult::common_prefixes"),
    ("field", "ListObjectsResult::is_truncated"),
    ("field", "ListObjectsResult::keys"),
    ("field", "ListObjectsResult::next_continuation_token"),
    ("type", "ObjectKey"),
    ("fn", "ObjectKey::as_str"),
    ("fn", "ObjectKey::new"),
    ("type", "ObjectMeta"),
    ("field", "ObjectMeta::content_type"),
    ("field", "ObjectMeta::etag"),
    ("field", "ObjectMeta::key"),
    ("field", "ObjectMeta::last_modified"),
    ("field", "ObjectMeta::size"),
    ("fn", "ObjectMeta::new"),
    ("fn", "ObjectMeta::with_content_type"),
    ("fn", "ObjectMeta::with_etag"),
    ("fn", "ObjectMeta::with_last_modified"),
    ("fn", "ObjectMeta::with_size"),
    ("type", "PresignOptions"),
    ("field", "PresignOptions::expires_in_secs"),
    ("field", "PresignOptions::method"),
    ("field", "PresignOptions::now"),
    ("fn", "PresignOptions::at"),
    ("fn", "PresignOptions::get"),
    ("fn", "PresignOptions::put"),
    ("type", "RetryConfig"),
    ("field", "RetryConfig::base_delay_ms"),
    ("field", "RetryConfig::jitter_ratio"),
    ("field", "RetryConfig::max_attempts"),
    ("field", "RetryConfig::max_delay_ms"),
    ("fn", "RetryConfig::new"),
    ("fn", "RetryConfig::validate"),
    ("fn", "RetryConfig::with_jitter_ratio"),
    ("fn", "RetryConfig::with_max_delay_ms"),
    ("type", "S3Client"),
    ("fn", "S3Client::config"),
    ("fn", "S3Client::connect"),
    ("fn", "S3Client::connect_from_env"),
    ("fn", "S3Client::delete_object"),
    ("fn", "S3Client::get_object"),
    ("fn", "S3Client::get_object_bytes"),
    ("fn", "S3Client::head_object"),
    ("fn", "S3Client::health_check"),
    ("fn", "S3Client::list_objects_v2"),
    ("fn", "S3Client::new"),
    ("fn", "S3Client::ping"),
    ("fn", "S3Client::put_object"),
    ("fn", "S3Client::put_object_stream"),
    ("type", "S3Config"),
    ("field", "S3Config::access_key_id"),
    ("field", "S3Config::access_key_secret"),
    ("field", "S3Config::allow_unsigned_payload_over_http"),
    ("field", "S3Config::bucket"),
    ("field", "S3Config::connect_timeout_ms"),
    ("field", "S3Config::endpoint"),
    ("field", "S3Config::force_path_style"),
    ("field", "S3Config::max_in_flight"),
    ("field", "S3Config::max_retries"),
    ("field", "S3Config::region"),
    ("field", "S3Config::request_timeout_ms"),
    ("field", "S3Config::session_token"),
    ("field", "S3Config::user_agent"),
    ("fn", "S3Config::bucket_url"),
    ("fn", "S3Config::effective_endpoint"),
    ("fn", "S3Config::endpoint_is_plain_http"),
    ("fn", "S3Config::object_url"),
    ("fn", "S3Config::service"),
    ("fn", "S3Config::builder"),
    ("fn", "S3Config::from_env"),
    ("fn", "S3Config::from_toml"),
    ("fn", "S3Config::validate"),
    ("type", "S3ConfigBuilder"),
    ("fn", "S3ConfigBuilder::access_key_id"),
    ("fn", "S3ConfigBuilder::access_key_secret"),
    ("fn", "S3ConfigBuilder::allow_unsigned_payload_over_http"),
    ("fn", "S3ConfigBuilder::aws_endpoint"),
    ("fn", "S3ConfigBuilder::bucket"),
    ("fn", "S3ConfigBuilder::build"),
    ("fn", "S3ConfigBuilder::connect_timeout"),
    ("fn", "S3ConfigBuilder::endpoint"),
    ("fn", "S3ConfigBuilder::force_path_style"),
    ("fn", "S3ConfigBuilder::from_config"),
    ("fn", "S3ConfigBuilder::max_in_flight"),
    ("fn", "S3ConfigBuilder::max_retries"),
    ("fn", "S3ConfigBuilder::new"),
    ("fn", "S3ConfigBuilder::region"),
    ("fn", "S3ConfigBuilder::request_timeout"),
    ("fn", "S3ConfigBuilder::session_token"),
    ("fn", "S3ConfigBuilder::user_agent"),
    ("type", "S3Health"),
    ("field", "S3Health::bucket"),
    ("field", "S3Health::endpoint"),
    ("field", "S3Health::healthy"),
    ("field", "S3Health::latency_ms"),
    ("type", "SignRequest"),
    ("field", "SignRequest::access_key_id"),
    ("field", "SignRequest::amz_date"),
    ("field", "SignRequest::canonical_uri"),
    ("field", "SignRequest::headers"),
    ("field", "SignRequest::method"),
    ("field", "SignRequest::payload_hash"),
    ("field", "SignRequest::query"),
    ("field", "SignRequest::region"),
    ("field", "SignRequest::secret_access_key"),
    ("field", "SignRequest::service"),
    ("fn", "SignRequest"),
    ("type", "Signature"),
    ("field", "Signature::authorization"),
    ("field", "Signature::canonical_request"),
    ("field", "Signature::credential_scope"),
    ("field", "Signature::signature"),
    ("field", "Signature::signed_headers"),
    ("field", "Signature::string_to_sign"),
    ("type", "UploadOptions"),
    ("field", "UploadOptions::content_type"),
    ("field", "UploadOptions::metadata"),
    ("field", "UploadOptions::storage_class"),
    ("fn", "UploadOptions::push_metadata"),
    ("fn", "UploadOptions::with_content_type"),
    ("fn", "UploadOptions::with_metadata"),
    ("fn", "UploadOptions::with_storage_class"),
    ("const", "ALGORITHM"),
    ("const", "DEFAULT_BASE_DELAY_MS"),
    ("const", "DEFAULT_CONNECT_TIMEOUT_MS"),
    ("const", "DEFAULT_JITTER_RATIO"),
    ("const", "DEFAULT_MAX_ATTEMPTS"),
    ("const", "DEFAULT_MAX_DELAY_MS"),
    ("const", "DEFAULT_MAX_IN_FLIGHT"),
    ("const", "DEFAULT_MAX_RETRIES"),
    ("const", "DEFAULT_REGION"),
    ("const", "DEFAULT_REQUEST_TIMEOUT_MS"),
    ("const", "DEFAULT_USER_AGENT"),
    ("const", "EMPTY_PAYLOAD_SHA256"),
    ("const", "ENV_ACCESS_KEY_ID"),
    ("const", "ENV_ACCESS_KEY_SECRET"),
    ("const", "ENV_ALLOW_UNSIGNED_PAYLOAD_OVER_HTTP"),
    ("const", "ENV_BUCKET"),
    ("const", "ENV_CONNECT_TIMEOUT_MS"),
    ("const", "ENV_ENDPOINT"),
    ("const", "ENV_FORCE_PATH_STYLE"),
    ("const", "ENV_MAX_IN_FLIGHT"),
    ("const", "ENV_MAX_RETRIES"),
    ("const", "ENV_PREFIX"),
    ("const", "ENV_REGION"),
    ("const", "ENV_REQUEST_TIMEOUT_MS"),
    ("const", "ENV_SESSION_TOKEN"),
    ("const", "ENV_USER_AGENT"),
    ("const", "HARD_MAX_CONNECT_TIMEOUT_MS"),
    ("const", "HARD_MAX_DELAY_MS"),
    ("const", "HARD_MAX_IN_FLIGHT"),
    ("const", "HARD_MAX_PRESIGN_EXPIRES_SECS"),
    ("const", "HARD_MAX_REQUEST_TIMEOUT_MS"),
    ("const", "HARD_MAX_RETRIES"),
    ("const", "MAX_BUCKET_NAME_LEN"),
    ("const", "MAX_ERROR_BODY_BYTES"),
    ("const", "MAX_ERROR_MESSAGE_CHARS"),
    ("const", "MAX_LIST_KEYS"),
    ("const", "MAX_OBJECT_KEY_BYTES"),
    ("const", "MAX_RETRY_ATTEMPTS"),
    ("const", "MIN_BUCKET_NAME_LEN"),
    ("const", "PRESIGN_SIGNED_HEADERS"),
    ("const", "S3_SERVICE"),
    ("const", "TERMINATOR"),
    ("const", "UNSIGNED_PAYLOAD"),
    ("fn", "authorization_header"),
    ("fn", "aws_endpoint_for_region"),
    ("fn", "backoff_delay"),
    ("fn", "build_delete_objects_body"),
    ("fn", "byte_stream_from_bytes"),
    ("fn", "canonical_headers"),
    ("fn", "canonical_query_string"),
    ("fn", "canonical_request"),
    ("fn", "canonical_uri_for_key"),
    ("fn", "credential_scope"),
    ("fn", "date_stamp"),
    ("fn", "default_retry_config"),
    ("fn", "hmac_sha256"),
    ("fn", "is_s3_retryable"),
    ("fn", "parse_delete_objects"),
    ("fn", "parse_error_code_message"),
    ("fn", "parse_list_objects_v2"),
    ("fn", "percent_encode"),
    ("fn", "presign_get"),
    ("fn", "presign_put"),
    ("fn", "presign_url"),
    ("fn", "sha256_hex"),
    ("fn", "sign_request"),
    ("fn", "signing_key"),
    ("fn", "string_to_sign"),
    ("fn", "with_retry"),
    ("fn", "with_retry_deadline"),
    ("type", "ByteStream"),
    ("type", "S3Result"),
];

mod cover {
    use super::E2E_MANIFEST;
    use std::collections::BTreeSet;
    use std::sync::{Mutex, OnceLock};

    fn log() -> &'static Mutex<BTreeSet<(&'static str, &'static str)>> {
        static LOG: OnceLock<Mutex<BTreeSet<(&'static str, &'static str)>>> = OnceLock::new();
        LOG.get_or_init(|| Mutex::new(BTreeSet::new()))
    }

    pub fn hit(kind: &'static str, id: &'static str) {
        assert!(
            E2E_MANIFEST
                .iter()
                .any(|(declared_kind, declared_id)| *declared_kind == kind && *declared_id == id),
            "登记了清单外的公开条目：{kind} {id}"
        );
        log().lock().expect("覆盖登记表锁中毒").insert((kind, id));
    }

    pub fn executed() -> BTreeSet<(&'static str, &'static str)> {
        log().lock().expect("覆盖登记表锁中毒").clone()
    }
}

fn hit(kind: &'static str, id: &'static str) {
    cover::hit(kind, id);
}

fn assert_manifest_wellformed() {
    let mut seen: BTreeSet<(&str, &str)> = BTreeSet::new();
    for (kind, id) in E2E_MANIFEST {
        assert!(
            matches!(*kind, "fn" | "type" | "field" | "const" | "variant"),
            "未知条目类别 {kind}（id={id}）"
        );
        assert!(seen.insert((kind, id)), "清单重复条目：{kind} {id}");
    }
    assert!(!E2E_MANIFEST.is_empty(), "清单不得为空");
}

fn assert_coverage_complete() {
    let declared: BTreeSet<(&str, &str)> = E2E_MANIFEST.iter().copied().collect();
    let executed = cover::executed();
    let missing: Vec<&(&str, &str)> = declared.difference(&executed).collect();
    let ghost: Vec<&(&str, &str)> = executed.difference(&declared).collect();
    assert!(
        missing.is_empty(),
        "以下 {} 条公开条目被声明却未执行：{missing:?}",
        missing.len()
    );
    assert!(
        ghost.is_empty(),
        "以下 {} 条执行未登记在清单：{ghost:?}",
        ghost.len()
    );
    eprintln!(
        "E2E 覆盖：{}/{} 条公开条目全部执行（s3x / 离线桩，≠ AWS PASS）",
        executed.len(),
        declared.len()
    );
}

const EMPTY_LIST: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
<ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"></ListBucketResult>";

fn serve_ok(bodies: Vec<&'static str>) -> (String, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("绑定本地端口必须成功");
    let addr = listener.local_addr().expect("读取本地地址");
    let handle = std::thread::spawn(move || {
        for body in bodies {
            let Ok((mut stream, _)) = listener.accept() else {
                break;
            };
            let _ = stream.set_read_timeout(Some(Duration::from_millis(800)));
            let mut buffer = [0_u8; 16384];
            let _ = stream.read(&mut buffer);
            let response = format!(
                "HTTP/1.1 200 OK\r\netag: \"e2e\"\r\ncontent-length: {}\r\ncontent-type: text/plain\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
        }
    });
    (format!("http://{addr}"), handle)
}

fn phase_constants() {
    let pairs = [
        ("ENV_PREFIX", ENV_PREFIX),
        ("ENV_ENDPOINT", ENV_ENDPOINT),
        ("ENV_REGION", ENV_REGION),
        ("ENV_BUCKET", ENV_BUCKET),
        ("ENV_ACCESS_KEY_ID", ENV_ACCESS_KEY_ID),
        ("ENV_ACCESS_KEY_SECRET", ENV_ACCESS_KEY_SECRET),
        ("ENV_SESSION_TOKEN", ENV_SESSION_TOKEN),
        ("ENV_FORCE_PATH_STYLE", ENV_FORCE_PATH_STYLE),
        (
            "ENV_ALLOW_UNSIGNED_PAYLOAD_OVER_HTTP",
            ENV_ALLOW_UNSIGNED_PAYLOAD_OVER_HTTP,
        ),
        ("ENV_REQUEST_TIMEOUT_MS", ENV_REQUEST_TIMEOUT_MS),
        ("ENV_CONNECT_TIMEOUT_MS", ENV_CONNECT_TIMEOUT_MS),
        ("ENV_MAX_RETRIES", ENV_MAX_RETRIES),
        ("ENV_MAX_IN_FLIGHT", ENV_MAX_IN_FLIGHT),
        ("ENV_USER_AGENT", ENV_USER_AGENT),
    ];
    for (id, value) in pairs {
        hit("const", id);
        assert!(value.starts_with(ENV_PREFIX), "{id} 必须带前缀");
    }
    hit("const", "DEFAULT_REGION");
    assert_eq!(DEFAULT_REGION, "us-east-1");
    hit("const", "DEFAULT_REQUEST_TIMEOUT_MS");
    assert_eq!(DEFAULT_REQUEST_TIMEOUT_MS, 30_000);
    hit("const", "DEFAULT_CONNECT_TIMEOUT_MS");
    assert_eq!(DEFAULT_CONNECT_TIMEOUT_MS, 5_000);
    hit("const", "DEFAULT_MAX_RETRIES");
    assert_eq!(DEFAULT_MAX_RETRIES, 3);
    hit("const", "DEFAULT_MAX_IN_FLIGHT");
    assert_eq!(DEFAULT_MAX_IN_FLIGHT, 64);
    hit("const", "DEFAULT_USER_AGENT");
    assert!(DEFAULT_USER_AGENT.starts_with("s3x/"));
    hit("const", "HARD_MAX_REQUEST_TIMEOUT_MS");
    assert_eq!(HARD_MAX_REQUEST_TIMEOUT_MS, 600_000);
    hit("const", "HARD_MAX_CONNECT_TIMEOUT_MS");
    assert_eq!(HARD_MAX_CONNECT_TIMEOUT_MS, 60_000);
    hit("const", "HARD_MAX_RETRIES");
    assert_eq!(HARD_MAX_RETRIES, 10);
    hit("const", "HARD_MAX_IN_FLIGHT");
    assert_eq!(HARD_MAX_IN_FLIGHT, 1_024);
    hit("const", "MIN_BUCKET_NAME_LEN");
    assert_eq!(MIN_BUCKET_NAME_LEN, 3);
    hit("const", "MAX_BUCKET_NAME_LEN");
    assert_eq!(MAX_BUCKET_NAME_LEN, 63);
    hit("const", "MAX_OBJECT_KEY_BYTES");
    assert_eq!(MAX_OBJECT_KEY_BYTES, 1024);
    hit("const", "MAX_ERROR_BODY_BYTES");
    assert_eq!(MAX_ERROR_BODY_BYTES, 4096);
    hit("const", "MAX_ERROR_MESSAGE_CHARS");
    assert_eq!(MAX_ERROR_MESSAGE_CHARS, 512);
    hit("const", "MAX_LIST_KEYS");
    assert_eq!(MAX_LIST_KEYS, 1_000);
    hit("const", "HARD_MAX_PRESIGN_EXPIRES_SECS");
    assert_eq!(HARD_MAX_PRESIGN_EXPIRES_SECS, 604_800);
    hit("const", "PRESIGN_SIGNED_HEADERS");
    assert_eq!(PRESIGN_SIGNED_HEADERS, "host");
    hit("const", "ALGORITHM");
    assert_eq!(ALGORITHM, "AWS4-HMAC-SHA256");
    hit("const", "TERMINATOR");
    assert_eq!(TERMINATOR, "aws4_request");
    hit("const", "S3_SERVICE");
    assert_eq!(S3_SERVICE, "s3");
    hit("const", "UNSIGNED_PAYLOAD");
    assert_eq!(UNSIGNED_PAYLOAD, "UNSIGNED-PAYLOAD");
    hit("const", "EMPTY_PAYLOAD_SHA256");
    assert_eq!(EMPTY_PAYLOAD_SHA256, sha256_hex(b""));
    hit("const", "MAX_RETRY_ATTEMPTS");
    assert_eq!(MAX_RETRY_ATTEMPTS, 10);
    hit("const", "DEFAULT_MAX_ATTEMPTS");
    assert_eq!(DEFAULT_MAX_ATTEMPTS, 3);
    hit("const", "DEFAULT_BASE_DELAY_MS");
    assert_eq!(DEFAULT_BASE_DELAY_MS, 100);
    hit("const", "DEFAULT_MAX_DELAY_MS");
    assert_eq!(DEFAULT_MAX_DELAY_MS, 5_000);
    hit("const", "DEFAULT_JITTER_RATIO");
    assert_eq!(DEFAULT_JITTER_RATIO, 0.2);
    hit("const", "HARD_MAX_DELAY_MS");
    assert_eq!(HARD_MAX_DELAY_MS, 60_000);
}

fn phase_errors() {
    hit("type", "S3Error");
    hit("type", "S3Result");
    let config = S3Error::Config("bad".into());
    hit("variant", "S3Error::Config");
    let connection = S3Error::Connection("down".into());
    hit("variant", "S3Error::Connection");
    let serialization = S3Error::Serialization("xml".into());
    hit("variant", "S3Error::Serialization");
    let timeout = S3Error::Timeout("late".into());
    hit("variant", "S3Error::Timeout");
    let unsupported = S3Error::Unsupported("no".into());
    hit("variant", "S3Error::Unsupported");
    let invalid = S3Error::InvalidObjectKey("..".into());
    hit("variant", "S3Error::InvalidObjectKey");
    let io = S3Error::from(std::io::Error::other("io"));
    hit("variant", "S3Error::Io");
    let backend = S3Error::Backend {
        status: 503,
        code: Some("SlowDown".into()),
        message: "slow".into(),
    };
    hit("variant", "S3Error::Backend");
    match &backend {
        S3Error::Backend {
            status,
            code,
            message,
        } => {
            assert_eq!(*status, 503);
            assert_eq!(code.as_deref(), Some("SlowDown"));
            assert_eq!(message, "slow");
        }
        _ => panic!("必须是 Backend"),
    }
    hit("fn", "S3Error::is_retryable");
    assert!(backend.is_retryable());
    assert!(connection.is_retryable());
    assert!(timeout.is_retryable());
    assert!(io.is_retryable());
    assert!(!config.is_retryable());
    assert!(!serialization.is_retryable());
    assert!(!unsupported.is_retryable());
    assert!(!invalid.is_retryable());
    hit("fn", "is_s3_retryable");
    assert!(is_s3_retryable(&backend));
    let _: S3Result<()> = Err(config);
}

fn phase_value_types() {
    hit("type", "ObjectKey");
    hit("fn", "ObjectKey::new");
    let key = ObjectKey::new("e2e/a.txt").expect("合法键");
    hit("fn", "ObjectKey::as_str");
    assert_eq!(key.as_str(), "e2e/a.txt");

    hit("type", "ObjectMeta");
    hit("fn", "ObjectMeta::new");
    hit("fn", "ObjectMeta::with_size");
    hit("fn", "ObjectMeta::with_etag");
    hit("fn", "ObjectMeta::with_last_modified");
    hit("fn", "ObjectMeta::with_content_type");
    let meta = ObjectMeta::new("k")
        .with_size(3)
        .with_etag("etag")
        .with_last_modified("now")
        .with_content_type("text/plain");
    let ObjectMeta {
        key: meta_key,
        size,
        etag,
        last_modified,
        content_type,
    } = meta;
    hit("field", "ObjectMeta::key");
    hit("field", "ObjectMeta::size");
    hit("field", "ObjectMeta::etag");
    hit("field", "ObjectMeta::last_modified");
    hit("field", "ObjectMeta::content_type");
    assert_eq!(meta_key, "k");
    assert_eq!(size, 3);
    assert_eq!(etag.as_deref(), Some("etag"));
    assert_eq!(last_modified.as_deref(), Some("now"));
    assert_eq!(content_type.as_deref(), Some("text/plain"));

    hit("type", "UploadOptions");
    hit("fn", "UploadOptions::with_content_type");
    hit("fn", "UploadOptions::with_metadata");
    hit("fn", "UploadOptions::push_metadata");
    hit("fn", "UploadOptions::with_storage_class");
    let upload = UploadOptions::default()
        .with_content_type("text/csv")
        .with_metadata(vec![("a".into(), "1".into())])
        .push_metadata("b", "2")
        .with_storage_class("STANDARD");
    let UploadOptions {
        content_type: up_ct,
        metadata,
        storage_class,
    } = upload;
    hit("field", "UploadOptions::content_type");
    hit("field", "UploadOptions::metadata");
    hit("field", "UploadOptions::storage_class");
    assert_eq!(up_ct.as_deref(), Some("text/csv"));
    assert_eq!(metadata.as_ref().map(Vec::len), Some(2));
    assert_eq!(storage_class.as_deref(), Some("STANDARD"));

    hit("type", "DownloadOptions");
    hit("fn", "DownloadOptions::with_range");
    let download = DownloadOptions::with_range(0, 1);
    hit("fn", "DownloadOptions::range_header");
    assert_eq!(download.range_header().as_deref(), Some("bytes=0-1"));
    let DownloadOptions { range } = download;
    hit("field", "DownloadOptions::range");
    assert_eq!(range, Some((0, 1)));

    hit("type", "RetryConfig");
    hit("fn", "RetryConfig::new");
    hit("fn", "RetryConfig::with_max_delay_ms");
    hit("fn", "RetryConfig::with_jitter_ratio");
    let retry = RetryConfig::new(2, 10)
        .with_max_delay_ms(20)
        .with_jitter_ratio(0.0);
    hit("fn", "RetryConfig::validate");
    retry.validate().expect("合法重试配置");
    let RetryConfig {
        max_attempts,
        base_delay_ms,
        max_delay_ms,
        jitter_ratio,
    } = retry;
    hit("field", "RetryConfig::max_attempts");
    hit("field", "RetryConfig::base_delay_ms");
    hit("field", "RetryConfig::max_delay_ms");
    hit("field", "RetryConfig::jitter_ratio");
    assert_eq!(max_attempts, 2);
    assert_eq!(base_delay_ms, 10);
    assert_eq!(max_delay_ms, 20);
    assert_eq!(jitter_ratio, 0.0);

    hit("type", "PresignOptions");
    hit("fn", "PresignOptions::get");
    hit("fn", "PresignOptions::put");
    hit("fn", "PresignOptions::at");
    let now = Utc.with_ymd_and_hms(2015, 8, 30, 12, 36, 0).unwrap();
    let opts = PresignOptions::get(60).at(now);
    let _put = PresignOptions::put(30);
    let PresignOptions {
        method,
        expires_in_secs,
        now: now_field,
    } = opts;
    hit("field", "PresignOptions::method");
    hit("field", "PresignOptions::expires_in_secs");
    hit("field", "PresignOptions::now");
    assert_eq!(method, "GET");
    assert_eq!(expires_in_secs, 60);
    assert_eq!(now_field, Some(now));

    hit("type", "ByteStream");
    hit("fn", "byte_stream_from_bytes");
    let stream: s3x::ByteStream = byte_stream_from_bytes(Bytes::from_static(b"x"));
    drop(stream);
}

fn phase_config() {
    hit("type", "S3ConfigBuilder");
    hit("fn", "S3ConfigBuilder::new");
    let _standalone = S3ConfigBuilder::new();
    hit("fn", "S3Config::builder");
    hit("fn", "S3ConfigBuilder::endpoint");
    hit("fn", "S3ConfigBuilder::aws_endpoint");
    hit("fn", "S3ConfigBuilder::region");
    hit("fn", "S3ConfigBuilder::bucket");
    hit("fn", "S3ConfigBuilder::access_key_id");
    hit("fn", "S3ConfigBuilder::access_key_secret");
    hit("fn", "S3ConfigBuilder::session_token");
    hit("fn", "S3ConfigBuilder::force_path_style");
    hit("fn", "S3ConfigBuilder::allow_unsigned_payload_over_http");
    hit("fn", "S3ConfigBuilder::request_timeout");
    hit("fn", "S3ConfigBuilder::connect_timeout");
    hit("fn", "S3ConfigBuilder::max_retries");
    hit("fn", "S3ConfigBuilder::max_in_flight");
    hit("fn", "S3ConfigBuilder::user_agent");
    hit("fn", "S3ConfigBuilder::build");
    let built = S3Config::builder()
        .aws_endpoint()
        .endpoint("https://s3.example.test")
        .region("eu-west-1")
        .bucket("examplebucket")
        .access_key_id("AKID")
        .access_key_secret("SECRET")
        .session_token("TOKEN")
        .force_path_style(true)
        .allow_unsigned_payload_over_http(true)
        .request_timeout(Duration::from_millis(400))
        .connect_timeout(Some(Duration::from_millis(200)))
        .max_retries(1)
        .max_in_flight(4)
        .user_agent("s3x-e2e")
        .build()
        .expect("构建必须成功");
    hit("fn", "S3ConfigBuilder::from_config");
    let _again = S3ConfigBuilder::from_config(built.clone())
        .build()
        .expect("from_config 必须成功");

    hit("type", "S3Config");
    hit("fn", "S3Config::validate");
    built.validate().expect("配置必须合法");
    hit("fn", "S3Config::effective_endpoint");
    hit("fn", "S3Config::endpoint_is_plain_http");
    hit("fn", "S3Config::bucket_url");
    hit("fn", "S3Config::object_url");
    hit("fn", "S3Config::service");
    let key = ObjectKey::new("k").expect("合法键");
    assert!(!built.effective_endpoint().is_empty());
    assert!(!built.endpoint_is_plain_http());
    assert!(built.bucket_url().contains("examplebucket"));
    assert!(built.object_url(&key).contains("/k"));
    assert_eq!(built.service(), S3_SERVICE);

    let S3Config {
        endpoint,
        region,
        bucket,
        access_key_id,
        access_key_secret,
        session_token,
        force_path_style,
        allow_unsigned_payload_over_http,
        request_timeout_ms,
        connect_timeout_ms,
        max_retries,
        max_in_flight,
        user_agent,
    } = built;
    hit("field", "S3Config::endpoint");
    hit("field", "S3Config::region");
    hit("field", "S3Config::bucket");
    hit("field", "S3Config::access_key_id");
    hit("field", "S3Config::access_key_secret");
    hit("field", "S3Config::session_token");
    hit("field", "S3Config::force_path_style");
    hit("field", "S3Config::allow_unsigned_payload_over_http");
    hit("field", "S3Config::request_timeout_ms");
    hit("field", "S3Config::connect_timeout_ms");
    hit("field", "S3Config::max_retries");
    hit("field", "S3Config::max_in_flight");
    hit("field", "S3Config::user_agent");
    assert!(endpoint.is_some());
    assert_eq!(region, "eu-west-1");
    assert_eq!(bucket, "examplebucket");
    assert_eq!(access_key_id, "AKID");
    assert_eq!(access_key_secret, "SECRET");
    assert_eq!(session_token.as_deref(), Some("TOKEN"));
    assert!(force_path_style);
    assert!(allow_unsigned_payload_over_http);
    assert_eq!(request_timeout_ms, 400);
    assert_eq!(connect_timeout_ms, 200);
    assert_eq!(max_retries, 1);
    assert_eq!(max_in_flight, 4);
    assert_eq!(user_agent, "s3x-e2e");

    hit("fn", "S3Config::from_toml");
    let toml = S3Config::from_toml(
        "bucket = \"examplebucket\"\nregion = \"us-east-1\"\naccess_key_id = \"AKID\"\n",
    )
    .expect("不含 secret 的 TOML 必须可解析");
    assert_eq!(toml.bucket, "examplebucket");
    let secret_err =
        S3Config::from_toml("access_key_secret = \"x\"\n").expect_err("TOML 必须拒凭据");
    assert!(matches!(secret_err, S3Error::Config(_)));
}

fn phase_env_and_connect() {
    let keys = [
        ENV_ENDPOINT,
        ENV_REGION,
        ENV_BUCKET,
        ENV_ACCESS_KEY_ID,
        ENV_ACCESS_KEY_SECRET,
        ENV_SESSION_TOKEN,
        ENV_FORCE_PATH_STYLE,
        ENV_ALLOW_UNSIGNED_PAYLOAD_OVER_HTTP,
        ENV_REQUEST_TIMEOUT_MS,
        ENV_CONNECT_TIMEOUT_MS,
        ENV_MAX_RETRIES,
        ENV_MAX_IN_FLIGHT,
        ENV_USER_AGENT,
    ];
    let previous: Vec<(String, Option<String>)> = keys
        .iter()
        .map(|k| ((*k).to_owned(), std::env::var(k).ok()))
        .collect();
    std::env::set_var(ENV_ENDPOINT, "http://127.0.0.1:9");
    std::env::set_var(ENV_REGION, "us-east-1");
    std::env::set_var(ENV_BUCKET, "examplebucket");
    std::env::set_var(ENV_ACCESS_KEY_ID, "AKID");
    std::env::set_var(ENV_ACCESS_KEY_SECRET, "SECRET");
    std::env::set_var(ENV_SESSION_TOKEN, "TOKEN");
    std::env::set_var(ENV_FORCE_PATH_STYLE, "true");
    std::env::set_var(ENV_ALLOW_UNSIGNED_PAYLOAD_OVER_HTTP, "true");
    std::env::set_var(ENV_REQUEST_TIMEOUT_MS, "400");
    std::env::set_var(ENV_CONNECT_TIMEOUT_MS, "200");
    std::env::set_var(ENV_MAX_RETRIES, "1");
    std::env::set_var(ENV_MAX_IN_FLIGHT, "2");
    std::env::set_var(ENV_USER_AGENT, "s3x-e2e-env");
    hit("fn", "S3Config::from_env");
    let from_env = S3Config::from_env().expect("环境变量配置必须成功");
    assert_eq!(from_env.bucket, "examplebucket");
    for (key, old) in previous {
        match old {
            Some(value) => std::env::set_var(&key, value),
            None => {
                std::env::remove_var(&key);
            }
        }
    }
}

fn phase_sign_presign_xml(config: &S3Config, key: &ObjectKey) {
    hit("fn", "percent_encode");
    assert_eq!(percent_encode("a b", true), "a%20b");
    hit("fn", "sha256_hex");
    hit("fn", "hmac_sha256");
    assert!(!hmac_sha256(b"k", b"m").is_empty());
    hit("fn", "signing_key");
    assert_eq!(
        signing_key(
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            "20150830",
            "us-east-1",
            "s3"
        )
        .len(),
        32
    );
    hit("fn", "date_stamp");
    assert_eq!(date_stamp("20150830T123600Z"), "20150830");
    hit("fn", "canonical_query_string");
    assert!(!canonical_query_string(&[("b", "2"), ("a", "1")]).is_empty());
    hit("fn", "canonical_headers");
    let (block, signed) = canonical_headers(&[("Host", "s3.amazonaws.com")]);
    assert!(block.contains("host:"));
    assert_eq!(signed, "host");
    hit("fn", "canonical_request");
    hit("type", "CanonicalRequest");
    let cr = canonical_request(
        "GET",
        "/",
        &[],
        &[("host", "s3.amazonaws.com")],
        EMPTY_PAYLOAD_SHA256,
    );
    let s3x::CanonicalRequest {
        canonical_request: cr_text,
        signed_headers,
    } = cr;
    hit("field", "CanonicalRequest::canonical_request");
    hit("field", "CanonicalRequest::signed_headers");
    assert!(cr_text.contains("GET"));
    assert_eq!(signed_headers, "host");
    hit("fn", "credential_scope");
    hit("fn", "string_to_sign");
    let scope = credential_scope("20150830", "us-east-1", S3_SERVICE);
    let sts = string_to_sign("20150830T123600Z", &scope, &cr_text);
    assert!(sts.starts_with(ALGORITHM));
    hit("fn", "authorization_header");
    assert!(
        authorization_header("AKID", "20150830", "us-east-1", S3_SERVICE, "host", "00")
            .contains("Signature=")
    );
    hit("fn", "canonical_uri_for_key");
    assert_eq!(canonical_uri_for_key(key), "/e2e/a.txt");
    hit("fn", "aws_endpoint_for_region");
    assert!(aws_endpoint_for_region("us-east-1").contains("amazonaws.com"));

    hit("type", "SignRequest");
    hit("fn", "SignRequest");
    let req = SignRequest {
        method: "GET",
        canonical_uri: "/",
        query: &[],
        headers: &[("host", "s3.amazonaws.com")],
        payload_hash: EMPTY_PAYLOAD_SHA256,
        amz_date: "20150830T123600Z",
        region: "us-east-1",
        service: S3_SERVICE,
        access_key_id: "AKID",
        secret_access_key: "SECRET",
    };
    hit("field", "SignRequest::method");
    hit("field", "SignRequest::canonical_uri");
    hit("field", "SignRequest::query");
    hit("field", "SignRequest::headers");
    hit("field", "SignRequest::payload_hash");
    hit("field", "SignRequest::amz_date");
    hit("field", "SignRequest::region");
    hit("field", "SignRequest::service");
    hit("field", "SignRequest::access_key_id");
    hit("field", "SignRequest::secret_access_key");
    assert_eq!(req.method, "GET");
    hit("fn", "sign_request");
    hit("type", "Signature");
    let Signature {
        authorization,
        canonical_request,
        signed_headers: sig_headers,
        string_to_sign,
        signature,
        credential_scope,
    } = sign_request(&req);
    hit("field", "Signature::authorization");
    hit("field", "Signature::canonical_request");
    hit("field", "Signature::signed_headers");
    hit("field", "Signature::string_to_sign");
    hit("field", "Signature::signature");
    hit("field", "Signature::credential_scope");
    assert!(authorization.contains("AWS4-HMAC-SHA256"));
    assert!(!canonical_request.is_empty());
    assert_eq!(sig_headers, "host");
    assert!(!string_to_sign.is_empty());
    assert_eq!(signature.len(), 64);
    assert!(credential_scope.contains("s3"));

    hit("fn", "presign_get");
    hit("fn", "presign_put");
    hit("fn", "presign_url");
    let get = presign_get(config, key, 60).expect("HTTPS 预签名 GET");
    let put = presign_put(config, key, 60).expect("HTTPS 预签名 PUT");
    let custom = presign_url(config, key, &PresignOptions::get(90)).expect("presign_url");
    assert!(get.contains("X-Amz-Signature="));
    assert!(put.contains("X-Amz-Algorithm="));
    assert!(custom.contains("X-Amz-Expires="));

    hit("fn", "parse_error_code_message");
    let parsed =
        parse_error_code_message("<Error><Code>NoSuchKey</Code><Message>gone</Message></Error>");
    assert_eq!(parsed, Some(("NoSuchKey".into(), "gone".into())));
    hit("fn", "parse_list_objects_v2");
    hit("type", "ListObjectsResult");
    let list = parse_list_objects_v2(
        "<ListBucketResult><IsTruncated>true</IsTruncated>\
         <NextContinuationToken>n</NextContinuationToken>\
         <Contents><Key>a</Key><Size>2</Size></Contents>\
         <CommonPrefixes><Prefix>p/</Prefix></CommonPrefixes></ListBucketResult>",
    )
    .expect("list xml");
    let s3x::ListObjectsResult {
        is_truncated,
        next_continuation_token,
        keys,
        common_prefixes,
    } = list;
    hit("field", "ListObjectsResult::is_truncated");
    hit("field", "ListObjectsResult::next_continuation_token");
    hit("field", "ListObjectsResult::keys");
    hit("field", "ListObjectsResult::common_prefixes");
    assert!(is_truncated);
    assert_eq!(next_continuation_token.as_deref(), Some("n"));
    assert_eq!(keys.len(), 1);
    assert_eq!(common_prefixes, vec!["p/".to_owned()]);

    hit("fn", "build_delete_objects_body");
    let body = build_delete_objects_body(std::slice::from_ref(key));
    assert!(body.contains(key.as_str()));
    hit("fn", "parse_delete_objects");
    hit("type", "DeleteObjectsResult");
    hit("type", "DeleteError");
    let deleted = parse_delete_objects(
        "<DeleteResult><Deleted><Key>a</Key></Deleted>\
         <Error><Key>b</Key><Code>AccessDenied</Code><Message>no</Message></Error></DeleteResult>",
    )
    .expect("delete xml");
    let s3x::DeleteObjectsResult { deleted, errors } = deleted;
    hit("field", "DeleteObjectsResult::deleted");
    hit("field", "DeleteObjectsResult::errors");
    assert_eq!(deleted, vec!["a".to_owned()]);
    let s3x::DeleteError {
        key: err_key,
        code,
        message,
    } = errors.into_iter().next().expect("一条失败");
    hit("field", "DeleteError::key");
    hit("field", "DeleteError::code");
    hit("field", "DeleteError::message");
    assert_eq!(err_key, "b");
    assert_eq!(code, "AccessDenied");
    assert_eq!(message, "no");
}

async fn phase_retry() {
    hit("fn", "default_retry_config");
    let retry = default_retry_config();
    hit("fn", "backoff_delay");
    assert!(backoff_delay(&retry, 1).as_millis() > 0);
    hit("fn", "with_retry");
    let ok = with_retry(&RetryConfig::new(1, 1), "e2e", || async {
        Ok::<_, S3Error>(7)
    })
    .await
    .expect("with_retry 成功");
    assert_eq!(ok, 7);
    hit("fn", "with_retry_deadline");
    let ok = with_retry_deadline(
        &RetryConfig::new(1, 1),
        "e2e",
        Duration::from_secs(1),
        || async { Ok::<_, S3Error>(8) },
    )
    .await
    .expect("with_retry_deadline 成功");
    assert_eq!(ok, 8);
}

async fn phase_client(endpoint: &str) {
    let config = S3Config::builder()
        .endpoint(endpoint)
        .region("us-east-1")
        .bucket("examplebucket")
        .access_key_id("AKID")
        .access_key_secret("SECRET")
        .force_path_style(true)
        .allow_unsigned_payload_over_http(true)
        .max_retries(1)
        .request_timeout(Duration::from_millis(800))
        .connect_timeout(Some(Duration::from_millis(400)))
        .build()
        .expect("桩服务配置");
    hit("type", "S3Client");
    hit("fn", "S3Client::new");
    let client = S3Client::new(config.clone()).expect("new");
    hit("fn", "S3Client::connect");
    let connected = S3Client::connect(config.clone())
        .await
        .expect("connect 不联网");
    drop(connected);

    let keys = [
        ENV_ENDPOINT,
        ENV_REGION,
        ENV_BUCKET,
        ENV_ACCESS_KEY_ID,
        ENV_ACCESS_KEY_SECRET,
    ];
    let previous: Vec<(String, Option<String>)> = keys
        .iter()
        .map(|k| ((*k).to_owned(), std::env::var(k).ok()))
        .collect();
    std::env::set_var(ENV_ENDPOINT, endpoint);
    std::env::set_var(ENV_REGION, "us-east-1");
    std::env::set_var(ENV_BUCKET, "examplebucket");
    std::env::set_var(ENV_ACCESS_KEY_ID, "AKID");
    std::env::set_var(ENV_ACCESS_KEY_SECRET, "SECRET");
    hit("fn", "S3Client::connect_from_env");
    let from_env = S3Client::connect_from_env()
        .await
        .expect("connect_from_env");
    drop(from_env);
    for (key, old) in previous {
        match old {
            Some(value) => std::env::set_var(&key, value),
            None => std::env::remove_var(&key),
        }
    }

    hit("fn", "S3Client::config");
    assert_eq!(client.config().bucket, "examplebucket");
    let key = ObjectKey::new("e2e/a.txt").expect("合法键");

    hit("fn", "S3Client::ping");
    client.ping().await.expect("桩 HEAD ping");
    hit("fn", "S3Client::health_check");
    hit("type", "S3Health");
    let health = client.health_check().await.expect("桩 health");
    let S3Health {
        healthy,
        endpoint: health_ep,
        bucket,
        latency_ms,
    } = health;
    hit("field", "S3Health::healthy");
    hit("field", "S3Health::endpoint");
    hit("field", "S3Health::bucket");
    hit("field", "S3Health::latency_ms");
    assert!(healthy);
    assert!(health_ep.contains("127.0.0.1"));
    assert_eq!(bucket, "examplebucket");
    let _ = latency_ms;

    hit("fn", "S3Client::put_object");
    client
        .put_object(&key, Bytes::from_static(b"abc"), &UploadOptions::default())
        .await
        .expect("put");
    hit("fn", "S3Client::put_object_stream");
    client
        .put_object_stream(
            &key,
            byte_stream_from_bytes(Bytes::from_static(b"xyz")),
            &UploadOptions::default(),
            Some(3),
        )
        .await
        .expect("put stream");
    hit("fn", "S3Client::get_object");
    let (meta, mut stream) = client
        .get_object(&key, &DownloadOptions::default())
        .await
        .expect("get");
    assert_eq!(meta.key, key.as_str());
    while let Some(chunk) = stream.next().await {
        chunk.expect("流块");
    }
    hit("fn", "S3Client::get_object_bytes");
    let bytes = client.get_object_bytes(&key).await.expect("get bytes");
    assert_eq!(&bytes[..], b"payload");
    hit("fn", "S3Client::head_object");
    let headed = client.head_object(&key).await.expect("head");
    assert_eq!(headed.key, key.as_str());
    hit("fn", "S3Client::list_objects_v2");
    let page = client
        .list_objects_v2(Some("e2e/"), None, Some(10))
        .await
        .expect("list");
    assert!(!page.is_truncated);
    hit("fn", "S3Client::delete_object");
    client.delete_object(&key).await.expect("delete");

    let inverted = match client
        .get_object(&key, &DownloadOptions::with_range(8, 1))
        .await
    {
        Err(error) => error,
        Ok(_) => panic!("倒序 range 必须本地失败"),
    };
    assert!(matches!(inverted, S3Error::Config(_)));
    let zero = client
        .list_objects_v2(None, None, Some(0))
        .await
        .expect_err("max_keys=0 必须本地失败");
    assert!(matches!(zero, S3Error::Config(_)));
}

#[tokio::test]
async fn e2e_public_api_offline_roundtrip() {
    assert_manifest_wellformed();
    phase_constants();
    phase_errors();
    phase_value_types();
    phase_config();
    phase_env_and_connect();
    let https = S3Config::builder()
        .endpoint("https://s3.example.test")
        .region("us-east-1")
        .bucket("examplebucket")
        .access_key_id("AKID")
        .access_key_secret("SECRET")
        .build()
        .expect("预签名用 HTTPS 配置");
    let key = ObjectKey::new("e2e/a.txt").expect("合法键");
    phase_sign_presign_xml(&https, &key);
    phase_retry().await;
    let (endpoint, handle) = serve_ok(vec![
        "", "", "", "", "payload", "payload", "", EMPTY_LIST, "",
    ]);
    phase_client(&endpoint).await;
    let _ = handle.join();
    assert_coverage_complete();
}
