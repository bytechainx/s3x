//! 公共 API 表面：类型存在性、`Send + Sync + Clone`、`serde::Deserialize` 与同步构造。

use s3x::{
    aws_endpoint_for_region, backoff_delay, byte_stream_from_bytes, canonical_request,
    canonical_uri_for_key, default_retry_config, is_s3_retryable, percent_encode, presign_get,
    presign_put, sign_request, signing_key, ByteStream, CanonicalRequest, DeleteError,
    DeleteObjectsResult, DownloadOptions, ListObjectsResult, ObjectKey, ObjectMeta, PresignOptions,
    RetryConfig, S3Client, S3Config, S3ConfigBuilder, S3Error, S3Health, S3Result, SignRequest,
    Signature, UploadOptions, ALGORITHM, DEFAULT_MAX_IN_FLIGHT, DEFAULT_MAX_RETRIES,
    DEFAULT_REGION, DEFAULT_REQUEST_TIMEOUT_MS, EMPTY_PAYLOAD_SHA256, ENV_ACCESS_KEY_ID,
    ENV_ACCESS_KEY_SECRET, ENV_BUCKET, ENV_ENDPOINT, ENV_PREFIX, ENV_REGION, ENV_SESSION_TOKEN,
    HARD_MAX_IN_FLIGHT, MAX_ERROR_BODY_BYTES, MAX_LIST_KEYS, MAX_OBJECT_KEY_BYTES,
    MAX_RETRY_ATTEMPTS, PRESIGN_SIGNED_HEADERS, S3_SERVICE, UNSIGNED_PAYLOAD,
};

fn assert_send_sync<T: Send + Sync>() {}
fn assert_send<T: Send>() {}
fn assert_clone<T: Clone>() {}
fn assert_debug<T: std::fmt::Debug>() {}
fn assert_deserialize<'de, T: serde::Deserialize<'de>>() {}

fn sample_config() -> S3Config {
    S3Config::builder()
        .endpoint("https://minio.example.com:9000")
        .region("eu-west-1")
        .bucket("examplebucket")
        .access_key_id("AKIDEXAMPLE")
        .access_key_secret("secret")
        .force_path_style(true)
        .max_in_flight(8)
        .max_retries(2)
        .build()
        .expect("测试配置必须有效")
}

#[test]
fn public_constants_are_stable() {
    assert_eq!(ENV_PREFIX, "FOUNDATIONX_S3X_");
    for name in [
        ENV_ENDPOINT,
        ENV_REGION,
        ENV_BUCKET,
        ENV_ACCESS_KEY_ID,
        ENV_ACCESS_KEY_SECRET,
        ENV_SESSION_TOKEN,
    ] {
        assert!(name.starts_with(ENV_PREFIX), "{name}");
    }
    assert_eq!(S3_SERVICE, "s3");
    assert_eq!(ALGORITHM, "AWS4-HMAC-SHA256");
    assert_eq!(UNSIGNED_PAYLOAD, "UNSIGNED-PAYLOAD");
    assert_eq!(PRESIGN_SIGNED_HEADERS, "host");
    assert_eq!(DEFAULT_REGION, "us-east-1");
    assert_eq!(DEFAULT_REQUEST_TIMEOUT_MS, 30_000);
    assert_eq!(DEFAULT_MAX_RETRIES, 3);
    assert_eq!(DEFAULT_MAX_IN_FLIGHT, 64);
    assert_eq!(MAX_RETRY_ATTEMPTS, 10);
    assert_eq!(HARD_MAX_IN_FLIGHT, 1_024);
    assert_eq!(MAX_OBJECT_KEY_BYTES, 1_024);
    assert_eq!(MAX_ERROR_BODY_BYTES, 4_096);
    assert_eq!(MAX_LIST_KEYS, 1_000);
    assert_eq!(EMPTY_PAYLOAD_SHA256.len(), 64);
}

#[test]
fn public_types_are_send_sync_clone_and_debug() {
    assert_send_sync::<S3Client>();
    assert_send_sync::<S3Config>();
    assert_send_sync::<S3ConfigBuilder>();
    assert_send_sync::<S3Health>();
    assert_send_sync::<S3Error>();
    assert_send_sync::<ObjectKey>();
    assert_send_sync::<ObjectMeta>();
    assert_send_sync::<UploadOptions>();
    assert_send_sync::<DownloadOptions>();
    assert_send_sync::<RetryConfig>();
    assert_send_sync::<PresignOptions>();
    assert_send_sync::<Signature>();
    assert_send_sync::<CanonicalRequest>();
    assert_send_sync::<ListObjectsResult>();
    assert_send_sync::<DeleteObjectsResult>();
    assert_send_sync::<DeleteError>();
    // `ByteStream` 是 `Box<dyn Stream + Send>`，只保证 `Send`。
    assert_send::<ByteStream>();

    assert_clone::<S3Client>();
    assert_clone::<S3Config>();
    assert_clone::<S3ConfigBuilder>();
    assert_clone::<S3Health>();
    assert_clone::<ObjectKey>();
    assert_clone::<ObjectMeta>();
    assert_clone::<UploadOptions>();
    assert_clone::<DownloadOptions>();
    assert_clone::<RetryConfig>();
    assert_clone::<PresignOptions>();

    assert_debug::<S3Client>();
    assert_debug::<S3Config>();
    assert_debug::<S3Health>();
    assert_debug::<ObjectKey>();
    assert_debug::<S3Error>();
    assert_deserialize::<S3Config>();
}

#[test]
fn client_construction_shares_state_across_clones() {
    let client = S3Client::new(sample_config()).expect("同步构造必须成功");
    let cloned = client.clone();
    assert_eq!(cloned.config().bucket, client.config().bucket);
    assert_eq!(cloned.config().max_in_flight, 8);
    let rendered = format!("{cloned:?}");
    assert!(rendered.contains("S3Client"), "{rendered}");
    assert!(!rendered.contains("secret"), "{rendered}");
}

#[test]
fn config_derives_deserialize_and_rejects_secrets_in_toml() {
    let config: S3Config = toml::from_str(
        r#"
bucket = "examplebucket"
region = "us-west-2"
access_key_id = "AKIDEXAMPLE"
request_timeout_ms = 1234
"#,
    )
    .expect("扁平 TOML 必须可反序列化");
    assert_eq!(config.bucket, "examplebucket");
    assert_eq!(config.region, "us-west-2");
    assert_eq!(config.request_timeout_ms, 1234);
    assert!(config.access_key_secret.is_empty());

    assert!(toml::from_str::<S3Config>("access_key_secret = \"hunter2\"").is_err());
    assert!(toml::from_str::<S3Config>("session_token = \"t\"").is_err());
    assert!(toml::from_str::<S3Config>("sink_id = \"x\"").is_err());
}

#[test]
fn error_type_is_usable_as_std_error() {
    let error: S3Error = S3ConfigBuilder::new().build().unwrap_err();
    assert!(matches!(error, S3Error::Config(_)));
    assert!(!error.is_retryable());
    assert!(std::error::Error::source(&error).is_none());

    let result: S3Result<()> = Err(error);
    assert!(result.is_err());

    let backend = S3Error::Backend {
        status: 503,
        code: Some("SlowDown".into()),
        message: "slow down".into(),
    };
    assert!(backend.is_retryable());
    assert!(backend.to_string().contains("SlowDown"));

    let r#unsupported = S3Error::Unsupported("nope".into());
    assert!(!r#unsupported.is_retryable());
}

#[test]
fn pure_helpers_are_reachable_from_the_crate_root() {
    let config = sample_config();
    let key = ObjectKey::new("dir/k.txt").expect("合法键");
    assert_eq!(
        config.object_url(&key),
        "https://minio.example.com:9000/examplebucket/dir/k.txt"
    );
    assert_eq!(
        config.bucket_url(),
        "https://minio.example.com:9000/examplebucket"
    );
    assert_eq!(canonical_uri_for_key(&key), "/dir/k.txt");
    assert_eq!(percent_encode("a b/c", false), "a%20b/c");
    assert_eq!(
        signing_key("secret", "20130524", "us-east-1", "s3").len(),
        32
    );
    assert_eq!(
        aws_endpoint_for_region("ap-southeast-2"),
        "https://s3.ap-southeast-2.amazonaws.com"
    );

    let canonical = canonical_request(
        "GET",
        "/",
        &[],
        &[("host", "example.amazonaws.com")],
        EMPTY_PAYLOAD_SHA256,
    );
    assert_eq!(canonical.signed_headers, "host");

    let signature: Signature = sign_request(&SignRequest {
        method: "GET",
        canonical_uri: "/",
        query: &[],
        headers: &[("host", "example.amazonaws.com")],
        payload_hash: EMPTY_PAYLOAD_SHA256,
        amz_date: "20150830T123600Z",
        region: "us-east-1",
        service: S3_SERVICE,
        access_key_id: "AKIDEXAMPLE",
        secret_access_key: "secret",
    });
    assert_eq!(signature.signature.len(), 64);
    assert!(signature.authorization.starts_with("AWS4-HMAC-SHA256 "));

    assert!(!presign_get(&config, &key, 60).is_empty());
    assert!(!presign_put(&config, &key, 60).is_empty());
    assert!(is_s3_retryable(&S3Error::Timeout("t".into())));
    assert!(backoff_delay(&default_retry_config(), 2).as_millis() > 0);
    assert_eq!(RetryConfig::default().max_attempts, DEFAULT_MAX_RETRIES);

    let options = UploadOptions::default()
        .with_content_type("text/plain")
        .with_storage_class("STANDARD")
        .push_metadata("owner", "team-a");
    assert!(options.metadata.is_some());
    let download = DownloadOptions::with_range(0, 9);
    assert_eq!(download.range_header().as_deref(), Some("bytes=0-9"));

    let meta = ObjectMeta::new("k").with_size(3).with_etag("e");
    assert_eq!(meta.size, 3);
    let _stream: ByteStream = byte_stream_from_bytes(bytes::Bytes::from_static(b"x"));
}
