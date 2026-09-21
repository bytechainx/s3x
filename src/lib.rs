//! `s3x` — AWS S3 及 S3 兼容对象存储适配器（SigV4 手写实现，不依赖 `aws-sdk`）。
//!
//! 只负责 S3 REST 协议、签名、对象读写与健康检查等基础设施原语；不含任何领域
//! 模型或业务编排，零内部耦合。
//!
//! # 特性
//!
//! - **AWS Signature Version 4**：[`sign_request`] 及相关原语实现完整的
//!   `AWS4-HMAC-SHA256`（含 S3 的「规范化 URI 不做二次编码」规则、查询串排序与
//!   百分号编码、头值折叠、同名头合并、`UNSIGNED-PAYLOAD`），并有 AWS 官方
//!   `aws-sig-v4-test-suite` 已知向量测试。
//! - **预签名 URL**：[`presign_get`] / [`presign_put`] 生成 query-string 方式签名的
//!   临时链接，有效期自动收敛到 1 秒 ~ 7 天。
//! - **数据面**：[`S3Client`] 提供 `put_object` / `put_object_stream` / `get_object`
//!   / `get_object_bytes` / `delete_object` / `head_object` / `list_objects_v2`。
//! - **寻址风格**：默认 virtual-hosted（`{bucket}.{endpoint}/{key}`，与 AWS 一致），
//!   [`S3Config::force_path_style`] 可切换为 path-style（`{endpoint}/{bucket}/{key}`），
//!   用于带点号的桶名或 MinIO / Ceph 等自建网关。
//! - **并发与重试**：[`S3Config::max_in_flight`] 以 `tokio::sync::Semaphore` 背压；
//!   失败按 [`RetryConfig`] 指数退避 + 抖动重试（可加总 deadline），
//!   [`S3Error::is_retryable`] 区分瞬时故障与永久故障。
//! - **错误安全**：错误消息只含 HTTP 状态码、S3 错误码与截断后的服务端消息
//!   （≤ 512 字符，响应前缀 ≤ 4 KiB）；secret access key / session token 永不进入
//!   错误消息、`Debug` 输出或 URL。
//! - **凭据注入**：`access_key_secret` 与 `session_token` 只能经环境变量或
//!   [`S3ConfigBuilder`] 注入，`from_toml` 会拒绝这两个键。
//!
//! # 快速开始
//!
//! ```no_run
//! use bytes::Bytes;
//! use s3x::{presign_get, ObjectKey, S3Client, S3Config, UploadOptions};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // 凭据只从环境变量或构建器注入，不会出现在 Debug / TOML 中。
//!     let config = S3Config::builder()
//!         .endpoint("https://minio.example.com:9000") // 省略则用 AWS 官方端点
//!         .region("us-east-1")
//!         .bucket("examplebucket")
//!         .access_key_id(std::env::var("FOUNDATIONX_S3X_ACCESS_KEY_ID")?)
//!         .access_key_secret(std::env::var("FOUNDATIONX_S3X_ACCESS_KEY_SECRET")?)
//!         .build()?;
//!
//!     // connect 只做校验与构造，不发网络请求；连通性用 ping 显式验证。
//!     let client = S3Client::connect(config).await?;
//!     client.ping().await?;
//!
//!     let key = ObjectKey::new("reports/2026-09.csv")?;
//!
//!     // 上传（自动 SigV4 签名，带 x-amz-content-sha256 / x-amz-date）
//!     client
//!         .put_object(&key, Bytes::from_static(b"a,b\n1,2\n"), &UploadOptions::default().with_content_type("text/csv"))
//!         .await?;
//!
//!     // 下载并读全量字节
//!     let bytes = client.get_object_bytes(&key).await?;
//!     assert_eq!(&bytes[..], b"a,b\n1,2\n");
//!
//!     // 生成临时下载链接（默认 1 小时，最长 7 天）
//!     let url = presign_get(&client.config(), &key, 3600)?;
//!     assert!(url.contains("X-Amz-Signature="));
//!
//!     let health = client.health_check().await?;
//!     println!("healthy={} latency={}ms", health.healthy, health.latency_ms);
//!     Ok(())
//! }
//! ```
//!
//! # 公开 API 一览
//!
//! | 类型 / 函数 | 用途 |
//! | --- | --- |
//! | [`S3Config`] / [`S3ConfigBuilder`] | 配置：`from_env` / `from_toml` / `validate` / `builder` / `effective_endpoint` |
//! | [`S3Client`] | 客户端：`new`（同步）/ `connect`（异步）/ `ping` / `health_check` + 数据面方法 |
//! | [`S3Health`] | 健康检查结果：`healthy` / `endpoint` / `bucket` / `latency_ms` |
//! | [`ObjectKey`] | 已校验的对象键（非空、无前导 `/`、无 `..`、无控制字符、≤ 1024 字节） |
//! | [`ObjectMeta`] / [`UploadOptions`] / [`DownloadOptions`] | 对象元数据与读写选项 |
//! | [`ByteStream`] / [`byte_stream_from_bytes`] | 下载流类型与内存流构造 |
//! | [`presign_get`] / [`presign_put`] / [`presign_url`] / [`PresignOptions`] | 预签名 URL |
//! | [`S3Error`] / [`S3Result`] | 错误类型与 `Result` 别名 |
//! | [`RetryConfig`] / [`with_retry`] / [`with_retry_deadline`] / [`backoff_delay`] | 重试策略（crate 内独立实现） |
//! | [`sign_request`] / [`canonical_request`] / [`percent_encode`] / [`signing_key`] | SigV4 原语（纯函数，便于复用与验证） |
//! | [`parse_list_objects_v2`] / [`ListObjectsResult`] | `ListObjectsV2` 响应解析 |
//! | [`build_delete_objects_body`] / [`parse_delete_objects`] | 批量删除请求体构造与结果解析 |
//!
//! # 配置
//!
//! 环境变量前缀为 `FOUNDATIONX_S3X_`，可用常量（如 [`ENV_BUCKET`]）
//! 避免硬编码字符串。`access_key_secret` 与 `session_token` 只能经环境变量或
//! [`S3ConfigBuilder`] 注入。

#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::unreachable
    )
)]
#![deny(missing_docs)]
#![forbid(unsafe_code)]

mod client;
mod config;
mod error;
mod presign;
mod retry;
mod sign;
mod types;
mod xml;

pub use client::{
    S3Client, S3Health, MAX_ERROR_BODY_BYTES, MAX_ERROR_MESSAGE_CHARS, MAX_LIST_KEYS,
};
pub use config::{
    aws_endpoint_for_region, S3Config, S3ConfigBuilder, DEFAULT_CONNECT_TIMEOUT_MS,
    DEFAULT_MAX_IN_FLIGHT, DEFAULT_MAX_RETRIES, DEFAULT_REGION, DEFAULT_REQUEST_TIMEOUT_MS,
    DEFAULT_USER_AGENT, ENV_ACCESS_KEY_ID, ENV_ACCESS_KEY_SECRET,
    ENV_ALLOW_UNSIGNED_PAYLOAD_OVER_HTTP, ENV_BUCKET, ENV_CONNECT_TIMEOUT_MS, ENV_ENDPOINT,
    ENV_FORCE_PATH_STYLE, ENV_MAX_IN_FLIGHT, ENV_MAX_RETRIES, ENV_PREFIX, ENV_REGION,
    ENV_REQUEST_TIMEOUT_MS, ENV_SESSION_TOKEN, ENV_USER_AGENT, HARD_MAX_CONNECT_TIMEOUT_MS,
    HARD_MAX_IN_FLIGHT, HARD_MAX_REQUEST_TIMEOUT_MS, HARD_MAX_RETRIES, MAX_BUCKET_NAME_LEN,
    MIN_BUCKET_NAME_LEN,
};
pub use error::{S3Error, S3Result};
pub use presign::{
    presign_get, presign_put, presign_url, PresignOptions, HARD_MAX_PRESIGN_EXPIRES_SECS,
    PRESIGN_SIGNED_HEADERS,
};
pub use retry::{
    backoff_delay, default_retry_config, is_s3_retryable, with_retry, with_retry_deadline,
    RetryConfig, DEFAULT_BASE_DELAY_MS, DEFAULT_JITTER_RATIO, DEFAULT_MAX_ATTEMPTS,
    DEFAULT_MAX_DELAY_MS, HARD_MAX_DELAY_MS, MAX_RETRY_ATTEMPTS,
};
pub use sign::{
    authorization_header, canonical_headers, canonical_query_string, canonical_request,
    canonical_uri_for_key, credential_scope, date_stamp, hmac_sha256, percent_encode, sha256_hex,
    sign_request, signing_key, string_to_sign, CanonicalRequest, SignRequest, Signature, ALGORITHM,
    EMPTY_PAYLOAD_SHA256, S3_SERVICE, TERMINATOR, UNSIGNED_PAYLOAD,
};
pub use types::{
    byte_stream_from_bytes, ByteStream, DownloadOptions, ObjectKey, ObjectMeta, UploadOptions,
    MAX_OBJECT_KEY_BYTES,
};
pub use xml::{
    build_delete_objects_body, parse_delete_objects, parse_error_code_message,
    parse_list_objects_v2, DeleteError, DeleteObjectsResult, ListObjectsResult,
};

#[cfg(test)]
mod public_api_surface {
    use super::*;

    /// crate 根导出的公共项在单元测试中被逐一点名，避免误删或改名。
    #[test]
    fn exports_are_named_and_constructible() {
        assert_eq!(ENV_PREFIX, "FOUNDATIONX_S3X_");
        assert_eq!(ENV_BUCKET, "FOUNDATIONX_S3X_BUCKET");
        assert_eq!(ENV_ACCESS_KEY_ID, "FOUNDATIONX_S3X_ACCESS_KEY_ID");
        assert_eq!(ENV_ACCESS_KEY_SECRET, "FOUNDATIONX_S3X_ACCESS_KEY_SECRET");
        assert_eq!(ENV_SESSION_TOKEN, "FOUNDATIONX_S3X_SESSION_TOKEN");
        assert_eq!(ENV_REGION, "FOUNDATIONX_S3X_REGION");
        assert_eq!(ENV_FORCE_PATH_STYLE, "FOUNDATIONX_S3X_FORCE_PATH_STYLE");
        assert_eq!(S3_SERVICE, "s3");
        assert_eq!(ALGORITHM, "AWS4-HMAC-SHA256");
        assert_eq!(TERMINATOR, "aws4_request");
        assert_eq!(UNSIGNED_PAYLOAD, "UNSIGNED-PAYLOAD");

        let config: S3Config = S3Config::builder()
            .endpoint("https://minio.example.com:9000")
            .region("eu-west-1")
            .bucket("examplebucket")
            .access_key_id("id")
            .access_key_secret("secret")
            .force_path_style(true)
            .build()
            .expect("配置有效");
        assert_eq!(
            config.effective_endpoint(),
            "https://minio.example.com:9000"
        );
        assert_eq!(
            config.bucket_url(),
            "https://minio.example.com:9000/examplebucket"
        );

        let key = ObjectKey::new("dir/k.txt").expect("合法键");
        assert_eq!(
            config.object_url(&key),
            "https://minio.example.com:9000/examplebucket/dir/k.txt"
        );
        assert_eq!(canonical_uri_for_key(&key), "/dir/k.txt");
        assert_eq!(percent_encode("a b", true), "a%20b");
        assert_eq!(sha256_hex(b""), EMPTY_PAYLOAD_SHA256);
        assert_eq!(date_stamp("20150830T123600Z"), "20150830");

        let url = presign_get(&config, &key, 60).expect("预签名必须成功");
        assert!(url.contains("X-Amz-Signature="), "{url}");
        assert_eq!(PRESIGN_SIGNED_HEADERS, "host");
        assert_eq!(HARD_MAX_PRESIGN_EXPIRES_SECS, 604_800);

        let client = S3Client::new(config).expect("同步构造");
        assert_eq!(client.config().bucket, "examplebucket");

        assert!(is_s3_retryable(&S3Error::Connection("x".into())));
        assert!(backoff_delay(&default_retry_config(), 1).as_millis() > 0);

        let meta = ObjectMeta::new("k").with_size(1);
        assert_eq!(meta.size, 1);
        assert_eq!(MAX_OBJECT_KEY_BYTES, 1024);
        assert_eq!(MAX_ERROR_BODY_BYTES, 4096);
        assert_eq!(MAX_LIST_KEYS, 1_000);
        assert_eq!(
            aws_endpoint_for_region("us-east-1"),
            "https://s3.us-east-1.amazonaws.com"
        );
    }

    #[test]
    fn public_types_are_send_sync_and_clone() {
        fn assert_send_sync<T: Send + Sync>() {}
        fn assert_clone<T: Clone>() {}
        fn assert_debug<T: std::fmt::Debug>() {}
        fn assert_deserialize<'de, T: serde::Deserialize<'de>>() {}

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

        assert_clone::<S3Client>();
        assert_clone::<S3Config>();
        assert_clone::<ObjectKey>();
        assert_clone::<RetryConfig>();

        assert_debug::<S3Client>();
        assert_debug::<S3Config>();
        assert_debug::<ObjectKey>();
        assert_debug::<S3Health>();
        assert_debug::<PresignOptions>();
        assert_debug::<CanonicalRequest>();

        assert_deserialize::<S3Config>();

        // 克隆后的句柄共享同一份内部状态。
        let client = S3Client::new(
            S3Config::builder()
                .bucket("examplebucket")
                .access_key_id("id")
                .access_key_secret("secret")
                .build()
                .expect("配置有效"),
        )
        .expect("构造成功");
        let cloned = client.clone();
        assert_eq!(cloned.config().bucket, client.config().bucket);
    }
}
