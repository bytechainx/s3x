#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::unreachable
)]
//! live 真连云（s3x）：需先 `source /home/zone/workspace/sre/secrets/env/s3x.env`。
//!
//! 全部用例 `#[ignore]`，默认不跑（CI 行为不变）。显式运行：
//!
//! ```bash
//! set -a; source /home/zone/workspace/sre/secrets/env/s3x.env; set +a
//! CARGO_TARGET_DIR=/home/workspace/bytechainx/.cargo/target \
//!   cargo test --test live_s3 -- --ignored --test-threads=1
//! ```
//!
//! 凭据只从环境变量读取，绝不硬编码。**真桶红线**（生产桶）：对象键一律落在
//! `bytechainx-e2e/<pid>-<nanos>/` 前缀内；一切 DELETE 只针对自己前缀内**先拼好
//! 变量**的完整键名；list 断言一律限定本进程前缀；每例尾部尽力清理自建对象，
//! 末尾清扫用例兜底（列出本进程前缀、逐键删除、复查断言为空）。
//!
//! 覆盖矩阵（公开面 → 执行用例）：
//!
//! - 配置面（`from_env`/`from_toml`/`validate`/`builder`/端点推导/Debug 脱敏）
//!   → `live_config_from_env_toml_builder_and_endpoints`
//! - 建连与探活（`new`/`connect`/`connect_from_env`/`config`/`ping`/`health_check`/
//!   `clone`/`Debug`）→ `live_client_connect_ping_health`
//! - 数据面（`put_object`/`get_object` 流式 + range/`get_object_bytes`/
//!   `head_object`/`delete_object` 幂等 + 404 负向）→
//!   `live_put_get_head_delete_roundtrip`
//! - 流式上传（`byte_stream_from_bytes`/`put_object_stream`，含与不带
//!   `content_length`）→ `live_put_object_stream`
//! - 列举（`list_objects_v2` 前缀限定 + 分页 + `max_keys` 收敛；真实 XML 经
//!   `parse_list_objects_v2` 解析）→ `live_list_objects_pagination`
//! - 预签名（`presign_put`/`presign_get`/`presign_url`/`PresignOptions`：裸 PUT /
//!   裸 GET / 篡改签名 403 / 过期签名 403）→ `live_presign_get_put_roundtrip`
//! - SigV4 原语（`sign_request`/`SignRequest`/`Signature`/`canonical_uri_for_key`/
//!   `authorization_header` 手工签名被真实 AWS 接受）→
//!   `live_sign_request_manual_roundtrip`
//! - 重试与错误面（`with_retry` 三条路径/`with_retry_deadline` 成功与超时/
//!   `backoff_delay`/`default_retry_config`/`is_retryable`/`is_s3_retryable`/
//!   `S3Error::Display`）→ `live_retry_and_error_surface`
//! - 纯项（`ObjectKey`/`ObjectMeta`/`UploadOptions`/`DownloadOptions` 构建器、
//!   SigV4 纯函数、`build_delete_objects_body`/`parse_delete_objects`、
//!   `parse_list_objects_v2` 纯路径）→ `live_pure_helpers_and_builders`
//! - 批量删除的**网络面不在公开 API 内**（客户端不提供该方法，见
//!   `src/client.rs` 模块文档：S3 要求 `Content-MD5`，本 crate 不引入摘要依赖），
//!   仅纯函数断言；multipart 上传同样**无公开 API**，故无对应用例。
//! - 清扫兜底 → `live_cleanup_sweep_no_residual`

use std::cell::Cell;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use chrono::{DateTime, Utc};
use futures_util::StreamExt;
use s3x::{
    authorization_header, aws_endpoint_for_region, backoff_delay, build_delete_objects_body,
    byte_stream_from_bytes, canonical_query_string, canonical_request, canonical_uri_for_key,
    date_stamp, default_retry_config, is_s3_retryable, parse_delete_objects, parse_list_objects_v2,
    percent_encode, presign_get, presign_put, presign_url, sha256_hex, sign_request, signing_key,
    with_retry, with_retry_deadline, DownloadOptions, ObjectKey, ObjectMeta, PresignOptions,
    RetryConfig, S3Client, S3Config, S3ConfigBuilder, S3Error, S3Health, SignRequest,
    UploadOptions, EMPTY_PAYLOAD_SHA256, HARD_MAX_PRESIGN_EXPIRES_SECS, MAX_LIST_KEYS,
    PRESIGN_SIGNED_HEADERS, S3_SERVICE,
};

/// 当前时刻的纳秒数（用于构造进程内唯一前缀）。
fn nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("系统时间应晚于 UNIX_EPOCH")
        .as_nanos()
}

/// 本进程的清扫前缀：`bytechainx-e2e/<pid>-`（只清理本进程创建的对象）。
fn run_prefix() -> String {
    format!("bytechainx-e2e/{}-", std::process::id())
}

/// 本用例唯一目录：`bytechainx-e2e/<pid>-<nanos>/<用途>/`。
fn unique_dir(use_case: &str) -> String {
    format!("{}{}/{}/", run_prefix(), nanos(), use_case)
}

/// 从真实环境变量加载配置（调用前须 `source` s3x.env）。
fn env_config() -> S3Config {
    S3Config::from_env().expect("FOUNDATIONX_S3X_* 必须已注入（先 source s3x.env）")
}

/// 尽力清理：只删除本用例先拼好变量的自建键。
async fn cleanup(client: &S3Client, keys: &[ObjectKey]) {
    for key in keys {
        let _ = client.delete_object(key).await;
    }
}

/// 列出本进程前缀下的全部键并逐键删除（删除前逐键校验落在本进程前缀内），
/// 返回删除数。
async fn sweep_run_prefix(client: &S3Client) -> usize {
    let prefix = run_prefix();
    let mut deleted = 0usize;
    let mut token: Option<String> = None;
    loop {
        let page = client
            .list_objects_v2(Some(&prefix), token.as_deref(), None)
            .await
            .expect("清扫前的列举必须成功");
        for meta in &page.keys {
            assert!(
                meta.key.starts_with(&prefix),
                "清扫只允许命中本进程前缀内的键"
            );
            let key = ObjectKey::new(meta.key.as_str()).expect("服务端返回的键必须合法");
            client.delete_object(&key).await.expect("清扫删除必须成功");
            deleted += 1;
        }
        if !page.is_truncated {
            break;
        }
        token = page.next_continuation_token;
    }
    deleted
}

/// 翻转预签名 URL 末尾签名的最后一个十六进制字符（用于服务端拒绝负向）。
fn mangle_signature(url: &str) -> String {
    const MARKER: &str = "X-Amz-Signature=";
    let pos = url.rfind(MARKER).expect("预签名 URL 必须含签名参数");
    let (head, sig) = url.split_at(pos + MARKER.len());
    let mut sig = sig.to_owned();
    let last = sig.pop().expect("签名必须非空");
    sig.push(if last == '0' { '1' } else { '0' });
    format!("{head}{sig}")
}

/// 配置面：from_env（真实环境变量）/ from_toml / validate / builder / 端点推导与脱敏。
#[tokio::test]
#[ignore = "需要真实 AWS S3 与 FOUNDATIONX_S3X_* 环境变量"]
async fn live_config_from_env_toml_builder_and_endpoints() {
    let config = env_config();
    assert!(!config.bucket.is_empty(), "环境变量必须提供 bucket");
    assert!(!config.region.is_empty(), "环境变量必须提供 region");
    config.validate().expect("环境变量配置必须通过完整校验");
    assert!(
        !config.force_path_style,
        "未设 FORCE_PATH_STYLE 时默认 virtual-hosted"
    );
    assert!(
        !config.endpoint_is_plain_http(),
        "HTTPS endpoint 不得判为明文"
    );

    // 端点推导：显式 endpoint 与按 region 推导的官方端点一致（同一 region）。
    let endpoint = config.effective_endpoint();
    assert_eq!(endpoint, aws_endpoint_for_region(&config.region));
    let bucket_url = config.bucket_url();
    assert!(
        bucket_url.starts_with(&format!("https://{}.", config.bucket)),
        "{bucket_url}"
    );
    let key = ObjectKey::new("dir/a b.txt").expect("合法键");
    let object_url = config.object_url(&key);
    assert!(object_url.starts_with(&bucket_url), "{object_url}");
    assert!(object_url.ends_with("/dir/a%20b.txt"), "{object_url}");
    assert_eq!(config.service(), S3_SERVICE);

    // builder 全链：以真实配置重建并覆盖非凭据项。
    let rebuilt = S3ConfigBuilder::from_config(config.clone())
        .max_in_flight(8)
        .max_retries(2)
        .user_agent("s3x-live-e2e/1")
        .build()
        .expect("builder 重建必须成功");
    assert_eq!(rebuilt.bucket, config.bucket);
    assert_eq!(rebuilt.region, config.region);
    assert_eq!(rebuilt.access_key_id, config.access_key_id);
    assert!(rebuilt.access_key_secret == config.access_key_secret);
    assert_eq!(rebuilt.max_in_flight, 8);
    assert_eq!(rebuilt.max_retries, 2);
    assert_eq!(rebuilt.user_agent, "s3x-live-e2e/1");

    // 敏感字段绝不进入 Debug 输出。
    let rendered = format!("{rebuilt:?}");
    assert!(rendered.contains("***"));
    assert!(!rendered.contains(&config.access_key_secret));
    assert!(rendered.contains(&config.access_key_id), "{rendered}");

    // from_toml：真实取值可经 TOML 表达；凭据键必须被拒绝（不回显取值）。
    let toml_text = format!(
        "bucket = \"{}\"\nregion = \"{}\"\nendpoint = \"{}\"\naccess_key_id = \"{}\"\n",
        config.bucket, config.region, endpoint, config.access_key_id
    );
    let parsed = S3Config::from_toml(&toml_text).expect("TOML 解析必须成功");
    assert_eq!(parsed.bucket, config.bucket);
    let full = S3ConfigBuilder::from_config(parsed)
        .access_key_secret(&config.access_key_secret)
        .build()
        .expect("注入凭据后必须通过完整校验");
    full.validate().expect("完整校验必须成功");
    assert!(
        S3Config::from_toml("bucket = \"b\"\naccess_key_secret = \"x\"\n").is_err(),
        "TOML 不得携带 secret"
    );

    // S3Client::new 只做校验与构造（不发网络请求）；config() 返回副本。
    let client = S3Client::new(full).expect("同步构造必须成功");
    assert_eq!(client.config().bucket, config.bucket);
}

/// 建连与探活：connect / connect_from_env / ping / health_check / clone / Debug。
#[tokio::test]
#[ignore = "需要真实 AWS S3 与 FOUNDATIONX_S3X_* 环境变量"]
async fn live_client_connect_ping_health() {
    let client = S3Client::connect(env_config())
        .await
        .expect("connect 必须成功（不发网络请求）");
    client.ping().await.expect("真实桶 HEAD 探测必须成功");

    let from_env = S3Client::connect_from_env()
        .await
        .expect("connect_from_env 必须成功");
    from_env.ping().await.expect("ping 必须成功");

    let health: S3Health = client.health_check().await.expect("健康检查恒为 Ok");
    assert!(health.healthy, "真实桶必须健康");
    assert_eq!(health.bucket, client.config().bucket);
    assert_eq!(health.endpoint, client.config().effective_endpoint());
    assert!(
        health.latency_ms < 10_000,
        "RTT 应有界: {}ms",
        health.latency_ms
    );

    // Debug 不含 secret；clone 共享同一份配置与连接池。
    let debug = format!("{client:?}");
    assert!(debug.contains(&client.config().bucket), "{debug}");
    assert!(!debug.contains(&client.config().access_key_secret));
    let cloned = client.clone();
    assert_eq!(cloned.config().bucket, client.config().bucket);
    cloned.ping().await.expect("克隆句柄必须同样可用");
}

/// 数据面主链路：put / get（流式 + range）/ get_object_bytes / head / delete，
/// 附 404 负向与幂等删除。对象键全部先拼好变量。
#[tokio::test]
#[ignore = "需要真实 AWS S3 与 FOUNDATIONX_S3X_* 环境变量"]
async fn live_put_get_head_delete_roundtrip() {
    let client = S3Client::connect(env_config())
        .await
        .expect("connect 必须成功");
    let dir = unique_dir("roundtrip");
    let key_str = format!("{dir}a.txt");
    let key_missing_str = format!("{dir}missing.txt");
    let key = ObjectKey::new(&key_str).expect("合法键");
    let key_missing = ObjectKey::new(&key_missing_str).expect("合法键");

    // put：content_type + 自定义元数据 + 存储类别（服务端真实接受并入库）。
    let body = Bytes::from_static(b"bytechainx-e2e-roundtrip-0123456789");
    let options = UploadOptions::default()
        .with_content_type("text/plain")
        .with_storage_class("STANDARD")
        .push_metadata("team", "bytechainx-e2e");
    let put_meta = client
        .put_object(&key, body.clone(), &options)
        .await
        .expect("上传必须成功");
    assert_eq!(put_meta.key, key_str);
    assert_eq!(put_meta.size, body.len() as u64);
    assert!(put_meta.etag.is_some(), "上传响应必须带 ETag");
    assert_eq!(put_meta.content_type.as_deref(), Some("text/plain"));

    // head：ETag / last_modified / content_type / size 与上传一致。
    let head = client.head_object(&key).await.expect("HEAD 必须成功");
    assert_eq!(head.key, key_str);
    assert_eq!(head.size, body.len() as u64);
    assert_eq!(head.etag, put_meta.etag);
    assert!(head.last_modified.is_some(), "HEAD 必须返回 Last-Modified");
    assert_eq!(head.content_type.as_deref(), Some("text/plain"));

    // get 全量：元数据 + 字节流逐块消费（流结束后可重复 poll 由单测覆盖）。
    let (meta, mut stream) = client
        .get_object(&key, &DownloadOptions::default())
        .await
        .expect("下载必须成功");
    assert_eq!(meta.key, key_str);
    assert_eq!(meta.size, body.len() as u64);
    assert_eq!(meta.etag, put_meta.etag);
    let mut collected = Vec::new();
    while let Some(chunk) = stream.next().await {
        collected.extend_from_slice(&chunk.expect("流式读取不得出错"));
    }
    assert_eq!(collected, body.to_vec());

    // get_object_bytes：便捷读全量，逐字节一致。
    let bytes = client.get_object_bytes(&key).await.expect("读全量必须成功");
    assert_eq!(bytes, body);

    // range 下载：bytes=2-5 → 闭区间 4 字节，与请求体的第 2..=5 字节一致。
    let (_, mut range_stream) = client
        .get_object(&key, &DownloadOptions::with_range(2, 5))
        .await
        .expect("范围下载必须成功");
    let mut ranged = Vec::new();
    while let Some(chunk) = range_stream.next().await {
        ranged.extend_from_slice(&chunk.expect("范围流不得出错"));
    }
    assert_eq!(ranged.as_slice(), &body[2..=5]);

    // 负向：缺失对象 → Backend 404 / NoSuchKey（真实错误体经 parse_error_code_message
    // 解析），且不可重试；head 同样报错。
    let error = client
        .get_object_bytes(&key_missing)
        .await
        .expect_err("缺失对象必须报错");
    match &error {
        S3Error::Backend { status, code, .. } => {
            assert_eq!(*status, 404);
            assert_eq!(code.as_deref(), Some("NoSuchKey"), "{error}");
        }
        other => panic!("意外的错误类型: {other:?}"),
    }
    assert!(!error.is_retryable());
    assert!(
        client.head_object(&key_missing).await.is_err(),
        "HEAD 缺失对象必须报错"
    );

    // delete：先删存在的键，再验证幂等（S3 对缺失键同样返回成功）。
    client.delete_object(&key).await.expect("删除必须成功");
    client.delete_object(&key).await.expect("删除必须幂等");
    assert!(
        client.get_object_bytes(&key).await.is_err(),
        "删除后不得再读到"
    );

    cleanup(&client, &[key, key_missing]).await;
}

/// 流式上传：byte_stream_from_bytes + put_object_stream（UNSIGNED-PAYLOAD，
/// HTTPS 放行），带与不带 content_length 两条路径。
#[tokio::test]
#[ignore = "需要真实 AWS S3 与 FOUNDATIONX_S3X_* 环境变量"]
async fn live_put_object_stream() {
    let client = S3Client::connect(env_config())
        .await
        .expect("connect 必须成功");
    let dir = unique_dir("stream");
    let key_str = format!("{dir}blob.bin");
    let key_chunked_str = format!("{dir}chunked.bin");
    let key = ObjectKey::new(&key_str).expect("合法键");
    let key_chunked = ObjectKey::new(&key_chunked_str).expect("合法键");

    // 显式 content_length 的流式上传（64 KiB）。
    let payload = Bytes::from(vec![7u8; 64 * 1024]);
    let stream = byte_stream_from_bytes(payload.clone());
    let meta = client
        .put_object_stream(
            &key,
            stream,
            &UploadOptions::default().with_content_type("application/octet-stream"),
            Some(payload.len() as u64),
        )
        .await
        .expect("流式上传必须成功");
    assert_eq!(meta.size, payload.len() as u64);
    assert!(meta.etag.is_some());
    let downloaded = client.get_object_bytes(&key).await.expect("下载必须成功");
    assert_eq!(downloaded, payload);

    // 不带 content_length（分块传输编码）：真实 AWS S3 不支持无 Content-Length 的
    // PUT（501 NotImplemented），此处作为服务端行为负向固化；MinIO 等兼容网关可支持。
    let stream = byte_stream_from_bytes(Bytes::from_static(b"chunked-body"));
    let chunked_error = client
        .put_object_stream(&key_chunked, stream, &UploadOptions::default(), None)
        .await
        .expect_err("真实 AWS 必须拒绝无 Content-Length 的 PUT");
    assert!(
        matches!(&chunked_error, S3Error::Backend { status: 501, .. }),
        "预期 501 NotImplemented，实际: {chunked_error:?}"
    );

    cleanup(&client, &[key, key_chunked]).await;
}

/// ListObjectsV2：前缀限定 + max_keys=1 分页翻完 + max_keys 超界收敛；
/// 真实响应 XML 经 crate 内的 parse_list_objects_v2 解码返回。
#[tokio::test]
#[ignore = "需要真实 AWS S3 与 FOUNDATIONX_S3X_* 环境变量"]
async fn live_list_objects_pagination() {
    let client = S3Client::connect(env_config())
        .await
        .expect("connect 必须成功");
    let dir = unique_dir("list");
    let names = ["a.txt", "b.txt", "c.txt"];
    let mut keys = Vec::new();
    for (i, name) in names.iter().enumerate() {
        let key_str = format!("{dir}{name}");
        let key = ObjectKey::new(&key_str).expect("合法键");
        client
            .put_object(
                &key,
                Bytes::from(format!("page-{i}")),
                &UploadOptions::default(),
            )
            .await
            .expect("预置对象必须成功");
        keys.push(key);
    }

    // 分页：每页 1 条，沿 continuation token 翻到 is_truncated=false。
    let mut seen: Vec<String> = Vec::new();
    let mut token: Option<String> = None;
    loop {
        let page = client
            .list_objects_v2(Some(&dir), token.as_deref(), Some(1))
            .await
            .expect("列举必须成功");
        assert!(page.keys.len() <= 1, "max_keys=1 时每页至多 1 条");
        for meta in &page.keys {
            assert!(
                meta.key.starts_with(&dir),
                "只允许看到自己前缀内的键: {}",
                meta.key
            );
            seen.push(meta.key.clone());
        }
        if !page.is_truncated {
            assert!(page.next_continuation_token.is_none());
            break;
        }
        token = page.next_continuation_token;
    }
    let mut expected: Vec<String> = names.iter().map(|name| format!("{dir}{name}")).collect();
    expected.sort();
    seen.sort();
    assert_eq!(seen, expected, "分页累计必须不重不漏");

    // max_keys 超界值由 crate 收敛到 MAX_LIST_KEYS 后服务端接受。
    let big = client
        .list_objects_v2(Some(&dir), None, Some(MAX_LIST_KEYS + 5))
        .await
        .expect("超界 max_keys 必须被收敛后接受");
    assert!(big.keys.len() <= names.len());
    assert!(big.keys.iter().all(|meta| meta.key.starts_with(&dir)));

    cleanup(&client, &keys).await;
}

/// 预签名 URL 端到端：presign_put 裸 PUT、presign_get 裸 GET、presign_url、
/// 篡改签名 403、过期签名 403。HTTP 请求复用 crate 既有 reqwest 依赖
///（未新增任何 dev-dependencies）。
#[tokio::test]
#[ignore = "需要真实 AWS S3 与 FOUNDATIONX_S3X_* 环境变量"]
async fn live_presign_get_put_roundtrip() {
    let config = env_config();
    let client = S3Client::connect(config.clone())
        .await
        .expect("connect 必须成功");
    let dir = unique_dir("presign");
    let key_str = format!("{dir}presigned.txt");
    let key = ObjectKey::new(&key_str).expect("合法键");

    // presign_put：无任何凭据头的裸 PUT 必须被服务端接受。
    let put_url = presign_put(&config, &key, 300).expect("生成 PUT 预签名必须成功");
    assert!(put_url.contains("X-Amz-Signature="), "{put_url}");
    assert!(put_url.contains("X-Amz-Expires=300"), "{put_url}");
    let http = reqwest::Client::new();
    let put_response = http
        .put(&put_url)
        .body(b"presigned-by-put-url".to_vec())
        .send()
        .await
        .expect("预签名 PUT 必须发出");
    assert_eq!(
        put_response.status(),
        reqwest::StatusCode::OK,
        "预签名 PUT 必须被接受"
    );

    // 经签名客户端回读校验：内容逐字节一致。
    let stored = client.get_object_bytes(&key).await.expect("回读必须成功");
    assert_eq!(stored, Bytes::from_static(b"presigned-by-put-url"));

    // presign_get：无凭据头的裸 GET 下载。
    let get_url = presign_get(&config, &key, 300).expect("生成 GET 预签名必须成功");
    let get_response = http
        .get(&get_url)
        .send()
        .await
        .expect("预签名 GET 必须发出");
    assert_eq!(get_response.status(), reqwest::StatusCode::OK);
    let body = get_response.bytes().await.expect("响应体必须可读");
    assert_eq!(&body[..], b"presigned-by-put-url");

    // presign_url + PresignOptions::get 走默认时钟，同样可用。
    let via_options =
        presign_url(&config, &key, &PresignOptions::get(300)).expect("presign_url 必须成功");
    let response = http.get(&via_options).send().await.expect("请求必须发出");
    assert_eq!(response.status(), reqwest::StatusCode::OK);

    // 篡改签名：服务端必须拒绝（403）。
    let mangled = mangle_signature(&get_url);
    let rejected = http.get(&mangled).send().await.expect("请求必须发出");
    assert_eq!(
        rejected.status(),
        reqwest::StatusCode::FORBIDDEN,
        "篡改签名不得被接受"
    );

    // 过期签名：签名时刻 10 分钟前、有效期 60 秒 → 服务端必须拒绝（403）。
    let stale: DateTime<Utc> = Utc::now() - chrono::Duration::minutes(10);
    let expired_url = presign_url(&config, &key, &PresignOptions::get(60).at(stale))
        .expect("生成过期预签名必须成功");
    let expired = http.get(&expired_url).send().await.expect("请求必须发出");
    assert_eq!(
        expired.status(),
        reqwest::StatusCode::FORBIDDEN,
        "过期预签名不得被接受"
    );

    // 常量顺带断言。
    assert_eq!(PRESIGN_SIGNED_HEADERS, "host");
    assert_eq!(HARD_MAX_PRESIGN_EXPIRES_SECS, 604_800);

    cleanup(&client, &[key]).await;
}

/// SigV4 原语端到端：用公开的 sign_request / canonical_uri_for_key /
/// authorization_header 手工签名，裸 HTTP 请求被真实 AWS 接受。
#[tokio::test]
#[ignore = "需要真实 AWS S3 与 FOUNDATIONX_S3X_* 环境变量"]
async fn live_sign_request_manual_roundtrip() {
    let config = env_config();
    let client = S3Client::connect(config.clone())
        .await
        .expect("connect 必须成功");
    let dir = unique_dir("sign");
    let key_str = format!("{dir}manual-sign.txt");
    let key = ObjectKey::new(&key_str).expect("合法键");
    client
        .put_object(
            &key,
            Bytes::from_static(b"manual-sigv4-body"),
            &UploadOptions::default(),
        )
        .await
        .expect("预置对象必须成功");

    // 手工构造签名输入：host 取自 bucket_url（virtual-hosted 含桶名前缀）。
    let bucket_url = url::Url::parse(&config.bucket_url()).expect("桶 URL 必须合法");
    let host = match bucket_url.port() {
        Some(port) => format!("{}:{port}", bucket_url.host_str().expect("必须有主机名")),
        None => bucket_url.host_str().expect("必须有主机名").to_owned(),
    };
    let amz_date = Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    // AWS SigV4 要求所有 `x-amz-*` 头必须参与签名，故与 crate 内部一致地签
    // host / x-amz-content-sha256 / x-amz-date 三个头。
    let request = SignRequest {
        method: "GET",
        canonical_uri: &canonical_uri_for_key(&key),
        query: &[],
        headers: &[
            ("host", host.as_str()),
            ("x-amz-content-sha256", EMPTY_PAYLOAD_SHA256),
            ("x-amz-date", amz_date.as_str()),
        ],
        payload_hash: EMPTY_PAYLOAD_SHA256,
        amz_date: &amz_date,
        region: &config.region,
        service: S3_SERVICE,
        access_key_id: &config.access_key_id,
        secret_access_key: &config.access_key_secret,
    };
    let signature = sign_request(&request);
    assert!(signature
        .authorization
        .starts_with("AWS4-HMAC-SHA256 Credential="));
    assert!(signature.signed_headers.contains("host"));
    assert!(signature
        .signed_headers
        .contains("x-amz-content-sha256;x-amz-date"));
    assert!(signature.string_to_sign.starts_with("AWS4-HMAC-SHA256\n"));
    assert_eq!(signature.signature.len(), 64);

    // 裸请求：只带 Authorization / x-amz-date / x-amz-content-sha256 三个头。
    let response = reqwest::Client::new()
        .get(config.object_url(&key))
        .header("authorization", &signature.authorization)
        .header("x-amz-date", &amz_date)
        .header("x-amz-content-sha256", EMPTY_PAYLOAD_SHA256)
        .send()
        .await
        .expect("手工签名请求必须发出");
    assert_eq!(
        response.status(),
        reqwest::StatusCode::OK,
        "真实 AWS 必须接受手工签名"
    );
    let body = response.bytes().await.expect("响应体必须可读");
    assert_eq!(&body[..], b"manual-sigv4-body");

    // authorization_header 纯函数与 sign_request 的 Authorization 输出一致。
    let scope_date = date_stamp(&amz_date);
    let manual = authorization_header(
        &config.access_key_id,
        scope_date,
        &config.region,
        S3_SERVICE,
        &signature.signed_headers,
        &signature.signature,
    );
    assert_eq!(manual, signature.authorization);

    cleanup(&client, &[key]).await;
}

/// 重试与错误面：with_retry 三条路径（成功 / 不可重试即停 / 可重试到上限）、
/// with_retry_deadline 成功与超时、backoff_delay / default_retry_config /
/// is_retryable / is_s3_retryable / S3Error::Display。
#[tokio::test]
#[ignore = "需要真实 AWS S3 与 FOUNDATIONX_S3X_* 环境变量"]
async fn live_retry_and_error_surface() {
    let client = S3Client::connect(env_config())
        .await
        .expect("connect 必须成功");
    let dir = unique_dir("retry");
    let key_str = format!("{dir}probe.txt");
    let key_missing_str = format!("{dir}missing.txt");
    let key = ObjectKey::new(&key_str).expect("合法键");
    let key_missing = ObjectKey::new(&key_missing_str).expect("合法键");
    client
        .put_object(
            &key,
            Bytes::from_static(b"retry-probe"),
            &UploadOptions::default(),
        )
        .await
        .expect("预置对象必须成功");

    let fast = RetryConfig::new(3, 1).with_jitter_ratio(0.0);
    assert!(fast.validate().is_ok());

    // 成功路径：真实 ping 一次成功。
    with_retry(&fast, "live-ping", || async { client.ping().await })
        .await
        .expect("with_retry 成功路径必须成功");

    // 不可重试错误（真实 404）：立即返回，只尝试一次。
    let attempts_404 = Cell::new(0u32);
    let result = with_retry(&fast, "live-404", || {
        attempts_404.set(attempts_404.get() + 1);
        async { client.get_object_bytes(&key_missing).await }
    })
    .await;
    assert!(result.is_err(), "缺失对象必须报错");
    assert_eq!(attempts_404.get(), 1, "不可重试错误必须只尝试一次");

    // 可重试错误：重试到上限后返回最后错误。
    let attempts_flaky = Cell::new(0u32);
    let result = with_retry(&fast, "live-flaky", || {
        attempts_flaky.set(attempts_flaky.get() + 1);
        async { Err::<Bytes, S3Error>(S3Error::Connection("模拟瞬时故障".to_owned())) }
    })
    .await;
    assert!(matches!(result, Err(S3Error::Connection(_))));
    assert_eq!(
        attempts_flaky.get(),
        fast.max_attempts,
        "可重试错误必须重试到上限"
    );

    // with_retry_deadline：成功路径。
    with_retry_deadline(&fast, "live-ping-dl", Duration::from_secs(30), || async {
        client.ping().await
    })
    .await
    .expect("deadline 内必须成功");

    // with_retry_deadline：1ns deadline 必然超时（真实网络往返远大于 1ns）。
    let error = with_retry_deadline(&fast, "live-timeout", Duration::from_nanos(1), || async {
        client.get_object_bytes(&key).await
    })
    .await
    .expect_err("1ns deadline 必须超时");
    assert!(matches!(error, S3Error::Timeout(_)), "{error:?}");

    // 纯函数顺带断言：退避封顶、默认配置有效、可重试判定。
    let default = default_retry_config();
    assert!(default.validate().is_ok());
    assert!(backoff_delay(&default, 1) <= Duration::from_millis(default.max_delay_ms));
    assert!(backoff_delay(&default, u32::MAX) <= Duration::from_millis(default.max_delay_ms));
    assert!(is_s3_retryable(&S3Error::Connection("x".into())));
    assert!(!is_s3_retryable(&S3Error::Config("x".into())));

    // 真实 404 错误：is_retryable 判永久故障；Display 含状态码与错误码、不含 secret。
    let not_found = client
        .get_object_bytes(&key_missing)
        .await
        .expect_err("缺失对象必须报错");
    assert!(!is_s3_retryable(&not_found));
    assert!(!not_found.is_retryable());
    let rendered = not_found.to_string();
    assert!(rendered.contains("404"), "{rendered}");
    assert!(rendered.contains("NoSuchKey"), "{rendered}");
    assert!(!rendered.contains(&client.config().access_key_secret));

    cleanup(&client, &[key, key_missing]).await;
}

/// 纯项与构建器顺带断言（无网络行为；随 live 套件一起跑保证矩阵完整）。
#[test]
#[ignore = "需要 FOUNDATIONX_S3X_* 环境变量（与其他 live 用例同一套件运行）"]
fn live_pure_helpers_and_builders() {
    // ObjectKey：校验 / Display / AsRef / TryFrom。
    let key = ObjectKey::new("dir/键.txt").expect("多字节合法键");
    assert_eq!(key.as_str(), "dir/键.txt");
    assert_eq!(key.to_string(), "dir/键.txt");
    assert_eq!(key.as_ref(), "dir/键.txt");
    assert_eq!(
        ObjectKey::try_from("k").expect("合法键"),
        ObjectKey::new("k").expect("合法键")
    );
    for bad in ["", "/lead", "../up", "a\rb"] {
        assert!(ObjectKey::new(bad).is_err(), "{bad:?} 必须被拒绝");
    }

    // ObjectMeta 构建器。
    let meta = ObjectMeta::new("k")
        .with_size(3)
        .with_etag("e")
        .with_last_modified("t")
        .with_content_type("c");
    assert_eq!(meta.key, "k");
    assert_eq!(meta.size, 3);
    assert_eq!(meta.etag.as_deref(), Some("e"));
    assert_eq!(meta.last_modified.as_deref(), Some("t"));
    assert_eq!(meta.content_type.as_deref(), Some("c"));

    // DownloadOptions / UploadOptions / PresignOptions 帮助器。
    assert_eq!(
        DownloadOptions::with_range(0, 9).range_header().as_deref(),
        Some("bytes=0-9")
    );
    assert!(DownloadOptions::with_range(9, 0).range_header().is_none());
    assert_eq!(
        UploadOptions::default()
            .with_content_type("text/plain")
            .content_type
            .as_deref(),
        Some("text/plain")
    );
    let uploaded = UploadOptions::default().push_metadata("a", "b");
    assert_eq!(
        uploaded.metadata.as_deref(),
        Some([("a".to_owned(), "b".to_owned())].as_slice())
    );
    assert_eq!(PresignOptions::default().method, "GET");
    assert_eq!(PresignOptions::default().expires_in_secs, 3_600);
    assert_eq!(PresignOptions::put(9).method, "PUT");
    assert_eq!(PresignOptions::get(9).expires_in_secs, 9);
    assert!(PresignOptions::get(9).at(Utc::now()).now.is_some());

    // SigV4 纯原语。
    assert_eq!(sha256_hex(b""), EMPTY_PAYLOAD_SHA256);
    assert_eq!(percent_encode("a b", true), "a%20b");
    assert_eq!(percent_encode("a/b", false), "a/b");
    assert_eq!(date_stamp("20260923T000000Z"), "20260923");
    let first = signing_key("secret", "20260923", "ap-northeast-1", "s3");
    assert_eq!(first.len(), 32);
    assert_eq!(
        first,
        signing_key("secret", "20260923", "ap-northeast-1", "s3"),
        "同输入必须同输出"
    );
    let canonical = canonical_request(
        "GET",
        "/k",
        &[("a", "1")],
        &[("host", "h")],
        EMPTY_PAYLOAD_SHA256,
    );
    assert!(canonical.canonical_request.starts_with("GET\n/k\n"));
    assert!(canonical.signed_headers.contains("host"));
    assert_eq!(
        canonical_query_string(&[("b", "2"), ("a", "1")]),
        "a=1&b=2",
        "查询串必须按键排序"
    );

    // XML 纯函数：批量删除**无网络面**（客户端不提供该方法），仅纯断言。
    let keys = [
        ObjectKey::new("x&y").expect("合法键"),
        ObjectKey::new("z").expect("合法键"),
    ];
    let body = build_delete_objects_body(&keys);
    assert!(body.starts_with("<?xml"), "{body}");
    assert!(body.contains("<Key>x&amp;y</Key>"), "{body}");
    assert!(body.contains("<Key>z</Key>"), "{body}");
    let parsed = parse_delete_objects(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Deleted><Key>a.txt</Key></Deleted>
</DeleteResult>"#,
    )
    .expect("解析必须成功");
    assert_eq!(parsed.deleted, ["a.txt".to_owned()]);
    assert!(parsed.errors.is_empty());

    // parse_list_objects_v2 纯路径（真实响应已由 live_list 用例经客户端覆盖）。
    let listed = parse_list_objects_v2(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>bucket</Name>
  <IsTruncated>false</IsTruncated>
  <Contents><Key>a%20b.txt</Key><Size>3</Size></Contents>
  <EncodingType>url</EncodingType>
</ListBucketResult>"#,
    )
    .expect("解析必须成功");
    assert!(!listed.is_truncated);
    assert_eq!(listed.keys.len(), 1);
    assert_eq!(
        listed.keys[0].key, "a b.txt",
        "encoding-type=url 必须百分号解码"
    );
}

/// 收尾清扫：列出本进程前缀下的全部键逐键删除，复查断言无残留。
#[tokio::test]
#[ignore = "需要真实 AWS S3 与 FOUNDATIONX_S3X_* 环境变量"]
async fn live_cleanup_sweep_no_residual() {
    let client = S3Client::connect(env_config())
        .await
        .expect("connect 必须成功");
    let deleted = sweep_run_prefix(&client).await;

    let prefix = run_prefix();
    let mut token: Option<String> = None;
    let mut leftover = 0usize;
    loop {
        let page = client
            .list_objects_v2(Some(&prefix), token.as_deref(), None)
            .await
            .expect("复查列举必须成功");
        leftover += page.keys.len();
        if !page.is_truncated {
            break;
        }
        token = page.next_continuation_token;
    }
    assert_eq!(
        leftover, 0,
        "清扫后本进程前缀内不得有残留（本次清扫删除 {deleted} 个对象）"
    );
}
