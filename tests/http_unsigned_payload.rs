#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::unreachable
)]
//! 「明文 HTTP + 未签名载荷」默认拒绝。
//!
//! `UNSIGNED-PAYLOAD` 表示签名**不覆盖请求体**；明文 HTTP 也不提供传输层完整性。
//! 两者叠加时请求体在链路上可被篡改而签名依然有效，因此 `put_object_stream`
//! 在 endpoint 为 `http` 时默认返回 [`S3Error::Config`]，需显式放行。
//!
//! 判据两条：错误类型必须是 `Config`（而不是「请求发出后失败」），且服务端
//! **没有收到任何请求**。预签名 URL（`presign_*`）恒定使用 `UNSIGNED-PAYLOAD`，
//! 因此受同一策略约束，但它是纯函数、不涉及服务端。全部离线运行。

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use s3x::{
    byte_stream_from_bytes, presign_get, presign_put, presign_url, ObjectKey, PresignOptions,
    S3Client, S3Config, S3Error, UploadOptions,
};

/// 桩服务：按序把每个 `body` 作为 `200 OK` 返回，并统计实际收到的请求数。
///
/// 传入空脚本时监听立即关闭，端口变为不可达——若被测代码错误地发出了请求，
/// 会以连接错误暴露（断言 `Config` 会失败），而不是静默通过。
fn serve_bodies(
    bodies: Vec<&'static str>,
) -> (String, Arc<AtomicUsize>, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("绑定本地端口必须成功");
    let addr = listener.local_addr().expect("读取本地地址");
    let hits: Arc<AtomicUsize> = Arc::new(AtomicUsize::new(0));
    let hits_server = hits.clone();
    let handle = std::thread::spawn(move || {
        for body in bodies {
            let Ok((mut stream, _)) = listener.accept() else {
                break;
            };
            let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
            let mut buffer = [0_u8; 8192];
            let _ = stream.read(&mut buffer);
            hits_server.fetch_add(1, Ordering::SeqCst);
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
        }
    });
    (format!("http://{addr}"), hits, handle)
}

fn config(endpoint: &str) -> S3Config {
    S3Config::builder()
        .endpoint(endpoint)
        .bucket("examplebucket")
        .access_key_id("AKIAIOSFODNN7EXAMPLE")
        .access_key_secret("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
        .force_path_style(true)
        .max_retries(1)
        .request_timeout(Duration::from_millis(300))
        .connect_timeout(Some(Duration::from_millis(300)))
        .build()
        .expect("测试配置必须有效")
}

fn key() -> ObjectKey {
    ObjectKey::new("probe.bin").expect("合法键")
}

fn stream_of(data: &'static [u8]) -> s3x::ByteStream {
    byte_stream_from_bytes(Bytes::from_static(data))
}

/// `endpoint_is_plain_http()` 必须只认明文 http。
#[test]
fn plain_http_detection_follows_endpoint_scheme() {
    assert!(config("http://127.0.0.1:9000").endpoint_is_plain_http());
    assert!(!config("https://s3.example.com").endpoint_is_plain_http());
    // 未显式配置 endpoint 时走 AWS 官方 HTTPS 端点。
    let default_endpoint = S3Config {
        endpoint: None,
        ..config("https://s3.example.com")
    };
    assert!(!default_endpoint.endpoint_is_plain_http());
}

/// 默认档位：明文 HTTP + 流式上传必须被**本地**拒绝，且请求不得发出。
#[tokio::test]
async fn streaming_upload_over_http_is_rejected_by_default() {
    // 空脚本：监听立刻关闭，端口不可达。
    let (endpoint, hits, server) = serve_bodies(Vec::new());
    let client = S3Client::new(config(&endpoint)).expect("客户端构造必须成功");

    let error = client
        .put_object_stream(
            &key(),
            stream_of(b"hello"),
            &UploadOptions::default(),
            Some(5),
        )
        .await
        .expect_err("明文 HTTP 上的流式上传必须被拒绝");

    assert!(
        matches!(error, S3Error::Config(_)),
        "应为配置错误（本地拒绝），实际为 {error:?}"
    );
    let message = error.to_string();
    assert!(
        message.contains("allow_unsigned_payload_over_http"),
        "错误消息应指明放行方式: {message}"
    );
    assert_eq!(
        hits.load(Ordering::SeqCst),
        0,
        "被拒绝的请求不应发出，服务端不得收到任何请求"
    );
    server.join().expect("桩服务线程不得 panic");
}

/// 显式放行后，同样的 http endpoint 应正常发出请求。
#[tokio::test]
async fn streaming_upload_over_http_is_allowed_when_opted_in() {
    let (endpoint, hits, server) = serve_bodies(vec![""]);
    let mut opted_in = config(&endpoint);
    opted_in.allow_unsigned_payload_over_http = true;
    let client = S3Client::new(opted_in).expect("客户端构造必须成功");

    let meta = client
        .put_object_stream(
            &key(),
            stream_of(b"hello"),
            &UploadOptions::default(),
            Some(5),
        )
        .await
        .expect("显式放行后应上传成功");

    assert_eq!(meta.key, "probe.bin");
    assert_eq!(hits.load(Ordering::SeqCst), 1, "放行后请求应到达服务端");
    server.join().expect("桩服务线程不得 panic");
}

/// 该判定只针对明文 http：HTTPS 端点不应报配置错误。
#[tokio::test]
async fn streaming_upload_over_https_is_not_rejected_locally() {
    // `127.0.0.1:1` 必然拒绝连接，因此会得到连接类错误——但不能是 Config。
    let client = S3Client::new(config("https://127.0.0.1:1")).expect("客户端构造必须成功");

    let error = client
        .put_object_stream(
            &key(),
            stream_of(b"hello"),
            &UploadOptions::default(),
            Some(5),
        )
        .await
        .expect_err("不可达端点必须失败");

    assert!(
        !matches!(error, S3Error::Config(_)),
        "HTTPS 不应被该判定拦下，实际为 {error:?}"
    );
    assert!(
        matches!(error, S3Error::Connection(_) | S3Error::Timeout(_)),
        "{error:?}"
    );
}

/// 回归：默认档位不影响明文 http 上的其它操作（它们的载荷哈希是真实 SHA-256）。
#[tokio::test]
async fn plain_http_still_allows_other_operations() {
    let (endpoint, hits, server) = serve_bodies(vec!["", "stored-body"]);
    let client = S3Client::new(config(&endpoint)).expect("客户端构造必须成功");

    client
        .put_object(
            &key(),
            Bytes::from_static(b"plain"),
            &UploadOptions::default(),
        )
        .await
        .expect("put_object 的载荷哈希覆盖请求体，不受该判定影响");

    let body = client
        .get_object_bytes(&key())
        .await
        .expect("get_object 不受该判定影响");
    assert_eq!(&body[..], b"stored-body");
    assert_eq!(hits.load(Ordering::SeqCst), 2);
    server.join().expect("桩服务线程不得 panic");
}

/// 预签名 URL 恒定使用 `UNSIGNED-PAYLOAD`，因此同样受默认拒绝策略约束。
#[test]
fn presign_over_http_is_rejected_by_default() {
    let config = config("http://minio.internal:9000");

    for error in [
        presign_get(&config, &key(), 60).expect_err("presign_get 必须被拒绝"),
        presign_put(&config, &key(), 60).expect_err("presign_put 必须被拒绝"),
        presign_url(&config, &key(), &PresignOptions::get(60)).expect_err("presign_url 必须被拒绝"),
    ] {
        assert!(
            matches!(error, S3Error::Config(_)),
            "应为配置错误，实际为 {error:?}"
        );
        assert!(
            error
                .to_string()
                .contains("allow_unsigned_payload_over_http"),
            "错误消息应指明放行方式: {error}"
        );
    }
}

/// 显式放行后，明文 HTTP 上同样可以生成预签名 URL。
#[test]
fn presign_over_http_is_allowed_when_opted_in() {
    let mut opted_in = config("http://minio.internal:9000");
    opted_in.allow_unsigned_payload_over_http = true;

    let url = presign_get(&opted_in, &key(), 60).expect("显式放行后应成功");
    // `config()` 使用 path-style 寻址。
    assert!(
        url.starts_with("http://minio.internal:9000/examplebucket/probe.bin?"),
        "{url}"
    );
    assert!(url.contains("X-Amz-Signature="), "{url}");
}

/// HTTPS 端点不受该策略约束（预签名是纯函数，无需网络）。
#[test]
fn presign_over_https_is_not_rejected() {
    let url = presign_get(&config("https://minio.internal:9000"), &key(), 60)
        .expect("HTTPS 不应被该判定拦下");
    assert!(
        url.starts_with("https://minio.internal:9000/examplebucket/probe.bin?"),
        "{url}"
    );

    // 未显式配置 endpoint 时走 AWS 官方 HTTPS 端点，同样放行。
    let default_endpoint = S3Config {
        endpoint: None,
        ..config("https://minio.internal:9000")
    };
    assert!(presign_get(&default_endpoint, &key(), 60).is_ok());
}
