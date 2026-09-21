//! HTTP 层瞬时故障的重试行为。
//!
//! 回归保护：状态码到 [`s3x::S3Error`] 的映射必须发生在**被重试的闭包内部**。
//! 曾经映射在 `with_retry` 返回之后，导致 `5xx` / `429` / `SlowDown` 这类
//! HTTP 层瞬时故障一次都不重试，`max_retries` 形同虚设。
//!
//! 每个用例用本地桩服务脚本化一串响应，并统计服务端**实际收到的请求数**，
//! 用它作为「是否真的重试了」的判据。全部离线运行。

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use s3x::{ObjectKey, S3Client, S3Config, S3Error, UploadOptions};

/// 503 的典型 S3 错误体（`SlowDown` 是常见的可重试瞬时故障）。
const SLOW_DOWN: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
<Error><Code>SlowDown</Code><Message>Please reduce your request rate.</Message></Error>";
/// 404 的典型 S3 错误体（不可重试）。
const NO_SUCH_KEY: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
<Error><Code>NoSuchKey</Code><Message>The specified key does not exist.</Message></Error>";
/// AWS 的 `RequestTimeout` 使用 HTTP **400**：只有「错误码优先于状态码」才能重试它。
const REQUEST_TIMEOUT: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
<Error><Code>RequestTimeout</Code>\
<Message>Your socket connection to the server was not read from or written to within \
the timeout period.</Message></Error>";

/// 桩服务收到的请求数。
type Hits = Arc<AtomicUsize>;

/// 按脚本顺序返回响应，服务完即关闭监听（多余请求会连接被拒）。
///
/// `responses` 为 `(状态行, 正文)` 序列，按序对应第 1、2、3… 次请求。
fn serve_script(
    responses: Vec<(&'static str, &'static str)>,
) -> (String, Hits, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("绑定本地端口必须成功");
    let addr = listener.local_addr().expect("读取本地地址");
    let hits: Hits = Arc::new(AtomicUsize::new(0));
    let hits_server = hits.clone();
    let handle = std::thread::spawn(move || {
        for (status_line, body) in responses {
            let Ok((mut stream, _)) = listener.accept() else {
                break;
            };
            let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
            // 读掉请求（小体积请求头 + 正文通常一次读完），避免客户端写入时收到 RST。
            let mut buffer = [0_u8; 8192];
            let _ = stream.read(&mut buffer);
            hits_server.fetch_add(1, Ordering::SeqCst);
            let response = format!(
                "{status_line}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
        }
    });
    (format!("http://{addr}"), hits, handle)
}

fn config(endpoint: &str, max_retries: u32) -> S3Config {
    S3Config::builder()
        .endpoint(endpoint)
        .bucket("examplebucket")
        .access_key_id("AKIAIOSFODNN7EXAMPLE")
        .access_key_secret("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
        .force_path_style(true)
        .request_timeout(Duration::from_millis(500))
        .connect_timeout(Some(Duration::from_millis(500)))
        .max_retries(max_retries)
        .build()
        .expect("测试配置必须有效")
}

fn key() -> ObjectKey {
    ObjectKey::new("probe.txt").expect("合法键")
}

/// `GET` 在连续 `5xx` 后成功：必须继续重试直到拿到 2xx。
#[tokio::test]
async fn retries_on_5xx_until_success() {
    let (endpoint, hits, server) = serve_script(vec![
        ("HTTP/1.1 503 Service Unavailable", SLOW_DOWN),
        ("HTTP/1.1 500 Internal Server Error", SLOW_DOWN),
        ("HTTP/1.1 200 OK", "hello-s3"),
    ]);
    let client = S3Client::new(config(&endpoint, 4)).expect("客户端构造必须成功");

    let body = client
        .get_object_bytes(&key())
        .await
        .expect("前两次失败后第三次必须成功");

    assert_eq!(&body[..], b"hello-s3");
    assert_eq!(
        hits.load(Ordering::SeqCst),
        3,
        "应恰好发起 3 次请求（2 次失败 + 1 次成功）"
    );
    server.join().expect("桩服务线程不得 panic");
}

/// `429 Too Many Requests` 属于 4xx，但明确可重试。
#[tokio::test]
async fn retries_on_429() {
    let (endpoint, hits, server) = serve_script(vec![
        ("HTTP/1.1 429 Too Many Requests", SLOW_DOWN),
        ("HTTP/1.1 200 OK", "after-throttle"),
    ]);
    let client = S3Client::new(config(&endpoint, 4)).expect("客户端构造必须成功");

    let body = client
        .get_object_bytes(&key())
        .await
        .expect("429 后重试必须成功");

    assert_eq!(&body[..], b"after-throttle");
    assert_eq!(hits.load(Ordering::SeqCst), 2, "429 必须重试一次");
    server.join().expect("桩服务线程不得 panic");
}

/// 持续 `5xx`：尝试次数必须恰好等于 `max_retries`（含首次），并返回可重试错误。
#[tokio::test]
async fn exhausts_max_retries_on_persistent_5xx() {
    let (endpoint, hits, server) = serve_script(vec![
        ("HTTP/1.1 503 Service Unavailable", SLOW_DOWN),
        ("HTTP/1.1 503 Service Unavailable", SLOW_DOWN),
        ("HTTP/1.1 503 Service Unavailable", SLOW_DOWN),
        ("HTTP/1.1 503 Service Unavailable", SLOW_DOWN),
    ]);
    let client = S3Client::new(config(&endpoint, 4)).expect("客户端构造必须成功");

    let error = client
        .get_object_bytes(&key())
        .await
        .expect_err("持续 503 必须失败");

    assert!(
        matches!(
            &error,
            S3Error::Backend {
                status: 503,
                code: Some(code),
                ..
            } if code == "SlowDown"
        ),
        "错误应保留状态码与 S3 错误码: {error:?}"
    );
    assert!(error.is_retryable(), "503 SlowDown 必须判为可重试");
    assert_eq!(
        hits.load(Ordering::SeqCst),
        4,
        "max_retries=4 表示最多 4 次尝试（含首次）"
    );
    server.join().expect("桩服务线程不得 panic");
}

/// AWS 的 `RequestTimeout` 挂在 HTTP `400` 上：必须按错误码重试，而不是按状态码放弃。
#[tokio::test]
async fn retries_request_timeout_on_http_400() {
    let (endpoint, hits, server) = serve_script(vec![
        ("HTTP/1.1 400 Bad Request", REQUEST_TIMEOUT),
        ("HTTP/1.1 200 OK", "after-timeout"),
    ]);
    let client = S3Client::new(config(&endpoint, 4)).expect("客户端构造必须成功");

    let body = client
        .get_object_bytes(&key())
        .await
        .expect("400 RequestTimeout 必须重试并在第二次成功");

    assert_eq!(&body[..], b"after-timeout");
    assert_eq!(
        hits.load(Ordering::SeqCst),
        2,
        "400 + RequestTimeout 必须重试一次（错误码优先于状态码）"
    );
    server.join().expect("桩服务线程不得 panic");
}

/// 对照：同为 400 但不含瞬时错误码时不得重试，避免把永久故障当限流。
#[tokio::test]
async fn does_not_retry_http_400_without_transient_code() {
    let invalid_request = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
<Error><Code>InvalidRequest</Code><Message>Bad request.</Message></Error>";
    let (endpoint, hits, server) =
        serve_script(vec![("HTTP/1.1 400 Bad Request", invalid_request)]);
    let client = S3Client::new(config(&endpoint, 4)).expect("客户端构造必须成功");

    let error = client
        .get_object_bytes(&key())
        .await
        .expect_err("400 InvalidRequest 必须失败");

    assert!(
        matches!(&error, S3Error::Backend { status: 400, .. }),
        "{error:?}"
    );
    assert!(!error.is_retryable(), "非瞬时错误码的 400 不可重试");
    assert_eq!(hits.load(Ordering::SeqCst), 1, "不得重试");
    server.join().expect("桩服务线程不得 panic");
}

/// 不可重试的 4xx：必须立即失败，不得浪费重试次数。
#[tokio::test]
async fn does_not_retry_non_retryable_4xx() {
    let (endpoint, hits, server) = serve_script(vec![("HTTP/1.1 404 Not Found", NO_SUCH_KEY)]);
    let client = S3Client::new(config(&endpoint, 4)).expect("客户端构造必须成功");

    let error = client
        .get_object_bytes(&key())
        .await
        .expect_err("404 必须失败");

    assert!(
        matches!(&error, S3Error::Backend { status: 404, .. }),
        "{error:?}"
    );
    assert!(!error.is_retryable(), "404 不得判为可重试");
    assert_eq!(hits.load(Ordering::SeqCst), 1, "不可重试错误必须只请求一次");
    server.join().expect("桩服务线程不得 panic");
}

/// 带请求体的写路径同样要重试，且每次重试都重新签名（正文哈希一致）。
#[tokio::test]
async fn retries_put_object_with_body() {
    let (endpoint, hits, server) = serve_script(vec![
        ("HTTP/1.1 503 Service Unavailable", SLOW_DOWN),
        ("HTTP/1.1 200 OK", ""),
    ]);
    let client = S3Client::new(config(&endpoint, 3)).expect("客户端构造必须成功");

    let meta = client
        .put_object(
            &key(),
            bytes::Bytes::from_static(b"payload"),
            &UploadOptions::default(),
        )
        .await
        .expect("503 后重试的 PUT 必须成功");

    assert_eq!(meta.key, "probe.txt");
    assert_eq!(meta.size, 7);
    assert_eq!(hits.load(Ordering::SeqCst), 2, "PUT 必须重试一次");
    server.join().expect("桩服务线程不得 panic");
}
