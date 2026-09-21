//! `ping()` 的失败与「可达但无权限」分支，以及 HTTP 错误体映射。
//!
//! - `127.0.0.1:1` 必然拒绝连接 -> `Err`（连接/超时类，可重试）；
//! - 本地一次性 TCP 服务返回 `403` -> `Ok(())`（端点可达，凭据无 `s3:ListBucket`）；
//! - 本地服务返回 `5xx` -> `Err`（可重试）；`4xx` -> `Err`（不可重试）；
//! - `GET` 响应体中的 `<Code>/<Message>` 会被提取进错误消息。
//!
//! 全部离线运行，不依赖真实对象存储。

use std::io::{Read, Write};
use std::net::TcpListener;
use std::time::Duration;

use s3x::{ObjectKey, S3Client, S3Config, S3Error, UploadOptions};

fn config(endpoint: &str) -> S3Config {
    S3Config::builder()
        .endpoint(endpoint)
        .bucket("examplebucket")
        .access_key_id("AKIAIOSFODNN7EXAMPLE")
        .access_key_secret("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
        .force_path_style(true)
        .request_timeout(Duration::from_millis(300))
        .connect_timeout(Some(Duration::from_millis(300)))
        .max_retries(1)
        .build()
        .expect("测试配置必须有效")
}

/// 起一个本地 HTTP 服务，最多处理 `connections` 个请求，返回 `http://addr`。
fn serve(
    status_line: &'static str,
    body: &'static str,
    connections: usize,
) -> (String, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("绑定本地端口必须成功");
    let addr = listener.local_addr().expect("读取本地地址");
    let handle = std::thread::spawn(move || {
        for _ in 0..connections {
            let Ok((mut stream, _)) = listener.accept() else {
                break;
            };
            let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
            // 先读掉请求头，避免客户端在写入时收到 RST。
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
    (format!("http://{addr}"), handle)
}

fn serve_once(
    status_line: &'static str,
    body: &'static str,
) -> (String, std::thread::JoinHandle<()>) {
    serve(status_line, body, 1)
}

#[tokio::test]
async fn ping_on_unreachable_endpoint_returns_err() {
    let client = S3Client::new(config("http://127.0.0.1:1")).expect("同步构造必须成功");

    let error = client.ping().await.expect_err("127.0.0.1:1 必须 ping 失败");
    assert!(
        matches!(error, S3Error::Connection(_) | S3Error::Timeout(_)),
        "{error:?}"
    );
    assert!(error.is_retryable(), "连接类错误应可重试");
}

#[tokio::test]
async fn health_check_reports_unhealthy_instead_of_failing() {
    let client = S3Client::new(config("http://127.0.0.1:1")).expect("同步构造必须成功");

    let health = client.health_check().await.expect("健康检查不返回 Err");
    assert!(!health.healthy);
    assert_eq!(health.bucket, "examplebucket");
    assert_eq!(health.endpoint, "http://127.0.0.1:1");
    assert!(health.latency_ms < 5_000, "耗时应被短超时约束");
}

#[tokio::test]
async fn data_plane_on_unreachable_endpoint_returns_err() {
    let client = S3Client::new(config("http://127.0.0.1:1")).expect("同步构造必须成功");
    let key = ObjectKey::new("k").expect("合法键");

    for label in [
        "put_object",
        "get_object_bytes",
        "head_object",
        "delete_object",
    ] {
        let failed = match label {
            "put_object" => client
                .put_object(
                    &key,
                    bytes::Bytes::from_static(b"x"),
                    &UploadOptions::default(),
                )
                .await
                .is_err(),
            "get_object_bytes" => client.get_object_bytes(&key).await.is_err(),
            "head_object" => client.head_object(&key).await.is_err(),
            _ => client.delete_object(&key).await.is_err(),
        };
        assert!(failed, "{label} 对不可达端点必须返回 Err");
    }

    assert!(client.get_object(&key, &Default::default()).await.is_err());
    assert!(client.list_objects_v2(None, None, None).await.is_err());
}

#[tokio::test]
async fn ping_treats_forbidden_as_reachable() {
    // ping 与 health_check 各发一次请求。
    let (endpoint, server) = serve("HTTP/1.1 403 Forbidden", "", 2);
    let client = S3Client::new(config(&endpoint)).expect("同步构造必须成功");

    client
        .ping()
        .await
        .expect("403 表示端点可达但无权限，应返回 Ok");
    let health = client.health_check().await.expect("健康检查");
    assert!(health.healthy, "403 仍算健康");
    server.join().expect("服务线程必须正常结束");
}

#[tokio::test]
async fn ping_succeeds_on_ok_response() {
    let (endpoint, server) = serve("HTTP/1.1 200 OK", "", 2);
    let client = S3Client::new(config(&endpoint)).expect("同步构造必须成功");

    client.ping().await.expect("200 必须成功");
    assert!(client.health_check().await.expect("健康检查").healthy);
    server.join().expect("服务线程必须正常结束");
}

#[tokio::test]
async fn ping_surfaces_server_errors_by_status() {
    let (endpoint, server) = serve_once("HTTP/1.1 500 Internal Server Error", "");
    let client = S3Client::new(config(&endpoint)).expect("同步构造必须成功");

    let error = client.ping().await.expect_err("500 必须返回 Err");
    match &error {
        S3Error::Backend {
            status,
            code,
            message,
        } => {
            assert_eq!(*status, 500);
            // HEAD 响应没有正文，S3 错误码无从提取，只能依赖状态码分类。
            assert!(code.is_none(), "{code:?}");
            assert!(message.contains("HTTP 500"), "{message}");
        }
        other => panic!("意外的错误类型: {other:?}"),
    }
    assert!(error.is_retryable(), "500 应可重试");
    server.join().expect("服务线程必须正常结束");
}

#[tokio::test]
async fn ping_reports_missing_bucket_as_error() {
    let (endpoint, server) = serve_once("HTTP/1.1 404 Not Found", "");
    let client = S3Client::new(config(&endpoint)).expect("同步构造必须成功");

    let error = client.ping().await.expect_err("404 必须返回 Err");
    match &error {
        S3Error::Backend { status, .. } => assert_eq!(*status, 404),
        other => panic!("意外的错误类型: {other:?}"),
    }
    assert!(!error.is_retryable(), "404 不可重试");
    server.join().expect("服务线程必须正常结束");
}

#[tokio::test]
async fn get_extracts_s3_error_code_and_message() {
    let (endpoint, server) = serve_once(
        "HTTP/1.1 404 Not Found",
        "<Error><Code>NoSuchKey</Code><Message>The specified key does not exist.</Message></Error>",
    );
    let client = S3Client::new(config(&endpoint)).expect("同步构造必须成功");
    let key = ObjectKey::new("missing.txt").expect("合法键");

    let error = client
        .get_object_bytes(&key)
        .await
        .expect_err("404 必须返回 Err");
    match &error {
        S3Error::Backend {
            status,
            code,
            message,
        } => {
            assert_eq!(*status, 404);
            assert_eq!(code.as_deref(), Some("NoSuchKey"));
            assert!(message.contains("does not exist"), "{message}");
        }
        other => panic!("意外的错误类型: {other:?}"),
    }
    assert!(!error.is_retryable());
    server.join().expect("服务线程必须正常结束");
}

#[tokio::test]
async fn oversized_error_message_is_truncated() {
    const LIMIT: usize = s3x::MAX_ERROR_MESSAGE_CHARS;
    let body: &'static str = Box::leak(
        format!(
            "<Error><Code>AccessDenied</Code><Message>{}</Message></Error>",
            "M".repeat(LIMIT * 2)
        )
        .into_boxed_str(),
    );
    let (endpoint, server) = serve_once("HTTP/1.1 403 Forbidden", body);
    let client = S3Client::new(config(&endpoint)).expect("同步构造必须成功");
    let key = ObjectKey::new("k").expect("合法键");

    let error = client
        .get_object_bytes(&key)
        .await
        .expect_err("403 必须返回 Err");
    match &error {
        S3Error::Backend { message, .. } => {
            let length = message.chars().count();
            assert!(
                length <= LIMIT + 1,
                "错误消息必须被截断，实际 {length} 字符"
            );
        }
        other => panic!("意外的错误类型: {other:?}"),
    }
    server.join().expect("服务线程必须正常结束");
}
