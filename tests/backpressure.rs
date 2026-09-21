#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::unreachable
)]
//! `max_in_flight` 并发背压必须覆盖**流式下载**的读取阶段。
//!
//! 回归保护：`get_object` 返回的字节流要持有并发许可，直到流被消费完或丢弃。
//! 曾经许可在「响应头返回」后就归还给池子，慢速大对象下载可以无限并发，
//! `max_in_flight` 对下载路径形同虚设。
//!
//! 判据是「第二个请求是否被额度阻塞」：`max_in_flight = 1` 时，只要首个下载流
//! 还活着，后续操作就必须在 `request_timeout_ms` 内拿不到许可而失败。
//! 全部离线运行。

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use futures_util::StreamExt;
use s3x::{DownloadOptions, ObjectKey, S3Client, S3Config, S3Error};

/// 桩服务：按序把每个 `body` 作为 `200 OK` 返回，并统计实际收到的请求数。
///
/// 脚本用尽后关闭监听，额外请求会连接被拒——若出现这种情况说明断言里的请求数
/// 预期有误，测试会以连接错误的形式暴露出来，而不是静默通过。
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
            let mut buffer = [0_u8; 4096];
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

/// `max_in_flight = 1` 且**不重试**：许可被占用时应立即以超时失败，
/// 避免重试退避把测试拖长。
fn config(endpoint: &str) -> S3Config {
    S3Config::builder()
        .endpoint(endpoint)
        .bucket("examplebucket")
        .access_key_id("AKIAIOSFODNN7EXAMPLE")
        .access_key_secret("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
        .force_path_style(true)
        .max_in_flight(1)
        .max_retries(1)
        .request_timeout(Duration::from_millis(200))
        .connect_timeout(Some(Duration::from_millis(200)))
        .build()
        .expect("测试配置必须有效")
}

fn key() -> ObjectKey {
    ObjectKey::new("probe.bin").expect("合法键")
}

/// 下载流未消费也未丢弃时，并发额度必须一直被占用。
#[tokio::test]
async fn download_stream_holds_permit_until_dropped() {
    let (endpoint, hits, server) = serve_bodies(vec!["payload-1", "payload-2"]);
    let client = S3Client::new(config(&endpoint)).expect("客户端构造必须成功");

    // 1. 取得下载流：此时唯一的并发许可已被该流持有。
    let (_meta, stream) = client
        .get_object(&key(), &DownloadOptions::default())
        .await
        .expect("首次下载必须成功");
    assert_eq!(hits.load(Ordering::SeqCst), 1);

    // 2. 额度被占，第二次请求必须在拿许可时超时——而不是照常发出。
    let blocked = client
        .get_object_bytes(&key())
        .await
        .expect_err("额度被占用时第二个请求必须失败");
    assert!(
        matches!(blocked, S3Error::Timeout(_)),
        "应是等待并发额度超时，实际为 {blocked:?}"
    );
    assert_eq!(
        hits.load(Ordering::SeqCst),
        1,
        "被背压挡住的请求不应到达服务端"
    );

    // 3. 丢弃下载流后额度归还，后续请求恢复正常。
    drop(stream);
    let body = client
        .get_object_bytes(&key())
        .await
        .expect("流被丢弃后额度应已归还");
    assert_eq!(&body[..], b"payload-2");
    assert_eq!(hits.load(Ordering::SeqCst), 2);
    server.join().expect("桩服务线程不得 panic");
}

/// 把流读到结束也应立即归还额度，无需等调用方 drop。
///
/// 注意本用例**不是**原缺陷（许可过早释放）的判据——修复前后它都会通过。它防的是
/// **反方向**的回归：把许可绑到流上之后若忘了在流结束时释放，额度就会被长期占住，
/// 池子逐渐枯竭。真正的判别用例是上面的
/// `download_stream_holds_permit_until_dropped`（在修复前会失败）。
#[tokio::test]
async fn download_stream_releases_permit_at_end_of_stream() {
    let (endpoint, hits, server) = serve_bodies(vec!["payload-1", "payload-2"]);
    let client = S3Client::new(config(&endpoint)).expect("客户端构造必须成功");

    let (_meta, mut stream) = client
        .get_object(&key(), &DownloadOptions::default())
        .await
        .expect("首次下载必须成功");

    let mut received = Vec::new();
    while let Some(chunk) = stream.next().await {
        received.extend_from_slice(&chunk.expect("读取响应体不应失败"));
    }
    assert_eq!(received, b"payload-1");

    // 流对象仍然活着，但已读到 EOF，额度应已归还。
    let body = client
        .get_object_bytes(&key())
        .await
        .expect("读到流结束后额度应已归还");
    assert_eq!(&body[..], b"payload-2");
    assert_eq!(hits.load(Ordering::SeqCst), 2);

    // 结束后再 poll 必须仍是 `None`，不得 panic。
    assert!(stream.next().await.is_none(), "结束后应恒为 None");
    drop(stream);
    server.join().expect("桩服务线程不得 panic");
}
