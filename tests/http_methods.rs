//! 每个公开操作真正发出的 HTTP 方法。
//!
//! 回归保护：方法名此前是字符串，经 `reqwest::Method::from_bytes(..).unwrap_or(GET)`
//! 转换——一旦某个调用点把方法名写错（例如 `"DELELE"`），解析失败会**静默回退成
//! GET**，既不报错也不会被任何测试发现。改成 [`reqwest::Method`] 常量后错误不再是
//! 可表达的状态，本用例则把「哪个操作该发哪个方法」钉死在端到端行为上。
//!
//! 桩服务记录每个请求的请求行首词（即 HTTP 方法），据此断言。全部离线运行。

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use s3x::{DownloadOptions, ObjectKey, S3Client, S3Config, UploadOptions};

/// 最小可解析的 `ListObjectsV2` 响应。
const EMPTY_LIST: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
<ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"></ListBucketResult>";

/// 桩服务：按序响应并记录每次请求的 HTTP 方法。
fn serve_recording(
    bodies: Vec<&'static str>,
) -> (String, Arc<Mutex<Vec<String>>>, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("绑定本地端口必须成功");
    let addr = listener.local_addr().expect("读取本地地址");
    let methods: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let methods_server = methods.clone();
    let handle = std::thread::spawn(move || {
        for body in bodies {
            let Ok((mut stream, _)) = listener.accept() else {
                break;
            };
            let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
            let mut buffer = [0_u8; 8192];
            let read = stream.read(&mut buffer).unwrap_or(0);
            // 请求行形如 `PUT /examplebucket/probe.bin HTTP/1.1`。
            let head = String::from_utf8_lossy(&buffer[..read]);
            let method = head
                .split_whitespace()
                .next()
                .expect("请求行必须存在首词")
                .to_owned();
            methods_server.lock().expect("方法表锁").push(method);

            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
        }
    });
    (format!("http://{addr}"), methods, handle)
}

fn config(endpoint: &str) -> S3Config {
    S3Config::builder()
        .endpoint(endpoint)
        .bucket("examplebucket")
        .access_key_id("AKIAIOSFODNN7EXAMPLE")
        .access_key_secret("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
        .force_path_style(true)
        .max_retries(1)
        .request_timeout(Duration::from_millis(500))
        .connect_timeout(Some(Duration::from_millis(500)))
        .build()
        .expect("测试配置必须有效")
}

fn key() -> ObjectKey {
    ObjectKey::new("probe.bin").expect("合法键")
}

#[tokio::test]
async fn every_operation_uses_its_expected_http_method() {
    // 响应脚本与下方调用顺序一一对应；空串表示该操作不读取响应体。
    let (endpoint, methods, server) = serve_recording(vec![
        "",         // ping            -> HEAD
        "",         // put_object      -> PUT
        "payload",  // get_object      -> GET
        "payload",  // get_object_bytes -> GET
        "",         // head_object     -> HEAD
        "",         // delete_object   -> DELETE
        EMPTY_LIST, // list_objects_v2 -> GET
    ]);
    let client = S3Client::new(config(&endpoint)).expect("客户端构造必须成功");

    client.ping().await.expect("ping 必须成功");
    client
        .put_object(
            &key(),
            bytes::Bytes::from_static(b"x"),
            &UploadOptions::default(),
        )
        .await
        .expect("put_object 必须成功");
    let (_meta, stream) = client
        .get_object(&key(), &DownloadOptions::default())
        .await
        .expect("get_object 必须成功");
    drop(stream);
    client
        .get_object_bytes(&key())
        .await
        .expect("get_object_bytes 必须成功");
    client
        .head_object(&key())
        .await
        .expect("head_object 必须成功");
    client
        .delete_object(&key())
        .await
        .expect("delete_object 必须成功");
    client
        .list_objects_v2(None, None, None)
        .await
        .expect("list_objects_v2 必须成功");

    let recorded = methods.lock().expect("方法表锁").clone();
    assert_eq!(
        recorded,
        vec!["HEAD", "PUT", "GET", "GET", "HEAD", "DELETE", "GET"],
        "各操作发出的 HTTP 方法必须与预期一致"
    );
    server.join().expect("桩服务线程不得 panic");
}
