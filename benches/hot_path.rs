#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::unreachable
)]
//! s3x 热路径：`S3Config` 构建校验 + SigV4 签名纯函数。
//!
//! 纯本地路径，不发起任何网络请求、不依赖 S3 服务。
use std::hint::black_box;
use std::time::Instant;

use s3x::{percent_encode, presign_get, sha256_hex, ObjectKey, S3Config};

fn iters() -> u32 {
    if std::env::args().any(|a| a == "--quick") {
        1_000
    } else {
        50_000
    }
}

fn main() {
    let n = iters();

    // 预热：配置构建 + 校验。
    for _ in 0..n.min(1_000) {
        let config = S3Config::builder()
            .endpoint("https://s3.amazonaws.com")
            .region("us-east-1")
            .bucket("bench-bucket")
            .access_key_id("bench-key-id")
            .access_key_secret("bench-key-secret")
            .build()
            .unwrap();
        config.validate().unwrap();
        black_box(&config);
    }
    // 预热：SigV4 相关纯函数与预签名 URL。
    let config = S3Config::builder()
        .endpoint("https://s3.amazonaws.com")
        .region("us-east-1")
        .bucket("bench-bucket")
        .access_key_id("bench-key-id")
        .access_key_secret("bench-key-secret")
        .build()
        .unwrap();
    let key = ObjectKey::new("reports/2026-09.csv").unwrap();
    for _ in 0..n.min(1_000) {
        black_box(sha256_hex(b"a,b\n1,2\n"));
        black_box(percent_encode("dir key/report+2026.csv", true));
        let url = presign_get(&config, &key, 60).unwrap();
        black_box(url);
    }

    let start = Instant::now();
    for i in 0..n {
        let config = S3Config::builder()
            .endpoint("https://s3.amazonaws.com")
            .region("us-east-1")
            .bucket("bench-bucket")
            .access_key_id("bench-key-id")
            .access_key_secret("bench-key-secret")
            .build()
            .unwrap();
        config.validate().unwrap();
        let digest = sha256_hex(b"a,b\n1,2\n");
        let encoded = percent_encode("dir key/report+2026.csv", true);
        let url = presign_get(&config, &key, 60).unwrap();
        black_box((i, &config, &digest, &encoded, &url));
    }
    let elapsed = start.elapsed();
    println!(
        "bench_s3x_hot_path: iters={n} total={elapsed:?} per_iter={:?}",
        elapsed / n
    );
}
