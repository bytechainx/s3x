#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::unreachable
)]
//! TDD 行为契约（特性 002）。
//!
//! 下表逐条登记 `specs/features/002-*/contracts/public-api-contract.md` 中 s3x 的全部入口。
//! 公开 API 已存在，先写断言只能得到假断言，因此每条入口都在 `/tmp` 的变异副本上
//! 观测过红、再在本树观测绿；变异描述与复现命令见 PR 描述。
//!
//! 数据面入口用**本地一次性 TCP 服务**驱动（path-style + loopback HTTP），完全离线、
//! 不依赖真实对象存储，也不使用 `#[ignore]`。
//!
//! // TDD-PROBE: S3Config::from_env | 变异：必填环境变量缺失时回落到默认值 | 红=from_env_requires_credentials | 绿=from_env_requires_credentials
//! // TDD-PROBE: S3Config::from_toml | 变异：TOML 中的 access_key_secret 被接受 | 红=from_toml_rejects_secret_keys | 绿=from_toml_rejects_secret_keys
//! // TDD-PROBE: S3Config::validate | 变异：桶名长度上界被放宽 | 红=validate_enforces_shape_and_bounds | 绿=validate_enforces_shape_and_bounds
//! // TDD-PROBE: S3Client::new | 变异：非法配置也能构造客户端 | 红=client_new_and_connect_do_not_network | 绿=client_new_and_connect_do_not_network
//! // TDD-PROBE: S3Client::connect | 变异：connect 发起网络请求 | 红=client_new_and_connect_do_not_network | 绿=client_new_and_connect_do_not_network
//! // TDD-PROBE: S3Client::ping | 变异：403 被当作不可达 | 红=ping_distinguishes_reachable_from_forbidden | 绿=ping_distinguishes_reachable_from_forbidden
//! // TDD-PROBE: S3Client::put_object | 变异：上传返回的元数据 size 恒为 0 | 红=put_object_returns_metadata | 绿=put_object_returns_metadata
//! // TDD-PROBE: S3Client::get_object_bytes | 变异：404 被当作成功返回空体 | 红=get_object_bytes_surfaces_404 | 绿=get_object_bytes_surfaces_404
//! // TDD-PROBE: S3Client::list_objects_v2 | 变异：列举结果丢弃全部 key | 红=list_objects_v2_parses_keys | 绿=list_objects_v2_parses_keys
//! // TDD-PROBE: ObjectKey::new | 变异：接受 `..` 路径片段 | 红=object_key_rejects_traversal | 绿=object_key_rejects_traversal
//! // TDD-PROBE: presign_get | 变异：有效期不再收敛到上限 | 红=presign_get_signs_and_clamps_expiry | 绿=presign_get_signs_and_clamps_expiry
//! // TDD-PROBE: S3Error::is_retryable | 变异：瞬时错误码不再优先于状态码 | 红=error_is_retryable_matrix | 绿=error_is_retryable_matrix

use std::io::{Read, Write};
use std::net::TcpListener;
use std::time::Duration;

use bytes::Bytes;
use s3x::{
    is_s3_retryable, presign_get, ListObjectsResult, ObjectKey, ObjectMeta, S3Client, S3Config,
    S3Error, UploadOptions, ENV_ACCESS_KEY_ID, ENV_ACCESS_KEY_SECRET,
    ENV_ALLOW_UNSIGNED_PAYLOAD_OVER_HTTP, ENV_BUCKET, ENV_CONNECT_TIMEOUT_MS, ENV_ENDPOINT,
    ENV_FORCE_PATH_STYLE, ENV_MAX_IN_FLIGHT, ENV_MAX_RETRIES, ENV_REGION, ENV_REQUEST_TIMEOUT_MS,
    ENV_SESSION_TOKEN, ENV_USER_AGENT, HARD_MAX_IN_FLIGHT, HARD_MAX_PRESIGN_EXPIRES_SECS,
    HARD_MAX_REQUEST_TIMEOUT_MS, HARD_MAX_RETRIES, MAX_BUCKET_NAME_LEN,
};

/// 环境变量是进程级共享状态：本文件的 env 用例必须串行。
static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

const ALL_ENV: [&str; 13] = [
    ENV_ENDPOINT,
    ENV_REGION,
    ENV_BUCKET,
    ENV_ACCESS_KEY_ID,
    ENV_ACCESS_KEY_SECRET,
    ENV_SESSION_TOKEN,
    ENV_FORCE_PATH_STYLE,
    ENV_REQUEST_TIMEOUT_MS,
    ENV_CONNECT_TIMEOUT_MS,
    ENV_MAX_RETRIES,
    ENV_MAX_IN_FLIGHT,
    ENV_USER_AGENT,
    ENV_ALLOW_UNSIGNED_PAYLOAD_OVER_HTTP,
];

fn env_guard() -> std::sync::MutexGuard<'static, ()> {
    ENV_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn clear_env() {
    for name in ALL_ENV {
        std::env::remove_var(name);
    }
}

const AK_ID: &str = "AKIAIOSFODNN7EXAMPLE";
const AK_SECRET: &str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

/// path-style + loopback HTTP + 单次尝试：本地桩服务每次操作只处理 1 个连接。
fn config(endpoint: &str) -> S3Config {
    S3Config::builder()
        .endpoint(endpoint)
        .bucket("examplebucket")
        .access_key_id(AK_ID)
        .access_key_secret(AK_SECRET)
        .force_path_style(true)
        .request_timeout(Duration::from_millis(300))
        .connect_timeout(Some(Duration::from_millis(300)))
        .max_retries(1)
        .build()
        .expect("测试配置必须有效")
}

/// 起一个本地一次性 HTTP 服务，最多处理 `connections` 个请求，返回 `http://addr`。
///
/// 服务线程随句柄被丢弃而分离；进程退出时自然结束，不阻塞用例。
fn serve(status_line: &'static str, body: &'static str, connections: usize) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("绑定本地端口必须成功");
    let addr = listener.local_addr().expect("读取本地地址");
    let _server = std::thread::spawn(move || {
        for _ in 0..connections {
            let Ok((mut stream, _)) = listener.accept() else {
                break;
            };
            let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
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
    format!("http://{addr}")
}

const LIST_BODY: &str = concat!(
    "<ListBucketResult>",
    "<Name>examplebucket</Name>",
    "<IsTruncated>false</IsTruncated>",
    "<Contents><Key>a.txt</Key><Size>3</Size><ETag>\"e1\"</ETag></Contents>",
    "<Contents><Key>dir/b.txt</Key><Size>5</Size></Contents>",
    "</ListBucketResult>"
);

/// `S3Config::from_env`：必填项（桶与凭据）缺失即 fail-closed；存在时按前缀读取。
#[test]
fn from_env_requires_credentials() {
    let _guard = env_guard();
    clear_env();

    let error = S3Config::from_env().expect_err("缺凭据必须失败");
    assert!(matches!(error, S3Error::Config(_)), "{error:?}");

    std::env::set_var(ENV_BUCKET, "env-bucket");
    std::env::set_var(ENV_ACCESS_KEY_ID, "env-id");
    std::env::set_var(ENV_ACCESS_KEY_SECRET, "env-secret");
    let config = S3Config::from_env().expect("三项必填齐备即成功");
    assert_eq!(config.bucket, "env-bucket");
    assert_eq!(config.access_key_id, "env-id");
    assert_eq!(config.region, "us-east-1", "region 未设置时取默认值");
    assert!(!config.force_path_style);

    // 覆盖项走同一前缀。
    std::env::set_var(ENV_REGION, "eu-west-1");
    std::env::set_var(ENV_FORCE_PATH_STYLE, "true");
    std::env::set_var(ENV_MAX_RETRIES, "5");
    std::env::set_var(ENV_ENDPOINT, "https://minio.example.com:9000");
    let config = S3Config::from_env().expect("覆盖项合法");
    assert_eq!(config.region, "eu-west-1");
    assert!(config.force_path_style);
    assert_eq!(config.max_retries, 5);
    assert_eq!(
        config.effective_endpoint(),
        "https://minio.example.com:9000"
    );

    // 越界必须报错，而不是静默收敛。
    std::env::set_var(ENV_MAX_RETRIES, (HARD_MAX_RETRIES + 1).to_string());
    let error = S3Config::from_env().expect_err("超过硬上限必须失败");
    assert!(error.to_string().contains("max_retries"), "{error}");

    clear_env();
}

/// `S3Config::from_toml`：凭据字段被 `deny_unknown_fields` 拒绝；非凭据字段可解析。
#[test]
fn from_toml_rejects_secret_keys() {
    let secret_line = format!(
        "bucket = \"examplebucket\"\naccess_key_id = \"{AK_ID}\"\naccess_key_secret = \"{AK_SECRET}\"\n"
    );
    let error = S3Config::from_toml(&secret_line).expect_err("access_key_secret 必须拒绝");
    assert!(error.to_string().contains("TOML"), "{error}");

    let token_line = "bucket = \"examplebucket\"\nsession_token = \"t\"\n";
    assert!(
        S3Config::from_toml(token_line).is_err(),
        "session_token 也必须拒绝"
    );

    // 合法 TOML：只含非凭据字段，解析后可直接用于构造 builder。
    let parsed = S3Config::from_toml(
        "endpoint = \"https://minio.example.com:9000\"\nbucket = \"examplebucket\"\n\
         access_key_id = \"AKIDEXAMPLE\"\nregion = \"eu-west-1\"\nmax_retries = 2\n",
    )
    .expect("非凭据字段必须可解析");
    assert_eq!(parsed.bucket, "examplebucket");
    assert_eq!(parsed.region, "eu-west-1");
    assert_eq!(parsed.max_retries, 2);
    // from_toml 只校验形态，凭据仍需外部注入；补上 secret 后完整校验通过。
    let complete = s3x::S3ConfigBuilder::from_config(parsed)
        .access_key_secret(AK_SECRET)
        .build()
        .expect("补齐凭据后必须有效");
    assert_eq!(complete.access_key_id, "AKIDEXAMPLE");

    let malformed = S3Config::from_toml("this is not = = toml").expect_err("语法错误");
    assert!(matches!(malformed, S3Error::Config(_)), "{malformed:?}");
}

/// `S3Config::validate`：endpoint / 桶名 / 超时 / 限额形态与硬上界。
#[test]
fn validate_enforces_shape_and_bounds() {
    let builder = || {
        S3Config::builder()
            .bucket("examplebucket")
            .access_key_id(AK_ID)
            .access_key_secret(AK_SECRET)
    };

    // 桶名长度闭区间 3..=63。
    builder().bucket("ab").build().expect_err("过短");
    builder()
        .bucket("a".repeat(MAX_BUCKET_NAME_LEN))
        .build()
        .expect("恰为 63 字节合法");
    builder()
        .bucket("a".repeat(MAX_BUCKET_NAME_LEN + 1))
        .build()
        .expect_err("过长");

    // endpoint 只支持 http/https，且不得含路径前缀或查询串。
    for endpoint in [
        "ftp://example.com",
        "https://example.com/prefix",
        "https://example.com/?x=1",
    ] {
        assert!(
            builder().endpoint(endpoint).build().is_err(),
            "{endpoint} 必须拒绝"
        );
    }
    builder()
        .endpoint("https://minio.example.com:9000")
        .build()
        .expect("合法 endpoint");
    // 未配置 endpoint 时推导 AWS 官方端点。
    let derived = builder().build().expect("合法配置");
    assert_eq!(
        derived.effective_endpoint(),
        "https://s3.us-east-1.amazonaws.com"
    );

    // 超时与限额的闭区间上界。
    assert!(builder()
        .request_timeout(Duration::from_millis(HARD_MAX_REQUEST_TIMEOUT_MS + 1))
        .build()
        .is_err());
    builder()
        .request_timeout(Duration::from_millis(HARD_MAX_REQUEST_TIMEOUT_MS))
        .build()
        .expect("恰为硬上界合法");
    assert!(builder().request_timeout(Duration::ZERO).build().is_err());
    assert!(builder().max_retries(0).build().is_err());
    assert!(builder().max_retries(HARD_MAX_RETRIES + 1).build().is_err());
    assert!(builder().max_in_flight(0).build().is_err());
    assert!(builder()
        .max_in_flight(HARD_MAX_IN_FLIGHT + 1)
        .build()
        .is_err());

    // 凭据非空；session_token 若配置则不得为空串。
    assert!(builder().access_key_id(" ").build().is_err());
    assert!(builder().access_key_secret("").build().is_err());
    assert!(builder().session_token("").build().is_err());
    builder()
        .session_token("t")
        .build()
        .expect("非空 token 合法");
}

/// `S3Client::new`（同步）与 `S3Client::connect`（异步）：只做校验与构造，不发网络请求。
#[tokio::test]
async fn client_new_and_connect_do_not_network() {
    // 不可达端点：两者都必须成功——连通性由 ping 显式承担。
    let client = S3Client::new(config("http://127.0.0.1:1")).expect("同步构造不联网");
    assert_eq!(client.config().bucket, "examplebucket");

    let connected = S3Client::connect(config("http://127.0.0.1:1"))
        .await
        .expect("connect 也不发网络请求");
    assert_eq!(connected.config().bucket, "examplebucket");

    // 非法配置：两者都必须 fail-fast。
    assert!(S3Client::new(S3Config::default()).is_err());
    assert!(S3Client::connect(S3Config::default()).await.is_err());

    let bad_endpoint = S3Config::builder()
        .endpoint("https://example.com/prefix")
        .bucket("examplebucket")
        .access_key_id(AK_ID)
        .access_key_secret(AK_SECRET)
        .build();
    assert!(bad_endpoint.is_err(), "endpoint 含路径前缀必须拒绝");
}

/// `S3Client::ping`：按状态码判定可达性——200 / 403 可达，404 不可重试，5xx 可重试。
#[tokio::test]
async fn ping_distinguishes_reachable_from_forbidden() {
    for status in ["HTTP/1.1 200 OK", "HTTP/1.1 403 Forbidden"] {
        let endpoint = serve(status, "", 2);
        let client = S3Client::new(config(&endpoint)).expect("同步构造");
        client
            .ping()
            .await
            .unwrap_or_else(|error| panic!("{status} 表示端点可达（403 仅无权限）：{error:?}"));
        assert!(client.health_check().await.expect("结构化结果").healthy);
    }

    let missing = serve("HTTP/1.1 404 Not Found", "", 2);
    let client = S3Client::new(config(&missing)).expect("同步构造");
    let error = client.ping().await.expect_err("404 必须失败");
    assert!(!error.is_retryable(), "404 不可重试：{error:?}");

    let failing = serve("HTTP/1.1 500 Internal Server Error", "", 2);
    let client = S3Client::new(config(&failing)).expect("同步构造");
    let error = client.ping().await.expect_err("500 必须失败");
    assert!(error.is_retryable(), "5xx 可重试：{error:?}");

    let unreachable = S3Client::new(config("http://127.0.0.1:1")).expect("同步构造");
    let error = unreachable.ping().await.expect_err("不可达必须失败");
    assert!(
        matches!(error, S3Error::Connection(_) | S3Error::Timeout(_)),
        "{error:?}"
    );
    assert!(error.is_retryable());
}

/// `S3Client::put_object`：上传成功后返回的元数据必须携带真实 key 与字节数。
#[tokio::test]
async fn put_object_returns_metadata() {
    let endpoint = serve("HTTP/1.1 200 OK", "", 2);
    let client = S3Client::new(config(&endpoint)).expect("同步构造");
    let key = ObjectKey::new("dir/object.txt").expect("合法键");
    let body = Bytes::from_static(b"hello s3x");

    let meta: ObjectMeta = client
        .put_object(&key, body.clone(), &UploadOptions::default())
        .await
        .expect("200 必须视为上传成功");
    assert_eq!(meta.key, "dir/object.txt");
    assert_eq!(meta.size, body.len() as u64, "元数据必须反映真实字节数");
    assert!(meta.etag.is_none(), "响应未带 ETag 时应为 None");
}

/// `S3Client::get_object_bytes`：读取响应体；404 归类远端错误并提取 S3 错误码。
#[tokio::test]
async fn get_object_bytes_surfaces_404() {
    let endpoint = serve("HTTP/1.1 200 OK", "body-bytes", 2);
    let client = S3Client::new(config(&endpoint)).expect("同步构造");
    let key = ObjectKey::new("a.txt").expect("合法键");
    let bytes = client.get_object_bytes(&key).await.expect("200 必须成功");
    assert_eq!(&bytes[..], b"body-bytes");

    let missing = serve(
        "HTTP/1.1 404 Not Found",
        "<Error><Code>NoSuchKey</Code><Message>The specified key does not exist.</Message></Error>",
        2,
    );
    let client = S3Client::new(config(&missing)).expect("同步构造");
    let error = client
        .get_object_bytes(&key)
        .await
        .expect_err("404 必须失败");
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
    assert!(!error.is_retryable(), "404 不可重试");
}

/// `S3Client::list_objects_v2`：解析键与大小；`max_keys=0` 在发请求前即拒绝。
#[tokio::test]
async fn list_objects_v2_parses_keys() {
    let endpoint = serve("HTTP/1.1 200 OK", LIST_BODY, 2);
    let client = S3Client::new(config(&endpoint)).expect("同步构造");
    let result: ListObjectsResult = client
        .list_objects_v2(None, None, Some(10))
        .await
        .expect("200 必须解析成功");
    assert_eq!(result.keys.len(), 2);
    assert_eq!(result.keys[0].key, "a.txt");
    assert_eq!(result.keys[0].size, 3);
    assert_eq!(result.keys[0].etag.as_deref(), Some("e1"));
    assert_eq!(result.keys[1].key, "dir/b.txt");
    assert!(!result.is_truncated);

    // max_keys 为 0 属本地参数错误：不得发出请求（端点不可达也不会变成网络错误）。
    let offline = S3Client::new(config("http://127.0.0.1:1")).expect("同步构造");
    let error = offline
        .list_objects_v2(None, None, Some(0))
        .await
        .expect_err("max_keys=0 必须拒绝");
    assert!(matches!(error, S3Error::Config(_)), "{error:?}");
}

/// `ObjectKey::new`：唯一合法对象键入口，构造期完成全部校验。
#[test]
fn object_key_rejects_traversal() {
    let too_long = "k".repeat(s3x::MAX_OBJECT_KEY_BYTES + 1);
    for bad in [
        "",
        "/leading",
        "..",
        "a/../b",
        "line\nbreak",
        "ansi\u{1b}[31m",
        too_long.as_str(),
    ] {
        assert!(ObjectKey::new(bad).is_err(), "非法键 {bad:?} 必须拒绝");
    }
    let ok = ObjectKey::new("dir/子目录/object v1.txt").expect("合法键");
    assert_eq!(ok.as_str(), "dir/子目录/object v1.txt");
    assert_eq!(ok.as_ref(), "dir/子目录/object v1.txt");
    assert_eq!(ok.to_string(), "dir/子目录/object v1.txt");
}

/// `presign_get`：query-string 方式签名；有效期收敛到 `1..=7 天`；明文 HTTP 需显式放行。
#[test]
fn presign_get_signs_and_clamps_expiry() {
    let base = S3Config::builder()
        .bucket("examplebucket")
        .access_key_id(AK_ID)
        .access_key_secret(AK_SECRET)
        .build()
        .expect("AWS 默认端点");
    let key = ObjectKey::new("dir/test.txt").expect("合法键");

    let url = presign_get(&base, &key, 900).expect("预签名必须成功");
    assert!(
        url.starts_with("https://examplebucket.s3.us-east-1.amazonaws.com/dir/test.txt?"),
        "{url}"
    );
    let parsed = url::Url::parse(&url).expect("预签名 URL 合法");
    let params: std::collections::BTreeMap<String, String> = parsed
        .query_pairs()
        .map(|(name, value)| (name.into_owned(), value.into_owned()))
        .collect();
    assert_eq!(params.get("X-Amz-Expires").map(String::as_str), Some("900"));
    assert_eq!(
        params.get("X-Amz-Algorithm").map(String::as_str),
        Some("AWS4-HMAC-SHA256")
    );
    assert!(params
        .get("X-Amz-Signature")
        .is_some_and(|signature| signature.len() == 64));
    assert!(!url.contains(AK_SECRET), "URL 不得携带 secret");

    // 有效期收敛：0 -> 1，极大 -> 7 天。
    let lower = url::Url::parse(&presign_get(&base, &key, 0).unwrap()).unwrap();
    let lower_expires = lower
        .query_pairs()
        .find(|(name, _)| name == "X-Amz-Expires")
        .map(|(_, value)| value.into_owned())
        .unwrap();
    assert_eq!(lower_expires, "1");
    let upper = url::Url::parse(&presign_get(&base, &key, u64::MAX).unwrap()).unwrap();
    let upper_expires = upper
        .query_pairs()
        .find(|(name, _)| name == "X-Amz-Expires")
        .map(|(_, value)| value.into_owned())
        .unwrap();
    assert_eq!(upper_expires, HARD_MAX_PRESIGN_EXPIRES_SECS.to_string());

    // 明文 HTTP endpoint：默认拒绝，显式放行后才可用。
    let plain = config("http://127.0.0.1:9000");
    let error = presign_get(&plain, &key, 60).expect_err("明文 HTTP 默认拒绝");
    assert!(matches!(error, S3Error::Config(_)), "{error:?}");
    let allowed = S3Config::builder()
        .endpoint("http://127.0.0.1:9000")
        .bucket("examplebucket")
        .access_key_id(AK_ID)
        .access_key_secret(AK_SECRET)
        .force_path_style(true)
        .allow_unsigned_payload_over_http(true)
        .build()
        .expect("显式放行");
    presign_get(&allowed, &key, 60).expect("显式放行后必须成功");
}

/// `S3Error::is_retryable`：错误码优先于状态码，其余按状态分类。
#[test]
fn error_is_retryable_matrix() {
    fn backend(status: u16, code: Option<&str>) -> S3Error {
        S3Error::Backend {
            status,
            code: code.map(str::to_owned),
            message: "m".to_owned(),
        }
    }

    for retryable in [
        S3Error::Connection("x".into()),
        S3Error::Io(std::io::Error::other("x")),
        S3Error::Timeout("x".into()),
        backend(500, None),
        backend(503, Some("ServiceUnavailable")),
        backend(429, None),
        backend(408, None),
        // 错误码优先：瞬时码挂在 3xx / 4xx 上同样可重试（AWS 的 RequestTimeout 是 400）。
        backend(400, Some("RequestTimeout")),
        backend(400, Some("SlowDown")),
        backend(403, Some("SlowDown")),
    ] {
        assert!(retryable.is_retryable(), "{retryable:?} 应可重试");
        assert!(is_s3_retryable(&retryable));
    }

    for permanent in [
        S3Error::Config("x".into()),
        S3Error::Serialization("x".into()),
        S3Error::Unsupported("x".into()),
        S3Error::InvalidObjectKey("x".into()),
        backend(400, Some("InvalidRequest")),
        backend(400, None),
        backend(401, None),
        backend(403, Some("SignatureDoesNotMatch")),
        backend(404, Some("NoSuchKey")),
        backend(409, None),
    ] {
        assert!(!permanent.is_retryable(), "{permanent:?} 不应可重试");
    }
}
