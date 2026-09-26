#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::unreachable
)]
//! SDD 规格对照（特性 002）：把 `docs/标准.md` 的章节条款转成可执行断言。
//!
//! // SPEC-MAP: S-1 | 1. 定位 | assert_positioning
//! // SPEC-MAP: S-2 | 2. 字段治理 / 数据约定 | assert_field_and_data_governance
//! // SPEC-MAP: S-3 | 3. 资源治理 | assert_resource_governance
//! // SPEC-MAP: S-4 | 4. 安全约定 | assert_security_contracts
//! // SPEC-MAP: S-5 | 5. 验收 | assert_acceptance
//! // SPEC-MAP: S-6 | 6. 质量门禁约束 | assert_quality_gates

use std::time::Duration;

use s3x::{
    aws_endpoint_for_region, backoff_delay, build_delete_objects_body, canonical_query_string,
    canonical_uri_for_key, date_stamp, default_retry_config, is_s3_retryable, parse_delete_objects,
    parse_list_objects_v2, percent_encode, presign_get, presign_put, sha256_hex, sign_request,
    signing_key, ObjectKey, S3Client, S3Config, S3Error, SignRequest, HARD_MAX_CONNECT_TIMEOUT_MS,
    HARD_MAX_IN_FLIGHT, HARD_MAX_PRESIGN_EXPIRES_SECS, HARD_MAX_REQUEST_TIMEOUT_MS,
    HARD_MAX_RETRIES, MAX_BUCKET_NAME_LEN, MAX_ERROR_BODY_BYTES, MAX_ERROR_MESSAGE_CHARS,
    MAX_LIST_KEYS, MAX_OBJECT_KEY_BYTES, MAX_RETRY_ATTEMPTS, MIN_BUCKET_NAME_LEN,
    PRESIGN_SIGNED_HEADERS, UNSIGNED_PAYLOAD,
};

const MANIFEST: &str = env!("CARGO_MANIFEST_DIR");
const AK_ID: &str = "AKIAIOSFODNN7EXAMPLE";
const AK_SECRET: &str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

fn standard_doc() -> String {
    std::fs::read_to_string(format!("{MANIFEST}/docs/标准.md")).expect("docs/标准.md 必须存在")
}

fn base_config() -> S3Config {
    S3Config::builder()
        .bucket("examplebucket")
        .access_key_id(AK_ID)
        .access_key_secret(AK_SECRET)
        .build()
        .expect("测试配置必须有效")
}

/// S-1：S3 及 S3 兼容访问原语，零内部耦合，手写 SigV4，不依赖 `aws-sdk`。
#[test]
fn assert_positioning() {
    let manifest = std::fs::read_to_string(format!("{MANIFEST}/Cargo.toml")).expect("Cargo.toml");
    for forbidden in ["aws-sdk", "aws-sigv4", "kernel", "contracts", "rusoto"] {
        assert!(
            !manifest.contains(forbidden),
            "不得依赖 {forbidden}（SigV4 为手写实现）"
        );
    }
    // 签名是可独立使用的纯函数：不需要任何客户端句柄。
    let signature = sign_request(&SignRequest {
        method: "GET",
        canonical_uri: "/k",
        query: &[],
        headers: &[("host", "examplebucket.s3.us-east-1.amazonaws.com")],
        payload_hash: UNSIGNED_PAYLOAD,
        amz_date: "20130524T000000Z",
        region: "us-east-1",
        service: s3x::S3_SERVICE,
        access_key_id: AK_ID,
        secret_access_key: AK_SECRET,
    });
    assert!(signature
        .authorization
        .starts_with("AWS4-HMAC-SHA256 Credential="));
    assert_eq!(signature.signed_headers, "host");
    assert_eq!(
        signature.credential_scope,
        "20130524/us-east-1/s3/aws4_request"
    );

    // AWS 官方端点按区域推导。
    assert_eq!(
        aws_endpoint_for_region("us-east-1"),
        "https://s3.us-east-1.amazonaws.com"
    );

    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<S3Client>();
    assert_send_sync::<S3Config>();
}

/// S-2：`ObjectKey` 是唯一合法键入口；SigV4 统一走纯函数原语并遵守 S3 编码规则；
/// XML 解析统一走 `xml` 模块；环境变量使用 `ENV_*` 常量。
#[test]
fn assert_field_and_data_governance() {
    // ObjectKey 构造期校验 + 数据面只接受 ObjectKey（类型系统保证）。
    assert_eq!(ObjectKey::new("dir/k.txt").unwrap().as_str(), "dir/k.txt");
    let too_long = "k".repeat(MAX_OBJECT_KEY_BYTES + 1);
    for bad in ["", "/leading", "../escape", "a\nb", too_long.as_str()] {
        assert!(ObjectKey::new(bad).is_err(), "非法键 {bad:?} 必须拒绝");
    }

    // 规范化 URI：不二次编码——路径分隔符保留，其余按 SigV4 规则编码。
    let key = ObjectKey::new("dir/a b.txt").expect("合法键");
    assert_eq!(canonical_uri_for_key(&key), "/dir/a%20b.txt");

    // 百分号编码：非保留字符原样，保留字符大写十六进制。
    assert_eq!(percent_encode("AZaz09-_.~", true), "AZaz09-_.~");
    assert_eq!(percent_encode("a b", true), "a%20b");
    assert_eq!(percent_encode("a/b", false), "a/b");
    assert_eq!(percent_encode("a/b", true), "a%2Fb");
    assert_eq!(percent_encode("中文", true), "%E4%B8%AD%E6%96%87");

    // 查询串：编码后排序并以 `&` 连接；无值子资源记 `key=`。
    assert_eq!(canonical_query_string(&[("b", "2"), ("a", "1")]), "a=1&b=2");
    assert_eq!(canonical_query_string(&[("uploads", "")]), "uploads=");

    // 摘要与时间戳原语。
    assert_eq!(sha256_hex(b""), s3x::EMPTY_PAYLOAD_SHA256);
    assert_eq!(date_stamp("20150830T123600Z"), "20150830");
    assert_eq!(date_stamp("bad"), "bad", "长度不足时原样返回");

    // XML 解析统一入口：ListObjectsV2 与 DeleteObjects。
    let xml = "<ListBucketResult><IsTruncated>true</IsTruncated>\
               <NextContinuationToken>T1</NextContinuationToken>\
               <Contents><Key>a</Key><Size>2</Size></Contents></ListBucketResult>";
    let listed = parse_list_objects_v2(xml).expect("解析成功");
    assert!(listed.is_truncated);
    assert_eq!(listed.next_continuation_token.as_deref(), Some("T1"));
    assert_eq!(listed.keys.len(), 1);
    let body = build_delete_objects_body(&[ObjectKey::new("a").unwrap()]);
    assert!(body.contains("<Key>a</Key>"), "{body}");
    let deleted = parse_delete_objects(
        "<DeleteResult><Deleted><Key>a</Key></Deleted>\
         <Error><Key>b</Key><Code>AccessDenied</Code><Message>denied</Message></Error>\
         </DeleteResult>",
    )
    .expect("解析成功");
    assert_eq!(deleted.deleted, vec!["a".to_owned()]);
    assert_eq!(deleted.errors.len(), 1);
    assert_eq!(deleted.errors[0].code, "AccessDenied");

    // 环境变量以常量登记，前缀统一。
    assert_eq!(s3x::ENV_PREFIX, "FOUNDATIONX_S3X_");
    assert_eq!(s3x::ENV_BUCKET, "FOUNDATIONX_S3X_BUCKET");
    assert!(s3x::ENV_ENDPOINT.starts_with(s3x::ENV_PREFIX));
}

/// S-3：并发背压、超时与重试上界、错误截断、预签名有效期收敛。
#[test]
fn assert_resource_governance() {
    // 常量基线。
    assert_eq!(HARD_MAX_IN_FLIGHT, 1_024);
    assert_eq!(HARD_MAX_REQUEST_TIMEOUT_MS, 600_000);
    assert_eq!(HARD_MAX_CONNECT_TIMEOUT_MS, 60_000);
    assert_eq!(HARD_MAX_RETRIES, 10);
    assert_eq!(MAX_RETRY_ATTEMPTS, HARD_MAX_RETRIES);
    assert_eq!(MAX_ERROR_MESSAGE_CHARS, 512);
    assert_eq!(MAX_ERROR_BODY_BYTES, 4_096);
    assert_eq!(MAX_LIST_KEYS, 1_000);
    assert_eq!(HARD_MAX_PRESIGN_EXPIRES_SECS, 604_800);

    let builder = || {
        S3Config::builder()
            .bucket("examplebucket")
            .access_key_id(AK_ID)
            .access_key_secret(AK_SECRET)
    };
    // 上界生效：越界 fail-closed（配置面拒绝，而不是静默接受）。
    assert!(builder()
        .request_timeout(Duration::from_millis(HARD_MAX_REQUEST_TIMEOUT_MS + 1))
        .build()
        .is_err());
    assert!(builder()
        .connect_timeout(Some(Duration::from_millis(HARD_MAX_CONNECT_TIMEOUT_MS + 1)))
        .build()
        .is_err());
    assert!(builder()
        .max_in_flight(HARD_MAX_IN_FLIGHT + 1)
        .build()
        .is_err());
    assert!(builder().max_retries(HARD_MAX_RETRIES + 1).build().is_err());
    // 恰好等于上界合法。
    builder()
        .request_timeout(Duration::from_millis(HARD_MAX_REQUEST_TIMEOUT_MS))
        .max_in_flight(HARD_MAX_IN_FLIGHT)
        .build()
        .expect("恰好等于硬上界合法");

    // 重试：指数退避 + 抖动，尝试次数有上限。
    let retry = default_retry_config();
    retry.validate().expect("默认重试配置合法");
    assert!(retry.max_attempts >= 1 && retry.max_attempts <= MAX_RETRY_ATTEMPTS);
    assert!(backoff_delay(&retry, 1) > Duration::ZERO);
    assert!(s3x::RetryConfig::new(MAX_RETRY_ATTEMPTS + 1, 10)
        .validate()
        .is_err());

    // 预签名有效期收敛到 1..=7 天。
    let key = ObjectKey::new("k").expect("合法键");
    let config = base_config();
    let expires = |url: String| -> String {
        url::Url::parse(&url)
            .expect("URL 合法")
            .query_pairs()
            .find(|(name, _)| name == "X-Amz-Expires")
            .map(|(_, value)| value.into_owned())
            .expect("必须含 X-Amz-Expires")
    };
    assert_eq!(expires(presign_get(&config, &key, 0).unwrap()), "1");
    assert_eq!(
        expires(presign_get(&config, &key, u64::MAX).unwrap()),
        HARD_MAX_PRESIGN_EXPIRES_SECS.to_string()
    );
    assert_eq!(expires(presign_get(&config, &key, 3_600).unwrap()), "3600");
    assert_eq!(PRESIGN_SIGNED_HEADERS, "host");
    // 对象键字节上限。
    assert_eq!(MAX_OBJECT_KEY_BYTES, 1_024);
}

/// S-4：凭据只经环境变量或 builder 注入；`from_toml` 拒绝；明文 HTTP 上
/// `UNSIGNED-PAYLOAD` 需显式放行；鉴权失败不重试。
#[test]
fn assert_security_contracts() {
    // from_toml 拒绝两个敏感键。
    for line in [
        "bucket = \"examplebucket\"\naccess_key_secret = \"x\"\n",
        "bucket = \"examplebucket\"\nsession_token = \"x\"\n",
    ] {
        assert!(S3Config::from_toml(line).is_err(), "{line} 必须拒绝");
    }

    // Debug 不回显 secret 与 token。
    let config = S3Config::builder()
        .bucket("examplebucket")
        .access_key_id(AK_ID)
        .access_key_secret(AK_SECRET)
        .session_token("session-token-value")
        .build()
        .unwrap();
    let debug = format!("{config:?}");
    assert!(!debug.contains(AK_SECRET), "{debug}");
    assert!(!debug.contains("session-token-value"), "{debug}");
    assert!(
        debug.contains("***"),
        "secret 与 token 固定渲染为 ***：{debug}"
    );

    // 预签名 URL 携带签名但不携带 secret。
    let key = ObjectKey::new("k").expect("合法键");
    for url in [
        presign_get(&config, &key, 60).unwrap(),
        presign_put(&config, &key, 60).unwrap(),
    ] {
        assert!(url.contains("X-Amz-Signature="), "{url}");
        assert!(!url.contains(AK_SECRET), "{url}");
    }

    // 明文 HTTP + UNSIGNED-PAYLOAD：默认拒绝，显式放行后可用。
    let plain = S3Config::builder()
        .endpoint("http://127.0.0.1:9000")
        .bucket("examplebucket")
        .access_key_id(AK_ID)
        .access_key_secret(AK_SECRET)
        .build()
        .expect("形态合法（明文 HTTP 仅策略受限）");
    assert!(presign_get(&plain, &key, 60).is_err(), "默认必须拒绝");
    let allowed = S3Config::builder()
        .endpoint("http://127.0.0.1:9000")
        .bucket("examplebucket")
        .access_key_id(AK_ID)
        .access_key_secret(AK_SECRET)
        .allow_unsigned_payload_over_http(true)
        .build()
        .unwrap();
    presign_get(&allowed, &key, 60).expect("显式放行后可用");

    // 鉴权/权限失败立即返回，不重试。
    let denied = S3Error::Backend {
        status: 403,
        code: Some("SignatureDoesNotMatch".to_owned()),
        message: "m".to_owned(),
    };
    assert!(!is_s3_retryable(&denied));
    assert!(!is_s3_retryable(&S3Error::InvalidObjectKey("x".into())));
    assert!(is_s3_retryable(&S3Error::Connection("x".into())));
}

/// S-5：验收面——四条门禁 + 热路径基准命令与测试覆盖清单均登记在标准文档中。
#[test]
fn assert_acceptance() {
    let standard = standard_doc();
    for command in [
        "cargo fmt --all --check",
        "cargo test --all-targets",
        "cargo clippy --all-targets -- -D warnings",
        "cargo package --no-verify",
        "cargo bench --bench hot_path -- --quick",
    ] {
        assert!(
            standard.contains(command),
            "验收命令 {command:?} 必须登记在 docs/标准.md"
        );
    }
    for coverage in [
        "SigV4 官方已知向量",
        "双寻址 URL 构造",
        "预签名有效期收敛",
        "ObjectKey",
        "重试分类",
        "凭据脱敏",
        "TDD",
        "SDD",
        "单元测试",
        "集成测试",
        "基准测试",
        "E2E",
        "tests/tdd_contracts.rs",
        "tests/sdd_spec.rs",
        "tests/e2e_s3.rs",
        "benches/hot_path.rs",
    ] {
        assert!(
            standard.contains(coverage),
            "覆盖清单 {coverage:?} 必须登记在 docs/标准.md"
        );
    }
}

/// S-6：crate 级质量门禁属性不得移除；公共 API 面由 lib.rs 的逐项点名测试锁定，
/// 且必须与 `docs/API.md` / `docs/标准.md` 同步。
#[test]
fn assert_quality_gates() {
    let lib = std::fs::read_to_string(format!("{MANIFEST}/src/lib.rs")).expect("src/lib.rs");
    for attribute in ["#![forbid(unsafe_code)]", "#![deny(missing_docs)]"] {
        assert!(lib.contains(attribute), "crate 级属性不得移除：{attribute}");
    }
    assert!(
        lib.contains("public_api_surface"),
        "公共 API 面必须由 lib.rs 的逐项点名测试锁定"
    );
    for doc in ["docs/API.md", "docs/标准.md"] {
        assert!(
            std::path::Path::new(MANIFEST).join(doc).is_file(),
            "新增/删除导出必须同步 {doc}"
        );
    }
    assert_eq!(MIN_BUCKET_NAME_LEN, 3);
    assert_eq!(MAX_BUCKET_NAME_LEN, 63);
    // 签名密钥派生是确定性纯函数（同一输入恒定输出）。
    let first = signing_key(AK_SECRET, "20130524", "us-east-1", "s3");
    let second = signing_key(AK_SECRET, "20130524", "us-east-1", "s3");
    assert_eq!(first, second);
}
