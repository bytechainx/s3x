#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::unreachable
)]
//! SigV4 已知向量（AWS 官方测试套件 + S3 文档示例）与预签名 URL 参数完整性。
//!
//! 向量来源：
//!
//! - `aws-sig-v4-test-suite`（`get-vanilla`、`get-vanilla-query-order-key-case`、
//!   `get-vanilla-query-order-key`、`get-header-key-duplicate`），凭据
//!   `AKIDEXAMPLE` / `wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY`，区域 `us-east-1`，
//!   服务 `service`，时间 `20150830T123600Z`；
//! - AWS S3 文档 `GET Object` / `PUT Object`：凭据 `AKIAIOSFODNN7EXAMPLE` /
//!   `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`，区域 `us-east-1`，
//!   时间 `20130524T000000Z`（注意此例 secret 中为 `/`，与测试套件不同）。

use chrono::{DateTime, TimeZone, Utc};
use s3x::{
    canonical_query_string, canonical_request, percent_encode, presign_get, presign_put,
    presign_url, sha256_hex, sign_request, ObjectKey, PresignOptions, S3Config, SignRequest,
    S3_SERVICE, UNSIGNED_PAYLOAD,
};

const SUITE_ACCESS_KEY: &str = "AKIDEXAMPLE";
const SUITE_SECRET_KEY: &str = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
const SUITE_AMZ_DATE: &str = "20150830T123600Z";
const EMPTY_PAYLOAD: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

fn suite_sign(
    method: &str,
    uri: &str,
    query: &[(&str, &str)],
    headers: &[(&str, &str)],
) -> s3x::Signature {
    sign_request(&SignRequest {
        method,
        canonical_uri: uri,
        query,
        headers,
        payload_hash: EMPTY_PAYLOAD,
        amz_date: SUITE_AMZ_DATE,
        region: "us-east-1",
        service: "service",
        access_key_id: SUITE_ACCESS_KEY,
        secret_access_key: SUITE_SECRET_KEY,
    })
}

#[test]
fn get_vanilla_matches_official_vector() {
    let signature = suite_sign(
        "GET",
        "/",
        &[],
        &[
            ("Host", "example.amazonaws.com"),
            ("X-Amz-Date", SUITE_AMZ_DATE),
        ],
    );
    assert_eq!(
        signature.canonical_request,
        "GET\n/\n\nhost:example.amazonaws.com\nx-amz-date:20150830T123600Z\n\nhost;x-amz-date\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(
        signature.string_to_sign,
        "AWS4-HMAC-SHA256\n20150830T123600Z\n20150830/us-east-1/service/aws4_request\nbb579772317eb040ac9ed261061d46c1f17a8133879d6129b6e1c25292927e63"
    );
    assert_eq!(
        signature.authorization,
        "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
    );
}

#[test]
fn get_vanilla_query_order_matches_official_vectors() {
    // 键名大小写敏感：`Param1` 先于 `Param2`。
    let by_key_case = suite_sign(
        "GET",
        "/",
        &[("Param2", "value2"), ("Param1", "value1")],
        &[
            ("Host", "example.amazonaws.com"),
            ("X-Amz-Date", SUITE_AMZ_DATE),
        ],
    );
    assert!(by_key_case
        .canonical_request
        .contains("\nParam1=value1&Param2=value2\n"));
    assert_eq!(
        by_key_case.signature,
        "b97d918cfa904a5beff61c982a1b6f458b799221646efd99d3219ec94cdf2500"
    );

    // 同名键按取值字节序排序：`Value1` 先于 `value2`。
    let by_value_order = suite_sign(
        "GET",
        "/",
        &[("Param1", "value2"), ("Param1", "Value1")],
        &[
            ("Host", "example.amazonaws.com"),
            ("X-Amz-Date", SUITE_AMZ_DATE),
        ],
    );
    assert!(by_value_order
        .canonical_request
        .contains("\nParam1=Value1&Param1=value2\n"));
    assert_eq!(
        by_value_order.signature,
        "eedbc4e291e521cf13422ffca22be7d2eb8146eecf653089df300a15b2382bd1"
    );
}

#[test]
fn duplicate_header_names_are_joined_in_order() {
    let signature = suite_sign(
        "GET",
        "/",
        &[],
        &[
            ("Host", "example.amazonaws.com"),
            ("My-Header1", "value2"),
            ("My-Header1", "value2"),
            ("My-Header1", "value1"),
            ("X-Amz-Date", SUITE_AMZ_DATE),
        ],
    );
    assert_eq!(signature.signed_headers, "host;my-header1;x-amz-date");
    assert!(signature
        .canonical_request
        .contains("my-header1:value2,value2,value1\n"));
    assert_eq!(
        signature.signature,
        "c9d5ea9f3f72853aea855b47ea873832890dbdd183b4468f858259531a5138ea"
    );
}

#[test]
fn s3_get_object_example_matches_documented_signature() {
    let signature = sign_request(&SignRequest {
        method: "GET",
        canonical_uri: "/test.txt",
        query: &[],
        headers: &[
            ("Host", "examplebucket.s3.amazonaws.com"),
            ("Range", "bytes=0-9"),
            ("x-amz-content-sha256", EMPTY_PAYLOAD),
            ("x-amz-date", "20130524T000000Z"),
        ],
        payload_hash: EMPTY_PAYLOAD,
        amz_date: "20130524T000000Z",
        region: "us-east-1",
        service: S3_SERVICE,
        access_key_id: "AKIAIOSFODNN7EXAMPLE",
        secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    });
    assert_eq!(
        signature.string_to_sign,
        "AWS4-HMAC-SHA256\n20130524T000000Z\n20130524/us-east-1/s3/aws4_request\n7344ae5b7ee6c3e7e6b0fe0640412a37625d1fbfff95c48bbb2dc43964946972"
    );
    assert_eq!(
        signature.authorization,
        "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
    );
}

#[test]
fn s3_put_object_example_keeps_preencoded_uri() {
    let body = b"Welcome to Amazon S3.";
    let payload_hash = sha256_hex(body);
    assert_eq!(
        payload_hash,
        "44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072"
    );
    let signature = sign_request(&SignRequest {
        method: "PUT",
        // `test$file.text` 的 URI 编码形式：S3 规则不做二次编码。
        canonical_uri: "/test%24file.text",
        query: &[],
        headers: &[
            ("date", "Fri, 24 May 2013 00:00:00 GMT"),
            ("Host", "examplebucket.s3.amazonaws.com"),
            ("x-amz-content-sha256", &payload_hash),
            ("x-amz-date", "20130524T000000Z"),
            ("x-amz-storage-class", "REDUCED_REDUNDANCY"),
        ],
        payload_hash: &payload_hash,
        amz_date: "20130524T000000Z",
        region: "us-east-1",
        service: S3_SERVICE,
        access_key_id: "AKIAIOSFODNN7EXAMPLE",
        secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    });
    assert_eq!(
        signature.signed_headers,
        "date;host;x-amz-content-sha256;x-amz-date;x-amz-storage-class"
    );
    assert_eq!(
        signature.signature,
        "98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd"
    );
}

#[test]
fn sigv4_is_deterministic_for_identical_input() {
    let headers = [
        ("host", "examplebucket.s3.us-east-1.amazonaws.com"),
        ("x-amz-content-sha256", EMPTY_PAYLOAD),
        ("x-amz-date", "20130524T000000Z"),
    ];
    let request = SignRequest {
        method: "GET",
        canonical_uri: "/k",
        query: &[("list-type", "2")],
        headers: &headers,
        payload_hash: EMPTY_PAYLOAD,
        amz_date: "20130524T000000Z",
        region: "us-east-1",
        service: S3_SERVICE,
        access_key_id: "AKIAIOSFODNN7EXAMPLE",
        secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    };
    let first = sign_request(&request);
    let second = sign_request(&request);
    assert_eq!(first, second);
    assert_eq!(first.signature.len(), 64);
    // 方法大小写不影响结果（统一转大写）。
    let mut uppercase = request;
    uppercase.method = "get";
    assert_eq!(sign_request(&uppercase), first);
}

#[test]
fn percent_encoding_follows_aws_rules() {
    assert_eq!(percent_encode("abcXYZ019-_.~", true), "abcXYZ019-_.~");
    assert_eq!(percent_encode("a b", true), "a%20b", "空格必须编码为 %20");
    assert_eq!(percent_encode("a+b", true), "a%2Bb");
    assert_eq!(percent_encode("a/b", true), "a%2Fb");
    assert_eq!(percent_encode("a/b", false), "a/b");
    assert_eq!(percent_encode("键", true), "%E9%94%AE");
    assert_eq!(percent_encode("\u{7f}", true), "%7F", "十六进制必须大写");
}

#[test]
fn canonical_query_string_encodes_and_sorts() {
    assert_eq!(canonical_query_string(&[]), "");
    assert_eq!(
        canonical_query_string(&[("prefix", "a b/c"), ("list-type", "2")]),
        "list-type=2&prefix=a%20b%2Fc"
    );
    assert_eq!(canonical_query_string(&[("uploads", "")]), "uploads=");
    // 未编码的 `=`、`&` 必须被编码，避免注入额外参数。
    assert_eq!(
        canonical_query_string(&[("continuation-token", "a=b&c")]),
        "continuation-token=a%3Db%26c"
    );
}

#[test]
fn canonical_request_includes_host_and_payload_hash() {
    let canonical = canonical_request(
        "GET",
        "/test.txt",
        &[],
        &[("host", "examplebucket.s3.amazonaws.com")],
        EMPTY_PAYLOAD,
    );
    assert_eq!(canonical.signed_headers, "host");
    assert_eq!(
        canonical.canonical_request,
        format!("GET\n/test.txt\n\nhost:examplebucket.s3.amazonaws.com\n\nhost\n{EMPTY_PAYLOAD}")
    );

    let unsigned = canonical_request("PUT", "/k", &[], &[("host", "h")], UNSIGNED_PAYLOAD);
    assert!(unsigned.canonical_request.ends_with(UNSIGNED_PAYLOAD));
}

fn presign_config() -> S3Config {
    S3Config::builder()
        .bucket("examplebucket")
        .region("us-east-1")
        .access_key_id("AKIAIOSFODNN7EXAMPLE")
        .access_key_secret("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
        .build()
        .expect("测试配置有效")
}

fn fixed_now() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2013, 5, 24, 0, 0, 0)
        .single()
        .expect("合法时间")
}

#[test]
fn presign_get_contains_every_required_parameter() {
    let config = presign_config();
    let key = ObjectKey::new("dir/test.txt").expect("合法键");
    let url = presign_get(&config, &key, 900).expect("预签名必须成功");
    let parsed = url::Url::parse(&url).expect("预签名 URL 必须合法");

    assert_eq!(parsed.scheme(), "https");
    assert_eq!(
        parsed.host_str(),
        Some("examplebucket.s3.us-east-1.amazonaws.com")
    );
    assert_eq!(parsed.path(), "/dir/test.txt");

    let params: std::collections::BTreeMap<String, String> = parsed
        .query_pairs()
        .map(|(name, value)| (name.into_owned(), value.into_owned()))
        .collect();
    assert_eq!(
        params.get("X-Amz-Algorithm").map(String::as_str),
        Some("AWS4-HMAC-SHA256")
    );
    assert_eq!(params.get("X-Amz-Expires").map(String::as_str), Some("900"));
    assert_eq!(
        params.get("X-Amz-SignedHeaders").map(String::as_str),
        Some("host")
    );
    let credential = params.get("X-Amz-Credential").expect("缺少凭据");
    assert!(
        credential.starts_with("AKIAIOSFODNN7EXAMPLE/"),
        "{credential}"
    );
    assert!(
        credential.ends_with("/us-east-1/s3/aws4_request"),
        "{credential}"
    );
    assert_eq!(credential.rsplit('/').count(), 5, "{credential}");
    let signature = params.get("X-Amz-Signature").expect("缺少签名");
    assert_eq!(signature.len(), 64);
    assert!(signature.chars().all(|c| c.is_ascii_hexdigit()));
    assert!(params.get("X-Amz-Date").is_some_and(|v| v.ends_with('Z')));
    assert!(!params.contains_key("X-Amz-Security-Token"));
    assert_eq!(params.len(), 6);
}

#[test]
fn presign_expires_is_clamped_to_hard_bounds() {
    let config = presign_config();
    let key = ObjectKey::new("k").expect("合法键");
    let expires_of = |seconds: u64| {
        let url = presign_get(&config, &key, seconds).expect("预签名必须成功");
        url::Url::parse(&url)
            .expect("合法 URL")
            .query_pairs()
            .find(|(name, _)| name == "X-Amz-Expires")
            .map(|(_, value)| value.into_owned())
            .expect("缺少 X-Amz-Expires")
    };
    assert_eq!(expires_of(0), "1");
    assert_eq!(expires_of(1), "1");
    assert_eq!(expires_of(604_800), "604800");
    assert_eq!(expires_of(604_801), "604800");
    assert_eq!(expires_of(u64::MAX), "604800");
    assert_eq!(expires_of(3_600), "3600");
}

#[test]
fn presign_is_reproducible_and_method_specific() {
    let config = presign_config();
    let key = ObjectKey::new("test.txt").expect("合法键");
    let options = PresignOptions::get(86400).at(fixed_now());
    let first = presign_url(&config, &key, &options).expect("预签名必须成功");
    assert_eq!(
        first,
        presign_url(&config, &key, &options).expect("预签名必须成功")
    );

    // 固定时钟锁定完整 URL（含查询串顺序、编码与签名）。
    assert_eq!(
        first,
        concat!(
            "https://examplebucket.s3.us-east-1.amazonaws.com/test.txt",
            "?X-Amz-Algorithm=AWS4-HMAC-SHA256",
            "&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request",
            "&X-Amz-Date=20130524T000000Z",
            "&X-Amz-Expires=86400",
            "&X-Amz-SignedHeaders=host",
            "&X-Amz-Signature=762f4fcbacec730d460b0e337f554e569e4fe98643baefad7af1276fe3084e7f",
        )
    );

    // PUT 与 GET 的签名不同。
    let put = presign_put(&config, &key, 86400).expect("预签名必须成功");
    assert!(put.contains("X-Amz-Signature="));
    let put_at = presign_url(&config, &key, &PresignOptions::put(86400).at(fixed_now()))
        .expect("预签名必须成功");
    assert_ne!(put_at, first);
}

#[test]
fn presign_honors_session_token_and_addressing_style() {
    let with_token = S3Config {
        session_token: Some("session-token".to_owned()),
        ..presign_config()
    };
    let key = ObjectKey::new("test.txt").expect("合法键");
    let url = presign_get(&with_token, &key, 60).expect("预签名必须成功");
    assert!(url.contains("X-Amz-Security-Token=session-token"), "{url}");
    assert!(
        !presign_get(&presign_config(), &key, 60)
            .expect("预签名必须成功")
            .contains("X-Amz-Security-Token"),
        "无 session token 时不得出现该参数"
    );

    let path_style = S3Config {
        endpoint: Some("https://minio.example.com:9000".to_owned()),
        force_path_style: true,
        ..presign_config()
    };
    let key = ObjectKey::new("dir/a b.txt").expect("合法键");
    let url = presign_get(&path_style, &key, 60).expect("预签名必须成功");
    assert!(
        url.starts_with("https://minio.example.com:9000/examplebucket/dir/a%20b.txt?"),
        "{url}"
    );
}
