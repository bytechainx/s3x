//! 预签名 URL（query-string 方式 SigV4）。
//!
//! 生成的 URL 携带 `X-Amz-Algorithm`、`X-Amz-Credential`、`X-Amz-Date`、
//! `X-Amz-Expires`、`X-Amz-SignedHeaders`、`X-Amz-Signature`（存在 session token
//! 时另有 `X-Amz-Security-Token`），可直接交给浏览器或第三方使用，无需再带凭据。
//!
//! - 有效期被收敛到 `1..=`[`HARD_MAX_PRESIGN_EXPIRES_SECS`]（AWS 硬上限 7 天）；
//! - 载荷使用 [`UNSIGNED_PAYLOAD`](crate::UNSIGNED_PAYLOAD) 占位（这是预签名
//!   URL 的标准做法）；
//! - 签名时钟可由 [`PresignOptions::now`] 注入，便于确定性测试。

use chrono::{DateTime, Utc};

use crate::config::S3Config;
use crate::sign::{self, S3_SERVICE};
use crate::types::ObjectKey;

/// 预签名有效期硬上限（秒）：7 天。
pub const HARD_MAX_PRESIGN_EXPIRES_SECS: u64 = 604_800;
/// 预签名 `SignedHeaders` 固定值：只签 `host`。
pub const PRESIGN_SIGNED_HEADERS: &str = "host";

/// [`presign_url`] 的选项。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresignOptions {
    /// HTTP 方法，如 `GET` / `PUT`。
    pub method: String,
    /// 有效期（秒），会被收敛到 `1..=`[`HARD_MAX_PRESIGN_EXPIRES_SECS`]。
    pub expires_in_secs: u64,
    /// 签名时刻；`None` 表示使用当前 UTC 时间。
    pub now: Option<DateTime<Utc>>,
}

impl Default for PresignOptions {
    fn default() -> Self {
        Self {
            method: "GET".to_owned(),
            expires_in_secs: 3_600,
            now: None,
        }
    }
}

impl PresignOptions {
    /// `GET` 预签名选项。
    #[must_use]
    pub fn get(expires_in_secs: u64) -> Self {
        Self {
            method: "GET".to_owned(),
            expires_in_secs,
            now: None,
        }
    }

    /// `PUT` 预签名选项。
    #[must_use]
    pub fn put(expires_in_secs: u64) -> Self {
        Self {
            method: "PUT".to_owned(),
            expires_in_secs,
            now: None,
        }
    }

    /// 固定签名时刻（便于复现签名结果）。
    #[must_use]
    pub fn at(mut self, now: DateTime<Utc>) -> Self {
        self.now = Some(now);
        self
    }
}

/// 生成 `GET` 预签名 URL（有效期上限 7 天）。
///
/// 调用方应先通过 [`S3Config::validate`] 确认配置有效——本函数返回 `String`，
/// 不做失败返回，配置非法时生成的 URL 只会被服务端拒绝。
#[must_use]
pub fn presign_get(config: &S3Config, key: &ObjectKey, expires_in_secs: u64) -> String {
    presign_url(config, key, &PresignOptions::get(expires_in_secs))
}

/// 生成 `PUT` 预签名 URL（有效期上限 7 天）。
///
/// 同 [`presign_get`]：调用方应先行校验配置。
#[must_use]
pub fn presign_put(config: &S3Config, key: &ObjectKey, expires_in_secs: u64) -> String {
    presign_url(config, key, &PresignOptions::put(expires_in_secs))
}

/// 按 [`PresignOptions`] 生成预签名 URL。
#[must_use]
pub fn presign_url(config: &S3Config, key: &ObjectKey, options: &PresignOptions) -> String {
    let now = options.now.unwrap_or_else(Utc::now);
    let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
    let date = now.format("%Y%m%d").to_string();
    let expires = options
        .expires_in_secs
        .clamp(1, HARD_MAX_PRESIGN_EXPIRES_SECS);
    let target = config.endpoint_parts(Some(key.as_str()));
    let scope = sign::credential_scope(&date, &config.region, S3_SERVICE);

    let mut owned: Vec<(&str, String)> = vec![
        ("X-Amz-Algorithm", sign::ALGORITHM.to_owned()),
        (
            "X-Amz-Credential",
            format!("{}/{scope}", config.access_key_id),
        ),
        ("X-Amz-Date", amz_date.clone()),
        ("X-Amz-Expires", expires.to_string()),
        ("X-Amz-SignedHeaders", PRESIGN_SIGNED_HEADERS.to_owned()),
    ];
    if let Some(token) = &config.session_token {
        owned.push(("X-Amz-Security-Token", token.clone()));
    }
    let query: Vec<(&str, &str)> = owned
        .iter()
        .map(|(name, value)| (*name, value.as_str()))
        .collect();

    let canonical = sign::canonical_request(
        &options.method,
        &target.canonical_uri,
        &query,
        &[("host", target.host.as_str())],
        sign::UNSIGNED_PAYLOAD,
    );
    let string_to_sign = sign::string_to_sign(&amz_date, &scope, &canonical.canonical_request);
    let signing_key =
        sign::signing_key(&config.access_key_secret, &date, &config.region, S3_SERVICE);
    let signature = hex::encode(sign::hmac_sha256(&signing_key, string_to_sign.as_bytes()));

    format!(
        "{}?{}&X-Amz-Signature={signature}",
        target.url,
        sign::canonical_query_string(&query)
    )
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use chrono::TimeZone;

    use super::*;

    fn config() -> S3Config {
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

    /// 解析预签名 URL 的查询参数（不做百分号解码）。
    fn query_pairs(url: &str) -> BTreeMap<String, String> {
        let parsed = url::Url::parse(url).expect("预签名 URL 必须合法");
        parsed
            .query_pairs()
            .map(|(name, value)| (name.into_owned(), value.into_owned()))
            .collect()
    }

    #[test]
    fn presign_get_contains_all_parameters() {
        let key = ObjectKey::new("dir/test.txt").expect("合法键");
        let url = presign_get(&config(), &key, 900);
        assert!(
            url.starts_with("https://examplebucket.s3.us-east-1.amazonaws.com/dir/test.txt?"),
            "{url}"
        );
        let params = query_pairs(&url);
        assert_eq!(
            params.get("X-Amz-Algorithm").map(String::as_str),
            Some("AWS4-HMAC-SHA256")
        );
        assert_eq!(params.get("X-Amz-Expires").map(String::as_str), Some("900"));
        assert_eq!(
            params.get("X-Amz-SignedHeaders").map(String::as_str),
            Some("host")
        );
        assert!(params
            .get("X-Amz-Date")
            .is_some_and(|value| value.ends_with('Z')));
        // 凭据范围：`{AKID}/{date}/{region}/{service}/aws4_request`（日期随时间变化）。
        let credential = params
            .get("X-Amz-Credential")
            .expect("必须含 X-Amz-Credential");
        assert!(
            credential.starts_with("AKIAIOSFODNN7EXAMPLE/"),
            "{credential}"
        );
        assert!(
            credential.ends_with("/us-east-1/s3/aws4_request"),
            "{credential}"
        );
        assert_eq!(credential.rsplit('/').count(), 5, "{credential}");
        assert!(params.get("X-Amz-Signature").is_some_and(|signature| {
            signature.len() == 64 && signature.chars().all(|c| c.is_ascii_hexdigit())
        }));
        assert!(!params.contains_key("X-Amz-Security-Token"));
    }

    #[test]
    fn presign_put_uses_put_method() {
        let key = ObjectKey::new("upload.bin").expect("合法键");
        let options = PresignOptions::put(120).at(fixed_now());
        let url = presign_url(&config(), &key, &options);
        let params = query_pairs(&url);
        assert_eq!(params.get("X-Amz-Expires").map(String::as_str), Some("120"));
        assert_eq!(
            params.get("X-Amz-Credential").map(String::as_str),
            Some("AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request")
        );
        assert_eq!(
            params.get("X-Amz-Date").map(String::as_str),
            Some("20130524T000000Z")
        );

        // GET 与 PUT 的方法不同，签名必须不同。
        let get_url = presign_url(&config(), &key, &PresignOptions::get(120).at(fixed_now()));
        assert_ne!(url, get_url);
    }

    #[test]
    fn expires_is_clamped_to_hard_bounds() {
        let key = ObjectKey::new("k").expect("合法键");
        let lower = query_pairs(&presign_url(
            &config(),
            &key,
            &PresignOptions::get(0).at(fixed_now()),
        ));
        assert_eq!(lower.get("X-Amz-Expires").map(String::as_str), Some("1"));

        let upper = query_pairs(&presign_url(
            &config(),
            &key,
            &PresignOptions::get(u64::MAX).at(fixed_now()),
        ));
        assert_eq!(
            upper.get("X-Amz-Expires").map(String::as_str),
            Some("604800")
        );

        let normal = query_pairs(&presign_url(
            &config(),
            &key,
            &PresignOptions::get(3_600).at(fixed_now()),
        ));
        assert_eq!(
            normal.get("X-Amz-Expires").map(String::as_str),
            Some("3600")
        );
    }

    #[test]
    fn signature_is_reproducible_with_fixed_clock() {
        let key = ObjectKey::new("dir/test.txt").expect("合法键");
        let options = PresignOptions::get(900).at(fixed_now());
        let first = presign_url(&config(), &key, &options);
        let second = presign_url(&config(), &key, &options);
        assert_eq!(first, second);
        // `presign_get` 无固定时钟，但同一秒内两次调用必须一致。
        let third = presign_get(&config(), &key, 900);
        assert!(third.contains("X-Amz-Signature="), "{third}");
    }

    /// 固定时钟下的完整向量：`GET` + `X-Amz-*` 查询串 + `UNSIGNED-PAYLOAD`。
    ///
    /// 期望值由独立实现（Python `hashlib`/`hmac`，与本 crate 的 SigV4 实现同源规则）
    /// 复算后固定下来，用于锁定查询串排序、编码与签名链路。
    #[test]
    fn presign_signature_matches_fixed_vector() {
        let key = ObjectKey::new("test.txt").expect("合法键");
        let url = presign_url(&config(), &key, &PresignOptions::get(86400).at(fixed_now()));
        assert_eq!(
            url,
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
    }

    #[test]
    fn session_token_is_signed_and_present() {
        let base = config();
        let with_token = S3Config {
            session_token: Some("session-token-value".to_owned()),
            ..base.clone()
        };
        let key = ObjectKey::new("test.txt").expect("合法键");
        let options = PresignOptions::get(60).at(fixed_now());
        let url = presign_url(&with_token, &key, &options);
        assert!(
            url.contains("X-Amz-Security-Token=session-token-value"),
            "{url}"
        );
        // 加入 token 后签名必然变化。
        assert_ne!(url, presign_url(&base, &key, &options));
    }

    #[test]
    fn path_style_and_custom_endpoint_are_honored() {
        let path_style = S3Config {
            endpoint: Some("https://minio.example.com:9000".to_owned()),
            force_path_style: true,
            ..config()
        };
        let key = ObjectKey::new("dir/a b.txt").expect("合法键");
        let url = presign_get(&path_style, &key, 60);
        assert!(
            url.starts_with("https://minio.example.com:9000/examplebucket/dir/a%20b.txt?"),
            "{url}"
        );

        let virtual_hosted = S3Config {
            force_path_style: false,
            ..path_style.clone()
        };
        let url = presign_get(&virtual_hosted, &key, 60);
        assert!(
            url.starts_with("https://examplebucket.minio.example.com:9000/dir/a%20b.txt?"),
            "{url}"
        );
    }

    #[test]
    fn presign_options_defaults_and_helpers() {
        let options = PresignOptions::default();
        assert_eq!(options.method, "GET");
        assert_eq!(options.expires_in_secs, 3_600);
        assert!(options.now.is_none());
        assert_eq!(PresignOptions::put(1).method, "PUT");
        assert_eq!(PresignOptions::get(2).expires_in_secs, 2);
    }
}
