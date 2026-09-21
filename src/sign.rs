//! AWS Signature Version 4（`AWS4-HMAC-SHA256`）纯函数实现。
//!
//! 实现要点（S3 变体）：
//!
//! - **URI 不做二次编码**：调用方传入的 `canonical_uri` 必须是已经 URI 编码的
//!   路径（S3 的特殊规则，与其它 AWS 服务不同）；
//! - **查询串**：键与值都按 [`percent_encode`] 编码（空格编码为 `%20` 而非 `+`），
//!   再按 `(键, 值)` 字节序排序；
//! - **规范化头**：头名转小写、值折叠连续空白、按头名排序，同名头按出现顺序用
//!   逗号连接；
//! - **载荷**：请求体 SHA-256 十六进制，或 [`UNSIGNED_PAYLOAD`]。[`UNSIGNED_PAYLOAD`]
//!   表示签名**不覆盖请求体**——AWS 将其列为 "unsigned payload option"，并建议
//!   「为增强安全性请包含载荷校验和」。它本身不是错误用法，但叠加明文 HTTP 后
//!   请求体将失去任何完整性保护。
//!
//! 已知向量测试覆盖 AWS 官方 `aws-sig-v4-test-suite` 的 `get-vanilla`、
//! `get-vanilla-query-order-key-case`、`get-vanilla-query-order-key`、
//! `get-header-key-duplicate`，以及 S3 文档的 `GET Object` / `PUT Object` 示例
//! （断言 `Authorization` 头与 `CanonicalRequest` 完全相等）。

use std::fmt;

use hmac::digest::Key;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

use crate::types::ObjectKey;

/// SigV4 算法名。
pub const ALGORITHM: &str = "AWS4-HMAC-SHA256";
/// SigV4 凭据范围终结串。
pub const TERMINATOR: &str = "aws4_request";
/// S3 的 SigV4 服务名。
pub const S3_SERVICE: &str = "s3";
/// 请求体未参与签名时使用的占位哈希（需要 HTTPS 且服务端支持）。
pub const UNSIGNED_PAYLOAD: &str = "UNSIGNED-PAYLOAD";
/// 空请求体的 SHA-256 十六进制值。
pub const EMPTY_PAYLOAD_SHA256: &str =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// 百分号编码的十六进制字母表（AWS 要求大写）。
const HEX_UPPER: &[u8; 16] = b"0123456789ABCDEF";

/// 计算数据的 SHA-256 十六进制摘要（小写）。
#[must_use]
pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

/// SHA-256 的分组大小（字节），也是 HMAC 密钥规整后的目标长度。
const SHA256_BLOCK_BYTES: usize = 64;

/// 按 RFC 2104 §2 把 HMAC 密钥规整为恰好一个分组。
///
/// - 密钥长于分组：先取 `SHA-256(key)`，再左补零；
/// - 否则：直接左补零。
///
/// 显式做这一步是为了让后续构造可以走**不可失败**的 [`Mac::new`]（取定长密钥），
/// 从而在签名路径上彻底消除 `Result` 与 `panic` 两种分支。
///
/// 该规则与 `hmac` crate 内部的 `get_der_key` 一致，并由差分测试
/// `hmac_sha256_matches_hmac_crate_across_key_lengths` 逐字节验证。
fn derive_key_block(key: &[u8]) -> [u8; SHA256_BLOCK_BYTES] {
    let mut block = [0_u8; SHA256_BLOCK_BYTES];
    if key.len() > SHA256_BLOCK_BYTES {
        // SHA-256 的输出恒为 32 字节，短于 64 字节分组，故此切片不会越界。
        let digest = Sha256::digest(key);
        block[..digest.len()].copy_from_slice(&digest);
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    block
}

/// 计算 HMAC-SHA256。
///
/// 密钥先按 RFC 2104 §2 规整为单个分组（见 [`derive_key_block`]），再以定长密钥
/// 构造，因此本函数**不存在任何可能失败或 panic 的分支**。
///
/// 这与早先的实现形成对比：旧版在理论上不可达的失败路径上静默返回空 `Vec`，
/// 而空密钥会产出一个**格式合法但内容错误**的签名，本地毫无提示、只在服务端
/// 表现为一个难以定位的 `403`。现在既不需要静默回退，也不依赖不可达断言。
#[must_use]
pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> Vec<u8> {
    let key_block: Key<Hmac<Sha256>> = derive_key_block(key).into();
    let mut mac = <Hmac<Sha256> as Mac>::new(&key_block);
    mac.update(msg);
    mac.finalize().into_bytes().to_vec()
}

/// 派生 SigV4 签名密钥：
/// `HMAC(HMAC(HMAC(HMAC("AWS4" + secret, date), region), service), "aws4_request")`。
#[must_use]
pub fn signing_key(
    secret_access_key: &str,
    date_yyyymmdd: &str,
    region: &str,
    service: &str,
) -> Vec<u8> {
    let initial = format!("AWS4{secret_access_key}");
    let date_key = hmac_sha256(initial.as_bytes(), date_yyyymmdd.as_bytes());
    let region_key = hmac_sha256(&date_key, region.as_bytes());
    let service_key = hmac_sha256(&region_key, service.as_bytes());
    hmac_sha256(&service_key, TERMINATOR.as_bytes())
}

/// 按 AWS 规则做百分号编码。
///
/// 保留字符集为 unreserved（`A-Za-z0-9-_.~`），其余字节编码为大写十六进制。
/// `encode_slash` 为 `true` 时 `/` 也会被编码（查询串用），为 `false` 时保留
/// `/`（对象键拼路径用）。
#[must_use]
pub fn percent_encode(value: &str, encode_slash: bool) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.as_bytes() {
        let unreserved = byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~');
        if unreserved || (!encode_slash && *byte == b'/') {
            encoded.push(char::from(*byte));
        } else {
            encoded.push('%');
            encoded.push(char::from(HEX_UPPER[usize::from(byte >> 4)]));
            encoded.push(char::from(HEX_UPPER[usize::from(byte & 0x0f)]));
        }
    }
    encoded
}

/// 由 ISO8601 基本格式时间戳（`YYYYMMDDTHHMMSSZ`）取出日期戳（`YYYYMMDD`）。
///
/// 长度不足 8 时原样返回（此时签名必然被服务端拒绝，交由错误映射处理）。
#[must_use]
pub fn date_stamp(amz_date: &str) -> &str {
    amz_date.get(..8).unwrap_or(amz_date)
}

/// 规范化查询串：编码后按键、值排序，以 `&` 连接。
///
/// 无值的子资源用空串表示（`?uploads` -> `uploads=`）。
#[must_use]
pub fn canonical_query_string(query: &[(&str, &str)]) -> String {
    let mut pairs: Vec<(String, String)> = query
        .iter()
        .map(|(key, value)| (percent_encode(key, true), percent_encode(value, true)))
        .collect();
    pairs.sort();
    pairs
        .into_iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>()
        .join("&")
}

/// 折叠头值中的连续空白（含首尾）。
fn collapse_whitespace(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// 构造规范化头块与已签名头列表。
///
/// 返回 `(canonical_headers, signed_headers)`：前者每行 `name:value\n` 且以换行
/// 结尾，后者为分号连接的排序后小写头名。
#[must_use]
pub fn canonical_headers(headers: &[(&str, &str)]) -> (String, String) {
    // 同名头按出现顺序聚合（AWS 要求用逗号连接），随后按头名排序。
    let mut groups: Vec<(String, Vec<String>)> = Vec::with_capacity(headers.len());
    for (name, value) in headers {
        let name = name.trim().to_ascii_lowercase();
        if name.is_empty() {
            continue;
        }
        let value = collapse_whitespace(value);
        match groups.iter_mut().find(|(existing, _)| *existing == name) {
            Some((_, values)) => values.push(value),
            None => groups.push((name, vec![value])),
        }
    }
    groups.sort_by(|left, right| left.0.cmp(&right.0));

    let mut canonical = String::new();
    let mut signed: Vec<String> = Vec::with_capacity(groups.len());
    for (name, values) in groups {
        canonical.push_str(&name);
        canonical.push(':');
        canonical.push_str(&values.join(","));
        canonical.push('\n');
        signed.push(name);
    }
    (canonical, signed.join(";"))
}

/// 规范化请求。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalRequest {
    /// 完整的规范化请求字符串（`CanonicalRequest`）。
    pub canonical_request: String,
    /// 已签名头列表（`SignedHeaders`，分号连接）。
    pub signed_headers: String,
}

/// 构造 `CanonicalRequest`。
///
/// - `method`：HTTP 方法，内部统一转大写；
/// - `canonical_uri`：**已 URI 编码**的路径（S3 规则，不再二次编码）；
/// - `query`：原始未编码的查询参数键值；
/// - `headers`：参与签名的头（原始名与值）；
/// - `payload_hash`：请求体 SHA-256 十六进制或 [`UNSIGNED_PAYLOAD`]。
#[must_use]
pub fn canonical_request(
    method: &str,
    canonical_uri: &str,
    query: &[(&str, &str)],
    headers: &[(&str, &str)],
    payload_hash: &str,
) -> CanonicalRequest {
    let query = canonical_query_string(query);
    let (headers_block, signed_headers) = canonical_headers(headers);
    let canonical_request = format!(
        "{}\n{canonical_uri}\n{query}\n{headers_block}\n{signed_headers}\n{payload_hash}",
        method.trim().to_ascii_uppercase()
    );
    CanonicalRequest {
        canonical_request,
        signed_headers,
    }
}

/// 构造凭据范围：`{date}/{region}/{service}/aws4_request`。
#[must_use]
pub fn credential_scope(date_yyyymmdd: &str, region: &str, service: &str) -> String {
    format!("{date_yyyymmdd}/{region}/{service}/{TERMINATOR}")
}

/// 构造待签字符串 `StringToSign`。
#[must_use]
pub fn string_to_sign(amz_date: &str, credential_scope: &str, canonical_request: &str) -> String {
    let digest = sha256_hex(canonical_request.as_bytes());
    format!("{ALGORITHM}\n{amz_date}\n{credential_scope}\n{digest}")
}

/// 构造 `Authorization` 头。
#[must_use]
pub fn authorization_header(
    access_key_id: &str,
    date_yyyymmdd: &str,
    region: &str,
    service: &str,
    signed_headers: &str,
    signature: &str,
) -> String {
    format!(
        "{ALGORITHM} Credential={access_key_id}/{}, SignedHeaders={signed_headers}, Signature={signature}",
        credential_scope(date_yyyymmdd, region, service)
    )
}

/// 对象键的规范化 URI（S3 规则：按字节百分号编码，保留 `/`，不做二次编码）。
#[must_use]
pub fn canonical_uri_for_key(key: &ObjectKey) -> String {
    format!("/{}", percent_encode(key.as_str(), false))
}

/// [`sign_request`] 的输入参数。
///
/// 手写 `Debug`，`secret_access_key` 固定渲染为 `***`。
#[derive(Clone, Copy)]
pub struct SignRequest<'a> {
    /// HTTP 方法（大写）。
    pub method: &'a str,
    /// 已 URI 编码的规范化 URI（S3 规则：不做二次编码）。
    pub canonical_uri: &'a str,
    /// 查询参数（原始未编码键值）。
    pub query: &'a [(&'a str, &'a str)],
    /// 参与签名的头（须包含 `host`）。
    pub headers: &'a [(&'a str, &'a str)],
    /// 请求体 SHA-256 十六进制或 [`UNSIGNED_PAYLOAD`]。
    pub payload_hash: &'a str,
    /// `x-amz-date` 取值（`YYYYMMDDTHHMMSSZ`）。
    pub amz_date: &'a str,
    /// 区域。
    pub region: &'a str,
    /// 服务名（S3 为 [`S3_SERVICE`]）。
    pub service: &'a str,
    /// Access Key ID。
    pub access_key_id: &'a str,
    /// Secret Access Key。
    pub secret_access_key: &'a str,
}

impl fmt::Debug for SignRequest<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignRequest")
            .field("method", &self.method)
            .field("canonical_uri", &self.canonical_uri)
            .field("query", &self.query)
            .field("headers", &self.headers)
            .field("payload_hash", &self.payload_hash)
            .field("amz_date", &self.amz_date)
            .field("region", &self.region)
            .field("service", &self.service)
            .field("access_key_id", &self.access_key_id)
            .field("secret_access_key", &"***")
            .finish()
    }
}

/// 一次 SigV4 签名的完整结果（不含任何凭据）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    /// `Authorization` 头取值。
    pub authorization: String,
    /// 规范化请求字符串。
    pub canonical_request: String,
    /// 已签名头列表。
    pub signed_headers: String,
    /// 待签字符串。
    pub string_to_sign: String,
    /// 签名（小写十六进制）。
    pub signature: String,
    /// 凭据范围。
    pub credential_scope: String,
}

/// 执行 SigV4 签名（header 方式）。
#[must_use]
pub fn sign_request(request: &SignRequest<'_>) -> Signature {
    let date = date_stamp(request.amz_date);
    let scope = credential_scope(date, request.region, request.service);
    let canonical = canonical_request(
        request.method,
        request.canonical_uri,
        request.query,
        request.headers,
        request.payload_hash,
    );
    let string_to_sign = string_to_sign(request.amz_date, &scope, &canonical.canonical_request);
    let signing_key = signing_key(
        request.secret_access_key,
        date,
        request.region,
        request.service,
    );
    let signature = hex::encode(hmac_sha256(&signing_key, string_to_sign.as_bytes()));
    let authorization = authorization_header(
        request.access_key_id,
        date,
        request.region,
        request.service,
        &canonical.signed_headers,
        &signature,
    );
    Signature {
        authorization,
        canonical_request: canonical.canonical_request,
        signed_headers: canonical.signed_headers,
        string_to_sign,
        signature,
        credential_scope: scope,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `aws-sig-v4-test-suite` 固定凭据。
    const ACCESS_KEY: &str = "AKIDEXAMPLE";
    const SECRET_KEY: &str = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
    const AMZ_DATE: &str = "20150830T123600Z";

    /// S3 文档示例固定凭据（注意：与测试套件的 secret 不同，此例中为 `/`）。
    const S3_ACCESS_KEY: &str = "AKIAIOSFODNN7EXAMPLE";
    const S3_SECRET_KEY: &str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

    fn suite_sign(
        method: &str,
        uri: &str,
        query: &[(&str, &str)],
        headers: &[(&str, &str)],
    ) -> Signature {
        sign_request(&SignRequest {
            method,
            canonical_uri: uri,
            query,
            headers,
            payload_hash: EMPTY_PAYLOAD_SHA256,
            amz_date: AMZ_DATE,
            region: "us-east-1",
            service: "service",
            access_key_id: ACCESS_KEY,
            secret_access_key: SECRET_KEY,
        })
    }

    #[test]
    fn percent_encode_follows_aws_unreserved_set() {
        assert_eq!(percent_encode("abcXYZ019-_.~", true), "abcXYZ019-_.~");
        assert_eq!(percent_encode("a b", true), "a%20b");
        assert_eq!(percent_encode("a/b", true), "a%2Fb");
        assert_eq!(percent_encode("a/b", false), "a/b");
        assert_eq!(percent_encode("test$file.text", false), "test%24file.text");
        assert_eq!(percent_encode("100%", true), "100%25");
        assert_eq!(percent_encode("键", true), "%E9%94%AE");
        assert_eq!(percent_encode("*", true), "%2A");
        // 十六进制必须大写。
        assert_eq!(percent_encode("\u{7f}", true), "%7F");
    }

    #[test]
    fn hash_and_hmac_match_known_values() {
        // 空串 SHA-256 的公开已知值。
        assert_eq!(sha256_hex(b""), EMPTY_PAYLOAD_SHA256);
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        // RFC 4231 测试用例 2：key = "Jefe", data = "what do ya want for nothing?"
        assert_eq!(
            hex::encode(hmac_sha256(b"Jefe", b"what do ya want for nothing?")),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    /// RFC 4231 的权威向量，覆盖**密钥长度**的各个分支：空密钥、短于分组
    /// （左补零）、恰等于分组（64 字节，不哈希）、超过分组（先哈希）。
    ///
    /// 这些向量是 [`derive_key_block`] 规整规则的锚点：任一处写错都会直接反映为
    /// 签名不符。它们**不能**区分「静默返回空 `Vec`」的旧实现——旧实现的失败
    /// 分支本就不可达，走的一直是正常路径；那一改动由本文件的设计（签名路径无
    /// 任何失败分支）与下面的差分测试共同保证。
    #[test]
    fn hmac_sha256_matches_rfc4231_vectors_across_key_lengths() {
        // 空密钥 + 空消息：仍必须是合法的 32 字节 HMAC，而不是任何形式的空值。
        assert_eq!(
            hex::encode(hmac_sha256(b"", b"")),
            "b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad"
        );
        // 分组大小边界（SHA-256 分组为 64 字节）：64 字节不哈希，65 字节先哈希。
        assert_eq!(
            hex::encode(hmac_sha256(&[0_u8; 64], b"msg")),
            "5f576a8d68fe4fb7eb823227246353c0870c3b0e878997341db1226b4bd88d61"
        );
        assert_eq!(
            hex::encode(hmac_sha256(&[0_u8; 65], b"msg")),
            "ef83f61dcfdce4d1c6c8d949d28f14f26e6e96c960f059b9f277410187986c26"
        );
        // RFC 4231 TC6：131 字节密钥（> 分组大小，必须先哈希）。
        let long_key = [0xaa_u8; 131];
        assert_eq!(
            hex::encode(hmac_sha256(
                &long_key,
                b"Test Using Larger Than Block-Size Key - Hash Key First"
            )),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
        // RFC 4231 TC7：超长密钥 + 超长消息。
        assert_eq!(
            hex::encode(hmac_sha256(
                &long_key,
                b"This is a test using a larger than block-size key and a larger than \
                  block-size data. The key needs to be hashed before being used by the \
                  HMAC algorithm."
            )),
            "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2"
        );
    }

    /// 差分测试：自实现的密钥规整必须与 `hmac` crate 的 `new_from_slice` 路径
    /// 在全部密钥长度分支上逐字节一致。
    ///
    /// 这是「自行规整 + 不可失败构造」方案的**正确性依据**：`derive_key_block`
    /// 一旦与 crate 内部规则出现偏差（例如长密钥少哈希一次、补零位置写错），
    /// 本用例会立即失败，而不会退化成线上难以定位的签名错误。
    ///
    /// 参考实现只在本测试中使用；生产路径不含任何可失败分支。
    #[test]
    fn hmac_sha256_matches_hmac_crate_across_key_lengths() {
        for len in [0, 1, 31, 32, 33, 63, 64, 65, 100, 131, 200, 1_000] {
            let key = vec![0x5a_u8; len];
            let msg = b"differential check";
            let mut reference = <Hmac<Sha256> as Mac>::new_from_slice(&key)
                .expect("HMAC 接受任意长度密钥，参考实现不会失败");
            reference.update(msg);
            assert_eq!(
                hmac_sha256(&key, msg),
                reference.finalize().into_bytes().to_vec(),
                "密钥长度 {len} 的实现与 hmac crate 不一致"
            );
        }
    }

    #[test]
    fn signing_key_is_deterministic_and_32_bytes() {
        let key = signing_key(SECRET_KEY, "20150830", "us-east-1", "service");
        assert_eq!(key.len(), 32);
        assert_eq!(
            key,
            signing_key(SECRET_KEY, "20150830", "us-east-1", "service")
        );
        assert_ne!(
            key,
            signing_key(SECRET_KEY, "20150831", "us-east-1", "service")
        );
        assert_ne!(
            key,
            signing_key(SECRET_KEY, "20150830", "us-west-2", "service")
        );
    }

    /// AWS 官方 `get-vanilla`：`GET / HTTP/1.1` + `Host` + `X-Amz-Date`。
    #[test]
    fn aws_test_suite_get_vanilla() {
        let signature = suite_sign(
            "GET",
            "/",
            &[],
            &[("Host", "example.amazonaws.com"), ("X-Amz-Date", AMZ_DATE)],
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

    /// AWS 官方 `get-vanilla-query-order-key-case`：查询串按键名排序且区分大小写。
    #[test]
    fn aws_test_suite_get_vanilla_query_order_key_case() {
        let signature = suite_sign(
            "GET",
            "/",
            &[("Param2", "value2"), ("Param1", "value1")],
            &[("Host", "example.amazonaws.com"), ("X-Amz-Date", AMZ_DATE)],
        );
        assert_eq!(
            signature.canonical_request,
            "GET\n/\nParam1=value1&Param2=value2\nhost:example.amazonaws.com\nx-amz-date:20150830T123600Z\n\nhost;x-amz-date\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            signature.authorization,
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=b97d918cfa904a5beff61c982a1b6f458b799221646efd99d3219ec94cdf2500"
        );
    }

    /// AWS 官方 `get-vanilla-query-order-key`：同名键按值字节序排序。
    #[test]
    fn aws_test_suite_get_vanilla_query_order_key() {
        let signature = suite_sign(
            "GET",
            "/",
            &[("Param1", "value2"), ("Param1", "Value1")],
            &[("Host", "example.amazonaws.com"), ("X-Amz-Date", AMZ_DATE)],
        );
        assert_eq!(
            signature.canonical_request,
            "GET\n/\nParam1=Value1&Param1=value2\nhost:example.amazonaws.com\nx-amz-date:20150830T123600Z\n\nhost;x-amz-date\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            signature.authorization,
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=eedbc4e291e521cf13422ffca22be7d2eb8146eecf653089df300a15b2382bd1"
        );
    }

    /// AWS 官方 `get-header-key-duplicate`：同名头按出现顺序用逗号连接。
    #[test]
    fn aws_test_suite_get_header_key_duplicate() {
        let signature = suite_sign(
            "GET",
            "/",
            &[],
            &[
                ("Host", "example.amazonaws.com"),
                ("My-Header1", "value2"),
                ("My-Header1", "value2"),
                ("My-Header1", "value1"),
                ("X-Amz-Date", AMZ_DATE),
            ],
        );
        assert_eq!(signature.signed_headers, "host;my-header1;x-amz-date");
        assert_eq!(
            signature.canonical_request,
            "GET\n/\n\nhost:example.amazonaws.com\nmy-header1:value2,value2,value1\nx-amz-date:20150830T123600Z\n\nhost;my-header1;x-amz-date\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            signature.string_to_sign,
            "AWS4-HMAC-SHA256\n20150830T123600Z\n20150830/us-east-1/service/aws4_request\ndc7f04a3abfde8d472b0ab1a418b741b7c67174dad1551b4117b15527fbe966c"
        );
        assert_eq!(
            signature.authorization,
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;my-header1;x-amz-date, Signature=c9d5ea9f3f72853aea855b47ea873832890dbdd183b4468f858259531a5138ea"
        );
    }

    /// S3 文档 `GET Object` 示例（`examplebucket/test.txt`，range 前 10 字节）。
    #[test]
    fn s3_doc_get_object_example() {
        let signature = sign_request(&SignRequest {
            method: "GET",
            canonical_uri: "/test.txt",
            query: &[],
            headers: &[
                ("Host", "examplebucket.s3.amazonaws.com"),
                ("Range", "bytes=0-9"),
                ("x-amz-content-sha256", EMPTY_PAYLOAD_SHA256),
                ("x-amz-date", "20130524T000000Z"),
            ],
            payload_hash: EMPTY_PAYLOAD_SHA256,
            amz_date: "20130524T000000Z",
            region: "us-east-1",
            service: S3_SERVICE,
            access_key_id: S3_ACCESS_KEY,
            secret_access_key: S3_SECRET_KEY,
        });
        assert_eq!(
            signature.canonical_request,
            "GET\n/test.txt\n\nhost:examplebucket.s3.amazonaws.com\nrange:bytes=0-9\nx-amz-content-sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\nx-amz-date:20130524T000000Z\n\nhost;range;x-amz-content-sha256;x-amz-date\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            signature.string_to_sign,
            "AWS4-HMAC-SHA256\n20130524T000000Z\n20130524/us-east-1/s3/aws4_request\n7344ae5b7ee6c3e7e6b0fe0640412a37625d1fbfff95c48bbb2dc43964946972"
        );
        assert_eq!(
            signature.signature,
            "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
        );
        assert_eq!(
            signature
                .authorization
                .chars()
                .filter(|c| *c == ',')
                .count(),
            2
        );
        assert!(signature.authorization.ends_with(
            "Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
        ));
    }

    /// S3 文档 `PUT Object` 示例：验证 URI 不再二次编码（`$` -> `%24`）。
    #[test]
    fn s3_doc_put_object_example_keeps_encoded_uri() {
        let body = b"Welcome to Amazon S3.";
        let payload_hash = sha256_hex(body);
        assert_eq!(
            payload_hash,
            "44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072"
        );
        let signature = sign_request(&SignRequest {
            method: "PUT",
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
            access_key_id: S3_ACCESS_KEY,
            secret_access_key: S3_SECRET_KEY,
        });
        assert_eq!(
            signature.signed_headers,
            "date;host;x-amz-content-sha256;x-amz-date;x-amz-storage-class"
        );
        assert_eq!(
            signature.string_to_sign,
            "AWS4-HMAC-SHA256\n20130524T000000Z\n20130524/us-east-1/s3/aws4_request\n9e0e90d9c76de8fa5b200d8c849cd5b8dc7a3be3951ddb7f6a76b4158342019d"
        );
        assert_eq!(
            signature.signature,
            "98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd"
        );
        // 规范化 URI 保持调用方传入的编码形式。
        assert!(signature
            .canonical_request
            .starts_with("PUT\n/test%24file.text\n\n"));
    }

    #[test]
    fn same_input_yields_same_signature_twice() {
        let headers = [
            ("Host", "examplebucket.s3.amazonaws.com"),
            ("x-amz-content-sha256", EMPTY_PAYLOAD_SHA256),
            ("x-amz-date", "20130524T000000Z"),
        ];
        let request = SignRequest {
            method: "GET",
            canonical_uri: "/test.txt",
            query: &[("list-type", "2")],
            headers: &headers,
            payload_hash: EMPTY_PAYLOAD_SHA256,
            amz_date: "20130524T000000Z",
            region: "us-east-1",
            service: S3_SERVICE,
            access_key_id: S3_ACCESS_KEY,
            secret_access_key: S3_SECRET_KEY,
        };
        let first = sign_request(&request);
        let second = sign_request(&request);
        assert_eq!(first, second);
        assert_eq!(first.signature.len(), 64);
    }

    #[test]
    fn canonical_headers_lowercases_sorts_and_collapses() {
        let (canonical, signed) = canonical_headers(&[
            ("X-Amz-Meta-B", "  two   spaces  "),
            ("Host", "example.amazonaws.com"),
            ("x-amz-meta-a", "1"),
        ]);
        assert_eq!(
            canonical,
            "host:example.amazonaws.com\nx-amz-meta-a:1\nx-amz-meta-b:two spaces\n"
        );
        assert_eq!(signed, "host;x-amz-meta-a;x-amz-meta-b");
    }

    #[test]
    fn canonical_query_string_encodes_and_sorts() {
        assert_eq!(canonical_query_string(&[]), "");
        assert_eq!(canonical_query_string(&[("b", "2"), ("a", "1")]), "a=1&b=2");
        assert_eq!(
            canonical_query_string(&[("prefix", "a b/c"), ("list-type", "2")]),
            "list-type=2&prefix=a%20b%2Fc"
        );
        // 无值子资源编码为 `key=`。
        assert_eq!(canonical_query_string(&[("uploads", "")]), "uploads=");
    }

    #[test]
    fn canonical_uri_for_key_encodes_bytes_but_keeps_slashes() {
        let key = ObjectKey::new("dir/sub file$1.txt").expect("合法键");
        assert_eq!(canonical_uri_for_key(&key), "/dir/sub%20file%241.txt");
        assert_eq!(
            canonical_uri_for_key(&ObjectKey::new("键").expect("合法键")),
            "/%E9%94%AE"
        );
    }

    #[test]
    fn credential_scope_and_string_to_sign_shape() {
        assert_eq!(
            credential_scope("20150830", "us-east-1", "service"),
            "20150830/us-east-1/service/aws4_request"
        );
        let string_to_sign = string_to_sign(AMZ_DATE, "scope", "canonical");
        assert_eq!(
            string_to_sign,
            format!(
                "AWS4-HMAC-SHA256\n{AMZ_DATE}\nscope\n{}",
                sha256_hex(b"canonical")
            )
        );
    }

    #[test]
    fn sign_request_debug_redacts_secret() {
        let request = SignRequest {
            method: "GET",
            canonical_uri: "/",
            query: &[],
            headers: &[("host", "example.amazonaws.com")],
            payload_hash: EMPTY_PAYLOAD_SHA256,
            amz_date: AMZ_DATE,
            region: "us-east-1",
            service: S3_SERVICE,
            access_key_id: ACCESS_KEY,
            secret_access_key: SECRET_KEY,
        };
        let rendered = format!("{request:?}");
        assert!(rendered.contains("***"), "{rendered}");
        assert!(!rendered.contains(SECRET_KEY), "{rendered}");
    }
}
