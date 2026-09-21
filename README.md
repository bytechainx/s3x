# s3x

[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

`s3x` 是一个零内部耦合的 **AWS S3 / S3 兼容对象存储适配器**，基于 `reqwest`
（rustls）与**手写的 AWS Signature Version 4** 实现，**不引入 `aws-sdk-s3`**
（因此也没有 smithy / hyper 版本联动负担）。

它只负责 S3 REST 协议、SigV4 签名、预签名 URL、对象读写与健康检查等基础设施
原语，**不包含**任何领域模型、业务分片或调度编排，可以零耦合地嵌入任意 Rust
服务。

- 零内部依赖，仅使用 crates.io 公开依赖
- SigV4 有 AWS 官方 `aws-sig-v4-test-suite` 已知向量测试（`get-vanilla` 等）
- 默认 virtual-hosted 寻址，`force_path_style` 一键切换到 path-style（MinIO / Ceph）
- 统一错误分类：`S3Error::is_retryable()` 区分瞬时故障与永久故障
- 错误消息不回显 secret access key / session token
- `max_in_flight` 信号量背压 + 指数退避抖动重试（crate 内独立实现）；
  背压覆盖**整个请求生命周期**——`get_object` 返回的下载流会继续持有并发额度，
  直到流被消费完或丢弃，慢速大对象下载同样受上限约束

## 安装

本 crate **不发布到 crates.io**，通过 git 依赖引入：

```toml
[dependencies]
s3x = { git = "https://github.com/bytechainx/s3x" }
```

## 最小可运行示例

```rust,no_run
use bytes::Bytes;
use s3x::{presign_get, ObjectKey, S3Client, S3Config, UploadOptions};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 凭据只从环境变量或构建器注入，不会出现在 Debug / TOML 中。
    let config = S3Config::builder()
        .endpoint("https://minio.example.com:9000") // 省略则用 AWS 官方端点
        .region("us-east-1")
        .bucket("examplebucket")
        .access_key_id(std::env::var("FOUNDATIONX_S3X_ACCESS_KEY_ID")?)
        .access_key_secret(std::env::var("FOUNDATIONX_S3X_ACCESS_KEY_SECRET")?)
        .build()?;

    // connect 只做校验与构造，不发网络请求；连通性用 ping 显式验证。
    let client = S3Client::connect(config).await?;
    client.ping().await?;

    let key = ObjectKey::new("reports/2026-09.csv")?;

    // 上传
    client
        .put_object(
            &key,
            Bytes::from_static(b"a,b\n1,2\n"),
            &UploadOptions::default().with_content_type("text/csv"),
        )
        .await?;

    // 下载（流式）
    let (meta, mut stream) = client.get_object(&key, &Default::default()).await?;
    println!("size={} etag={:?}", meta.size, meta.etag);
    use futures_util::StreamExt;
    while let Some(chunk) = stream.next().await {
        let _chunk = chunk?;
    }

    // 下载（一次性读全量）
    let bytes = client.get_object_bytes(&key).await?;
    assert_eq!(&bytes[..], b"a,b\n1,2\n");

    // 预签名 URL（默认 1 小时，最长 7 天）
    let url = presign_get(&client.config(), &key, 3600)?;
    println!("{url}");

    let health = client.health_check().await?;
    println!("healthy={} latency={}ms", health.healthy, health.latency_ms);
    Ok(())
}
```

### 用环境变量直接建连

```rust,no_run
use s3x::S3Client;

let client = S3Client::connect_from_env().await?;
client.ping().await?;
```

## 公开 API

| 类型 / 函数 | 说明 |
| --- | --- |
| `S3Config` / `S3ConfigBuilder` | 配置：`from_env()`、`from_toml()`、`validate()`、`builder()`、`effective_endpoint()`、`bucket_url()`、`object_url()` |
| `S3Client` | 客户端：`new(config)`（同步构造，无网络）、`connect(config)`、`connect_from_env()`、`ping()`、`health_check()` |
| `S3Health` | 健康检查结果：`healthy` / `endpoint` / `bucket` / `latency_ms` |
| `ObjectKey` | 已校验对象键（非空、无前导 `/`、无 `..`、无控制字符、UTF-8 ≤ 1024 字节） |
| `ObjectMeta` | 元数据：`key` / `size` / `etag` / `last_modified` / `content_type` |
| `UploadOptions` | 上传选项：`content_type` / `metadata`（`x-amz-meta-*`）/ `storage_class` |
| `DownloadOptions` | 下载选项：`range: Option<(u64, u64)>` |
| `ByteStream` / `byte_stream_from_bytes` | 下载字节流（`Result<Bytes, std::io::Error>`）与内存流构造 |
| `presign_get` / `presign_put` / `presign_url` / `PresignOptions` | 预签名 URL（返回 `S3Result<String>`；有效期自动收敛到 1..=604800 秒） |
| `S3Error` / `S3Result` | 统一错误类型与 `Result` 别名，`is_retryable()` 区分瞬时/永久 |
| `RetryConfig` / `with_retry` / `with_retry_deadline` / `backoff_delay` / `is_s3_retryable` | 重试策略（crate 内独立实现） |
| `sign_request` / `canonical_request` / `canonical_headers` / `canonical_query_string` / `percent_encode` / `signing_key` / `hmac_sha256` / `sha256_hex` / `credential_scope` / `string_to_sign` / `authorization_header` | SigV4 原语（纯函数，便于复用与自测） |
| `parse_list_objects_v2` / `ListObjectsResult` | `ListObjectsV2` 响应解析（支持 `encoding-type=url` 解码） |
| `build_delete_objects_body` / `parse_delete_objects` / `DeleteObjectsResult` | 批量删除请求体构造与结果解析 |

数据面方法（`S3Client`）：

| 方法 | 说明 |
| --- | --- |
| `ping()` | `HEAD /{bucket}`；`401` / `403` 视为「端点可达但无权限」，返回 `Ok(())` |
| `health_check()` | 返回 `S3Health`（失败体现在 `healthy = false`，不返回 `Err`） |
| `put_object(key, bytes, options)` | 上传内存数据，返回 `ObjectMeta` |
| `put_object_stream(key, stream, options, content_length)` | 流式上传（`UNSIGNED-PAYLOAD`，不重试） |
| `get_object(key, options)` | 返回 `(ObjectMeta, ByteStream)` |
| `get_object_bytes(key)` | 一次性读全量 `Bytes` |
| `delete_object(key)` | 删除单个对象（幂等，可重试） |
| `head_object(key)` | 只取元数据 |
| `list_objects_v2(prefix, continuation_token, max_keys)` | 列举对象（固定 `encoding-type=url`） |

## 签名与寻址

### AWS Signature Version 4

所有请求都使用 `AWS4-HMAC-SHA256` 头签名，固定附带：

| 请求头 | 说明 |
| --- | --- |
| `Authorization` | `AWS4-HMAC-SHA256 Credential=…/…, SignedHeaders=…, Signature=…` |
| `x-amz-content-sha256` | 请求体 SHA-256（流式上传时为 `UNSIGNED-PAYLOAD`） |
| `x-amz-date` | `YYYYMMDDTHHMMSSZ`（UTC） |
| `x-amz-security-token` | 配置了 `session_token` 时自动附带并参与签名 |

实现细节与 S3 的特殊规则一致：

- **规范化 URI 不做二次编码**：对象键按字节百分号编码（保留 `/`），签名直接使用
  这个已编码路径（`test$file.text` → `/test%24file.text`，而不是 `%2524`）；
- **查询串**：键与值都按 AWS unreserved 集合（`A-Za-z0-9-_.~`）编码，空格编码为
  `%20`（不是 `+`），再按 `(键, 值)` 字节序排序；
- **规范化头**：头名转小写、值折叠连续空白、按头名排序，同名头按出现顺序用逗号
  连接；
- 已知向量覆盖 `aws-sig-v4-test-suite` 的 `get-vanilla`、
  `get-vanilla-query-order-key-case`、`get-vanilla-query-order-key`、
  `get-header-key-duplicate`，以及 S3 文档的 `GET Object` / `PUT Object` 示例
  （断言 `CanonicalRequest` 与 `Authorization` 完全相等）。

### virtual-hosted 与 path-style

| 风格 | 请求形式 | 何时使用 |
| --- | --- | --- |
| virtual-hosted（默认） | `https://{bucket}.{endpoint}/{key}` | AWS 官方端点；桶名不含 `.` |
| path-style（`force_path_style = true`） | `https://{endpoint}/{bucket}/{key}` | 桶名含 `.`（TLS 证书不匹配）、MinIO / Ceph / 自建网关 |

未配置 `endpoint` 时使用 AWS 官方端点 `https://s3.{region}.amazonaws.com`，此时
virtual-hosted 形式为 `https://{bucket}.s3.{region}.amazonaws.com`。endpoint 不
支持带路径前缀（`https://host/base`），配置时会被 `validate()` 拒绝。

### 预签名 URL

`presign_get` / `presign_put` 生成 query-string 方式签名的临时链接，包含
`X-Amz-Algorithm`、`X-Amz-Credential`、`X-Amz-Date`、`X-Amz-Expires`、
`X-Amz-SignedHeaders`、`X-Amz-Signature`（有 session token 时另有
`X-Amz-Security-Token`），载荷用 `UNSIGNED-PAYLOAD` 占位。有效期会被收敛到
`1..=604800` 秒（AWS 硬上限 7 天）。

返回 `S3Result<String>`。唯一的失败来源是**明文 HTTP 策略**：预签名 URL 恒定使用
`UNSIGNED-PAYLOAD`，endpoint 为 `http` 且未显式放行时返回 `S3Error::Config`（原因
同「明文 HTTP 上禁止未签名载荷」）。**其余配置项不做校验**——bucket 与凭据等必填项
请仍先用 `S3Config::validate()` 确认，否则生成的链接只会被服务端拒绝。

```rust
// 明文 HTTP 需要显式放行（默认拒绝）
let mut config = config.clone();
config.allow_unsigned_payload_over_http = true;
let url = presign_get(&config, &key, 3600)?;
```

## 配置项

环境变量前缀为 `FOUNDATIONX_S3X_`；`from_toml()` 使用同名扁平字段。

由于 TOML 不携带密钥，`from_toml()` 只校验**非凭据字段**（endpoint / region /
bucket / 超时 / 限额 / `user_agent`）。凭据需经环境变量或构建器注入后，
`validate()`（或 `S3Client::new` / `connect`）才会做含凭据的完整校验：

```rust,no_run
use s3x::{S3Config, S3ConfigBuilder};

fn build() -> Result<S3Config, Box<dyn std::error::Error>> {
    let parsed =
        S3Config::from_toml("bucket = \"examplebucket\"\naccess_key_id = \"AKIDEXAMPLE\"\n")?;
    let config = S3ConfigBuilder::from_config(parsed)
        .access_key_secret(std::env::var("FOUNDATIONX_S3X_ACCESS_KEY_SECRET")?)
        .build()?;
    Ok(config)
}
```

| 环境变量 | TOML / 字段 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `FOUNDATIONX_S3X_ENDPOINT` | `endpoint` | 空（AWS 官方端点） | 自定义 endpoint，仅 `http`/`https`，不支持路径前缀 |
| `FOUNDATIONX_S3X_REGION` | `region` | `us-east-1` | 区域；小写字母/数字/连字符 |
| `FOUNDATIONX_S3X_BUCKET` | `bucket` | 空（必填） | 桶名；3..=63 字节，小写字母/数字/`.`/`-`，首尾为字母或数字，非 IPv4 |
| `FOUNDATIONX_S3X_ACCESS_KEY_ID` | `access_key_id` | 空（必填） | Access Key ID |
| `FOUNDATIONX_S3X_ACCESS_KEY_SECRET` | — | 空（必填） | Secret Access Key；**不允许**写入 TOML |
| `FOUNDATIONX_S3X_SESSION_TOKEN` | — | 空 | 临时凭据 session token；**不允许**写入 TOML |
| `FOUNDATIONX_S3X_FORCE_PATH_STYLE` | `force_path_style` | `false` | `true` 时使用 path-style 寻址 |
| `FOUNDATIONX_S3X_REQUEST_TIMEOUT_MS` | `request_timeout_ms` | `30000` | 单次请求超时，上限 `600000` |
| `FOUNDATIONX_S3X_CONNECT_TIMEOUT_MS` | `connect_timeout_ms` | `5000` | 连接超时，上限 `60000`；`0` 表示不单独限制 |
| `FOUNDATIONX_S3X_MAX_RETRIES` | `max_retries` | `3` | 最大尝试次数（含首次），1..=10；`1` 表示不重试 |
| `FOUNDATIONX_S3X_MAX_IN_FLIGHT` | `max_in_flight` | `64` | 全局并发上限，1..=1024 |
| `FOUNDATIONX_S3X_USER_AGENT` | `user_agent` | `s3x/<version>` | `User-Agent` 头 |
| `FOUNDATIONX_S3X_ALLOW_UNSIGNED_PAYLOAD_OVER_HTTP` | `allow_unsigned_payload_over_http` | `false` | 是否允许在明文 HTTP endpoint 上使用未签名载荷，见「安全约定」 |

布尔变量兼容 `1/0`、`true/false`、`yes/no`、`on/off`。

### 安全约定

- **明文 HTTP 上禁止未签名载荷**：`put_object_stream` 的载荷哈希是
  `UNSIGNED-PAYLOAD`，即**签名不覆盖请求体**。HTTPS 下传输层仍保证完整性，但明文
  HTTP 下两个环节同时失守——请求体可被链路篡改而签名依然有效。因此 endpoint 为
  `http` 时该操作默认返回配置错误；确认可接受该降级（例如本地 MinIO 调试）时才用
  `allow_unsigned_payload_over_http` 显式放行。`put_object` / `get_object` 等操作的
  载荷哈希是真实 SHA-256，不受此限制。**预签名 URL 恒定使用 `UNSIGNED-PAYLOAD`，
  因此同样默认拒绝**（`presign_get` / `presign_put` / `presign_url` 返回
  `S3Result<String>`）——除载荷不受保护外，签名本体与 session token 也会随 URL
  明文传输，而这类 URL 通常要交给浏览器或第三方。
  > 命名说明：AWS 将 `UNSIGNED-PAYLOAD` 列为 "unsigned payload option"，并**建议**
  > （而非要求）包含载荷校验和；本 crate 的默认拒绝是自身的**安全策略**，不是服务端
  > 的硬性约束。
- `access_key_secret` 与 `session_token` 只能经环境变量或 `S3ConfigBuilder`
  注入；`from_toml()` 会因为 `deny_unknown_fields` 直接拒绝这两个键。
- `Debug` 输出中这两个字段固定渲染为 `***`；`SignRequest` 的 `Debug` 同样脱敏。
- 错误消息只保留 HTTP 状态码、S3 错误码（如 `SlowDown`、`NoSuchKey`）与截断后的
  服务端 `<Message>`（≤ 512 字符）；读取错误响应最多 4 KiB，避免日志放大。
- 可重试判定（`S3Error::is_retryable()`，**错误码优先于状态码**）：
  - **可重试**：网络 / IO / 超时类错误；响应体错误码为 `SlowDown` /
    `RequestTimeout` / `InternalError` / `ServiceUnavailable` 的**任意**状态码；
    HTTP `408` / `429` / `5xx`。
  - **不可重试**：配置错误、序列化错误、对象键非法、不支持的操作，以及
    **其余全部 4xx**（含 401 / 403 / 404）。
  - 之所以先看错误码：AWS 的 `RequestTimeout` 使用 HTTP `400`，只按状态码判定
    会把它当成永久故障漏掉重试。只有明确列出的瞬时错误码才享受这一豁免——
    `403 SignatureDoesNotMatch` 这类鉴权失败仍不会重试。
  - 重试次数始终受 `max_retries`（默认 3，上限 10）约束，不会无限重试。

## 与 ossx 的区别

| 维度 | `s3x` | `ossx` |
| --- | --- | --- |
| 服务端 | AWS S3 及 S3 兼容存储 | 阿里云 OSS |
| 签名 | AWS Signature Version 4（`AWS4-HMAC-SHA256`，HMAC-SHA256 派生签名密钥） | OSS Signature V1（HMAC-SHA1 + Base64） |
| 签名输入 | `CanonicalRequest`（方法/URI/查询串/规范化头/载荷哈希） | `StringToSign`（VERB/Content-MD5/Content-Type/Date/CanonicalizedResource） |
| 寻址 | virtual-hosted（默认）或 path-style | `{bucket}.{endpoint}` 或自定义域名 |
| 预签名 | `X-Amz-Signature` 系列查询参数（`expires_in_secs`，上限 7 天） | `OSSAccessKeyId` / `Expires` / `Signature`（绝对过期时间戳） |
| 临时凭据 | `session_token` → `x-amz-security-token` | STS `SecurityToken` 头 |
| 载荷校验 | 每请求 `x-amz-content-sha256`（流式用 `UNSIGNED-PAYLOAD`） | 可选 `Content-MD5` |
| 批量删除 | 只提供请求体/响应纯函数（S3 要求额外校验和头） | — |

两者共享同一套 API 形态：`XxxConfig`（`from_env` / `from_toml` / `validate` /
`builder`）、`XxxClient`（`new` / `connect` / `ping` / `health_check` + 数据面）、
`XxxError::is_retryable`、`ObjectKey` / `ObjectMeta` / `UploadOptions` /
`DownloadOptions` / `ByteStream`。签名算法不同，因此签名相关的函数不通用。

## 测试

```bash
cargo test
```

集成测试全部离线运行：SigV4 使用 AWS 官方测试套件与文档示例的已知向量，配置与
纯函数用例不触碰网络，失败路径统一用 `127.0.0.1:1`（必然拒绝连接）验证。

SigV4 已知向量来源：

- `aws-sig-v4-test-suite`：`get-vanilla`、`get-vanilla-query-order-key-case`、
  `get-vanilla-query-order-key`、`get-header-key-duplicate`；
- AWS S3 文档 `GET Object`（`f0e8bdb8…`）与 `PUT Object`（`98ad7217…`）示例。

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this crate by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.
