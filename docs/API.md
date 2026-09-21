# s3x 公开 API

**版本 / 角色**：`s3x 0.1.0` · AWS S3 及 S3 兼容对象存储适配器（手写 SigV4，不依赖 aws-sdk）

## 公开消费面

| 主题 | 类型 / 函数 | 说明 |
| --- | --- | --- |
| 配置 | `S3Config` / `S3ConfigBuilder` | `from_env`（前缀 `FOUNDATIONX_S3X_`）/ `from_toml` / `validate` / `builder` / `effective_endpoint` / `bucket_url` / `object_url` |
| 端点 | `aws_endpoint_for_region` | AWS 官方区域端点推导 |
| 客户端 | `S3Client` | `new`（同步）/ `connect`（异步，只校验构造）/ `ping` / `health_check` + `put_object` / `put_object_stream` / `get_object` / `get_object_bytes` / `delete_object` / `head_object` / `list_objects_v2` |
| 健康 | `S3Health` | `healthy` / `endpoint` / `bucket` / `latency_ms` |
| 对象键 | `ObjectKey` | 已校验：非空、无前导 `/`、无 `..`、无控制字符、≤ 1024 字节（`MAX_OBJECT_KEY_BYTES`） |
| 数据形态 | `ObjectMeta` / `UploadOptions` / `DownloadOptions` / `ByteStream` / `byte_stream_from_bytes` | 元数据、读写选项与下载流 |
| 预签名 | `presign_get` / `presign_put` / `presign_url` / `PresignOptions` | query-string 签名临时 URL，有效期收敛到 1 秒 ~ 7 天（`HARD_MAX_PRESIGN_EXPIRES_SECS`） |
| 错误 | `S3Error`（`is_retryable`）/ `S3Result` | 错误消息只含 HTTP 状态码、S3 错误码与截断后的服务端消息 |
| 重试 | `RetryConfig` / `with_retry` / `with_retry_deadline` / `backoff_delay` / `is_s3_retryable` | 指数退避 + 抖动，可加总 deadline；crate 内独立实现 |
| SigV4 原语 | `sign_request` / `canonical_request` / `canonical_headers` / `canonical_query_string` / `canonical_uri_for_key` / `percent_encode` / `signing_key` / `hmac_sha256` / `sha256_hex` / `string_to_sign` / `credential_scope` / `date_stamp` / `authorization_header` | 纯函数，便于复用与验证；含 `UNSIGNED-PAYLOAD` 支持 |
| XML | `parse_list_objects_v2` / `ListObjectsResult` / `build_delete_objects_body` / `parse_delete_objects` / `parse_error_code_message` | ListObjectsV2 / 批量删除 / 错误响应解析 |
| 上界常量 | `MAX_ERROR_BODY_BYTES`（4096）/ `MAX_ERROR_MESSAGE_CHARS`（512）/ `MAX_LIST_KEYS`（1000）/ `HARD_MAX_*` | 资源与错误体截断上界 |

## 寻址风格

- 默认 virtual-hosted：`{bucket}.{endpoint}/{key}`（与 AWS 一致）；
- `S3Config::force_path_style` 切换为 path-style：`{endpoint}/{bucket}/{key}`，
  用于带点号的桶名或 MinIO / Ceph 等自建网关。

## 最小用法

```rust,no_run
use bytes::Bytes;
use s3x::{presign_get, ObjectKey, S3Client, S3Config, UploadOptions};

# #[tokio::main]
# async fn main() -> Result<(), Box<dyn std::error::Error>> {
let config = S3Config::builder()
    .endpoint("https://minio.example.com:9000") // 省略则用 AWS 官方端点
    .region("us-east-1")
    .bucket("examplebucket")
    .access_key_id(std::env::var("FOUNDATIONX_S3X_ACCESS_KEY_ID")?)
    .access_key_secret(std::env::var("FOUNDATIONX_S3X_ACCESS_KEY_SECRET")?)
    .build()?;

let client = S3Client::connect(config).await?; // 不发网络请求
client.ping().await?;

let key = ObjectKey::new("reports/2026-09.csv")?;
client
    .put_object(&key, Bytes::from_static(b"a,b\n1,2\n"), &UploadOptions::default().with_content_type("text/csv"))
    .await?;
let bytes = client.get_object_bytes(&key).await?;
let url = presign_get(&client.config(), &key, 3600)?;
# Ok(())
# }
```

## 能力边界

- 只做 S3 REST 协议、签名、对象读写与健康检查等基础设施原语；不含领域模型或业务编排。
- SigV4 为手写实现，以 AWS 官方 `aws-sig-v4-test-suite` 已知向量测试为准；不覆盖 SigV4a、
  chunked transfer 签名等扩展。
- secret access key / session token 永不进入错误消息、`Debug` 输出或 URL；
  `from_toml` 直接拒绝这两个键。
- 预签名 URL 依赖本机时钟；明文 HTTP 上的 `UNSIGNED-PAYLOAD` 需显式开启
  （`ENV_ALLOW_UNSIGNED_PAYLOAD_OVER_HTTP`）。
