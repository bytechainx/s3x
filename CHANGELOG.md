# Changelog — s3x

本文件记录 `s3x` 的用户可见变更，遵循 [Keep a Changelog](https://keepachangelog.com/)
与 [Semantic Versioning](https://semver.org/)。

`s3x` 不是从 `xhyper.rs` 抽取的模块：该工程内没有 S3 驱动，本仓库的 SigV4 签名、
预签名、寻址模式与重试均为独立实现，从 `0.1.0` 起算。

## [Unreleased]

## [0.1.0] - 2026-09-21

### 新增

- 配置 `S3Config` / `S3ConfigBuilder`：`from_env`（环境变量前缀 `FOUNDATIONX_S3X_`）/
  `from_toml` / `validate` / `builder`，并提供 `effective_endpoint` / `bucket_url` /
  `object_url` 与 AWS 区域端点推导 `aws_endpoint_for_region`。
- 客户端 `S3Client`：同步 `new` 与异步 `connect`（只做校验与构造，不发网络请求）、
  `ping` / `health_check`，数据面 `put_object` / `put_object_stream` / `get_object` /
  `get_object_bytes` / `delete_object` / `head_object` / `list_objects_v2`。
- 对象键 `ObjectKey`：非空、无前导 `/`、无 `..`、无控制字符、≤ `MAX_OBJECT_KEY_BYTES`
  （1024）字节；数据面方法只接受 `ObjectKey`。
- 数据形态 `ObjectMeta` / `UploadOptions` / `DownloadOptions` / `ByteStream` /
  `byte_stream_from_bytes`。
- 手写 AWS Signature Version 4：`sign_request` 及 `canonical_request` /
  `canonical_headers` / `canonical_query_string` / `canonical_uri_for_key` /
  `percent_encode` / `signing_key` / `hmac_sha256` / `sha256_hex` / `string_to_sign` /
  `credential_scope` / `date_stamp` / `authorization_header` 等纯函数原语，含
  `UNSIGNED-PAYLOAD`；签名以 AWS 官方 `aws-sig-v4-test-suite` 已知向量测试为准。
- 预签名 URL：`presign_get` / `presign_put` / `presign_url` / `PresignOptions`，
  query-string 方式签名，有效期自动收敛到 1 秒 ~ 7 天（`HARD_MAX_PRESIGN_EXPIRES_SECS`）。
- 寻址风格：默认 virtual-hosted（`{bucket}.{endpoint}/{key}`），`force_path_style`
  切换为 path-style（`{endpoint}/{bucket}/{key}`），用于带点号桶名与 MinIO / Ceph 等自建网关。
- 重试 `RetryConfig` / `with_retry` / `with_retry_deadline` / `backoff_delay` /
  `is_s3_retryable`：指数退避 + 抖动，可加总 deadline；crate 内独立实现。
- 错误 `S3Error`（含 `is_retryable`）/ `S3Result`：错误消息只含 HTTP 状态码、S3 错误码与
  截断后的服务端消息（≤ `MAX_ERROR_MESSAGE_CHARS` = 512，响应前缀 ≤ `MAX_ERROR_BODY_BYTES`
  = 4096）。
- XML 解析面：`parse_list_objects_v2` / `ListObjectsResult` / `build_delete_objects_body` /
  `parse_delete_objects` / `parse_error_code_message`。
- 并发背压：`max_in_flight` 以 `tokio::sync::Semaphore` 限流，额度覆盖**整个请求生命周期**
  （下载流会继续持有额度直到被消费完或丢弃）；连接 / 请求超时与重试次数在构建期校验并
  clamp 到 `HARD_MAX_*`。

### 说明

- 本 crate **不发布到 crates.io**，仅以 GitHub 源码 / git 依赖形式复用；`cargo package`
  只作元数据完整性校验。
- 只做 S3 REST 协议、签名、对象读写与健康检查等基础设施原语；不含领域模型或业务编排。
- 手写 SigV4 **不引入 `aws-sdk-s3`**，也不覆盖 SigV4a、chunked transfer 签名等扩展。
- `access_key_secret` 与 `session_token` 只能经环境变量或 `S3ConfigBuilder` 注入，
  `from_toml` 会拒绝这两个键；二者永不进入错误消息、`Debug` 输出或 URL。
- 预签名 URL 依赖本机时钟；明文 HTTP 上的 `UNSIGNED-PAYLOAD` 必须经
  `ENV_ALLOW_UNSIGNED_PAYLOAD_OVER_HTTP` 显式开启；鉴权 / 权限失败立即返回、不重试。
