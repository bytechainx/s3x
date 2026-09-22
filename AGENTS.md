# s3x Agent 指南

> 本文件为 AI Agent 在本仓库工作时的入口指南。

## 项目定位

AWS S3 及 S3 兼容对象存储适配器：手写 SigV4 实现（不依赖 aws-sdk），virtual-hosted / path-style 双寻址，对象读写、预签名 URL、并发背压与重试。

## 技术栈

- Rust edition 2021, rust-version 1.85
- 关键依赖: `reqwest`（rustls-tls + stream）、`tokio`、`hmac`/`sha2`/`hex`（SigV4）、`percent-encoding`、`quick-xml`、`bytes`、`serde`、`thiserror`、`tracing`、`chrono`、`toml`、`url`
- 零内部耦合，不依赖 kernel/contracts 等私有 crate

## 代码结构

```text
src/
├── lib.rs      # 入口：模块声明 + 受控 re-export + 公开 API 面测试
├── client.rs   # S3Client 门面：类型定义（S3Client / Inner / RequestSpec / S3Health）、
│               # HTTP 层辅助（错误映射、响应流包装、header 读取）与内联测试
├── client/
│   ├── api.rs   # 数据面实现：impl S3Client（new/connect/ping/health_check/put/get/delete/head/list）
│   └── inner.rs # 共享状态的请求构造与发送：impl Inner
├── config.rs   # S3Config 门面：ENV_*/DEFAULT_*/HARD_MAX_* 常量、定义与 Default/Debug、
│               # from_env/from_toml/validate/builder/apply_env_overrides、内联测试
├── config/
│   ├── builder.rs  # S3ConfigBuilder（链式覆盖）
│   ├── endpoint.rs # 端点与寻址：effective_endpoint / *_url / endpoint_parts / aws_endpoint_for_region
│   ├── env.rs      # 环境变量读取辅助
│   └── validate.rs # 字段校验：endpoint 拆分、region 与 bucket 规则
├── error.rs    # S3Error / S3Result
├── presign.rs  # presign_get / presign_put / presign_url 预签名 URL
├── retry.rs    # RetryConfig / with_retry / backoff_delay 重试策略
├── sign.rs     # sign_request / canonical_request / signing_key 等 SigV4 纯函数原语
├── types.rs    # ObjectKey / ObjectMeta / UploadOptions / DownloadOptions / ByteStream
└── xml.rs      # ListObjectsV2 / DeleteObjects / 错误响应 XML 解析
```

## 开发约定

- 注释与文档使用简体中文；标识符保持英文
- 错误：`S3Error` thiserror 枚举 + `#[non_exhaustive]` + `S3Result<T>` 别名
- 配置：结构体 + `builder()`/`from_env()`（前缀 `FOUNDATIONX_S3X_`）/`from_toml()` + `validate()` + fail-fast
- `access_key_secret` 与 `session_token` 只能经 env 或 builder 注入，`from_toml` 会拒绝这两个键；`Debug` 脱敏
- 禁止裸 `unwrap()`（库代码）
- async tokio，禁止阻塞 I/O；`#![forbid(unsafe_code)]`
- SigV4 改动必须通过 AWS 官方 `aws-sig-v4-test-suite` 已知向量测试
- 资源上界在构建期校验并 clamp 到 `HARD_MAX_*`

## 门禁（P0）

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
```

热路径基准（离线，无需 S3 服务）：

```bash
cargo bench --bench hot_path -- --quick
```

## 相关文档

- 组织 Rust 规范：`~/org-config/rulesets/rust/RULES.md`
- API 文档：`docs/API.md`
- 标准与验收：`docs/标准.md`
- 术语与领域语言：`CONTEXT.md`
- 贡献指南：`CONTRIBUTING.md`
- 变更记录：`CHANGELOG.md`
- 基准测试：`benches/hot_path.rs`
