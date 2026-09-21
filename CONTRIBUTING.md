# CONTRIBUTING.md — 贡献指南（s3x）

本文件面向贡献者，汇总本地门禁与提交约定。
AI Agent 的工作约定另见 [`AGENTS.md`](./AGENTS.md)；术语与领域语言见 [`CONTEXT.md`](./CONTEXT.md)。

## 开发流程

- 本仓库是**独立的单 crate 仓库**，不依赖 `xhyper.rs` 主工程及其内部 crate（`kernel` /
  `contracts` 等），只依赖 crates.io 公开包；**不引入 `aws-sdk-s3`**。
- substantial 变更走 feature branch → PR → review → merge，**禁止直接 push `main`**。
- `main` 已启用分支保护：要求 PR + 必需检查 `fmt / clippy / test`，
  `required_approving_review_count = 0`（单人也能合并），禁止强推与删除。
- 合并方式固定为 **create a merge commit**。注意仓库设置是
  `merge_commit_title = MERGE_MESSAGE` + `merge_commit_message = PR_TITLE`，因此
  `gh pr merge` 必须显式传 `--subject` 与 `--body`，否则会产出通用
  `Merge pull request #N from …` 标题。
- 提交信息遵循 Conventional Commits（`feat:` / `fix:` / `docs:` / `ci:` / `chore:` /
  `refactor:`），描述用简体中文。

## 本地门禁（P0 三件套）

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
```

本仓库无可选 feature，上述命令原样执行即可（`--all-targets` 已覆盖 tests 与 benches）。
全部测试离线运行，不依赖真实 S3 服务（SigV4 用 AWS 官方已知向量，连接失败路径用不可达地址）。
热路径基准同样是离线的：

```bash
cargo bench --bench hot_path -- --quick
```

元数据完整性门禁（**不发布 crates.io**，此命令只校验打包元数据）：

```bash
cargo package --no-verify --allow-dirty
```

## 复用口径（不发布 crates.io）

- 本 crate **不发布到 crates.io**，仅以 GitHub 源码 / git 依赖形式复用。
- 文档与元数据中不得出现「可独立发布」「可直接 `cargo publish`」等表述，
  也不得放置 crates.io / docs.rs 徽章与外链。
- `Cargo.toml` 的 `documentation` 指向 `https://github.com/bytechainx/s3x#readme`。
- 消费方引入方式（README「安装」小节为准）：

  ```toml
  [dependencies]
  s3x = { git = "https://github.com/bytechainx/s3x" }
  ```

## 开发约定

- 注释、文档、错误消息使用**简体中文**；标识符保持英文。
- 错误类型：`thiserror` 枚举 + `#[non_exhaustive]` + `pub type S3Result<T>` 别名，
  并保留 `is_retryable` 分类。
- 不在库代码里裸 `unwrap()`（`[lints.clippy]` 已 `deny` `unwrap_used` / `expect_used` / `panic`）。
- 所有 `pub` 项必须有中文 `///` 文档（`missing_docs` 已 `deny`），`unsafe_code` 已 `forbid`。
- 集成测试**必须离线运行**，不触碰真实网络。
- **SigV4 以官方向量为准**：任何签名改动必须通过 AWS 官方 `aws-sig-v4-test-suite` 已知向量
  测试；不得为「让测试通过」而修改期望值。
- **对象键单一入口**：数据面方法只接受 `ObjectKey`，不得新增接受裸 `&str` 的键参数。
- **凭据注入面固定**：`access_key_secret` 与 `session_token` 只能经环境变量或
  `S3ConfigBuilder` 注入，`from_toml` 拒绝这两个键，`Debug` 一律脱敏。
- **上界集中治理**：并发、超时、重试与预签名有效期在构建期校验并 clamp 到 `HARD_MAX_*`；
  XML 解析统一走 `xml` 模块，禁止在 `client` 内散落手工解析。
- **公共 API 面须同步**：新增或删除导出必须同步 `lib.rs` 的 `public_api_surface` 测试、
  `docs/API.md` 与 `docs/标准.md`；breaking 变更走 SemVer major 并记入 `CHANGELOG.md`。
- edition 2021，MSRV `rust-version = "1.85"`（改动依赖时同步核对）。

## 提交前自检清单

- [ ] `cargo fmt --all -- --check` 通过
- [ ] `cargo clippy --all-targets -- -D warnings` 通过
- [ ] `cargo test --all-targets` 通过
- [ ] `cargo package --no-verify --allow-dirty` 通过
- [ ] 新增 `pub` 项都有中文 `///` 文档
- [ ] 文档中无「可独立发布」/ crates.io / docs.rs 表述
- [ ] SigV4 改动已通过 AWS 官方 `aws-sig-v4-test-suite` 向量
- [ ] 新增导出已同步 `public_api_surface` 测试与 `docs/API.md` / `docs/标准.md`
