//! S3 连接配置（[`S3Config`] / [`S3ConfigBuilder`]）。
//!
//! 配置来源与优先级：
//!
//! 1. [`S3Config::default`] 内置默认值；
//! 2. TOML 文本（[`S3Config::from_toml`]）或环境变量（[`S3Config::from_env`]）；
//! 3. [`S3Config::validate`] 在建立连接前 fail-fast。
//!
//! 敏感字段 [`S3Config::access_key_secret`] 与 [`S3Config::session_token`]：
//! `Debug` 输出固定脱敏为 `***`，且**不从 TOML 反序列化**（`deny_unknown_fields`
//! 会直接拒绝这两个键），只能通过环境变量或 [`S3ConfigBuilder`] 注入。

use std::fmt;
use std::time::Duration;

use serde::Deserialize;

use crate::error::{S3Error, S3Result};
use crate::sign::{self, S3_SERVICE};
use crate::types::ObjectKey;

/// 环境变量前缀。
pub const ENV_PREFIX: &str = "FOUNDATIONX_S3X_";
/// 环境变量：自定义 endpoint（缺省为 AWS 官方端点）。
pub const ENV_ENDPOINT: &str = "FOUNDATIONX_S3X_ENDPOINT";
/// 环境变量：区域。
pub const ENV_REGION: &str = "FOUNDATIONX_S3X_REGION";
/// 环境变量：存储桶名。
pub const ENV_BUCKET: &str = "FOUNDATIONX_S3X_BUCKET";
/// 环境变量：Access Key ID。
pub const ENV_ACCESS_KEY_ID: &str = "FOUNDATIONX_S3X_ACCESS_KEY_ID";
/// 环境变量：Secret Access Key。
pub const ENV_ACCESS_KEY_SECRET: &str = "FOUNDATIONX_S3X_ACCESS_KEY_SECRET";
/// 环境变量：临时凭据的 session token。
pub const ENV_SESSION_TOKEN: &str = "FOUNDATIONX_S3X_SESSION_TOKEN";
/// 环境变量：是否强制 path-style 寻址。
pub const ENV_FORCE_PATH_STYLE: &str = "FOUNDATIONX_S3X_FORCE_PATH_STYLE";
/// 环境变量：是否允许在明文 HTTP endpoint 上使用 `UNSIGNED-PAYLOAD`（默认 `false`）。
pub const ENV_ALLOW_UNSIGNED_PAYLOAD_OVER_HTTP: &str =
    "FOUNDATIONX_S3X_ALLOW_UNSIGNED_PAYLOAD_OVER_HTTP";
/// 环境变量：请求超时（毫秒）。
pub const ENV_REQUEST_TIMEOUT_MS: &str = "FOUNDATIONX_S3X_REQUEST_TIMEOUT_MS";
/// 环境变量：连接超时（毫秒，`0` 表示不单独限制）。
pub const ENV_CONNECT_TIMEOUT_MS: &str = "FOUNDATIONX_S3X_CONNECT_TIMEOUT_MS";
/// 环境变量：最大尝试次数（含首次请求）。
pub const ENV_MAX_RETRIES: &str = "FOUNDATIONX_S3X_MAX_RETRIES";
/// 环境变量：全局并发上限。
pub const ENV_MAX_IN_FLIGHT: &str = "FOUNDATIONX_S3X_MAX_IN_FLIGHT";
/// 环境变量：`User-Agent`。
pub const ENV_USER_AGENT: &str = "FOUNDATIONX_S3X_USER_AGENT";

/// 默认区域。
pub const DEFAULT_REGION: &str = "us-east-1";
/// 默认请求超时（毫秒）。
pub const DEFAULT_REQUEST_TIMEOUT_MS: u64 = 30_000;
/// 默认连接超时（毫秒）。
pub const DEFAULT_CONNECT_TIMEOUT_MS: u64 = 5_000;
/// 默认最大尝试次数（含首次请求）。
pub const DEFAULT_MAX_RETRIES: u32 = 3;
/// 默认全局并发上限。
pub const DEFAULT_MAX_IN_FLIGHT: usize = 64;
/// 默认 `User-Agent`。
pub const DEFAULT_USER_AGENT: &str = concat!("s3x/", env!("CARGO_PKG_VERSION"));

/// 请求超时硬上限（毫秒）。
pub const HARD_MAX_REQUEST_TIMEOUT_MS: u64 = 600_000;
/// 连接超时硬上限（毫秒）。
pub const HARD_MAX_CONNECT_TIMEOUT_MS: u64 = 60_000;
/// 尝试次数硬上限（含首次请求）。
pub const HARD_MAX_RETRIES: u32 = 10;
/// 并发上限硬上限。
pub const HARD_MAX_IN_FLIGHT: usize = 1_024;
/// 存储桶名长度下限。
pub const MIN_BUCKET_NAME_LEN: usize = 3;
/// 存储桶名长度上限。
pub const MAX_BUCKET_NAME_LEN: usize = 63;

/// S3 客户端配置。
///
/// 所有字段均为 `pub`，可直接用结构体字面量 + `..Default::default()` 构造；
/// 敏感字段的 `Debug` 输出被脱敏。
#[derive(Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct S3Config {
    /// 自定义 endpoint；`None` 表示 AWS 官方端点
    /// （由 [`S3Config::effective_endpoint`] 依据 `region` 推导）。
    pub endpoint: Option<String>,
    /// 区域（SigV4 凭据范围与官方端点都依赖它）。
    pub region: String,
    /// 存储桶名。
    pub bucket: String,
    /// Access Key ID。
    pub access_key_id: String,
    /// Secret Access Key。
    ///
    /// **敏感字段**：`Debug` 脱敏，且不从 TOML 反序列化（只能经环境变量或
    /// [`S3ConfigBuilder::access_key_secret`] 注入）。
    #[serde(skip)]
    pub access_key_secret: String,
    /// 临时凭据对应的 session token（`x-amz-security-token`）。
    ///
    /// **敏感字段**：同 [`S3Config::access_key_secret`]。
    #[serde(skip)]
    pub session_token: Option<String>,
    /// 是否强制 path-style 寻址（`{endpoint}/{bucket}/{key}`）。
    ///
    /// `false`（默认）时使用 virtual-hosted 风格（`{bucket}.{endpoint}/{key}`），
    /// 与 AWS 官方行为一致；带点号的桶名或自签证书场景建议置为 `true`。
    pub force_path_style: bool,
    /// 是否允许在**明文 HTTP** endpoint 上使用 `UNSIGNED-PAYLOAD`（默认 `false`）。
    ///
    /// `UNSIGNED-PAYLOAD` 表示签名**不覆盖请求体**。走 HTTPS 时传输层仍能保证
    /// 完整性，但若同时是明文 HTTP，请求体在链路上可被篡改而签名依然有效——
    /// 两个环节同时失守。因此默认拒绝；
    /// 只有使用方显式确认这是可接受的降级（例如本地 MinIO 调试）时才放行。
    pub allow_unsigned_payload_over_http: bool,
    /// 单次请求超时（毫秒），上限 [`HARD_MAX_REQUEST_TIMEOUT_MS`]。
    pub request_timeout_ms: u64,
    /// 连接（TCP/TLS 握手）超时（毫秒）；`0` 表示只受请求超时约束。
    pub connect_timeout_ms: u64,
    /// 最大尝试次数（含首次请求，`1` 表示不重试），上限 [`HARD_MAX_RETRIES`]。
    pub max_retries: u32,
    /// 全局并发上限（信号量许可数，`1..=`[`HARD_MAX_IN_FLIGHT`]）。
    ///
    /// 许可覆盖**整个请求生命周期**，包括 [`crate::S3Client::get_object`] 返回的
    /// 字节流的后续读取：流被消费完或丢弃时才释放额度。
    pub max_in_flight: usize,
    /// `User-Agent` 头。
    pub user_agent: String,
}

impl Default for S3Config {
    fn default() -> Self {
        Self {
            endpoint: None,
            region: DEFAULT_REGION.to_owned(),
            bucket: String::new(),
            access_key_id: String::new(),
            access_key_secret: String::new(),
            session_token: None,
            force_path_style: false,
            allow_unsigned_payload_over_http: false,
            request_timeout_ms: DEFAULT_REQUEST_TIMEOUT_MS,
            connect_timeout_ms: DEFAULT_CONNECT_TIMEOUT_MS,
            max_retries: DEFAULT_MAX_RETRIES,
            max_in_flight: DEFAULT_MAX_IN_FLIGHT,
            user_agent: DEFAULT_USER_AGENT.to_owned(),
        }
    }
}

impl fmt::Debug for S3Config {
    /// 手写 `Debug`：secret 与 session token 固定渲染为 `***`。
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("S3Config")
            .field("endpoint", &self.endpoint)
            .field("region", &self.region)
            .field("bucket", &self.bucket)
            .field("access_key_id", &self.access_key_id)
            .field("access_key_secret", &"***")
            .field("session_token", &self.session_token.as_ref().map(|_| "***"))
            .field("force_path_style", &self.force_path_style)
            .field(
                "allow_unsigned_payload_over_http",
                &self.allow_unsigned_payload_over_http,
            )
            .field("request_timeout_ms", &self.request_timeout_ms)
            .field("connect_timeout_ms", &self.connect_timeout_ms)
            .field("max_retries", &self.max_retries)
            .field("max_in_flight", &self.max_in_flight)
            .field("user_agent", &self.user_agent)
            .finish()
    }
}

impl S3Config {
    /// 从环境变量加载（前缀 `FOUNDATIONX_S3X_`），未设置项使用默认值。
    ///
    /// 加载后立即 [`validate`](Self::validate)。
    pub fn from_env() -> S3Result<Self> {
        let mut config = Self::default();
        config.apply_env_overrides()?;
        config.validate()?;
        Ok(config)
    }

    /// 从 TOML 文本解析并校验（**不**读取环境变量，便于确定性测试）。
    ///
    /// 期望扁平字段；`access_key_secret` 与 `session_token` 不允许出现在 TOML 中
    /// （会被 `deny_unknown_fields` 拒绝），避免密钥进入版本库。
    ///
    /// 因此本方法只校验**非凭据字段**（endpoint / region / bucket / 超时 / 限额 /
    /// `user_agent`）。凭据必须另行经环境变量或 [`S3ConfigBuilder`] 注入，之后
    /// [`validate`](Self::validate)（或 [`crate::S3Client::new`]）才会做完整校验：
    ///
    /// ```no_run
    /// use s3x::{S3Config, S3ConfigBuilder};
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let parsed = S3Config::from_toml("bucket = \"examplebucket\"\naccess_key_id = \"AKIDEXAMPLE\"\n")?;
    /// let config = S3ConfigBuilder::from_config(parsed)
    ///     .access_key_secret(std::env::var("FOUNDATIONX_S3X_ACCESS_KEY_SECRET")?)
    ///     .build()?; // 完整校验（含凭据非空）
    /// # let _ = config;
    /// # Ok(())
    /// # }
    /// ```
    pub fn from_toml(text: &str) -> S3Result<Self> {
        let config: Self = toml::from_str(text)
            .map_err(|error| S3Error::Config(format!("TOML 解析失败: {}", error.message())))?;
        config.validate_shape()?;
        Ok(config)
    }

    /// 完整校验配置合法性（建立连接前 fail-fast），含凭据非空。
    pub fn validate(&self) -> S3Result<()> {
        self.validate_shape()?;
        if self.access_key_id.trim().is_empty() {
            return Err(S3Error::Config("access_key_id 不能为空".to_owned()));
        }
        if self.access_key_secret.is_empty() {
            return Err(S3Error::Config("access_key_secret 不能为空".to_owned()));
        }
        if self
            .session_token
            .as_deref()
            .is_some_and(|token| token.is_empty())
        {
            return Err(S3Error::Config(
                "session_token 若配置则不能为空字符串".to_owned(),
            ));
        }
        Ok(())
    }

    /// 校验除凭据以外的字段（`access_key_id` 仅做非空白检查）。
    fn validate_shape(&self) -> S3Result<()> {
        self.validate_endpoint()?;
        validate_region(&self.region)?;
        validate_bucket(&self.bucket)?;
        if self.access_key_id.trim().is_empty() {
            return Err(S3Error::Config("access_key_id 不能为空".to_owned()));
        }
        if self
            .session_token
            .as_deref()
            .is_some_and(|token| token.is_empty())
        {
            return Err(S3Error::Config(
                "session_token 若配置则不能为空字符串".to_owned(),
            ));
        }
        if self.request_timeout_ms == 0 || self.request_timeout_ms > HARD_MAX_REQUEST_TIMEOUT_MS {
            return Err(S3Error::Config(format!(
                "request_timeout_ms 必须落在 1..={HARD_MAX_REQUEST_TIMEOUT_MS} 范围内"
            )));
        }
        if self.connect_timeout_ms > HARD_MAX_CONNECT_TIMEOUT_MS {
            return Err(S3Error::Config(format!(
                "connect_timeout_ms 不得超过硬上限 {HARD_MAX_CONNECT_TIMEOUT_MS}"
            )));
        }
        if self.max_retries == 0 || self.max_retries > HARD_MAX_RETRIES {
            return Err(S3Error::Config(format!(
                "max_retries 必须落在 1..={HARD_MAX_RETRIES} 范围内"
            )));
        }
        if self.max_in_flight == 0 || self.max_in_flight > HARD_MAX_IN_FLIGHT {
            return Err(S3Error::Config(format!(
                "max_in_flight 必须落在 1..={HARD_MAX_IN_FLIGHT} 范围内"
            )));
        }
        if self.user_agent.trim().is_empty() {
            return Err(S3Error::Config("user_agent 不能为空".to_owned()));
        }
        Ok(())
    }

    /// 校验 endpoint：必须是 `http`/`https`、带主机名、不含查询串/片段，
    /// 且路径前缀为空（不支持把桶挂在子路径下的反代场景）。
    ///
    /// 未配置或仅含空白时视为使用 AWS 官方端点，与 [`S3Config::effective_endpoint`]
    /// 的判定保持一致。
    fn validate_endpoint(&self) -> S3Result<()> {
        let Some(endpoint) = self
            .endpoint
            .as_deref()
            .map(str::trim)
            .filter(|endpoint| !endpoint.is_empty())
        else {
            return Ok(());
        };
        let parsed = url::Url::parse(endpoint)
            .map_err(|_| S3Error::Config("endpoint 不是合法 URL".to_owned()))?;
        if !matches!(parsed.scheme(), "http" | "https") {
            return Err(S3Error::Config(
                "endpoint 只支持 http/https 协议".to_owned(),
            ));
        }
        if parsed.host_str().unwrap_or_default().is_empty() {
            return Err(S3Error::Config("endpoint 缺少主机名".to_owned()));
        }
        if parsed.query().is_some() || parsed.fragment().is_some() {
            return Err(S3Error::Config("endpoint 不能包含查询串或片段".to_owned()));
        }
        if !matches!(parsed.path(), "" | "/") {
            return Err(S3Error::Config(
                "endpoint 不能包含路径前缀（请使用独立域名或端口区分服务）".to_owned(),
            ));
        }
        Ok(())
    }

    /// 链式构建器入口。
    #[must_use]
    pub fn builder() -> S3ConfigBuilder {
        S3ConfigBuilder::new()
    }

    /// 实际使用的 endpoint。
    ///
    /// - 未配置 `endpoint` 时返回 AWS 官方端点
    ///   `https://s3.{region}.amazonaws.com`；
    /// - 否则返回自定义 endpoint（去掉尾部 `/`）。
    #[must_use]
    pub fn effective_endpoint(&self) -> String {
        match self.endpoint.as_deref().map(str::trim) {
            Some(endpoint) if !endpoint.is_empty() => endpoint.trim_end_matches('/').to_owned(),
            _ => format!("https://s3.{}.amazonaws.com", self.region),
        }
    }

    /// 当前生效的 endpoint 是否为**明文 HTTP**（非 TLS）。
    ///
    /// 用于判定「未签名载荷」是否处于**无任何完整性保护**的状态：`UNSIGNED-PAYLOAD`
    /// 本身就不覆盖请求体，若再叠加明文传输，请求体在链路上可被篡改而签名依然有效。
    /// endpoint 无法解析时返回 `false`（交由 [`S3Config::validate`] 报错）。
    #[must_use]
    pub fn endpoint_is_plain_http(&self) -> bool {
        url::Url::parse(&self.effective_endpoint()).is_ok_and(|parsed| parsed.scheme() == "http")
    }

    /// 桶级请求的完整 URL（无查询串）。
    #[must_use]
    pub fn bucket_url(&self) -> String {
        self.endpoint_parts(None).url
    }

    /// 对象级请求的完整 URL（无查询串）。
    #[must_use]
    pub fn object_url(&self, key: &ObjectKey) -> String {
        self.endpoint_parts(Some(key.as_str())).url
    }

    /// SigV4 服务名（S3 固定为 [`S3_SERVICE`]）。
    #[must_use]
    pub fn service(&self) -> &'static str {
        S3_SERVICE
    }

    /// 一次请求的寻址三元组：完整 URL、`Host` 头、规范化 URI。
    pub(crate) fn endpoint_parts(&self, key: Option<&str>) -> EndpointParts {
        let (scheme, authority) = split_endpoint(&self.effective_endpoint());
        let encoded_key = key.map(|key| sign::percent_encode(key, false));
        if self.force_path_style {
            let mut canonical_uri = format!("/{}", self.bucket);
            if let Some(key) = &encoded_key {
                canonical_uri.push('/');
                canonical_uri.push_str(key);
            }
            EndpointParts {
                url: format!("{scheme}://{authority}{canonical_uri}"),
                host: authority,
                canonical_uri,
            }
        } else {
            let host = format!("{}.{authority}", self.bucket);
            let canonical_uri = match &encoded_key {
                Some(key) => format!("/{key}"),
                None => "/".to_owned(),
            };
            EndpointParts {
                url: format!("{scheme}://{host}{canonical_uri}"),
                host,
                canonical_uri,
            }
        }
    }

    /// 从环境变量覆盖当前配置（env 值优先于结构体已有值）。
    fn apply_env_overrides(&mut self) -> S3Result<()> {
        if let Some(value) = env_trimmed(ENV_ENDPOINT) {
            self.endpoint = Some(value);
        }
        if let Some(value) = env_trimmed(ENV_REGION) {
            self.region = value;
        }
        if let Some(value) = env_trimmed(ENV_BUCKET) {
            self.bucket = value;
        }
        if let Some(value) = env_trimmed(ENV_ACCESS_KEY_ID) {
            self.access_key_id = value;
        }
        if let Ok(value) = std::env::var(ENV_ACCESS_KEY_SECRET) {
            self.access_key_secret = value;
        }
        if let Some(value) = env_trimmed(ENV_SESSION_TOKEN) {
            self.session_token = Some(value);
        }
        if let Some(value) = env_bool(ENV_FORCE_PATH_STYLE)? {
            self.force_path_style = value;
        }
        if let Some(value) = env_bool(ENV_ALLOW_UNSIGNED_PAYLOAD_OVER_HTTP)? {
            self.allow_unsigned_payload_over_http = value;
        }
        if let Some(value) = env_parsed::<u64>(ENV_REQUEST_TIMEOUT_MS)? {
            self.request_timeout_ms = value;
        }
        if let Some(value) = env_parsed::<u64>(ENV_CONNECT_TIMEOUT_MS)? {
            self.connect_timeout_ms = value;
        }
        if let Some(value) = env_parsed::<u32>(ENV_MAX_RETRIES)? {
            self.max_retries = value;
        }
        if let Some(value) = env_parsed::<usize>(ENV_MAX_IN_FLIGHT)? {
            self.max_in_flight = value;
        }
        if let Some(value) = env_trimmed(ENV_USER_AGENT) {
            self.user_agent = value;
        }
        Ok(())
    }
}

/// 寻址三元组（crate 内部使用）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EndpointParts {
    /// 完整 URL（不含查询串）。
    pub(crate) url: String,
    /// `Host` 头取值（virtual-hosted 时含桶名前缀）。
    pub(crate) host: String,
    /// 参与签名的规范化 URI（已 URI 编码，S3 规则不做二次编码）。
    pub(crate) canonical_uri: String,
}

/// [`S3Config`] 的链式构建器。
#[derive(Clone, Debug, Default)]
pub struct S3ConfigBuilder {
    inner: S3Config,
}

impl S3ConfigBuilder {
    /// 从默认值开始。
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: S3Config::default(),
        }
    }

    /// 从已有配置开始（便于在既有配置上覆盖少量字段）。
    #[must_use]
    pub fn from_config(config: S3Config) -> Self {
        Self { inner: config }
    }

    /// 设置自定义 endpoint（`None` 表示 AWS 官方端点）。
    #[must_use]
    pub fn endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.inner.endpoint = Some(endpoint.into());
        self
    }

    /// 清除自定义 endpoint，回退到 AWS 官方端点。
    #[must_use]
    pub fn aws_endpoint(mut self) -> Self {
        self.inner.endpoint = None;
        self
    }

    /// 设置区域。
    #[must_use]
    pub fn region(mut self, region: impl Into<String>) -> Self {
        self.inner.region = region.into();
        self
    }

    /// 设置存储桶名。
    #[must_use]
    pub fn bucket(mut self, bucket: impl Into<String>) -> Self {
        self.inner.bucket = bucket.into();
        self
    }

    /// 设置 Access Key ID。
    #[must_use]
    pub fn access_key_id(mut self, access_key_id: impl Into<String>) -> Self {
        self.inner.access_key_id = access_key_id.into();
        self
    }

    /// 设置 Secret Access Key（不会出现在 `Debug` 输出中）。
    #[must_use]
    pub fn access_key_secret(mut self, access_key_secret: impl Into<String>) -> Self {
        self.inner.access_key_secret = access_key_secret.into();
        self
    }

    /// 设置 session token（不会出现在 `Debug` 输出中）。
    #[must_use]
    pub fn session_token(mut self, session_token: impl Into<String>) -> Self {
        self.inner.session_token = Some(session_token.into());
        self
    }

    /// 设置是否强制 path-style 寻址。
    #[must_use]
    pub fn force_path_style(mut self, force_path_style: bool) -> Self {
        self.inner.force_path_style = force_path_style;
        self
    }

    /// 允许在明文 HTTP endpoint 上使用 `UNSIGNED-PAYLOAD`（默认拒绝）。
    ///
    /// 仅在确认「请求体完整性不受保护」可接受时开启（例如本地 MinIO 调试）。
    pub fn allow_unsigned_payload_over_http(mut self, allow: bool) -> Self {
        self.inner.allow_unsigned_payload_over_http = allow;
        self
    }

    /// 设置请求超时。
    #[must_use]
    pub fn request_timeout(mut self, timeout: Duration) -> Self {
        self.inner.request_timeout_ms = u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX);
        self
    }

    /// 设置连接超时（`None` 表示不单独限制）。
    #[must_use]
    pub fn connect_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.inner.connect_timeout_ms = timeout
            .map(|timeout| u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX))
            .unwrap_or(0);
        self
    }

    /// 设置最大尝试次数（含首次请求）。
    #[must_use]
    pub fn max_retries(mut self, max_retries: u32) -> Self {
        self.inner.max_retries = max_retries;
        self
    }

    /// 设置全局并发上限。
    #[must_use]
    pub fn max_in_flight(mut self, max_in_flight: usize) -> Self {
        self.inner.max_in_flight = max_in_flight;
        self
    }

    /// 设置 `User-Agent`。
    #[must_use]
    pub fn user_agent(mut self, user_agent: impl Into<String>) -> Self {
        self.inner.user_agent = user_agent.into();
        self
    }

    /// 校验并产出配置。
    pub fn build(self) -> S3Result<S3Config> {
        self.inner.validate()?;
        Ok(self.inner)
    }
}

/// 拆分 `scheme://authority`；无协议前缀时兜底为 `https`（`validate` 已拒绝该形态）。
fn split_endpoint(endpoint: &str) -> (String, String) {
    match url::Url::parse(endpoint) {
        Ok(parsed) => {
            let scheme = parsed.scheme().to_owned();
            let host = parsed.host_str().unwrap_or_default().to_owned();
            let authority = match parsed.port() {
                Some(port) => format!("{host}:{port}"),
                None => host,
            };
            (scheme, authority)
        }
        Err(_) => match endpoint.split_once("://") {
            Some((scheme, rest)) => (scheme.to_owned(), rest.trim_end_matches('/').to_owned()),
            None => ("https".to_owned(), endpoint.to_owned()),
        },
    }
}

/// 校验区域名：小写字母/数字/连字符，不以连字符开头或结尾，长度 `1..=64`。
fn validate_region(region: &str) -> S3Result<()> {
    let region = region.trim();
    let valid = !region.is_empty()
        && region.len() <= 64
        && !region.starts_with('-')
        && !region.ends_with('-')
        && region
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
    if valid {
        Ok(())
    } else {
        Err(S3Error::Config(
            "region 只允许小写字母、数字与连字符（不以连字符开头/结尾，长度 1..=64）".to_owned(),
        ))
    }
}

/// 校验存储桶名（AWS 通用存储桶命名规则）。
fn validate_bucket(bucket: &str) -> S3Result<()> {
    let len = bucket.len();
    if !(MIN_BUCKET_NAME_LEN..=MAX_BUCKET_NAME_LEN).contains(&len) {
        return Err(S3Error::Config(format!(
            "bucket 长度必须落在 {MIN_BUCKET_NAME_LEN}..={MAX_BUCKET_NAME_LEN} 之间"
        )));
    }
    let first = bucket.chars().next().unwrap_or_default();
    let last = bucket.chars().next_back().unwrap_or_default();
    if !(first.is_ascii_lowercase() || first.is_ascii_digit())
        || !(last.is_ascii_lowercase() || last.is_ascii_digit())
    {
        return Err(S3Error::Config(
            "bucket 必须以小写字母或数字开头与结尾".to_owned(),
        ));
    }
    if !bucket
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '-' | '.'))
    {
        return Err(S3Error::Config(
            "bucket 只允许小写字母、数字、连字符与点号".to_owned(),
        ));
    }
    if bucket.contains("..") {
        return Err(S3Error::Config("bucket 不能包含连续的 `.`".to_owned()));
    }
    if bucket.parse::<std::net::Ipv4Addr>().is_ok() {
        return Err(S3Error::Config("bucket 不能是 IPv4 地址形式".to_owned()));
    }
    Ok(())
}

/// 读取 trim 后非空的环境变量。
fn env_trimmed(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

/// 读取并解析环境变量；解析失败只报告变量名，不回显取值。
fn env_parsed<T>(name: &str) -> S3Result<Option<T>>
where
    T: std::str::FromStr,
{
    match std::env::var(name) {
        Ok(value) => value
            .trim()
            .parse::<T>()
            .map(Some)
            .map_err(|_| S3Error::Config(format!("环境变量 {name} 取值非法"))),
        Err(_) => Ok(None),
    }
}

/// 读取布尔型环境变量，兼容 `1/0`、`true/false`、`yes/no`、`on/off`。
fn env_bool(name: &str) -> S3Result<Option<bool>> {
    let Some(value) = env_trimmed(name) else {
        return Ok(None);
    };
    match value.to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(Some(true)),
        "0" | "false" | "no" | "off" => Ok(Some(false)),
        _ => Err(S3Error::Config(format!("环境变量 {name} 取值非法"))),
    }
}

/// 缺省 endpoint 的 AWS 官方形态（供文档与测试引用）。
///
/// # Examples
///
/// ```
/// use s3x::aws_endpoint_for_region;
///
/// assert_eq!(
///     aws_endpoint_for_region("ap-east-1"),
///     "https://s3.ap-east-1.amazonaws.com"
/// );
/// ```
#[must_use]
pub fn aws_endpoint_for_region(region: &str) -> String {
    format!("https://s3.{region}.amazonaws.com")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 环境变量是进程级共享状态；涉及 env 的用例必须串行，避免并行测试互相干扰。
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// 获取环境变量用例的串行令牌（锁中毒时继续，测试仍可复现）。
    fn env_guard() -> std::sync::MutexGuard<'static, ()> {
        ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn valid_config() -> S3Config {
        S3Config::builder()
            .bucket("examplebucket")
            .access_key_id("AKIAIOSFODNN7EXAMPLE")
            .access_key_secret("secret")
            .build()
            .expect("测试配置必须有效")
    }

    #[test]
    fn default_values_and_aws_endpoint() {
        let config = S3Config::default();
        assert!(config.endpoint.is_none());
        assert_eq!(config.region, DEFAULT_REGION);
        assert_eq!(
            config.effective_endpoint(),
            "https://s3.us-east-1.amazonaws.com"
        );
        assert_eq!(config.service(), S3_SERVICE);
        assert!(!config.force_path_style);
        // 默认配置缺少凭据与桶名，必须 fail-closed。
        assert!(config.validate().is_err());
    }

    #[test]
    fn effective_endpoint_trims_trailing_slash() {
        let config = S3Config {
            endpoint: Some("https://minio.example.com:9000///".to_owned()),
            ..Default::default()
        };
        assert_eq!(
            config.effective_endpoint(),
            "https://minio.example.com:9000"
        );
        let blank = S3Config {
            endpoint: Some("   ".to_owned()),
            ..Default::default()
        };
        assert_eq!(
            blank.effective_endpoint(),
            "https://s3.us-east-1.amazonaws.com"
        );
        assert_eq!(
            aws_endpoint_for_region("eu-west-1"),
            "https://s3.eu-west-1.amazonaws.com"
        );
    }

    #[test]
    fn endpoint_parts_path_style_and_virtual_hosted() {
        let config = S3Config {
            endpoint: Some("https://minio.example.com:9000".to_owned()),
            bucket: "examplebucket".to_owned(),
            ..Default::default()
        };
        let key = ObjectKey::new("dir/sub file.txt").expect("合法键");

        let virtual_hosted = config.endpoint_parts(Some(key.as_str()));
        assert_eq!(
            virtual_hosted.url,
            "https://examplebucket.minio.example.com:9000/dir/sub%20file.txt"
        );
        assert_eq!(virtual_hosted.host, "examplebucket.minio.example.com:9000");
        assert_eq!(virtual_hosted.canonical_uri, "/dir/sub%20file.txt");

        let path_style = S3Config {
            force_path_style: true,
            ..config.clone()
        };
        let parts = path_style.endpoint_parts(Some(key.as_str()));
        assert_eq!(
            parts.url,
            "https://minio.example.com:9000/examplebucket/dir/sub%20file.txt"
        );
        assert_eq!(parts.host, "minio.example.com:9000");
        assert_eq!(parts.canonical_uri, "/examplebucket/dir/sub%20file.txt");

        // 桶级请求：virtual-hosted 的规范化 URI 为 `/`。
        assert_eq!(config.endpoint_parts(None).canonical_uri, "/");
        assert_eq!(
            config.endpoint_parts(None).url,
            "https://examplebucket.minio.example.com:9000/"
        );
        assert_eq!(
            path_style.endpoint_parts(None).canonical_uri,
            "/examplebucket"
        );
    }

    #[test]
    fn endpoint_parts_normalizes_host_case_and_default_ports() {
        let config = S3Config {
            endpoint: Some("HTTPS://MinIO.Example.COM:443".to_owned()),
            bucket: "examplebucket".to_owned(),
            ..Default::default()
        };
        // 与 reqwest 实际发送的 Host 头保持一致（URL 解析器会小写主机名、省略默认端口）。
        assert_eq!(
            config.endpoint_parts(None).host,
            "examplebucket.minio.example.com"
        );
        assert_eq!(
            config.bucket_url(),
            "https://examplebucket.minio.example.com/"
        );
        assert_eq!(
            config.object_url(&ObjectKey::new("k").expect("合法键")),
            "https://examplebucket.minio.example.com/k"
        );
    }

    #[test]
    fn validate_rejects_bad_region_and_bucket() {
        let mut config = valid_config();
        config.region = "US-East-1".to_owned();
        assert!(config
            .validate()
            .unwrap_err()
            .to_string()
            .contains("region"));

        config = valid_config();
        config.region = String::new();
        assert!(config.validate().is_err());
        config.region = "-bad".to_owned();
        assert!(config.validate().is_err());

        config = valid_config();
        config.bucket = "ab".to_owned();
        assert!(config
            .validate()
            .unwrap_err()
            .to_string()
            .contains("bucket"));
        config.bucket = "Example-Bucket".to_owned();
        assert!(config.validate().is_err());
        config.bucket = "-bucket".to_owned();
        assert!(config.validate().is_err());
        config.bucket = "bucket-".to_owned();
        assert!(config.validate().is_err());
        config.bucket = "a..b".to_owned();
        assert!(config.validate().is_err());
        config.bucket = "192.168.5.4".to_owned();
        assert!(config.validate().is_err());
        config.bucket = "example.bucket".to_owned();
        assert!(config.validate().is_ok());
        config.bucket = "examplebucket".to_owned();
        assert!(config.validate().is_ok());

        // 63 字节通过，64 字节拒绝。
        let mut config = valid_config();
        config.bucket = "b".repeat(MAX_BUCKET_NAME_LEN);
        assert!(config.validate().is_ok());
        config.bucket = "b".repeat(MAX_BUCKET_NAME_LEN + 1);
        assert!(config.validate().is_err());
    }

    #[test]
    fn validate_rejects_bad_endpoint() {
        // 全空白 endpoint 视为未配置（与 AWS 官方端点兜底一致）。
        let blank = S3Config {
            endpoint: Some("  ".to_owned()),
            ..valid_config()
        };
        assert!(blank.validate().is_ok());

        let cases = [
            "ftp://example.com",
            "https://",
            "not a url",
            "https://example.com/base/path",
            "https://example.com/?a=1",
            "https://example.com/#frag",
        ];
        for endpoint in cases {
            let config = S3Config {
                endpoint: Some(endpoint.to_owned()),
                ..valid_config()
            };
            assert!(
                config.validate().is_err(),
                "endpoint `{endpoint}` 必须被拒绝"
            );
        }
        for endpoint in [
            "http://127.0.0.1:9000",
            "https://minio.example.com",
            "https://minio.example.com:9000/",
        ] {
            let config = S3Config {
                endpoint: Some(endpoint.to_owned()),
                ..valid_config()
            };
            assert!(config.validate().is_ok(), "endpoint `{endpoint}` 必须通过");
        }
    }

    #[test]
    fn validate_rejects_bad_limits_and_credentials() {
        let mut config = valid_config();
        config.access_key_id = "  ".to_owned();
        assert!(config.validate().is_err());

        config = valid_config();
        config.access_key_secret = String::new();
        assert!(config.validate().is_err());

        config = valid_config();
        config.session_token = Some(String::new());
        assert!(config.validate().is_err());

        config = valid_config();
        config.request_timeout_ms = 0;
        assert!(config.validate().is_err());
        config.request_timeout_ms = HARD_MAX_REQUEST_TIMEOUT_MS + 1;
        assert!(config.validate().is_err());
        config.request_timeout_ms = HARD_MAX_REQUEST_TIMEOUT_MS;
        assert!(config.validate().is_ok());

        config = valid_config();
        config.connect_timeout_ms = HARD_MAX_CONNECT_TIMEOUT_MS + 1;
        assert!(config.validate().is_err());
        config.connect_timeout_ms = 0;
        assert!(config.validate().is_ok(), "0 表示不单独限制连接超时");

        config = valid_config();
        config.max_retries = 0;
        assert!(config.validate().is_err());
        config.max_retries = HARD_MAX_RETRIES + 1;
        assert!(config.validate().is_err());

        config = valid_config();
        config.max_in_flight = 0;
        assert!(config.validate().is_err());
        config.max_in_flight = HARD_MAX_IN_FLIGHT + 1;
        assert!(config.validate().is_err());

        config = valid_config();
        config.user_agent = " ".to_owned();
        assert!(config.validate().is_err());
    }

    #[test]
    fn debug_redacts_secret_and_session_token() {
        let config = S3Config::builder()
            .bucket("examplebucket")
            .access_key_id("AKIAIOSFODNN7EXAMPLE")
            .access_key_secret("super-secret-key")
            .session_token("super-secret-token")
            .build()
            .expect("配置有效");
        let rendered = format!("{config:?}");
        assert!(rendered.contains("***"), "{rendered}");
        assert!(!rendered.contains("super-secret-key"), "{rendered}");
        assert!(!rendered.contains("super-secret-token"), "{rendered}");
        // Access Key ID 不是密钥，允许出现在 Debug 中（便于排障）。
        assert!(rendered.contains("AKIAIOSFODNN7EXAMPLE"), "{rendered}");
    }

    #[test]
    fn toml_parses_flat_fields_and_rejects_secrets() {
        let config = S3Config::from_toml(
            r#"
bucket = "examplebucket"
region = "eu-west-1"
access_key_id = "AKIAIOSFODNN7EXAMPLE"
force_path_style = true
request_timeout_ms = 1500
connect_timeout_ms = 200
max_retries = 4
max_in_flight = 8
endpoint = "https://minio.example.com:9000"
"#,
        )
        .expect("TOML 解析必须成功");
        assert_eq!(config.bucket, "examplebucket");
        assert_eq!(config.region, "eu-west-1");
        assert!(config.force_path_style);
        assert_eq!(config.request_timeout_ms, 1500);
        assert_eq!(config.connect_timeout_ms, 200);
        assert_eq!(config.max_retries, 4);
        assert_eq!(config.max_in_flight, 8);
        // 敏感字段只能经环境变量/构建器注入。
        assert!(config.access_key_secret.is_empty());
        assert!(config.session_token.is_none());

        // 密钥不允许写入 TOML（错误消息不回显取值）。
        let error =
            S3Config::from_toml("bucket = \"examplebucket\"\naccess_key_secret = \"hunter2\"\n")
                .expect_err("TOML 中的 secret 必须被拒绝");
        assert!(!error.to_string().contains("hunter2"), "{error}");

        let error = S3Config::from_toml("bucket = \"examplebucket\"\nsession_token = \"t\"\n")
            .expect_err("TOML 中的 session_token 必须被拒绝");
        assert!(!error.to_string().contains("t ="), "{error}");

        assert!(S3Config::from_toml("bucket = \"examplebucket\"\nunknown = 1\n").is_err());
        assert!(S3Config::from_toml("this is not toml").is_err());

        // TOML 不携带密钥：结构校验通过，但完整校验仍要求凭据非空。
        let structural =
            S3Config::from_toml("bucket = \"examplebucket\"\naccess_key_id = \"id\"\n")
                .expect("结构合法");
        let error = structural
            .validate()
            .expect_err("缺少 access_key_secret 时完整校验必须失败");
        assert!(error.to_string().contains("access_key_secret"), "{error}");
        assert!(
            S3ConfigBuilder::from_config(structural)
                .access_key_secret("secret")
                .build()
                .is_ok(),
            "注入密钥后应通过完整校验"
        );
    }

    #[test]
    fn toml_does_not_read_env_overrides() {
        let _guard = env_guard();
        std::env::set_var(ENV_BUCKET, "from-env-bucket");
        let config = S3Config::from_toml("bucket = \"from-toml-bucket\"\naccess_key_id = \"id\"\n")
            .expect("TOML 解析");
        std::env::remove_var(ENV_BUCKET);
        assert_eq!(
            config.bucket, "from-toml-bucket",
            "from_toml 必须与环境变量隔离"
        );
    }

    #[test]
    fn from_env_applies_overrides_and_validates() {
        let _guard = env_guard();
        let names = [
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
        ];
        // 先清空，避免与外部环境互相干扰。
        for name in names {
            std::env::remove_var(name);
        }
        assert!(S3Config::from_env().is_err(), "缺少必填项必须 fail-closed");

        std::env::set_var(ENV_BUCKET, "examplebucket");
        std::env::set_var(ENV_ACCESS_KEY_ID, "AKIAIOSFODNN7EXAMPLE");
        std::env::set_var(ENV_ACCESS_KEY_SECRET, "secret-from-env");
        std::env::set_var(ENV_REGION, "ap-southeast-2");
        std::env::set_var(ENV_ENDPOINT, "https://minio.example.com:9000");
        std::env::set_var(ENV_FORCE_PATH_STYLE, "yes");
        std::env::set_var(ENV_REQUEST_TIMEOUT_MS, "2500");
        std::env::set_var(ENV_CONNECT_TIMEOUT_MS, "300");
        std::env::set_var(ENV_MAX_RETRIES, "5");
        std::env::set_var(ENV_MAX_IN_FLIGHT, "16");
        std::env::set_var(ENV_SESSION_TOKEN, "token-from-env");
        std::env::set_var(ENV_USER_AGENT, "custom-agent/1");

        let config = S3Config::from_env().expect("环境变量配置必须有效");
        for name in names {
            std::env::remove_var(name);
        }

        assert_eq!(config.bucket, "examplebucket");
        assert_eq!(config.region, "ap-southeast-2");
        assert_eq!(config.access_key_secret, "secret-from-env");
        assert_eq!(config.session_token.as_deref(), Some("token-from-env"));
        assert!(config.force_path_style);
        assert_eq!(config.request_timeout_ms, 2500);
        assert_eq!(config.connect_timeout_ms, 300);
        assert_eq!(config.max_retries, 5);
        assert_eq!(config.max_in_flight, 16);
        assert_eq!(config.user_agent, "custom-agent/1");
        assert_eq!(
            config.effective_endpoint(),
            "https://minio.example.com:9000"
        );
        assert!(!format!("{config:?}").contains("secret-from-env"));

        // 非法数值只报告变量名。
        std::env::set_var(ENV_REQUEST_TIMEOUT_MS, "not-a-number");
        let error = S3Config::from_env().expect_err("非法数值必须拒绝");
        std::env::remove_var(ENV_REQUEST_TIMEOUT_MS);
        assert!(
            error.to_string().contains(ENV_REQUEST_TIMEOUT_MS),
            "{error}"
        );
        assert!(!error.to_string().contains("not-a-number"), "{error}");

        std::env::set_var(ENV_FORCE_PATH_STYLE, "maybe");
        assert!(S3Config::from_env().is_err());
        std::env::remove_var(ENV_FORCE_PATH_STYLE);
    }

    #[test]
    fn builder_overrides_and_produces_valid_config() {
        let config = S3Config::builder()
            .bucket("examplebucket")
            .region("us-west-2")
            .access_key_id("id")
            .access_key_secret("secret")
            .session_token("token")
            .force_path_style(true)
            .request_timeout(Duration::from_millis(900))
            .connect_timeout(Some(Duration::from_millis(100)))
            .max_retries(2)
            .max_in_flight(4)
            .user_agent("agent/2")
            .build()
            .expect("构建必须成功");
        assert_eq!(config.request_timeout_ms, 900);
        assert_eq!(config.connect_timeout_ms, 100);
        assert_eq!(config.max_retries, 2);
        assert_eq!(config.max_in_flight, 4);
        assert_eq!(config.user_agent, "agent/2");

        let rebuilt = S3ConfigBuilder::from_config(config)
            .connect_timeout(None)
            .build()
            .expect("重新构建");
        assert_eq!(rebuilt.connect_timeout_ms, 0);
    }

    #[test]
    fn builder_rejects_invalid_config() {
        let error = S3Config::builder()
            .bucket("examplebucket")
            .access_key_id("id")
            .build()
            .expect_err("缺少 secret 必须拒绝");
        assert!(matches!(error, S3Error::Config(_)));
        assert!(!error.is_retryable());
    }
}
