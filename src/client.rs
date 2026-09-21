//! S3 客户端：SigV4 头签名、并发背压、重试与数据面操作。
//!
//! 所有请求都经过同一条链路：获取 [`Semaphore`] 许可 → 计算 `x-amz-date` /
//! `x-amz-content-sha256` → SigV4 签名 → 发送 → 状态码与 XML 错误映射 →
//! 按 [`RetryConfig`](crate::RetryConfig) 策略重试。
//!
//! 说明：
//!
//! - [`S3Client::connect`] **不发起网络请求**，只做配置校验与 HTTP 客户端构造；
//!   连通性请用 [`S3Client::ping`] 显式验证（`HEAD /{bucket}`）。
//! - [`S3Client::put_object_stream`] 使用 `UNSIGNED-PAYLOAD` 占位哈希，因此要求
//!   HTTPS（或服务端接受该占位）；流式请求体无法回放，故不做重试。
//! - 批量删除只提供请求体构造与结果解析的纯函数（见
//!   [`build_delete_objects_body`](crate::build_delete_objects_body) /
//!   [`parse_delete_objects`](crate::parse_delete_objects)）：S3 要求
//!   该接口附带 `Content-MD5`（或等价校验和头），本 crate 不引入摘要依赖。
//! - `max_in_flight` 覆盖**整个请求生命周期**：并发许可由请求发起时取得，直到
//!   响应处理完毕才释放。[`S3Client::get_object`] 返回的字节流会**继续持有**该许可
//!   （见 [`guarded_body_stream`]），因此流未被消费完或未被丢弃之前，不会让出并发额度。

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use bytes::Bytes;
use futures_core::Stream;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use reqwest::StatusCode;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tracing::debug;

use crate::config::S3Config;
use crate::error::{S3Error, S3Result};
use crate::retry::{self, RetryConfig};
use crate::sign::{self, SignRequest, UNSIGNED_PAYLOAD};
use crate::types::{ByteStream, DownloadOptions, ObjectKey, ObjectMeta, UploadOptions};
use crate::xml::{self, ListObjectsResult};

/// 读取**错误**响应时最多保留的字节数（避免无界读取与日志放大）。
pub const MAX_ERROR_BODY_BYTES: usize = 4096;
/// 错误消息中保留的最大字符数。
pub const MAX_ERROR_MESSAGE_CHARS: usize = 512;
/// 单次 `ListObjectsV2` 允许的最大页大小。
pub const MAX_LIST_KEYS: usize = 1_000;

/// 健康检查结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct S3Health {
    /// `HEAD /{bucket}` 是否可用（`401` / `403` 视为“可达但无权限”，仍算健康）。
    pub healthy: bool,
    /// 实际使用的 endpoint。
    pub endpoint: String,
    /// 目标存储桶。
    pub bucket: String,
    /// `HEAD /{bucket}` 往返耗时（毫秒）。
    pub latency_ms: u64,
}

/// 一次请求的签名输入（方法、寻址、参与签名的头与载荷哈希）。
struct RequestSpec {
    method: reqwest::Method,
    /// 完整 URL（不含查询串）。
    url: String,
    /// `Host` 头（参与签名）。
    host: String,
    /// 规范化 URI（参与签名）。
    canonical_uri: String,
    /// 查询参数（参与签名）。
    query: Vec<(String, String)>,
    /// 除 `host` / `x-amz-date` / `x-amz-content-sha256` 之外的附加签名头。
    extra_headers: Vec<(String, String)>,
    /// 载荷哈希或 [`UNSIGNED_PAYLOAD`]。
    payload_hash: String,
}

impl RequestSpec {
    /// 构造基础请求描述；`payload_hash` 默认为空请求体的哈希。
    fn new(method: &str, config: &S3Config, key: Option<&str>) -> Self {
        let parts = config.endpoint_parts(key);
        Self {
            method: request_method(method),
            url: parts.url,
            host: parts.host,
            canonical_uri: parts.canonical_uri,
            query: Vec::new(),
            extra_headers: Vec::new(),
            payload_hash: sign::EMPTY_PAYLOAD_SHA256.to_owned(),
        }
    }

    fn with_query(mut self, query: Vec<(String, String)>) -> Self {
        self.query = query;
        self
    }

    fn with_headers(mut self, headers: Vec<(String, String)>) -> Self {
        self.extra_headers = headers;
        self
    }

    fn with_payload_hash(mut self, payload_hash: impl Into<String>) -> Self {
        self.payload_hash = payload_hash.into();
        self
    }
}

/// 内部方法名到 [`reqwest::Method`] 的映射（所有调用点都传入合法常量）。
fn request_method(method: &str) -> reqwest::Method {
    reqwest::Method::from_bytes(method.as_bytes()).unwrap_or(reqwest::Method::GET)
}

/// 共享状态：HTTP 客户端、配置、重试策略与背压信号量。
struct Inner {
    http: reqwest::Client,
    config: S3Config,
    retry: RetryConfig,
    sem: Arc<Semaphore>,
}

/// S3 客户端。
///
/// 内部为 `Arc`，克隆廉价；克隆体共享同一个 `reqwest::Client` 连接池与并发额度。
#[derive(Clone)]
pub struct S3Client {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for S3Client {
    /// 只打印目标端点与桶名（不含任何凭据）。
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S3Client")
            .field("endpoint", &self.inner.config.effective_endpoint())
            .field("bucket", &self.inner.config.bucket)
            .field("force_path_style", &self.inner.config.force_path_style)
            .field("max_in_flight", &self.inner.config.max_in_flight)
            .finish()
    }
}

impl S3Client {
    /// 同步构造客户端：仅做配置校验并构造 `reqwest::Client`，**不发起网络请求**。
    pub fn new(config: S3Config) -> S3Result<Self> {
        config.validate()?;
        let http = build_http_client(&config)?;
        let retry = RetryConfig::new(config.max_retries, retry::DEFAULT_BASE_DELAY_MS);
        let sem = Arc::new(Semaphore::new(config.max_in_flight));
        Ok(Self {
            inner: Arc::new(Inner {
                http,
                config,
                retry,
                sem,
            }),
        })
    }

    /// 按配置构造客户端（异步入口，与同级适配器保持一致的调用形态）。
    ///
    /// **本方法不发起任何网络请求**：配置非法时返回 [`S3Error::Config`]，但不会
    /// 校验远端可达性或凭据有效性。需要确认「桶可达」请显式调用
    /// [`S3Client::ping`]——这是刻意的取舍：`HEAD /{bucket}` 需要
    /// `s3:ListBucket` 权限，把探测塞进 `connect` 会让只具备对象级权限的凭据
    /// 无法建连。
    pub async fn connect(config: S3Config) -> S3Result<Self> {
        Self::new(config)
    }

    /// 从环境变量加载配置并构造客户端（同样不发起网络请求）。
    pub async fn connect_from_env() -> S3Result<Self> {
        Self::connect(S3Config::from_env()?).await
    }

    /// 当前配置的副本。
    #[must_use]
    pub fn config(&self) -> S3Config {
        self.inner.config.clone()
    }

    /// 连通性探测：`HEAD /{bucket}`。
    ///
    /// - `2xx` -> `Ok(())`；
    /// - `401` / `403` -> `Ok(())`（端点可达，但当前凭据没有 `s3:ListBucket`
    ///   权限；在只授予对象级权限的部署中这是正常状态）；
    /// - 其它状态码（如 `404` 桶不存在）或传输失败 -> `Err`。
    pub async fn ping(&self) -> S3Result<()> {
        let spec = RequestSpec::new("HEAD", &self.inner.config, None);
        let response = self.inner.send(&spec, None).await?;
        let status = response.status();
        if is_reachable_without_permission(status) {
            debug!(
                status = status.as_u16(),
                "s3 ping 返回权限错误，端点视为可达"
            );
            return Ok(());
        }
        if !status.is_success() {
            let body = read_body_prefix(response).await;
            return Err(map_http_error(status, &body));
        }
        Ok(())
    }

    /// 健康检查：返回结构化结果（失败体现在 `healthy = false`，不返回 `Err`）。
    ///
    /// `Result` 仅用于与同级适配器保持 API 形态一致；正常路径恒为 `Ok`。
    pub async fn health_check(&self) -> S3Result<S3Health> {
        let started = Instant::now();
        let healthy = self.ping().await.is_ok();
        Ok(S3Health {
            healthy,
            endpoint: self.inner.config.effective_endpoint(),
            bucket: self.inner.config.bucket.clone(),
            latency_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        })
    }

    /// 上传一段内存数据。
    ///
    /// 返回的对象元数据取自响应头（`ETag`）；`size` 为请求体字节数。
    pub async fn put_object(
        &self,
        key: &ObjectKey,
        body: Bytes,
        options: &UploadOptions,
    ) -> S3Result<ObjectMeta> {
        let size = u64::try_from(body.len()).unwrap_or(u64::MAX);
        let spec = RequestSpec::new("PUT", &self.inner.config, Some(key.as_str()))
            .with_headers(options.additional_headers()?)
            .with_payload_hash(sign::sha256_hex(&body));
        let response = retry::with_retry(&self.inner.retry, "put_object", || {
            let spec = &spec;
            let body = body.clone();
            async move { self.inner.send_checked(spec, Some(body)).await }
        })
        .await?;
        Ok(ObjectMeta {
            key: key.as_str().to_owned(),
            size,
            etag: header_value(response.headers(), "etag"),
            last_modified: None,
            content_type: options.content_type.clone(),
        })
    }

    /// 以字节流上传（长度未知时使用）。
    ///
    /// 载荷哈希固定为 [`UNSIGNED_PAYLOAD`]，因此需要 HTTPS 或服务端接受该占位；
    /// 请求体无法回放，**不做重试**。`content_length` 为 `Some` 时显式设置
    /// `Content-Length`（否则使用分块传输编码）。
    pub async fn put_object_stream(
        &self,
        key: &ObjectKey,
        stream: ByteStream,
        options: &UploadOptions,
        content_length: Option<u64>,
    ) -> S3Result<ObjectMeta> {
        let spec = RequestSpec::new("PUT", &self.inner.config, Some(key.as_str()))
            .with_headers(options.additional_headers()?)
            .with_payload_hash(UNSIGNED_PAYLOAD);
        let _permit = self.inner.acquire().await?;
        let mut request = self
            .inner
            .build_request(&spec, None)?
            .body(reqwest::Body::wrap_stream(stream));
        if let Some(content_length) = content_length {
            request = request.header(reqwest::header::CONTENT_LENGTH, content_length);
        }
        let response = request
            .send()
            .await
            .map_err(|error| map_transport_error(&error))?;
        let status = response.status();
        if !status.is_success() {
            let response_body = read_body_prefix(response).await;
            return Err(map_http_error(status, &response_body));
        }
        Ok(ObjectMeta {
            key: key.as_str().to_owned(),
            size: content_length.unwrap_or_default(),
            etag: header_value(response.headers(), "etag"),
            last_modified: None,
            content_type: options.content_type.clone(),
        })
    }

    /// 下载对象：返回元数据与字节流（内容按需读取）。
    ///
    /// 返回的流会**持有**一个 `max_in_flight` 并发许可，直到流被消费完或丢弃；
    /// 因此调用方应及时消费或丢弃该流，否则会占着并发额度不放。
    pub async fn get_object(
        &self,
        key: &ObjectKey,
        options: &DownloadOptions,
    ) -> S3Result<(ObjectMeta, ByteStream)> {
        let headers = match options.range {
            Some((start, end)) if start > end => {
                return Err(S3Error::Config("下载范围非法：起点不得大于终点".to_owned()));
            }
            Some((start, end)) => vec![("range".to_owned(), format!("bytes={start}-{end}"))],
            None => Vec::new(),
        };
        let spec =
            RequestSpec::new("GET", &self.inner.config, Some(key.as_str())).with_headers(headers);
        // 许可在重试闭包内逐次获取/释放；成功后交由响应体流持有。
        let (permit, response) = retry::with_retry(&self.inner.retry, "get_object", || {
            let spec = &spec;
            async move { self.inner.send_checked_holding_permit(spec, None).await }
        })
        .await?;
        let meta = object_meta_from_headers(key, response.headers());
        Ok((meta, guarded_body_stream(permit, response)))
    }

    /// 下载对象并读完全部字节。
    pub async fn get_object_bytes(&self, key: &ObjectKey) -> S3Result<Bytes> {
        let spec = RequestSpec::new("GET", &self.inner.config, Some(key.as_str()));
        let response = retry::with_retry(&self.inner.retry, "get_object_bytes", || {
            let spec = &spec;
            async move { self.inner.send_checked(spec, None).await }
        })
        .await?;
        response
            .bytes()
            .await
            .map_err(|error| map_transport_error(&error))
    }

    /// 删除单个对象（幂等，可安全重试）。
    pub async fn delete_object(&self, key: &ObjectKey) -> S3Result<()> {
        let spec = RequestSpec::new("DELETE", &self.inner.config, Some(key.as_str()));
        retry::with_retry(&self.inner.retry, "delete_object", || {
            let spec = &spec;
            async move { self.inner.send_checked(spec, None).await }
        })
        .await?;
        Ok(())
    }

    /// 读取对象元数据（`HEAD`，不下载内容）。
    pub async fn head_object(&self, key: &ObjectKey) -> S3Result<ObjectMeta> {
        let spec = RequestSpec::new("HEAD", &self.inner.config, Some(key.as_str()));
        let response = retry::with_retry(&self.inner.retry, "head_object", || {
            let spec = &spec;
            async move { self.inner.send_checked(spec, None).await }
        })
        .await?;
        // HEAD 响应没有正文；错误码由状态码推导。
        Ok(object_meta_from_headers(key, response.headers()))
    }

    /// 列举对象（`ListObjectsV2`）。
    ///
    /// 请求固定携带 `encoding-type=url`，因此响应中的对象键与公共前缀会被百分号
    /// 解码后返回。`max_keys` 会被收敛到 `1..=`[`MAX_LIST_KEYS`]。
    pub async fn list_objects_v2(
        &self,
        prefix: Option<&str>,
        continuation_token: Option<&str>,
        max_keys: Option<usize>,
    ) -> S3Result<ListObjectsResult> {
        let mut query = vec![
            ("list-type".to_owned(), "2".to_owned()),
            ("encoding-type".to_owned(), "url".to_owned()),
        ];
        if let Some(prefix) = prefix {
            query.push(("prefix".to_owned(), prefix.to_owned()));
        }
        if let Some(token) = continuation_token {
            query.push(("continuation-token".to_owned(), token.to_owned()));
        }
        if let Some(max_keys) = max_keys {
            if max_keys == 0 {
                return Err(S3Error::Config("max_keys 必须 ≥ 1".to_owned()));
            }
            query.push((
                "max-keys".to_owned(),
                max_keys.min(MAX_LIST_KEYS).to_string(),
            ));
        }
        let spec = RequestSpec::new("GET", &self.inner.config, None).with_query(query);
        let response = retry::with_retry(&self.inner.retry, "list_objects_v2", || {
            let spec = &spec;
            async move { self.inner.send_checked(spec, None).await }
        })
        .await?;
        // 成功响应必须完整读取（页面大小由 max-keys 约束）。
        let body = response
            .bytes()
            .await
            .map_err(|error| map_transport_error(&error))?;
        let text = String::from_utf8_lossy(&body);
        xml::parse_list_objects_v2(&text).map_err(|error| with_body_prefix(error, &text))
    }
}

impl Inner {
    /// 获取一次并发许可（背压入口）；超时或信号量关闭都会失败。
    async fn acquire(&self) -> S3Result<OwnedSemaphorePermit> {
        let timeout = Duration::from_millis(self.config.request_timeout_ms);
        match tokio::time::timeout(timeout, self.sem.clone().acquire_owned()).await {
            Ok(Ok(permit)) => Ok(permit),
            Ok(Err(_)) => Err(S3Error::Connection("并发信号量已关闭".to_owned())),
            Err(_) => Err(S3Error::Timeout(format!(
                "等待 s3 并发额度超时（max_in_flight={}）",
                self.config.max_in_flight
            ))),
        }
    }

    /// 计算 SigV4 签名并组装 [`reqwest::RequestBuilder`]。
    fn build_request(
        &self,
        spec: &RequestSpec,
        body: Option<Bytes>,
    ) -> S3Result<reqwest::RequestBuilder> {
        let amz_date = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
        let mut signed: Vec<(String, String)> = Vec::with_capacity(spec.extra_headers.len() + 4);
        signed.push(("host".to_owned(), spec.host.clone()));
        signed.extend(spec.extra_headers.iter().cloned());
        signed.push(("x-amz-content-sha256".to_owned(), spec.payload_hash.clone()));
        signed.push(("x-amz-date".to_owned(), amz_date.clone()));
        if let Some(token) = &self.config.session_token {
            signed.push(("x-amz-security-token".to_owned(), token.clone()));
        }

        let query: Vec<(&str, &str)> = spec
            .query
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
            .collect();
        let headers: Vec<(&str, &str)> = signed
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
            .collect();
        let signature = sign::sign_request(&SignRequest {
            method: spec.method.as_str(),
            canonical_uri: &spec.canonical_uri,
            query: &query,
            headers: &headers,
            payload_hash: &spec.payload_hash,
            amz_date: &amz_date,
            region: &self.config.region,
            service: self.config.service(),
            access_key_id: &self.config.access_key_id,
            secret_access_key: &self.config.access_key_secret,
        });

        let url = if query.is_empty() {
            spec.url.clone()
        } else {
            format!("{}?{}", spec.url, sign::canonical_query_string(&query))
        };
        let mut request = self
            .http
            .request(spec.method.clone(), &url)
            .header(reqwest::header::AUTHORIZATION, signature.authorization);
        for (name, value) in &signed {
            // `Host` 由 reqwest 依据 URL 生成，重复设置会与之冲突。
            if name == "host" {
                continue;
            }
            let header_name = HeaderName::from_bytes(name.as_bytes())
                .map_err(|_| S3Error::Config("请求头名非法".to_owned()))?;
            let header_value = HeaderValue::from_str(value)
                .map_err(|_| S3Error::Config("请求头取值非法".to_owned()))?;
            request = request.header(header_name, header_value);
        }
        Ok(match body {
            Some(body) => request.body(body),
            None => request,
        })
    }

    /// 签名并发送一次请求（含并发背压与传输错误映射）。
    ///
    /// 本方法**不检查 HTTP 状态码**：任何响应都返回 `Ok`。需要让
    /// [`retry::with_retry`] 对 HTTP 层瞬时故障生效时，请改用
    /// [`Inner::send_checked`]；`ping` 需要自行容忍 401/403，因此继续使用本方法。
    async fn send(&self, spec: &RequestSpec, body: Option<Bytes>) -> S3Result<reqwest::Response> {
        let _permit = self.acquire().await?;
        self.build_request(spec, body)?
            .send()
            .await
            .map_err(|error| map_transport_error(&error))
    }

    /// 发送一次请求，并把非 2xx 状态映射为 [`S3Error`]。
    ///
    /// 状态码到错误的映射必须发生在**被重试的闭包内部**：否则
    /// [`retry::with_retry`] 只能看到传输层错误，`max_retries` 对
    /// `5xx` / `429` / `SlowDown` 等 HTTP 层瞬时故障完全失效。
    /// `Ok` 返回值保证状态码为 2xx。
    ///
    /// 并发许可在本方法返回时释放——即只覆盖「请求发出 → 响应头返回」。需要读取
    /// 响应体的调用方请改用 [`Inner::send_checked_holding_permit`]，否则
    /// `max_in_flight` 约束不到响应体传输阶段。
    async fn send_checked(
        &self,
        spec: &RequestSpec,
        body: Option<Bytes>,
    ) -> S3Result<reqwest::Response> {
        let response = self.send(spec, body).await?;
        let status = response.status();
        if status.is_success() {
            return Ok(response);
        }
        // 错误体只读前缀（上限 `MAX_ERROR_BODY_BYTES`），用于提取 S3 `<Code>`。
        let response_body = read_body_prefix(response).await;
        Err(map_http_error(status, &response_body))
    }

    /// 与 [`Inner::send_checked`] 相同，但把并发许可一并交出。
    ///
    /// 供**下载**路径使用：调用方必须把许可附着到响应体流上（见
    /// [`guarded_body_stream`]），使 `max_in_flight` 覆盖响应体传输阶段。
    /// 若拿到许可后不绑定而让它立即析构，就等于退回「只约束请求发起」的旧行为。
    async fn send_checked_holding_permit(
        &self,
        spec: &RequestSpec,
        body: Option<Bytes>,
    ) -> S3Result<(OwnedSemaphorePermit, reqwest::Response)> {
        let permit = self.acquire().await?;
        let response = self
            .build_request(spec, body)?
            .send()
            .await
            .map_err(|error| map_transport_error(&error))?;
        let status = response.status();
        if status.is_success() {
            return Ok((permit, response));
        }
        let response_body = read_body_prefix(response).await;
        Err(map_http_error(status, &response_body))
    }
}

/// 持有并发许可的响应体流。
///
/// `max_in_flight` 的语义是「同时在途的请求上限」。响应体的读取发生在
/// [`S3Client::get_object`] 返回**之后**，若不把许可带到这里，慢速大对象下载可以
/// 无限并发，并发上限便形同虚设。因此许可随本结构体保存：
///
/// - 读到流结束（`None`）时**立即**归还额度，不必等调用方 drop；
/// - 调用方提前 drop 时随析构归还；
/// - 结束后再被 poll 仍返回 `None`，**不 panic**。
///
/// 最后一点是刻意不用 [`futures_util::stream::unfold`] 的原因：后者在返回过
/// `None` 之后再被 poll 会直接 panic，那等于给公开的下载流引入一条可被误用触发的
/// panic 路径。
struct GuardedBodyStream {
    /// 响应体流；读到结束后置 `None`。
    body: Option<futures_util::stream::BoxStream<'static, Result<Bytes, reqwest::Error>>>,
    /// 并发许可；置 `None` 即归还额度。
    permit: Option<OwnedSemaphorePermit>,
}

impl Stream for GuardedBodyStream {
    type Item = Result<Bytes, std::io::Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        let Some(body) = this.body.as_mut() else {
            // 已结束：保持返回 `None`，可安全重复 poll。
            return Poll::Ready(None);
        };
        match body.as_mut().poll_next(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Some(Ok(chunk))) => Poll::Ready(Some(Ok(chunk))),
            Poll::Ready(Some(Err(error))) => Poll::Ready(Some(Err(std::io::Error::other(error)))),
            Poll::Ready(None) => {
                this.body = None;
                // 传输结束即归还并发额度，无需等待流被 drop。
                this.permit = None;
                Poll::Ready(None)
            }
        }
    }
}

/// 把并发许可附着到响应体流上（见 [`GuardedBodyStream`]）。
fn guarded_body_stream(permit: OwnedSemaphorePermit, response: reqwest::Response) -> ByteStream {
    Box::pin(GuardedBodyStream {
        body: Some(Box::pin(response.bytes_stream())),
        permit: Some(permit),
    })
}

/// 构造 `reqwest::Client`（超时、`User-Agent` 与连接池）。
fn build_http_client(config: &S3Config) -> S3Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder()
        .user_agent(config.user_agent.clone())
        .timeout(Duration::from_millis(config.request_timeout_ms));
    if config.connect_timeout_ms > 0 {
        builder = builder.connect_timeout(Duration::from_millis(config.connect_timeout_ms));
    }
    builder
        .build()
        .map_err(|error| S3Error::Config(format!("HTTP 客户端构建失败: {error}")))
}

/// `401` / `403`：端点可达，但当前凭据无权执行该操作。
fn is_reachable_without_permission(status: StatusCode) -> bool {
    status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN
}

/// 从响应头构造对象元数据。
fn object_meta_from_headers(key: &ObjectKey, headers: &HeaderMap) -> ObjectMeta {
    let size = header_value(headers, "content-length")
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or_default();
    ObjectMeta {
        key: key.as_str().to_owned(),
        size,
        etag: header_value(headers, "etag"),
        last_modified: header_value(headers, "last-modified"),
        content_type: header_value(headers, "content-type"),
    }
}

/// 读取响应头取值（缺失或非 UTF-8 时返回 `None`，并去掉 ETag 的引号）。
fn header_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.trim_matches('"').to_owned())
        .filter(|value| !value.is_empty())
}

/// 把传输层错误映射为连接/超时错误（不回显 URL 与凭据）。
fn map_transport_error(error: &reqwest::Error) -> S3Error {
    if error.is_timeout() {
        return S3Error::Timeout("请求超时（远端未在时限内响应）".to_owned());
    }
    let stage = if error.is_connect() {
        "建立连接"
    } else if error.is_body() {
        "发送请求体"
    } else if error.is_decode() {
        "解析响应"
    } else if error.is_redirect() {
        "跟随重定向"
    } else if error.is_request() {
        "构造请求"
    } else {
        "传输"
    };
    S3Error::Connection(format!("{stage}失败（远端不可达或被拒绝）"))
}

/// 把 HTTP 状态码与 S3 错误体映射为错误。
///
/// `message` 只保留服务端 `<Message>` 并按 [`MAX_ERROR_MESSAGE_CHARS`] 截断，
/// 不含任何凭据。
fn map_http_error(status: StatusCode, body: &[u8]) -> S3Error {
    let text = String::from_utf8_lossy(body);
    let (code, message) = match xml::parse_error_code_message(&text) {
        Some((code, message)) => (
            Some(code),
            truncate_chars(&message, MAX_ERROR_MESSAGE_CHARS),
        ),
        None => (None, format!("S3 请求失败（HTTP {}）", status.as_u16())),
    };
    S3Error::Backend {
        status: status.as_u16(),
        code,
        message,
    }
}

/// 有界读取响应体前缀（最多 [`MAX_ERROR_BODY_BYTES`]）。
async fn read_body_prefix(response: reqwest::Response) -> Vec<u8> {
    let mut prefix = Vec::with_capacity(MAX_ERROR_BODY_BYTES);
    let mut stream = response.bytes_stream();
    while prefix.len() < MAX_ERROR_BODY_BYTES {
        match futures_util::StreamExt::next(&mut stream).await {
            Some(Ok(chunk)) => {
                let remaining = MAX_ERROR_BODY_BYTES - prefix.len();
                prefix.extend_from_slice(&chunk[..chunk.len().min(remaining)]);
                if chunk.len() >= remaining {
                    break;
                }
            }
            Some(Err(_)) | None => break,
        }
    }
    prefix
}

/// 截断字符串到指定字符数。
fn truncate_chars(value: &str, max_chars: usize) -> String {
    if value.chars().count() <= max_chars {
        return value.to_owned();
    }
    let mut truncated: String = value.chars().take(max_chars).collect();
    truncated.push('…');
    truncated
}

/// 序列化错误附带（已截断的）响应前缀：便于定位，又不会放大日志。
fn with_body_prefix(error: S3Error, body: &str) -> S3Error {
    S3Error::Serialization(format!(
        "{}；响应前缀: {}",
        error,
        truncate_chars(body, MAX_ERROR_MESSAGE_CHARS)
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(bucket: &str) -> S3Config {
        S3Config::builder()
            .bucket(bucket)
            .access_key_id("AKIAIOSFODNN7EXAMPLE")
            .access_key_secret("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
            .request_timeout(Duration::from_millis(300))
            .connect_timeout(Some(Duration::from_millis(300)))
            .max_retries(1)
            .build()
            .expect("测试配置有效")
    }

    fn build(request: &RequestSpec, config: &S3Config, body: Option<Bytes>) -> reqwest::Request {
        let client = S3Client::new(config.clone()).expect("构造成功");
        client
            .inner
            .build_request(request, body)
            .expect("构造请求成功")
            .build()
            .expect("Build 成功")
    }

    fn authorization(request: &reqwest::Request) -> String {
        request
            .headers()
            .get(reqwest::header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .expect("必须带 Authorization")
            .to_owned()
    }

    #[test]
    fn new_builds_client_without_network() {
        let client = S3Client::new(config("examplebucket")).expect("同步构造必须成功");
        assert_eq!(client.config().bucket, "examplebucket");
        assert_eq!(client.inner.retry.max_attempts, 1);
        let rendered = format!("{client:?}");
        assert!(rendered.contains("examplebucket"), "{rendered}");
        assert!(!rendered.contains("wJalrXUtnFEMI"), "{rendered}");
    }

    #[test]
    fn new_rejects_invalid_config() {
        let error = S3Client::new(S3Config::default()).expect_err("默认配置必须拒绝");
        assert!(matches!(error, S3Error::Config(_)));
    }

    #[test]
    fn request_is_signed_for_path_style() {
        let config = S3Config {
            endpoint: Some("https://minio.example.com:9000".to_owned()),
            force_path_style: true,
            ..config("examplebucket")
        };
        let key = ObjectKey::new("dir/a b.txt").expect("合法键");
        let spec = RequestSpec::new("PUT", &config, Some(key.as_str()))
            .with_headers(vec![("content-type".to_owned(), "text/plain".to_owned())])
            .with_payload_hash(sign::sha256_hex(b"hello"));
        let request = build(&spec, &config, Some(Bytes::from_static(b"hello")));

        assert_eq!(request.method(), reqwest::Method::PUT);
        assert_eq!(
            request.url().as_str(),
            "https://minio.example.com:9000/examplebucket/dir/a%20b.txt"
        );
        let authorization = authorization(&request);
        assert!(
            authorization.starts_with("AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/"),
            "{authorization}"
        );
        assert!(
            authorization
                .contains("SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date"),
            "{authorization}"
        );
        assert_eq!(
            request
                .headers()
                .get("x-amz-content-sha256")
                .and_then(|value| value.to_str().ok()),
            Some(sign::sha256_hex(b"hello").as_str())
        );
        assert!(request.headers().get("x-amz-security-token").is_none());
    }

    #[test]
    fn request_is_signed_for_virtual_hosted_style() {
        let config = config("examplebucket");
        let key = ObjectKey::new("dir/a b.txt").expect("合法键");
        let spec = RequestSpec::new("GET", &config, Some(key.as_str()));
        let request = build(&spec, &config, None);
        assert_eq!(
            request.url().as_str(),
            "https://examplebucket.s3.us-east-1.amazonaws.com/dir/a%20b.txt"
        );
        let authorization = authorization(&request);
        assert!(
            authorization.contains("SignedHeaders=host;x-amz-content-sha256;x-amz-date"),
            "{authorization}"
        );
        assert_eq!(
            request
                .headers()
                .get("x-amz-content-sha256")
                .and_then(|value| value.to_str().ok()),
            Some(sign::EMPTY_PAYLOAD_SHA256)
        );
    }

    #[test]
    fn session_token_is_sent_and_signed() {
        let config = S3Config {
            session_token: Some("token-value".to_owned()),
            ..config("examplebucket")
        };
        let spec = RequestSpec::new("GET", &config, None);
        let request = build(&spec, &config, None);
        assert_eq!(
            request
                .headers()
                .get("x-amz-security-token")
                .and_then(|value| value.to_str().ok()),
            Some("token-value")
        );
        assert!(
            authorization(&request).contains("x-amz-security-token"),
            "session token 必须参与签名"
        );
    }

    #[test]
    fn query_parameters_are_encoded_and_sorted_in_url() {
        let config = config("examplebucket");
        let spec = RequestSpec::new("GET", &config, None).with_query(vec![
            ("list-type".to_owned(), "2".to_owned()),
            ("encoding-type".to_owned(), "url".to_owned()),
            ("prefix".to_owned(), "a b/".to_owned()),
        ]);
        let request = build(&spec, &config, None);
        assert_eq!(
            request.url().query(),
            Some("encoding-type=url&list-type=2&prefix=a%20b%2F")
        );
    }

    #[test]
    fn map_http_error_extracts_code_and_truncates() {
        let error = map_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            b"<Error><Code>SlowDown</Code><Message>Please reduce your request rate.</Message></Error>",
        );
        match &error {
            S3Error::Backend {
                status,
                code,
                message,
            } => {
                assert_eq!(*status, 503);
                assert_eq!(code.as_deref(), Some("SlowDown"));
                assert!(message.starts_with("Please reduce"), "{message}");
            }
            other => panic!("意外的错误类型: {other:?}"),
        }
        assert!(error.is_retryable());

        let permanent = map_http_error(
            StatusCode::FORBIDDEN,
            b"<Error><Code>SignatureDoesNotMatch</Code><Message>nope</Message></Error>",
        );
        assert!(!permanent.is_retryable());

        let plain = map_http_error(StatusCode::NOT_FOUND, b"not xml");
        assert!(matches!(
            plain,
            S3Error::Backend {
                status: 404,
                code: None,
                ..
            }
        ));

        let long = format!(
            "<Error><Code>X</Code><Message>{}</Message></Error>",
            "m".repeat(MAX_ERROR_MESSAGE_CHARS * 2)
        );
        match map_http_error(StatusCode::BAD_REQUEST, long.as_bytes()) {
            S3Error::Backend { message, .. } => {
                assert!(message.chars().count() <= MAX_ERROR_MESSAGE_CHARS + 1);
            }
            other => panic!("意外的错误类型: {other:?}"),
        }
    }

    #[test]
    fn object_meta_from_headers_reads_expected_fields() {
        let mut headers = HeaderMap::new();
        headers.insert("content-length", HeaderValue::from_static("42"));
        headers.insert("etag", HeaderValue::from_static("\"abc\""));
        headers.insert("content-type", HeaderValue::from_static("text/plain"));
        headers.insert(
            "last-modified",
            HeaderValue::from_static("Wed, 21 Oct 2015 07:28:00 GMT"),
        );
        let key = ObjectKey::new("k").expect("合法键");
        let meta = object_meta_from_headers(&key, &headers);
        assert_eq!(meta.key, "k");
        assert_eq!(meta.size, 42);
        assert_eq!(meta.etag.as_deref(), Some("abc"), "ETag 引号必须被去掉");
        assert_eq!(meta.content_type.as_deref(), Some("text/plain"));
        assert_eq!(
            meta.last_modified.as_deref(),
            Some("Wed, 21 Oct 2015 07:28:00 GMT")
        );

        assert!(object_meta_from_headers(&key, &HeaderMap::new())
            .etag
            .is_none());
    }

    #[test]
    fn truncate_chars_is_bounded() {
        assert_eq!(truncate_chars("abc", 10), "abc");
        assert_eq!(truncate_chars("abcdef", 3), "abc…");
        assert_eq!(truncate_chars("", 0), "");
    }

    #[tokio::test]
    async fn ping_on_unreachable_endpoint_returns_err() {
        let client = S3Client::new(S3Config {
            endpoint: Some("http://127.0.0.1:1".to_owned()),
            force_path_style: true,
            ..config("examplebucket")
        })
        .expect("构造成功");

        let error = client.ping().await.expect_err("127.0.0.1:1 必须失败");
        assert!(
            matches!(error, S3Error::Connection(_) | S3Error::Timeout(_)),
            "{error:?}"
        );
        assert!(error.is_retryable());

        let health = client.health_check().await.expect("健康检查不返回 Err");
        assert!(!health.healthy);
        assert_eq!(health.bucket, "examplebucket");
        assert_eq!(health.endpoint, "http://127.0.0.1:1");
    }

    #[tokio::test]
    async fn data_plane_on_unreachable_endpoint_returns_err() {
        let client = S3Client::new(S3Config {
            endpoint: Some("http://127.0.0.1:1".to_owned()),
            force_path_style: true,
            ..config("examplebucket")
        })
        .expect("构造成功");
        let key = ObjectKey::new("k").expect("合法键");

        assert!(client
            .put_object(&key, Bytes::from_static(b"x"), &UploadOptions::default())
            .await
            .is_err());
        assert!(client
            .get_object(&key, &DownloadOptions::default())
            .await
            .is_err());
        assert!(client.get_object_bytes(&key).await.is_err());
        assert!(client.delete_object(&key).await.is_err());
        assert!(client.head_object(&key).await.is_err());
        assert!(client.list_objects_v2(None, None, None).await.is_err());
    }

    #[tokio::test]
    async fn list_objects_rejects_zero_max_keys_before_network() {
        let client = S3Client::new(config("examplebucket")).expect("构造成功");
        let error = client
            .list_objects_v2(None, None, Some(0))
            .await
            .expect_err("max_keys=0 必须拒绝");
        assert!(matches!(error, S3Error::Config(_)));
    }

    #[tokio::test]
    async fn get_object_rejects_inverted_range_before_network() {
        let client = S3Client::new(config("examplebucket")).expect("构造成功");
        let key = ObjectKey::new("k").expect("合法键");
        // `(ObjectMeta, ByteStream)` 不实现 Debug，故用 matches! 判定。
        let result = client
            .get_object(&key, &DownloadOptions::with_range(9, 0))
            .await;
        assert!(
            matches!(result, Err(S3Error::Config(_))),
            "反向范围必须拒绝"
        );
    }
}
