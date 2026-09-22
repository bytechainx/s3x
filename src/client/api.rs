//! `S3Client` 的数据面实现。
//!
//! 自 `src/client.rs` 下沉而来：`impl S3Client`。类型定义（`S3Client` / `Inner` /
//! `RequestSpec`）与 HTTP 层辅助（错误映射、响应流包装等）仍留在门面 `src/client.rs`；
//! 本模块是它的子模块，故可直接使用那些私有项。

use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;
use reqwest::Method;
use tokio::sync::Semaphore;
use tracing::debug;

use crate::config::S3Config;
use crate::error::{S3Error, S3Result};
use crate::retry::{self, RetryConfig};
use crate::sign::{self, UNSIGNED_PAYLOAD};
use crate::types::{ByteStream, DownloadOptions, ObjectKey, ObjectMeta, UploadOptions};
use crate::xml::{self, ListObjectsResult};

use super::{
    build_http_client, guarded_body_stream, header_value, is_reachable_without_permission,
    map_http_error, map_transport_error, object_meta_from_headers, read_body_prefix,
    with_body_prefix, Inner, RequestSpec, S3Client, S3Health, MAX_LIST_KEYS,
};

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
        let spec = RequestSpec::new(Method::HEAD, &self.inner.config, None);
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
        let spec = RequestSpec::new(Method::PUT, &self.inner.config, Some(key.as_str()))
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
    /// 载荷哈希固定为 [`UNSIGNED_PAYLOAD`]，即**签名不覆盖请求体**。HTTPS 下传输层
    /// 仍保证完整性，但明文 HTTP 下两个环节会同时失守（请求体可被篡改而签名依然
    /// 有效），因此本方法在 endpoint 为 `http` 时默认返回 [`S3Error::Config`]；
    /// 确认可接受该降级（例如本地 MinIO 调试）时，用
    /// [`S3Config::allow_unsigned_payload_over_http`](crate::S3Config::allow_unsigned_payload_over_http)
    /// 或环境变量 `FOUNDATIONX_S3X_ALLOW_UNSIGNED_PAYLOAD_OVER_HTTP` 显式放行。
    ///
    /// 请求体无法回放，**不做重试**。`content_length` 为 `Some` 时显式设置
    /// `Content-Length`（否则使用分块传输编码）。
    pub async fn put_object_stream(
        &self,
        key: &ObjectKey,
        stream: ByteStream,
        options: &UploadOptions,
        content_length: Option<u64>,
    ) -> S3Result<ObjectMeta> {
        self.reject_unsigned_payload_over_http()?;
        let spec = RequestSpec::new(Method::PUT, &self.inner.config, Some(key.as_str()))
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
        let spec = RequestSpec::new(Method::GET, &self.inner.config, Some(key.as_str()))
            .with_headers(headers);
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
        let spec = RequestSpec::new(Method::GET, &self.inner.config, Some(key.as_str()));
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

    /// 拒绝「明文 HTTP + 未签名载荷」这一组合。
    ///
    /// `UNSIGNED-PAYLOAD` 不覆盖请求体，明文传输也不提供完整性，二者叠加时请求体
    /// 在链路上可被篡改而签名依然有效。默认拒绝，可用配置或环境变量显式放行。
    fn reject_unsigned_payload_over_http(&self) -> S3Result<()> {
        let config = &self.inner.config;
        if config.endpoint_is_plain_http() && !config.allow_unsigned_payload_over_http {
            return Err(S3Error::Config(
                "明文 HTTP endpoint 不允许使用 UNSIGNED-PAYLOAD：签名不覆盖请求体，\
                 传输层亦无完整性保护，请求体可被篡改。请改用 HTTPS，或设置 \
                 allow_unsigned_payload_over_http / \
                 FOUNDATIONX_S3X_ALLOW_UNSIGNED_PAYLOAD_OVER_HTTP 显式接受该降级"
                    .to_owned(),
            ));
        }
        Ok(())
    }

    /// 删除单个对象（幂等，可安全重试）。
    pub async fn delete_object(&self, key: &ObjectKey) -> S3Result<()> {
        let spec = RequestSpec::new(Method::DELETE, &self.inner.config, Some(key.as_str()));
        retry::with_retry(&self.inner.retry, "delete_object", || {
            let spec = &spec;
            async move { self.inner.send_checked(spec, None).await }
        })
        .await?;
        Ok(())
    }

    /// 读取对象元数据（`HEAD`，不下载内容）。
    pub async fn head_object(&self, key: &ObjectKey) -> S3Result<ObjectMeta> {
        let spec = RequestSpec::new(Method::HEAD, &self.inner.config, Some(key.as_str()));
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
        let spec = RequestSpec::new(Method::GET, &self.inner.config, None).with_query(query);
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
