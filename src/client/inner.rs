//! `Inner`：共享状态的请求构造与发送。
//!
//! 自 `src/client.rs` 下沉而来：`impl Inner`。`Inner` 的定义仍在门面 `src/client.rs`
//! （其私有字段对子模块可见）；四个方法由门面的 `impl S3Client` 调用，故提为 `pub(super)`。

use std::time::Duration;

use bytes::Bytes;
use reqwest::header::{HeaderName, HeaderValue};
use tokio::sync::OwnedSemaphorePermit;

use crate::error::{S3Error, S3Result};
use crate::sign::{self, SignRequest};

use super::{map_http_error, map_transport_error, read_body_prefix, Inner, RequestSpec};

impl Inner {
    /// 获取一次并发许可（背压入口）；超时或信号量关闭都会失败。
    pub(super) async fn acquire(&self) -> S3Result<OwnedSemaphorePermit> {
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
    pub(super) fn build_request(
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
    pub(super) async fn send(
        &self,
        spec: &RequestSpec,
        body: Option<Bytes>,
    ) -> S3Result<reqwest::Response> {
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
    pub(super) async fn send_checked(
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
    pub(super) async fn send_checked_holding_permit(
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
