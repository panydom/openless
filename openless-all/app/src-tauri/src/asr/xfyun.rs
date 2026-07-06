//! iFlytek (讯飞) Real-time ASR (实时语音转写标准版) client.
//!
//! Uses the DashScope-style WebSocket protocol with HMAC-SHA1 signature
//! authentication. Audio is sent as raw 16 kHz / 16-bit / mono PCM frames;
//! the server returns JSON text messages with interim and final results.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine;
use futures_util::{SinkExt, StreamExt};
use hmac::{Hmac, Mac};
use parking_lot::Mutex as ParkingMutex;
use serde_json::{json, Value};
use sha1::Sha1;
use tokio::net::TcpStream;
use tokio::runtime::Handle;
use tokio::sync::{mpsc, oneshot, Mutex as AsyncMutex, Notify};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};

use super::{AudioConsumer, RawTranscript};

pub const PROVIDER_ID: &str = "xfyun-rtasr";
pub const DEFAULT_ENDPOINT: &str = "wss://rtasr.xfyun.cn/v1/ws";
pub const DEFAULT_LANG: &str = "cn";
/// 40 ms of 16 kHz / 16-bit / mono PCM = 1280 bytes (iFlytek recommended chunk).
pub const TARGET_AUDIO_CHUNK_BYTES: usize = 1_280;
const BYTES_PER_MS: u64 = 32;
/// end marker 发送后若 2s 无新消息到达，则认为服务端已静默并触发 partial 兜底。
const SILENCE_TIMEOUT: Duration = Duration::from_secs(2);

type WsStream = WebSocketStream<MaybeTlsStream<TcpStream>>;
type WsSink = futures_util::stream::SplitSink<WsStream, Message>;
type SharedWriter = Arc<AsyncMutex<Option<WsSink>>>;

#[derive(Clone, Debug)]
pub struct XfyunCredentials {
    /// 讯飞开放平台 App ID.
    pub app_id: String,
    /// 讯飞开放平台 API Key (接口密钥).
    pub api_key: String,
    /// WebSocket 接口地址.
    pub endpoint: String,
}

#[derive(Debug, thiserror::Error)]
pub enum XfyunASRError {
    #[error("credentials missing")]
    CredentialsMissing,
    #[error("connection failed: {0}")]
    ConnectionFailed(String),
    #[error("signa generation failed: {0}")]
    SignaFailed(String),
    #[error("server error {code}: {desc}")]
    ServerError { code: String, desc: String },
    #[error("no final result")]
    NoFinalResult,
    #[error("final result timed out")]
    FinalResultTimeout,
}

enum SendItem {
    Audio(Vec<u8>),
    Finish(oneshot::Sender<Result<(), XfyunASRError>>),
}

#[derive(Default)]
struct SyncState {
    task_started: bool,
    task_finished: bool,
    pending_audio: Vec<u8>,
    audio_scratch: Vec<u8>,
    bytes_received: u64,
    runtime: Option<Handle>,
    start: Option<Instant>,
    final_tx: Option<oneshot::Sender<Result<RawTranscript, XfyunASRError>>>,
    send_tx: Option<mpsc::UnboundedSender<SendItem>>,
    /// seg_id → text, sorted by seg_id for final assembly.
    final_segments: BTreeMap<i64, String>,
    /// seg_id → interim text for the current segment.
    partial_segments: BTreeMap<i64, String>,
    last_result_text: String,
}

pub struct XfyunStreamingASR {
    credentials: XfyunCredentials,
    state: ParkingMutex<SyncState>,
    writer: SharedWriter,
    final_rx: ParkingMutex<Option<oneshot::Receiver<Result<RawTranscript, XfyunASRError>>>>,
    task_started: Arc<Notify>,
    /// 每当 record_result 存入了新的 interim/final 结果时通知，用于
    /// await_final_result 做静默超时检测（end 后 2s 无新消息 → 用 partial 兜底）。
    result_notify: Arc<Notify>,
}

impl XfyunStreamingASR {
    pub fn new(credentials: XfyunCredentials) -> Self {
        log::info!(
            "[xfyun-asr] new instance: endpoint={}, app_id={}",
            credentials.endpoint,
            &credentials.app_id[..credentials.app_id.len().min(4)],
        );
        Self {
            credentials,
            state: ParkingMutex::new(SyncState::default()),
            writer: Arc::new(AsyncMutex::new(None)),
            final_rx: ParkingMutex::new(None),
            task_started: Arc::new(Notify::new()),
            result_notify: Arc::new(Notify::new()),
        }
    }

    pub async fn open_session(self: &Arc<Self>) -> Result<(), XfyunASRError> {
        log::info!("[xfyun-asr] open_session: starting");

        if self.credentials.app_id.trim().is_empty()
            || self.credentials.api_key.trim().is_empty()
        {
            log::error!("[xfyun-asr] open_session: credentials missing");
            return Err(XfyunASRError::CredentialsMissing);
        }

        let url = build_session_url(&self.credentials)
            .map_err(|e| XfyunASRError::SignaFailed(e.to_string()))?;

        let endpoint_display = &self.credentials.endpoint.trim();
        let endpoint_display = if endpoint_display.is_empty() {
            DEFAULT_ENDPOINT
        } else {
            endpoint_display
        };
        log::info!(
            "[xfyun-asr] open_session: connecting to {} (app_id prefix: {})",
            endpoint_display,
            &self.credentials.app_id[..self.credentials.app_id.len().min(4)],
        );

        let request = url
            .into_client_request()
            .map_err(|e| XfyunASRError::ConnectionFailed(e.to_string()))?;

        let (ws, _resp) = connect_async(request)
            .await
            .map_err(|e| XfyunASRError::ConnectionFailed(e.to_string()))?;
        log::info!("[xfyun-asr] open_session: WebSocket connected");
        let (write, read) = ws.split();
        *self.writer.lock().await = Some(write);

        let (final_tx, final_rx) = oneshot::channel();
        let (send_tx, mut send_rx) = mpsc::unbounded_channel::<SendItem>();
        {
            let mut st = self.state.lock();
            *st = SyncState::default();
            st.runtime = Some(Handle::current());
            st.start = Some(Instant::now());
            st.final_tx = Some(final_tx);
            st.send_tx = Some(send_tx);
        }
        *self.final_rx.lock() = Some(final_rx);

        // Audio send worker — serializes writes to the WebSocket.
        let writer_for_worker = Arc::clone(&self.writer);
        let worker_sent_bytes = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let worker_sent_bytes_clone = Arc::clone(&worker_sent_bytes);
        tokio::spawn(async move {
            while let Some(item) = send_rx.recv().await {
                match item {
                    SendItem::Audio(chunk) => {
                        let size = chunk.len();
                        if let Err(e) = send_binary(&writer_for_worker, chunk).await {
                            log::error!("[xfyun-asr] audio frame send failed (size={size}): {e}");
                        } else {
                            worker_sent_bytes_clone.fetch_add(size as u64, std::sync::atomic::Ordering::Relaxed);
                        }
                    }
                    SendItem::Finish(done) => {
                        log::info!("[xfyun-asr] audio send worker: sending end marker");
                        // Send the end marker: {"end": true} as binary.
                        let end_msg = serde_json::to_vec(&json!({"end": true}))
                            .unwrap_or_default();
                        let result = send_binary(&writer_for_worker, end_msg)
                            .await
                            .map_err(|e| XfyunASRError::ConnectionFailed(e.to_string()));
                        let _ = done.send(result);
                    }
                }
            }
            let total = worker_sent_bytes_clone.load(std::sync::atomic::Ordering::Relaxed);
            log::info!("[xfyun-asr] audio send worker: channel closed, sent {total} bytes total");
        });

        // Receive loop — parses JSON text messages from the server.
        let weak_self = Arc::downgrade(self);
        tokio::spawn(async move {
            let mut msg_count: u64 = 0;
            let mut read = read;
            while let Some(msg) = read.next().await {
                let Some(this) = weak_self.upgrade() else {
                    log::debug!("[xfyun-asr] receive loop: self dropped, exiting");
                    break;
                };
                match msg {
                    Ok(Message::Text(text)) => {
                        msg_count += 1;
                        log::info!(
                            "[xfyun-asr] receive loop: => msg #{msg_count}, text_len={}, action=\"{}\"",
                            text.len(),
                            serde_json::from_str::<Value>(&text)
                                .ok()
                                .and_then(|v| v.get("action").and_then(Value::as_str).map(|s| s.to_string()))
                                .unwrap_or_else(|| "?parse_failed?".to_string()),
                        );
                        let keep_going = this.handle_text_message(&text);
                        log::info!(
                            "[xfyun-asr] receive loop: <= msg #{msg_count} handled, keep_going={keep_going}"
                        );
                        if !keep_going {
                            break;
                        }
                    }
                    Ok(Message::Close(frame)) => {
                        log::info!(
                            "[xfyun-asr] receive loop: server closed connection (frame: {frame:?})"
                        );
                        this.finish_with_partial_or_error(XfyunASRError::NoFinalResult);
                        break;
                    }
                    Ok(Message::Ping(_) | Message::Pong(_)) => {
                        log::debug!("[xfyun-asr] receive loop: ping/pong");
                    }
                    Ok(Message::Binary(data)) => {
                        log::warn!(
                            "[xfyun-asr] receive loop: unexpected binary message (len={})",
                            data.len()
                        );
                    }
                    Ok(_) => {}
                    Err(e) => {
                        log::error!("[xfyun-asr] receive loop: error #{msg_count}: {e}");
                        this.finish_with_partial_or_error(XfyunASRError::ConnectionFailed(
                            e.to_string(),
                        ));
                        break;
                    }
                }
            }
            log::info!("[xfyun-asr] receive loop: exiting after {msg_count} messages");
        });

        log::info!("[xfyun-asr] open_session: workers spawned, session ready");
        Ok(())
    }

    pub async fn send_last_frame(&self) -> Result<(), XfyunASRError> {
        log::info!("[xfyun-asr] send_last_frame: entering");

        // 关键：等待服务端握手确认（started 消息），否则音频和结束标记可能
        // 在 session 确认前到达，导致服务端无结果返回，await_final_result 超时。
        // 与 Bailian 实现的等待模式一致。
        let started = self.task_started.notified();
        tokio::pin!(started);
        started.as_mut().enable();
        let ready = {
            let st = self.state.lock();
            st.task_started || st.task_finished
        };
        if !ready {
            log::info!("[xfyun-asr] send_last_frame: waiting for handshake (task_started)...");
            tokio::time::timeout(Duration::from_secs(5), started)
                .await
                .map_err(|_| {
                    log::warn!("[xfyun-asr] send_last_frame: waiting for task_started timed out");
                    XfyunASRError::FinalResultTimeout
                })?;
            log::info!("[xfyun-asr] send_last_frame: handshake received, proceeding");
        } else {
            log::info!("[xfyun-asr] send_last_frame: handshake already ready");
        }

        let (send_tx, tail_chunks, last_chunk) = {
            let mut st = self.state.lock();
            let send_tx = st.send_tx.clone();
            if !st.pending_audio.is_empty() {
                let pending_size = st.pending_audio.len();
                let pending = std::mem::take(&mut st.pending_audio);
                log::info!("[xfyun-asr] send_last_frame: merging {pending_size} bytes from pending_audio into scratch");
                st.audio_scratch.extend_from_slice(&pending);
            }
            log::info!(
                "[xfyun-asr] send_last_frame: audio_scratch has {} bytes before drain",
                st.audio_scratch.len()
            );
            // 使用 drain_audio_chunks 确保尾部音频按 1280 bytes 分片发送，
            // 与讯飞官方建议的 40ms/1280 字节分片对齐。
            let chunks = drain_audio_chunks(&mut st.audio_scratch);
            // 关键修复：flush audio_scratch 中不足 1280 bytes 的残片，
            // 否则这些尾部音频字节从未被发送给服务器。
            let leftover = std::mem::take(&mut st.audio_scratch);
            let last = if leftover.is_empty() {
                None
            } else {
                Some(leftover)
            };
            (send_tx, chunks, last)
        };
        let Some(send_tx) = send_tx else {
            log::warn!("[xfyun-asr] send_last_frame: send_tx already taken (canceled?)");
            return Ok(());
        };
        let tail_chunk_count = tail_chunks.len();
        let tail_byte_count = last_chunk.as_ref().map_or(0, |v| v.len());
        for chunk in tail_chunks {
            let _ = send_tx.send(SendItem::Audio(chunk));
        }
        if let Some(tail) = last_chunk {
            let _ = send_tx.send(SendItem::Audio(tail));
        }
        log::info!(
            "[xfyun-asr] send_last_frame: flushed {tail_chunk_count} chunk(s) + {tail_byte_count} byte(s) tail; now sending end marker",
        );
        let (done_tx, done_rx) = oneshot::channel();
        send_tx
            .send(SendItem::Finish(done_tx))
            .map_err(|_| XfyunASRError::ConnectionFailed("send worker closed".to_string()))?;
        done_rx
            .await
            .map_err(|_| XfyunASRError::ConnectionFailed("finish ack dropped".to_string()))?;

        log::info!("[xfyun-asr] send_last_frame: end marker sent and acked");
        Ok(())
    }

    /// 从已积累的 partial/final segments 中组装最佳可用转写文本。
    /// 用于超时回退：服务端只返回了 interim 结果但没有 final 结果时使用。
    ///
    /// 合并 final + partial segments，final 优先覆盖同 seg_id 的 partial。
    /// 这是修复遗漏字的关键：不能只取 final_segments 而丢弃 partial_segments，
    /// 否则尚未 finalize 的 seg_id 的文本会全部丢失。
    fn build_partial_result(&self) -> Option<RawTranscript> {
        let mut st = self.state.lock();
        st.task_finished = true;
        let text = {
            // 合并 final + partial，final 优先覆盖同 seg_id 的 partial。
            let mut all: BTreeMap<i64, String> = BTreeMap::new();
            for (k, v) in &st.partial_segments {
                all.insert(*k, v.clone());
            }
            for (k, v) in &st.final_segments {
                all.insert(*k, v.clone());
            }
            if !all.is_empty() {
                let segments: Vec<String> = all.values().cloned().collect();
                merge_segments(&segments)
            } else if !st.last_result_text.trim().is_empty() {
                st.last_result_text.clone()
            } else {
                return None;
            }
        };
        let duration_ms = if st.bytes_received > 0 {
            st.bytes_received / BYTES_PER_MS
        } else {
            st.start
                .map(|start| start.elapsed().as_millis() as u64)
                .unwrap_or_default()
        };
        Some(RawTranscript { text, duration_ms })
    }

    pub async fn await_final_result(&self) -> Result<RawTranscript, XfyunASRError> {
        log::info!("[xfyun-asr] await_final_result: entering (silence_timeout={}s)", SILENCE_TIMEOUT.as_secs());
        let rx = self.final_rx.lock().take();
        let Some(mut rx) = rx else {
            log::warn!("[xfyun-asr] await_final_result: no receiver (already taken or canceled)");
            return Err(XfyunASRError::NoFinalResult);
        };

        // 静默超时检测循环：end 后 2s 无新消息 → 用 partial 兜底。
        // 逻辑：
        //   1. 等待 oneshot 通道（服务端主动返回 final 结果）或
        //      2s 静默超时或新的 interim 通知。
        //   2. 收到新通知 → 重置 2s 定时器继续等待。
        //   3. 2s 无新消息 → build_partial_result() 兜底返回。
        //   4. oneshot 通道收到 final 结果 → 立即返回。
        loop {
            let notified = self.result_notify.notified();
            tokio::pin!(notified);

            tokio::select! {
                result = &mut rx => {
                    match result {
                        Ok(r) => {
                            log::info!("[xfyun-asr] await_final_result: received final result");
                            return r;
                        }
                        Err(_) => {
                            log::warn!("[xfyun-asr] await_final_result: sender dropped without result");
                            return Err(XfyunASRError::NoFinalResult);
                        }
                    }
                }
                _ = tokio::time::sleep(SILENCE_TIMEOUT) => {
                    log::info!("[xfyun-asr] await_final_result: {}s silence — trying partial", SILENCE_TIMEOUT.as_secs());
                    // 服务端可能不返回 final 结果（尤其是短音频场景）。
                    // 用已积累的 interim/final segments 组装最佳可用文本。
                    if let Some(partial) = self.build_partial_result() {
                        log::info!(
                            "[xfyun-asr] await_final_result: partial fallback, text_len={}",
                            partial.text.len()
                        );
                        // 关闭 WebSocket，防止连接泄漏。协调层成功路径不会调 cancel()。
                        self.close_on_runtime();
                        return Ok(partial);
                    }
                    log::warn!("[xfyun-asr] await_final_result: no partial result available either");
                    return Err(XfyunASRError::FinalResultTimeout);
                }
                _ = &mut notified => {
                    // 新的 result 消息到达 — 重置静默定时器继续等待。
                    log::debug!("[xfyun-asr] await_final_result: new result arrived, resetting silence timer");
                    continue;
                }
            }
        }
    }

    pub fn cancel(&self) {
        log::info!("[xfyun-asr] cancel: called");
        {
            let mut st = self.state.lock();
            let pending_size = st.pending_audio.len();
            let scratch_size = st.audio_scratch.len();
            st.pending_audio.clear();
            st.audio_scratch.clear();
            st.send_tx.take();
            st.final_tx.take();
            st.task_finished = true;
            log::info!(
                "[xfyun-asr] cancel: cleared buffers (pending={pending_size}, scratch={scratch_size})"
            );
        }
        // 唤醒可能正在等待 task_started 的 send_last_frame，
        // 避免 cancel 后 send_last_frame 还要等满 5 秒超时。
        self.task_started.notify_waiters();

        // 关键修复：不用 try_lock（静默失败 → 连接泄漏），而是 spawn 一个
        // async 任务通过 lock().await 等待 writer 锁释放后取走并关闭。
        // 与 Bailian 实现一致，确保 WebSocket 始终被关闭。
        let writer = Arc::clone(&self.writer);
        if let Ok(handle) = Handle::try_current() {
            handle.spawn(async move {
                log::info!("[xfyun-asr] cancel: closing websocket (tokio runtime)");
                let _ = close_writer(&writer).await;
            });
        } else {
            std::thread::spawn(move || {
                log::info!("[xfyun-asr] cancel: closing websocket (new thread runtime)");
                if let Ok(rt) = tokio::runtime::Runtime::new() {
                    rt.block_on(async move {
                        let _ = close_writer(&writer).await;
                    });
                }
            });
        }
    }

    fn handle_text_message(&self, text: &str) -> bool {
        let text_preview: String = text.chars().take(300).collect();
        log::info!(
            "[xfyun-asr] handle_text_message: => ENTER, raw_preview=\"{}\"",
            text_preview,
        );

        let value: Value = match serde_json::from_str(text) {
            Ok(v) => v,
            Err(e) => {
                log::warn!("[xfyun-asr] handle_text_message: invalid json event: {e}, raw_preview=\"{}\"", &text[..text.len().min(200)]);
                return true;
            }
        };

        let action = value
            .get("action")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let code = value
            .get("code")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let sid = value
            .get("sid")
            .and_then(Value::as_str)
            .unwrap_or("");

        log::info!(
            "[xfyun-asr] handle_text_message: parsed action=\"{action}\", code={code}, sid={sid}"
        );

        let result = match action {
            "started" => {
                log::info!("[xfyun-asr] handle_text_message: => started branch: handshake success sid={sid}");
                // Handshake success — mark task started and flush pending audio.
                self.mark_task_started();
                true
            }
            "result" => {
                if code != "0" {
                    log::warn!("[xfyun-asr] handle_text_message: => result branch: non-zero code={code}, sid={sid}");
                    return true;
                }
                log::info!(
                    "[xfyun-asr] handle_text_message: => result branch: sid={sid}, payload_len={}",
                    value.get("data").and_then(Value::as_str).map_or(0, |s| s.len()),
                );
                self.record_result(&value);
                true
            }
            "error" => {
                let desc = value
                    .get("desc")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown error")
                    .to_string();
                log::error!("[xfyun-asr] handle_text_message: => error branch: code={code} desc={desc} sid={sid}");
                self.finish_error(XfyunASRError::ServerError {
                    code: code.to_string(),
                    desc,
                });
                false
            }
            action => {
                log::warn!("[xfyun-asr] handle_text_message: => unknown branch: action=\"{action}\", sid={sid}");
                true
            }
        };

        log::info!(
            "[xfyun-asr] handle_text_message: <= EXIT, action=\"{action}\", result={result}"
        );
        result
    }

    fn mark_task_started(&self) {
        let (send_tx, chunks) = {
            let mut st = self.state.lock();
            st.task_started = true;
            if !st.pending_audio.is_empty() {
                let pending_size = st.pending_audio.len();
                let pending = std::mem::take(&mut st.pending_audio);
                log::info!("[xfyun-asr] mark_task_started: flushing {pending_size} bytes of pending audio");
                st.audio_scratch.extend_from_slice(&pending);
            }
            let send_tx = st.send_tx.clone();
            let chunks = drain_audio_chunks(&mut st.audio_scratch);
            (send_tx, chunks)
        };
        let chunk_count = chunks.len();
        let total_bytes: usize = chunks.iter().map(|c| c.len()).sum();
        if let Some(tx) = send_tx {
            for chunk in chunks {
                let _ = tx.send(SendItem::Audio(chunk));
            }
        }
        log::info!("[xfyun-asr] mark_task_started: flushed {chunk_count} chunk(s), {total_bytes} bytes to send worker");
        self.task_started.notify_waiters();
    }

    fn record_result(&self, value: &Value) {
        let data_str = match value.get("data").and_then(Value::as_str) {
            Some(s) => s,
            None => {
                log::warn!("[xfyun-asr] record_result: result without data field");
                return;
            }
        };
        let data: Value = match serde_json::from_str(data_str) {
            Ok(v) => v,
            Err(e) => {
                log::warn!("[xfyun-asr] record_result: failed to parse data json: {e}");
                return;
            }
        };

        // Extract seg_id and result type.
        let seg_id = data
            .get("seg_id")
            .and_then(Value::as_i64)
            .unwrap_or(0);

        let result_type = data
            .pointer("/cn/st/type")
            .and_then(Value::as_str)
            .unwrap_or("1");
        let is_final = result_type == "0";

        // Extract text from cn.st.rt[].cw[].w
        let text = extract_words(&data);
        if text.is_empty() {
            log::debug!("[xfyun-asr] record_result: seg_id={seg_id}, type={result_type}, text is empty (skipped)");
            return;
        }

        let text_preview: String = text.chars().take(60).collect();
        if is_final {
            log::info!(
                "[xfyun-asr] record_result: seg_id={seg_id}, final, text_len={}, preview=\"{}\"",
                text.len(),
                text_preview,
            );
        } else {
            log::debug!(
                "[xfyun-asr] record_result: seg_id={seg_id}, interim, text_len={}, preview=\"{}\"",
                text.len(),
                text_preview,
            );
        }

        let mut st = self.state.lock();
        st.last_result_text = text.clone();

        if is_final {
            st.final_segments.insert(seg_id, text);
            st.partial_segments.remove(&seg_id);
        } else {
            st.partial_segments.insert(seg_id, text);
        }

        // 通知 await_final_result 的静默检测循环：有新结果到达，重置 2s 定时器。
        self.result_notify.notify_one();
    }

    fn finish_success(&self) {
        let (tx, text, duration_ms, seg_count, last_result_text) = {
            let mut st = self.state.lock();
            if st.task_finished {
                log::debug!("[xfyun-asr] finish_success: already finished, returning");
                return;
            }
            st.task_finished = true;
            st.send_tx.take();
            let last_result = st.last_result_text.clone();
            // 合并 final + partial segments，final 优先覆盖同 seg_id 的 partial。
            let mut all: BTreeMap<i64, String> = BTreeMap::new();
            for (k, v) in &st.final_segments {
                all.insert(*k, v.clone());
            }
            for (k, v) in &st.partial_segments {
                // final 已覆盖同 seg_id 的 segment，不覆盖它。
                all.entry(*k).or_insert_with(|| v.clone());
            }
            let seg_count = all.len();
            let text = if !all.is_empty() {
                let segments: Vec<String> = all.values().cloned().collect();
                merge_segments(&segments)
            } else if !st.last_result_text.trim().is_empty() {
                st.last_result_text.clone()
            } else {
                String::new()
            };
            let duration_ms = if st.bytes_received > 0 {
                st.bytes_received / BYTES_PER_MS
            } else {
                st.start
                    .map(|start| start.elapsed().as_millis() as u64)
                    .unwrap_or_default()
            };
            (st.final_tx.take(), text, duration_ms, seg_count, last_result)
        };
        let text_preview: String = text.chars().take(80).collect();
        log::info!(
            "[xfyun-asr] finish_success: final_segments={seg_count}, last_result_text=\"{}\", merged_text_len={}, merged_preview=\"{}\", duration_ms={duration_ms}",
            &last_result_text[..last_result_text.len().min(40)],
            text.len(),
            text_preview,
        );
        if let Some(tx) = tx {
            let _ = tx.send(Ok(RawTranscript { text, duration_ms }));
        }
        self.close_on_runtime();
    }

    fn finish_with_partial_or_error(&self, error: XfyunASRError) {
        let has_partial = {
            let st = self.state.lock();
            !st.last_result_text.trim().is_empty()
                || !st.final_segments.is_empty()
                || !st.partial_segments.is_empty()
        };
        if has_partial {
            self.finish_success();
        } else {
            self.finish_error(error);
        }
    }

    fn finish_error(&self, error: XfyunASRError) {
        log::info!("[xfyun-asr] finish_error: {error}");
        let tx = {
            let mut st = self.state.lock();
            if st.task_finished {
                log::debug!("[xfyun-asr] finish_error: already finished, returning");
                return;
            }
            st.task_finished = true;
            st.send_tx.take();
            st.final_tx.take()
        };
        if let Some(tx) = tx {
            log::debug!("[xfyun-asr] finish_error: sending error result via oneshot");
            let _ = tx.send(Err(error));
        }
        self.close_on_runtime();
    }

    fn close_on_runtime(&self) {
        log::info!("[xfyun-asr] close_on_runtime: closing WebSocket writer");
        let writer = Arc::clone(&self.writer);
        if let Some(handle) = self.state.lock().runtime.clone() {
            handle.spawn(async move {
                let _ = close_writer(&writer).await;
            });
        } else {
            log::warn!("[xfyun-asr] close_on_runtime: no runtime handle, writer may leak");
        }
    }
}

impl AudioConsumer for XfyunStreamingASR {
    fn consume_pcm_chunk(&self, pcm: &[u8]) {
        if pcm.is_empty() {
            return;
        }
        let chunk_size = pcm.len();
        let (send_tx, chunks, buffered) = {
            let mut st = self.state.lock();
            let accum = st.bytes_received.saturating_add(chunk_size as u64);
            st.bytes_received = accum;
            if !st.task_started {
                st.pending_audio.extend_from_slice(pcm);
                log::debug!(
                    "[xfyun-asr] consume_pcm_chunk: {} bytes buffered to pending (total pending={}, total received={})",
                    chunk_size,
                    st.pending_audio.len(),
                    accum,
                );
                return;
            }
            st.audio_scratch.extend_from_slice(pcm);
            let chunks = drain_audio_chunks(&mut st.audio_scratch);
            (st.send_tx.clone(), chunks, st.audio_scratch.len())
        };
        if let Some(tx) = send_tx {
            let chunk_count = chunks.len();
            let total_bytes: usize = chunks.iter().map(|c| c.len()).sum();
            for chunk in chunks {
                let _ = tx.send(SendItem::Audio(chunk));
            }
            log::debug!(
                "[xfyun-asr] consume_pcm_chunk: received {} bytes → queued {chunk_count} chunk(s) ({total_bytes} bytes), scratch remaining={buffered}",
                chunk_size,
            );
        } else {
            log::debug!(
                "[xfyun-asr] consume_pcm_chunk: {} bytes added to scratch (no send_tx, total received={})",
                chunk_size,
                chunk_size,
            );
        }
    }
}

// ─────────────────────────── helpers ───────────────────────────

/// Build the iFlytek WebSocket URL with HMAC-SHA1 signature.
fn build_session_url(creds: &XfyunCredentials) -> Result<String, XfyunASRError> {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| XfyunASRError::SignaFailed(e.to_string()))?
        .as_secs();
    log::debug!("[xfyun-asr] build_session_url: timestamp={ts}");

    let base_string = format!("{}{}", creds.app_id.trim(), ts);

    // MD5 the base string, then convert to hex string.
    // 文档：baseString → MD5 → 十六进制字符串 → HmacSHA1
    let md5_digest = md5::compute(base_string.as_bytes());
    let md5_hex = format!("{:x}", md5_digest);    log::debug!("[xfyun-asr] build_session_url: base_string_len={}, md5_hex_len={}", base_string.len(), md5_hex.len());

    // HMAC-SHA1 with api_key on the hex string, then base64 encode.
    type HmacSha1 = Hmac<Sha1>;
    let mut mac = HmacSha1::new_from_slice(creds.api_key.trim().as_bytes())
        .map_err(|e| XfyunASRError::SignaFailed(e.to_string()))?;
    mac.update(md5_hex.as_bytes());
    let signa = base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes());
    log::debug!("[xfyun-asr] build_session_url: signa generated (len={})", signa.len());

    let endpoint = if creds.endpoint.trim().is_empty() {
        DEFAULT_ENDPOINT
    } else {
        creds.endpoint.trim()
    };

    // Append query parameters to the endpoint URL.
    let separator = if endpoint.contains('?') { '&' } else { '?' };
    let url = format!(
        "{}{}appid={}&ts={}&signa={}&lang={}",
        endpoint,
        separator,
        urlencoding::encode(creds.app_id.trim()),
        ts,
        urlencoding::encode(&signa),
        urlencoding::encode(DEFAULT_LANG),
    );
    log::info!(
        "[xfyun-asr] build_session_url: url={} (signa truncated)",
        url[..url.len().min(120)].to_string() + "...",
    );
    Ok(url)
}

/// Extract recognized words from the nested iFlytek result JSON.
///
/// Structure: `cn.st.rt[].ws[].cw[].w` — each `rt` is a sentence,
/// each `ws` is a word group, each `cw` is a word.
fn extract_words(data: &Value) -> String {
    let Some(rts) = data
        .pointer("/cn/st/rt")
        .and_then(Value::as_array)
    else {
        return String::new();
    };

    let mut text = String::new();
    for rt in rts {
        if let Some(wss) = rt.get("ws").and_then(Value::as_array) {
            for ws in wss {
                if let Some(cws) = ws.get("cw").and_then(Value::as_array) {
                    for cw in cws {
                        if let Some(w) = cw.get("w").and_then(Value::as_str) {
                            text.push_str(w);
                        }
                    }
                }
            }
        }
    }
    text
}

/// Merge overlapping text segments (same dedup logic as Bailian).
fn merge_segments(segments: &[String]) -> String {
    let mut result = String::new();
    for (idx, seg) in segments.iter().enumerate() {
        if result.is_empty() {
            result = seg.clone();
            continue;
        }
        let result_chars: Vec<char> = result.chars().collect();
        let seg_chars: Vec<char> = seg.chars().collect();
        let max_overlap = result_chars.len().min(seg_chars.len());
        let mut overlap = 0;
        for n in (2..=max_overlap).rev() {
            if result_chars[result_chars.len() - n..] == seg_chars[..n] {
                overlap = n;
                break;
            }
        }
        let tail: String = seg_chars[overlap..].iter().collect();
        log::debug!(
            "[xfyun-asr] merge_segments: seg[{}] overlap={}, tail_len={}",
            idx,
            overlap,
            tail.len(),
        );
        result.push_str(&tail);
    }
    result
}

fn drain_audio_chunks(buffer: &mut Vec<u8>) -> Vec<Vec<u8>> {
    let mut chunks = Vec::new();
    while buffer.len() >= TARGET_AUDIO_CHUNK_BYTES {
        chunks.push(buffer.drain(..TARGET_AUDIO_CHUNK_BYTES).collect());
    }
    chunks
}

async fn send_binary(writer: &SharedWriter, data: Vec<u8>) -> Result<(), XfyunASRError> {
    let size = data.len();
    let mut guard = writer.lock().await;
    let Some(ws) = guard.as_mut() else {
        return Err(XfyunASRError::ConnectionFailed(
            "websocket writer not available".to_string(),
        ));
    };
    ws.send(Message::Binary(data))
        .await
        .map(|_| {
            log::trace!("[xfyun-asr] send_binary: sent {size} bytes to websocket");
        })
        .map_err(|e| XfyunASRError::ConnectionFailed(e.to_string()))
}

async fn close_writer(writer: &SharedWriter) -> Result<(), XfyunASRError> {
    let mut guard = writer.lock().await;
    if let Some(mut ws) = guard.take() {
        log::info!("[xfyun-asr] close_writer: closing WebSocket connection");
        let _ = ws.close().await;
        log::info!("[xfyun-asr] close_writer: WebSocket closed");
    } else {
        log::debug!("[xfyun-asr] close_writer: writer already taken");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── merge_segments ──

    #[test]
    fn merge_segments_dedupes_overlap() {
        let segments = vec!["你好吗".to_string(), "好吗我们".to_string()];
        assert_eq!(merge_segments(&segments), "你好吗我们");
    }

    #[test]
    fn merge_segments_no_overlap() {
        let segments = vec!["今天".to_string(), "天气真好".to_string()];
        assert_eq!(merge_segments(&segments), "今天天气真好");
    }

    #[test]
    fn merge_segments_single_segment() {
        let segments = vec!["仅一段".to_string()];
        assert_eq!(merge_segments(&segments), "仅一段");
    }

    #[test]
    fn merge_segments_empty_input() {
        let segments: Vec<String> = vec![];
        assert_eq!(merge_segments(&segments), "");
    }

    // ── extract_words ──

    #[test]
    fn extract_words_parses_nested_structure() {
        let data = serde_json::json!({
            "cn": {
                "st": {
                    "rt": [{
                        "ws": [{
                            "cw": [
                                {"w": "你好"},
                                {"w": "！"}
                            ]
                        }]
                    }],
                    "type": "1"
                }
            },
            "seg_id": 0
        });
        assert_eq!(extract_words(&data), "你好！");
    }

    #[test]
    fn extract_words_handles_empty_rt() {
        let data = serde_json::json!({
            "cn": { "st": { "rt": [], "type": "1" } },
            "seg_id": 0
        });
        assert_eq!(extract_words(&data), "");
    }

    #[test]
    fn extract_words_handles_missing_cn() {
        let data = serde_json::json!({ "seg_id": 0 });
        assert_eq!(extract_words(&data), "");
    }

    // ── drain_audio_chunks ──

    #[test]
    fn drain_audio_chunks_keeps_tail_buffered() {
        let mut buffer = vec![1u8; TARGET_AUDIO_CHUNK_BYTES * 2 + 17];
        let chunks = drain_audio_chunks(&mut buffer);
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0].len(), TARGET_AUDIO_CHUNK_BYTES);
        assert_eq!(chunks[1].len(), TARGET_AUDIO_CHUNK_BYTES);
        assert_eq!(buffer.len(), 17);
    }

    // ── build_session_url ──

    #[test]
    fn build_session_url_contains_required_params() {
        let creds = XfyunCredentials {
            app_id: "test123".to_string(),
            api_key: "key456".to_string(),
            endpoint: "wss://rtasr.xfyun.cn/v1/ws".to_string(),
        };
        let url = build_session_url(&creds).unwrap();
        assert!(url.starts_with("wss://rtasr.xfyun.cn/v1/ws?"));
        assert!(url.contains("appid=test123"));
        assert!(url.contains("signa="));
        assert!(url.contains("lang=cn"));
        assert!(url.contains("ts="));
    }

    #[test]
    fn build_session_url_uses_default_endpoint_when_empty() {
        let creds = XfyunCredentials {
            app_id: "test".to_string(),
            api_key: "key".to_string(),
            endpoint: "".to_string(),
        };
        let url = build_session_url(&creds).unwrap();
        assert!(url.starts_with("wss://rtasr.xfyun.cn/v1/ws?"));
    }

    // ── record_result integration ──

    #[test]
    fn record_result_final_segment_is_stored() {
        let asr = XfyunStreamingASR::new(XfyunCredentials {
            app_id: "a".into(),
            api_key: "k".into(),
            endpoint: "wss://rtasr.xfyun.cn/v1/ws".into(),
        });
        let event = serde_json::json!({
            "action": "result",
            "code": "0",
            "data": serde_json::json!({
                "cn": {
                    "st": {
                        "rt": [{"ws": [{"cw": [{"w": "你好"}]}]}],
                        "type": "0"
                    }
                },
                "seg_id": 0
            }).to_string()
        });
        asr.record_result(&event);
        let st = asr.state.lock();
        assert_eq!(st.final_segments.len(), 1);
        assert_eq!(st.final_segments.get(&0).unwrap(), "你好");
    }

    #[test]
    fn record_result_interim_is_stored_in_partial() {
        let asr = XfyunStreamingASR::new(XfyunCredentials {
            app_id: "a".into(),
            api_key: "k".into(),
            endpoint: "wss://rtasr.xfyun.cn/v1/ws".into(),
        });
        let event = serde_json::json!({
            "action": "result",
            "code": "0",
            "data": serde_json::json!({
                "cn": {
                    "st": {
                        "rt": [{"ws": [{"cw": [{"w": "你"}]}]}],
                        "type": "1"
                    }
                },
                "seg_id": 1
            }).to_string()
        });
        asr.record_result(&event);
        let st = asr.state.lock();
        assert!(st.final_segments.is_empty());
        assert_eq!(st.partial_segments.get(&1).unwrap(), "你");
    }

    #[test]
    fn record_result_heartbeat_skipped() {
        let asr = XfyunStreamingASR::new(XfyunCredentials {
            app_id: "a".into(),
            api_key: "k".into(),
            endpoint: "wss://rtasr.xfyun.cn/v1/ws".into(),
        });
        // A heartbeat message has action "result" but data may be empty.
        let event = serde_json::json!({
            "action": "result",
            "code": "0",
            "data": ""
        });
        asr.record_result(&event);
        let st = asr.state.lock();
        assert!(st.final_segments.is_empty());
        assert!(st.partial_segments.is_empty());
    }
}
