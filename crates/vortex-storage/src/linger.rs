use bytes::Bytes;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};
use vortex_core::VortexError;
use crate::partition::{AppendResult, PartitionLog};

pub struct PendingAppend {
    pub key: Option<Bytes>,
    pub payload: Bytes,
    pub expected_seq: Option<u64>,
    pub responder: oneshot::Sender<Result<AppendResult, VortexError>>,
}

#[derive(Clone)]
pub struct AdaptiveLingerQueue {
    tx: mpsc::Sender<PendingAppend>,
}

impl AdaptiveLingerQueue {
    pub fn new(
        partition: PartitionLog,
        linger_duration: Duration,
        max_batch_records: usize,
        max_batch_bytes: usize,
    ) -> Self {
        Self::from_shared(
            std::sync::Arc::new(tokio::sync::RwLock::new(partition)),
            linger_duration,
            max_batch_records,
            max_batch_bytes,
        )
    }

    pub fn from_shared(
        partition: std::sync::Arc<tokio::sync::RwLock<PartitionLog>>,
        linger_duration: Duration,
        max_batch_records: usize,
        max_batch_bytes: usize,
    ) -> Self {
        let (tx, mut rx) = mpsc::channel::<PendingAppend>(10_000);

        tokio::spawn(async move {
            let mut batch: Vec<PendingAppend> = Vec::with_capacity(max_batch_records);
            let mut accumulated_bytes = 0usize;

            loop {
                let timeout_fut = tokio::time::sleep(linger_duration);
                tokio::pin!(timeout_fut);

                tokio::select! {
                    biased;

                    maybe_item = rx.recv() => {
                        match maybe_item {
                            Some(item) => {
                                let item_len = item.payload.len() + item.key.as_ref().map_or(0, |k| k.len()) + 52;
                                accumulated_bytes += item_len;
                                batch.push(item);

                                if batch.len() >= max_batch_records || accumulated_bytes >= max_batch_bytes {
                                    flush_batch(&partition, &mut batch, &mut accumulated_bytes).await;
                                }
                            }
                            None => {
                                if !batch.is_empty() {
                                    flush_batch(&partition, &mut batch, &mut accumulated_bytes).await;
                                }
                                break;
                            }
                        }
                    }
                    _ = &mut timeout_fut, if !batch.is_empty() => {
                        flush_batch(&partition, &mut batch, &mut accumulated_bytes).await;
                    }
                }
            }
        });

        Self { tx }
    }

    pub async fn submit(
        &self,
        key: Option<Bytes>,
        payload: Bytes,
        expected_seq: Option<u64>,
    ) -> Result<AppendResult, VortexError> {
        let (resp_tx, resp_rx) = oneshot::channel();
        let item = PendingAppend {
            key,
            payload,
            expected_seq,
            responder: resp_tx,
        };

        self.tx
            .send(item)
            .await
            .map_err(|_| VortexError::Io("Linger queue worker has shut down".into()))?;

        resp_rx
            .await
            .map_err(|_| VortexError::Io("Linger worker dropped response channel".into()))?
    }

    pub async fn shutdown(&self) {
        // Dropping senders will cause the background loop to flush and exit
    }
}

async fn flush_batch(
    partition: &std::sync::Arc<tokio::sync::RwLock<PartitionLog>>,
    batch: &mut Vec<PendingAppend>,
    accumulated_bytes: &mut usize,
) {
    if batch.is_empty() {
        return;
    }

    let items = std::mem::take(batch);
    *accumulated_bytes = 0;

    let mut records_to_append = Vec::with_capacity(items.len());
    let mut responders = Vec::with_capacity(items.len());

    for item in items {
        records_to_append.push((item.key, item.payload, item.expected_seq));
        responders.push(item.responder);
    }

    let mut log = partition.write().await;
    let append_res = log.append_batch_authenticated(records_to_append);
    match append_res {
        Ok(results) => {
            for (responder, result) in responders.into_iter().zip(results) {
                let _ = responder.send(Ok(result));
            }
        }
        Err(err) => {
            for responder in responders {
                let _ = responder.send(Err(VortexError::Io(err.to_string())));
            }
        }
    }
}
