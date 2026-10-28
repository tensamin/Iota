use super::*;
use iota_connection::message_common::CommunicationResponseExt;
use iota_identity::relay_protocol::files::{MAX_CONTROL_BYTES, REPLICA_CHUNK_BYTES, ReplicaRead};
use iota_storage::util::files::replication::{self, Job};
use iota_util::mtp_compat::OptionalDataValueExt;
use mtp::codec::{CommunicationType, DataType, DataValue};

static NEXT_REQUEST: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(1);

impl PeerManager {
    pub(super) fn start_file_replication(self: &Arc<Self>) {
        if self.file_worker_started.swap(true, Ordering::AcqRel) {
            return;
        }
        let manager = self.clone();
        let mut tasks = self.outgoing.lock().expect("peer supervisor lock poisoned");
        if let Some(tasks) = tasks.as_mut() {
            tasks.spawn(async move {
                let mut interval = tokio::time::interval(std::time::Duration::from_secs(2));
                interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                loop {
                    tokio::select! { _ = manager.shutdown.cancelled() => break, _ = interval.tick() => {} }
                    if let Err(error) = iota_storage::util::files::maintenance() {
                        iota_logger::log!("File maintenance failed: {}",error);
                    }
                    let jobs = match replication::jobs() {
                        Ok(jobs) => jobs,
                        Err(error) => { iota_logger::log!("Cannot load file replication jobs: {}",error); continue; }
                    };
                    for job in jobs {
                        let result = tokio::select! {
                            _ = manager.shutdown.cancelled() => return,
                            result = tokio::time::timeout(std::time::Duration::from_secs(30),manager.transfer_file_ranges(&job)) => result,
                        };
                        if !matches!(result,Ok(Ok(()))) {
                            let _ = replication::failed(&job);
                        }
                    }
                }
            });
        }
    }

    async fn transfer_file_ranges(self: &Arc<Self>, job: &Job) -> Result<(), String> {
        let mut offset = replication::progress(job).map_err(|e| e.to_string())?;
        for _ in 0..16 {
            if offset == job.manifest.ciphertext_size {
                return replication::complete(job).map_err(|e| e.to_string());
            }
            let mut request = job.request.clone();
            request.offset = offset;
            let bytes = if job.source_node == self.identity.node_id().as_str() {
                replication::read(&request, None).map_err(|e| e.to_string())?
            } else {
                let node = IotaNodeId::new(&job.source_node).map_err(|e| e.to_string())?;
                self.request_file_range(&node, &request).await?
            };
            if bytes.is_empty() || bytes.len() > REPLICA_CHUNK_BYTES {
                return Err("invalid replica range".into());
            }
            replication::append(job, offset, &bytes).map_err(|e| e.to_string())?;
            offset += bytes.len() as i64;
        }
        Ok(())
    }

    async fn request_file_range(
        self: &Arc<Self>,
        node: &IotaNodeId,
        request: &ReplicaRead,
    ) -> Result<Vec<u8>, String> {
        if !self.router.has_connection(node) {
            self.connect_best(node).await.map_err(|e| e.to_string())?;
        }
        let connection = self
            .router
            .peers
            .read()
            .ok()
            .and_then(|peers| peers.get(node).map(|peer| peer.1.clone()))
            .ok_or("peer unavailable")?;
        let key = connection
            .authenticated_key()
            .ok_or("unauthenticated peer")?;
        self.validate_established_peer(node, &key)
            .await
            .map_err(|e| e.to_string())?;
        let id = NEXT_REQUEST.fetch_add(1, Ordering::Relaxed).max(1);
        let frame = CommunicationValue::new(CommunicationType::FileReplicaRead)
            .with_id(id)
            .add_typed_default(
                DataType::Json,
                DataValue::Str(serde_json::to_string(request).map_err(|e| e.to_string())?),
            );
        let response = connection
            .send_peer_control(frame)
            .await
            .map_err(|e| e.to_string())?;
        self.validate_established_peer(node, &key)
            .await
            .map_err(|e| e.to_string())?;
        if response.id() != Some(id)
            || !response.is_type(CommunicationType::FileReplicaReadResponse)
            || response
                .get_data(DataType::Offset)
                .and_then(DataValue::as_number)
                != Some(request.offset.into())
        {
            return Err("replica response mismatch".into());
        }
        response
            .get_data(DataType::Blob)
            .and_then(DataValue::as_bytes)
            .ok_or("replica response has no bytes".into())
    }

    pub(super) async fn file_range_response(
        &self,
        node: &IotaNodeId,
        key: &PublicKeyBundle,
        frame: &CommunicationValue,
    ) -> Option<CommunicationValue> {
        self.validate_established_peer(node, key).await.ok()?;
        let _permit = self.file_reads.try_acquire().ok()?;
        let json = frame.get_data(DataType::Json).as_str()?;
        if json.len() > MAX_CONTROL_BYTES {
            return None;
        }
        let request: ReplicaRead = serde_json::from_str(json).ok()?;
        let result = replication::read(&request, Some(node.as_str()));
        self.validate_established_peer(node, key).await.ok()?;
        let response = match result {
            Ok(bytes) => CommunicationValue::new_with_type_map(
                CommunicationType::FileReplicaReadResponse,
                frame.type_map()?,
            )
            .with_request_id(frame)
            .add_typed_default(
                DataType::Offset,
                DataValue::SignedNumber(request.offset.into()),
            )
            .add_typed_default(DataType::Blob, DataValue::Bytes(bytes)),
            Err(_) => CommunicationValue::new_with_type_map(
                CommunicationType::FileReplicaReadResponse,
                frame.type_map()?,
            )
            .with_request_id(frame)
            .add_typed_default(DataType::State, DataValue::Str("denied".into())),
        };
        Some(response)
    }
}
