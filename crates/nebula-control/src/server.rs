//! The `NebulaControl` gRPC service (README.md §11.2).

use std::pin::Pin;
use std::sync::Arc;

use nebula_proto::nebula_control_server::NebulaControl;
use nebula_proto::{
    FetchModuleRequest, HeartbeatRequest, HeartbeatResponse, ModuleChunk, RegisterRequest,
    RegisterResponse,
};
use tonic::codegen::tokio_stream::Stream;
use tonic::{Request, Response, Status};

use crate::membership::{Membership, HEARTBEAT_INTERVAL};
use crate::registry::{Registry, CHUNK_BYTES};

type ChunkStream = Pin<Box<dyn Stream<Item = Result<ModuleChunk, Status>> + Send + 'static>>;

#[derive(Debug)]
pub struct ControlService {
    membership: Arc<Membership>,
    registry: Arc<Registry>,
}

impl ControlService {
    pub fn new(membership: Arc<Membership>, registry: Arc<Registry>) -> Self {
        Self {
            membership,
            registry,
        }
    }
}

#[tonic::async_trait]
impl NebulaControl for ControlService {
    async fn register(
        &self,
        request: Request<RegisterRequest>,
    ) -> Result<Response<RegisterResponse>, Status> {
        let request = request.into_inner();
        if request.node_id.is_empty() || request.address.is_empty() {
            return Err(Status::invalid_argument("node_id and address are required"));
        }

        self.membership
            .register(&request.node_id, &request.address, request.generation);

        Ok(Response::new(RegisterResponse {
            heartbeat_interval_ms: HEARTBEAT_INTERVAL.as_millis() as u32,
        }))
    }

    async fn heartbeat(
        &self,
        request: Request<HeartbeatRequest>,
    ) -> Result<Response<HeartbeatResponse>, Status> {
        let request = request.into_inner();
        let known = self.membership.heartbeat(
            &request.node_id,
            request.generation,
            request.in_flight,
            request.queue_depth,
            request.cache_bytes,
        );

        // Not an error: a worker beating at a control plane that has forgotten
        // it is a normal consequence of the control plane restarting, and the
        // fix is for the worker to register again.
        Ok(Response::new(HeartbeatResponse {
            re_register: !known,
        }))
    }

    type FetchModuleStream = ChunkStream;

    async fn fetch_module(
        &self,
        request: Request<FetchModuleRequest>,
    ) -> Result<Response<Self::FetchModuleStream>, Status> {
        let hash = request.into_inner().content_hash;

        // `read` validates the shape of `hash` before it touches the
        // filesystem, so a traversal attempt lands here as `not_found` rather
        // than as a file.
        let artifact = self
            .registry
            .read(&hash)
            .map_err(|_| Status::not_found("unknown content_hash"))?;

        // Read then chunk, rather than streaming off the disk. Artifacts are
        // capped at 32 MiB (§6.4) and a cold start is rare by construction, so
        // the simpler code wins; revisit if the cap ever rises.
        let mut chunks: Vec<Result<ModuleChunk, Status>> = artifact
            .chunks(CHUNK_BYTES)
            .enumerate()
            .map(|(index, data)| {
                let offset = (index * CHUNK_BYTES) as u64;
                Ok(ModuleChunk {
                    data: data.to_vec(),
                    offset,
                    last: offset as usize + data.len() >= artifact.len(),
                })
            })
            .collect();

        // A zero-byte artifact yields no chunks, and a client waiting for
        // `last` would wait forever. Send one empty terminator instead.
        if chunks.is_empty() {
            chunks.push(Ok(ModuleChunk {
                data: Vec::new(),
                offset: 0,
                last: true,
            }));
        }

        Ok(Response::new(Box::pin(tonic::codegen::tokio_stream::iter(
            chunks,
        ))))
    }
}
