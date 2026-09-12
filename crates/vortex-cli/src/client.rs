use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use vortex_core::{error::Result, record::Record, VortexError};
use vortex_protocol::{
    CreateTopicRequest, CreateTopicResponse, ErrorResponse, FetchRequest, FetchResponse, Frame,
    MessageType, ProduceRequest, ProduceResponse,
};

pub struct VortexClient {
    stream: TcpStream,
    next_req_id: u32,
    buffer: BytesMut,
}

impl VortexClient {
    pub async fn connect(addr: &str) -> Result<Self> {
        let stream = TcpStream::connect(addr)
            .await
            .map_err(|e| VortexError::Io(format!("Connection to {} failed: {}", addr, e)))?;

        Ok(Self {
            stream,
            next_req_id: 1,
            buffer: BytesMut::with_capacity(64 * 1024),
        })
    }

    pub async fn create_topic(&mut self, topic: &str, partitions: u32) -> Result<bool> {
        let req_id = self.alloc_req_id();
        let frame = CreateTopicRequest {
            topic: topic.to_string(),
            partitions,
        }
        .encode(req_id);

        self.stream
            .write_all(&frame.encode())
            .await
            .map_err(|e| VortexError::Io(e.to_string()))?;

        let resp_frame = self.read_response().await?;
        if resp_frame.msg_type == MessageType::ErrorResp {
            let mut p = resp_frame.payload;
            let err = ErrorResponse::decode(&mut p)?;
            return Err(VortexError::Io(format!("Server error [{}]: {}", err.code, err.message)));
        }

        let mut p = resp_frame.payload;
        let resp = CreateTopicResponse::decode(&mut p)?;
        Ok(resp.success)
    }

    pub async fn produce(
        &mut self,
        topic: &str,
        partition: u32,
        key: Option<Bytes>,
        value: Bytes,
    ) -> Result<ProduceResponse> {
        let req_id = self.alloc_req_id();
        let frame = ProduceRequest {
            topic: topic.to_string(),
            partition,
            key,
            value,
        }
        .encode(req_id);

        self.stream
            .write_all(&frame.encode())
            .await
            .map_err(|e| VortexError::Io(e.to_string()))?;

        let resp_frame = self.read_response().await?;
        if resp_frame.msg_type == MessageType::ErrorResp {
            let mut p = resp_frame.payload;
            let err = ErrorResponse::decode(&mut p)?;
            return Err(VortexError::Io(format!("Server error [{}]: {}", err.code, err.message)));
        }

        let mut p = resp_frame.payload;
        ProduceResponse::decode(&mut p)
    }

    pub async fn fetch(
        &mut self,
        topic: &str,
        partition: u32,
        start_offset: u64,
        max_bytes: u32,
    ) -> Result<Vec<Record>> {
        let req_id = self.alloc_req_id();
        let frame = FetchRequest {
            topic: topic.to_string(),
            partition,
            start_offset,
            max_bytes,
        }
        .encode(req_id);

        self.stream
            .write_all(&frame.encode())
            .await
            .map_err(|e| VortexError::Io(e.to_string()))?;

        let resp_frame = self.read_response().await?;
        if resp_frame.msg_type == MessageType::ErrorResp {
            let mut p = resp_frame.payload;
            let err = ErrorResponse::decode(&mut p)?;
            return Err(VortexError::Io(format!("Server error [{}]: {}", err.code, err.message)));
        }

        let mut p = resp_frame.payload;
        let resp = FetchResponse::decode(&mut p)?;
        Ok(resp.records)
    }

    async fn read_response(&mut self) -> Result<Frame> {
        loop {
            if let Some(frame) = Frame::decode(&mut self.buffer)? {
                return Ok(frame);
            }

            let n = self
                .stream
                .read_buf(&mut self.buffer)
                .await
                .map_err(|e| VortexError::Io(e.to_string()))?;

            if n == 0 {
                return Err(VortexError::Io("Server closed connection unexpectedly".to_string()));
            }
        }
    }

    fn alloc_req_id(&mut self) -> u32 {
        let id = self.next_req_id;
        self.next_req_id = self.next_req_id.wrapping_add(1);
        id
    }
}
