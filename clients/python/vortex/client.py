import asyncio
import time
from typing import Optional, List
from .protocol import (
    Frame, Record, ProduceReceipt, API_KEY_PRODUCE,
    encode_frame, decode_frame, encode_produce_payload, decode_produce_response
)
from .crypto import compute_record_hash

class VortexClient:
    def __init__(self, host: str = "127.0.0.1", port: int = 9092, client_id: str = "vortex-py-v0.1.0", timeout: float = 5.0):
        self.host = host
        self.port = port
        self.client_id = client_id
        self.timeout = timeout
        self.correlation_id = 0
        self._reader: Optional[asyncio.StreamReader] = None
        self._writer: Optional[asyncio.StreamWriter] = None

    async def connect(self):
        if self._reader is None or self._writer is None:
            self._reader, self._writer = await asyncio.wait_for(
                asyncio.open_connection(self.host, self.port),
                timeout=self.timeout
            )

    async def produce(self, topic: str, value: bytes, key: bytes = b"", partition: int = 0) -> ProduceReceipt:
        await self.connect()
        self.correlation_id += 1
        cid = self.correlation_id
        
        now_ms = int(time.time() * 1000)
        rec_hash = compute_record_hash(b"\x00" * 32, 0, now_ms, key, value)
        rec = Record(0, now_ms, b"\x00" * 32, rec_hash, key, value)
        
        payload = encode_produce_payload(topic, partition, [rec])
        frame = Frame(API_KEY_PRODUCE, 1, cid, self.client_id, payload)
        raw_req = encode_frame(frame)
        
        self._writer.write(raw_req)
        await self._writer.drain()
        
        raw_len = await asyncio.wait_for(self._reader.readexactly(4), timeout=self.timeout)
        import struct
        total_len = struct.unpack(">I", raw_len)[0]
        body = await asyncio.wait_for(self._reader.readexactly(total_len), timeout=self.timeout)
        
        resp_frame, _ = decode_frame(raw_len + body)
        if resp_frame.correlation_id != cid:
            raise ValueError(f"Correlation ID mismatch: expected {cid}, got {resp_frame.correlation_id}")
            
        return decode_produce_response(resp_frame.payload)

    async def fetch(self, topic: str, partition: int = 0, start_offset: int = 0) -> List[Record]:
        return []

    async def close(self):
        if self._writer:
            self._writer.close()
            try:
                await self._writer.wait_closed()
            except Exception:
                pass
            self._writer = None
            self._reader = None

