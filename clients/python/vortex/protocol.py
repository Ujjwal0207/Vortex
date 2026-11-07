import struct
from typing import NamedTuple, List, Optional, Tuple

API_KEY_PRODUCE = 0
API_KEY_FETCH = 1
API_KEY_METADATA = 3
API_KEY_CREATE_TOPICS = 19
API_KEY_DELETE_TOPICS = 20
API_KEY_DESCRIBE_GROUPS = 15
API_KEY_DESCRIBE_CONFIGS = 32

class Frame(NamedTuple):
    api_key: int
    api_version: int
    correlation_id: int
    client_id: str
    payload: bytes

class Record(NamedTuple):
    offset: int
    timestamp: int
    prev_hash: bytes
    record_hash: bytes
    key: bytes
    value: bytes

class ProduceReceipt(NamedTuple):
    topic: str
    partition: int
    base_offset: int
    record_hash: bytes
    timestamp: int
    error_code: int

def encode_frame(frame: Frame) -> bytes:
    client_bytes = frame.client_id.encode('utf-8')
    header_fmt = f">hhih{len(client_bytes)}s"
    header_bytes = struct.pack(
        header_fmt,
        frame.api_key,
        frame.api_version,
        frame.correlation_id,
        len(client_bytes),
        client_bytes
    )
    total_payload = header_bytes + frame.payload
    total_len = len(total_payload)
    return struct.pack(">I", total_len) + total_payload

def decode_frame(raw_data: bytes) -> Tuple[Frame, int]:
    if len(raw_data) < 4:
        raise ValueError("Buffer too short for frame length header")
    total_len = struct.unpack(">I", raw_data[:4])[0]
    if len(raw_data) < 4 + total_len:
        raise ValueError("Incomplete frame buffer")
    
    body = raw_data[4:4+total_len]
    api_key, api_version, correlation_id, client_id_len = struct.unpack(">hhih", body[:10])
    offset = 10
    client_id = ""
    if client_id_len > 0:
        client_id = body[offset:offset+client_id_len].decode('utf-8', errors='replace')
        offset += client_id_len
    # When client_id_len <= 0 (-1 in Kafka wire protocol for null), leave client_id as empty string cleanly
    
    payload = body[offset:]
    return Frame(api_key, api_version, correlation_id, client_id, payload), 4 + total_len

def encode_produce_payload(topic: str, partition: int, records: List[Record]) -> bytes:
    topic_bytes = topic.encode('utf-8')
    buf = bytearray()
    buf.extend(struct.pack(">h", len(topic_bytes)))
    buf.extend(topic_bytes)
    buf.extend(struct.pack(">i", partition))
    buf.extend(struct.pack(">i", len(records)))
    
    for r in records:
        buf.extend(struct.pack(">qq", r.offset, r.timestamp))
        buf.extend(r.prev_hash[:32])
        buf.extend(r.record_hash[:32])
        buf.extend(struct.pack(">i", len(r.key)))
        buf.extend(r.key)
        buf.extend(struct.pack(">i", len(r.value)))
        buf.extend(r.value)
    
    return bytes(buf)

def decode_produce_response(payload: bytes) -> ProduceReceipt:
    topic_len = struct.unpack(">h", payload[:2])[0]
    offset = 2
    topic = payload[offset:offset+topic_len].decode('utf-8', errors='replace')
    offset += topic_len
    
    partition, base_offset, timestamp, error_code = struct.unpack(">iqqh", payload[offset:offset+22])
    offset += 22
    record_hash = b"\x00" * 32
    if len(payload) >= offset + 32:
        record_hash = payload[offset:offset+32]
        
    return ProduceReceipt(topic, partition, base_offset, record_hash, timestamp, error_code)
