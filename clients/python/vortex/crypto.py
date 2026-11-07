import hashlib
import struct
import zlib
from typing import List, Tuple
from .protocol import Record

def compute_crc32(data: bytes) -> int:
    return zlib.crc32(data) & 0xFFFFFFFF

def compute_record_hash(prev_hash: bytes, offset: int, timestamp: int, key: bytes, value: bytes) -> bytes:
    h = hashlib.sha256()
    h.update(prev_hash[:32])
    h.update(struct.pack(">q", offset))
    h.update(struct.pack(">q", timestamp))
    h.update(struct.pack(">i", len(key)))
    h.update(key)
    h.update(struct.pack(">i", len(value)))
    h.update(value)
    return h.digest()

def verify_hash_chain(records: List[Record], initial_prev_hash: bytes = b"\x00" * 32) -> Tuple[bool, int]:
    expected_prev = initial_prev_hash
    for i, r in enumerate(records):
        if r.prev_hash != expected_prev:
            return False, i
        calc_hash = compute_record_hash(r.prev_hash, r.offset, r.timestamp, r.key, r.value)
        if calc_hash != r.record_hash:
            return False, i
        expected_prev = r.record_hash
    return True, len(records)

