import unittest
import struct
from vortex import Frame, Record, compute_crc32, compute_record_hash, verify_hash_chain
from vortex.protocol import encode_frame, decode_frame, encode_produce_payload, decode_produce_response

class TestVortexPythonSDK(unittest.TestCase):
    def test_frame_encoding_and_decoding(self):
        orig = Frame(
            api_key=0,
            api_version=2,
            correlation_id=101,
            client_id="python-agent",
            payload=b"payload-bytes-12345"
        )
        encoded = encode_frame(orig)
        decoded, length = decode_frame(encoded)
        
        self.assertEqual(length, len(encoded))
        self.assertEqual(decoded.api_key, orig.api_key)
        self.assertEqual(decoded.api_version, orig.api_version)
        self.assertEqual(decoded.correlation_id, orig.correlation_id)
        self.assertEqual(decoded.client_id, orig.client_id)
        self.assertEqual(decoded.payload, orig.payload)

    def test_hash_chain_verification(self):
        records = []
        prev = b"\x00" * 32
        for i in range(10):
            val = f"record-{i}".encode('utf-8')
            h = compute_record_hash(prev, i, 1700000000 + i, b"key", val)
            rec = Record(i, 1700000000 + i, prev, h, b"key", val)
            records.append(rec)
            prev = h
            
        valid, count = verify_hash_chain(records)
        self.assertTrue(valid)
        self.assertEqual(count, 10)
        
        # Corrupt single byte in payload
        bad_rec = Record(records[4].offset, records[4].timestamp, records[4].prev_hash, records[4].record_hash, b"key", b"tampered")
        records[4] = bad_rec
        
        invalid, err_idx = verify_hash_chain(records)
        self.assertFalse(invalid)
        self.assertEqual(err_idx, 4)

    def test_crc32_and_payload_codecs(self):
        data = b"vortex-checksum-test"
        crc = compute_crc32(data)
        self.assertIsInstance(crc, int)
        self.assertGreater(crc, 0)
        
        rec = Record(0, 1000, b"\x00"*32, b"\x01"*32, b"k", b"v")
        payload = encode_produce_payload("test_topic", 0, [rec])
        self.assertGreater(len(payload), 0)

if __name__ == '__main__':
    unittest.main()

