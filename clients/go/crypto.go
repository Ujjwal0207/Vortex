package vortex

import (
	"crypto/sha256"
	"encoding/binary"
	"hash/crc32"
)

// ComputeCrc32 calculates standard IEEE CRC32 of data
func ComputeCrc32(data []byte) uint32 {
	return crc32.ChecksumIEEE(data)
}

// ComputeRecordHashPure calculates the cryptographic commitment hash for a record.
// Follows the Vortex canonical header serialization:
// SHA256(prev_hash || offset || timestamp || key || value)
func ComputeRecordHash(prevHash [32]byte, offset int64, timestamp int64, key []byte, value []byte) [32]byte {
	h := sha256.New()
	h.Write(prevHash[:])

	var numBuf [8]byte
	binary.BigEndian.PutUint64(numBuf[:], uint64(offset))
	h.Write(numBuf[:])

	binary.BigEndian.PutUint64(numBuf[:], uint64(timestamp))
	h.Write(numBuf[:])

	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(key)))
	h.Write(lenBuf[:])
	h.Write(key)

	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(value)))
	h.Write(lenBuf[:])
	h.Write(value)

	var digest [32]byte
	copy(digest[:], h.Sum(nil))
	return digest
}

// VerifyHashChain validates that a slice of records maintains an unbroken linear cryptographic hash chain
func VerifyHashChain(records []Record, initialPrevHash [32]byte) (bool, int) {
	currentExpectedPrev := initialPrevHash
	for i, rec := range records {
		if rec.PrevHash != currentExpectedPrev {
			return false, i
		}
		computedHash := ComputeRecordHash(rec.PrevHash, rec.Offset, rec.Timestamp, rec.Key, rec.Value)
		if computedHash != rec.RecordHash {
			return false, i
		}
		currentExpectedPrev = rec.RecordHash
	}
	return true, len(records)
}

