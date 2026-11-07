package vortex

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
)

// Standard Vortex & Kafka API Keys
const (
	ApiKeyProduce        int16 = 0
	ApiKeyFetch          int16 = 1
	ApiKeyListOffsets    int16 = 2
	ApiKeyMetadata       int16 = 3
	ApiKeyCreateTopics   int16 = 19
	ApiKeyDeleteTopics   int16 = 20
	ApiKeyDescribeGroups int16 = 15
	ApiKeyDescribeConfigs int16 = 32
)

// Magic bytes for VTX1 native frame header
var MagicVTX1 = [4]byte{'V', 'T', 'X', '1'}

// Frame represents a binary protocol request or response
type Frame struct {
	ApiKey        int16
	ApiVersion    int16
	CorrelationID int32
	ClientID      string
	Payload       []byte
}

// EncodeFrame encodes a Frame into BigEndian binary wire format
func EncodeFrame(f *Frame) ([]byte, error) {
	buf := new(bytes.Buffer)

	// Reserve 4 bytes for total length prefix
	lengthPlaceholder := make([]byte, 4)
	if _, err := buf.Write(lengthPlaceholder); err != nil {
		return nil, err
	}

	// Write ApiKey, ApiVersion, CorrelationID
	if err := binary.Write(buf, binary.BigEndian, f.ApiKey); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.BigEndian, f.ApiVersion); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.BigEndian, f.CorrelationID); err != nil {
		return nil, err
	}

	// Write ClientID (int16 length + utf8 string)
	clientBytes := []byte(f.ClientID)
	if err := binary.Write(buf, binary.BigEndian, int16(len(clientBytes))); err != nil {
		return nil, err
	}
	if _, err := buf.Write(clientBytes); err != nil {
		return nil, err
	}

	// Write Payload
	if _, err := buf.Write(f.Payload); err != nil {
		return nil, err
	}

	// Calculate and write the actual frame length (excluding the 4-byte length header)
	rawBytes := buf.Bytes()
	frameLen := uint32(len(rawBytes) - 4)
	binary.BigEndian.PutUint32(rawBytes[0:4], frameLen)

	return rawBytes, nil
}

// DecodeFrame reads and decodes a Frame from an io.Reader
func DecodeFrame(r io.Reader) (*Frame, error) {
	var totalLen uint32
	if err := binary.Read(r, binary.BigEndian, &totalLen); err != nil {
		return nil, err
	}

	if totalLen > 64*1024*1024 {
		return nil, errors.New("frame length exceeds 64MB limit")
	}

	frameBuf := make([]byte, totalLen)
	if _, err := io.ReadFull(r, frameBuf); err != nil {
		return nil, err
	}

	reader := bytes.NewReader(frameBuf)

	var apiKey, apiVersion int16
	var correlationID int32
	if err := binary.Read(reader, binary.BigEndian, &apiKey); err != nil {
		return nil, err
	}
	if err := binary.Read(reader, binary.BigEndian, &apiVersion); err != nil {
		return nil, err
	}
	if err := binary.Read(reader, binary.BigEndian, &correlationID); err != nil {
		return nil, err
	}

	var clientIDLen int16
	if err := binary.Read(reader, binary.BigEndian, &clientIDLen); err != nil {
		return nil, err
	}

	clientID := ""
	if clientIDLen > 0 {
		clientBytes := make([]byte, clientIDLen)
		if _, err := io.ReadFull(reader, clientBytes); err != nil {
			return nil, err
		}
		clientID = string(clientBytes)
	}
	// Note: clientIDLen <= 0 (including -1 for Kafka null string) is treated as empty string cleanly

	payload := make([]byte, reader.Len())
	if _, err := io.ReadFull(reader, payload); err != nil {
		return nil, err
	}

	return &Frame{
		ApiKey:        apiKey,
		ApiVersion:    apiVersion,
		CorrelationID: correlationID,
		ClientID:      clientID,
		Payload:       payload,
	}, nil
}

// Record represents a single Vortex stream record with cryptographic commitments
type Record struct {
	Offset     int64
	Timestamp  int64
	PrevHash   [32]byte
	RecordHash [32]byte
	Key        []byte
	Value      []byte
}

// ProduceReceipt represents confirmation of durable write
type ProduceReceipt struct {
	Topic       string
	Partition   int32
	BaseOffset  int64
	RecordHash  [32]byte
	Timestamp   int64
	ErrorCode   int16
}

// EncodeProducePayload serializes a produce request payload
func EncodeProducePayload(topic string, partition int32, records []Record) ([]byte, error) {
	buf := new(bytes.Buffer)

	// Topic name
	topicBytes := []byte(topic)
	if err := binary.Write(buf, binary.BigEndian, int16(len(topicBytes))); err != nil {
		return nil, err
	}
	buf.Write(topicBytes)

	// Partition
	if err := binary.Write(buf, binary.BigEndian, partition); err != nil {
		return nil, err
	}

	// Number of records
	if err := binary.Write(buf, binary.BigEndian, int32(len(records))); err != nil {
		return nil, err
	}

	// Records
	for _, rec := range records {
		if err := binary.Write(buf, binary.BigEndian, rec.Offset); err != nil {
			return nil, err
		}
		if err := binary.Write(buf, binary.BigEndian, rec.Timestamp); err != nil {
			return nil, err
		}
		buf.Write(rec.PrevHash[:])
		buf.Write(rec.RecordHash[:])

		if err := binary.Write(buf, binary.BigEndian, int32(len(rec.Key))); err != nil {
			return nil, err
		}
		buf.Write(rec.Key)

		if err := binary.Write(buf, binary.BigEndian, int32(len(rec.Value))); err != nil {
			return nil, err
		}
		buf.Write(rec.Value)
	}

	return buf.Bytes(), nil
}

// DecodeProduceResponse parses a produce response payload
func DecodeProduceResponse(payload []byte) (*ProduceReceipt, error) {
	reader := bytes.NewReader(payload)

	var topicLen int16
	if err := binary.Read(reader, binary.BigEndian, &topicLen); err != nil {
		return nil, err
	}

	topicBytes := make([]byte, topicLen)
	if _, err := io.ReadFull(reader, topicBytes); err != nil {
		return nil, err
	}

	var partition int32
	var baseOffset int64
	var timestamp int64
	var errorCode int16

	if err := binary.Read(reader, binary.BigEndian, &partition); err != nil {
		return nil, err
	}
	if err := binary.Read(reader, binary.BigEndian, &baseOffset); err != nil {
		return nil, err
	}
	if err := binary.Read(reader, binary.BigEndian, &timestamp); err != nil {
		return nil, err
	}
	if err := binary.Read(reader, binary.BigEndian, &errorCode); err != nil {
		return nil, err
	}

	var recordHash [32]byte
	if reader.Len() >= 32 {
		if _, err := io.ReadFull(reader, recordHash[:]); err != nil {
			return nil, err
		}
	}

	return &ProduceReceipt{
		Topic:      string(topicBytes),
		Partition:  partition,
		BaseOffset: baseOffset,
		RecordHash: recordHash,
		Timestamp:  timestamp,
		ErrorCode:  errorCode,
	}, nil
}
