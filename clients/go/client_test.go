package vortex

import (
	"bytes"
	"context"
	"net"
	"sync"
	"testing"
	"time"
)

func TestFrameEncodingAndDecoding(t *testing.T) {
	orig := &Frame{
		ApiKey:        ApiKeyProduce,
		ApiVersion:    2,
		CorrelationID: 42,
		ClientID:      "test-client",
		Payload:       []byte("sample-vortex-payload-bytes"),
	}

	encoded, err := EncodeFrame(orig)
	if err != nil {
		t.Fatalf("failed to encode frame: %v", err)
	}

	decoded, err := DecodeFrame(bytes.NewReader(encoded))
	if err != nil {
		t.Fatalf("failed to decode frame: %v", err)
	}

	if decoded.ApiKey != orig.ApiKey {
		t.Errorf("expected ApiKey %d, got %d", orig.ApiKey, decoded.ApiKey)
	}
	if decoded.ApiVersion != orig.ApiVersion {
		t.Errorf("expected ApiVersion %d, got %d", orig.ApiVersion, decoded.ApiVersion)
	}
	if decoded.CorrelationID != orig.CorrelationID {
		t.Errorf("expected CorrelationID %d, got %d", orig.CorrelationID, decoded.CorrelationID)
	}
	if decoded.ClientID != orig.ClientID {
		t.Errorf("expected ClientID %s, got %s", orig.ClientID, decoded.ClientID)
	}
	if !bytes.Equal(decoded.Payload, orig.Payload) {
		t.Errorf("payload mismatch")
	}
}

func TestCryptographicLineageChain(t *testing.T) {
	var initialHash [32]byte
	records := make([]Record, 10)
	currPrev := initialHash

	for i := 0; i < 10; i++ {
		rec := Record{
			Offset:    int64(i),
			Timestamp: 1700000000 + int64(i),
			PrevHash:  currPrev,
			Key:       []byte("key"),
			Value:     []byte("value"),
		}
		rec.RecordHash = ComputeRecordHash(rec.PrevHash, rec.Offset, rec.Timestamp, rec.Key, rec.Value)
		currPrev = rec.RecordHash
		records[i] = rec
	}

	valid, count := VerifyHashChain(records, initialHash)
	if !valid || count != 10 {
		t.Fatalf("hash chain should be valid, count: %d", count)
	}

	// Corrupt a record in the middle
	records[5].Value = []byte("corrupted-value")
	invalid, errIdx := VerifyHashChain(records, initialHash)
	if invalid || errIdx != 5 {
		t.Fatalf("corrupted hash chain was not caught at index 5, got idx: %d", errIdx)
	}
}

func TestMockBrokerClientProduceFlow(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	// Mock server loop
	go func() {
		req, err := DecodeFrame(serverConn)
		if err != nil {
			return
		}

		// Reply with valid produce response
		respBuf := new(bytes.Buffer)
		topic := "test_topic"
		respBuf.Write([]byte{0x00, byte(len(topic))})
		respBuf.Write([]byte(topic))
		// partition: 0, baseOffset: 100, timestamp: 1700000000, errorCode: 0, hash: [32]byte
		var numBuf [8]byte
		respBuf.Write([]byte{0x00, 0x00, 0x00, 0x00}) // partition 0
		numBuf[7] = 100
		respBuf.Write(numBuf[:])                      // offset 100
		respBuf.Write(numBuf[:])                      // timestamp
		respBuf.Write([]byte{0x00, 0x00})             // error code 0
		respBuf.Write(make([]byte, 32))               // 32-byte hash

		respFrame := &Frame{
			ApiKey:        ApiKeyProduce,
			ApiVersion:    1,
			CorrelationID: req.CorrelationID,
			ClientID:      "mock-broker",
			Payload:       respBuf.Bytes(),
		}
		encoded, _ := EncodeFrame(respFrame)
		serverConn.Write(encoded)
	}()

	client, err := NewClient(Config{
		Timeout: 2 * time.Second,
		Dialer: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return clientConn, nil
		},
	})
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	defer client.Close()

	receipt, err := client.Produce(context.Background(), "test_topic", 0, []byte("key"), []byte("value"))
	if err != nil {
		t.Fatalf("produce failed: %v", err)
	}

	if receipt.Topic != "test_topic" {
		t.Errorf("expected topic test_topic, got %s", receipt.Topic)
	}
	if receipt.ErrorCode != 0 {
		t.Errorf("expected error code 0, got %d", receipt.ErrorCode)
	}
}

func TestConcurrentClientPooling(t *testing.T) {
	client, err := NewClient(Config{
		Timeout:        2 * time.Second,
		MaxConnections: 4,
		Dialer: func(ctx context.Context, network, addr string) (net.Conn, error) {
			cConn, sConn := net.Pipe()
			go func(c net.Conn) {
				defer c.Close()
				for {
					req, err := DecodeFrame(c)
					if err != nil {
						return
					}
					respBuf := new(bytes.Buffer)
					respBuf.Write([]byte{0x00, 0x04, 't', 'e', 's', 't'})
					respBuf.Write(make([]byte, 2 + 4 + 8 + 8 + 2 + 32))
					respFrame := &Frame{
						ApiKey:        ApiKeyProduce,
						ApiVersion:    1,
						CorrelationID: req.CorrelationID,
						Payload:       respBuf.Bytes(),
					}
					encoded, _ := EncodeFrame(respFrame)
					c.Write(encoded)
				}
			}(sConn)
			return cConn, nil
		},
	})
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	defer client.Close()

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = client.Produce(context.Background(), "test", 0, []byte("k"), []byte("v"))
		}()
	}
	wg.Wait()
}

func TestGenAiEventProducing(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	client, err := NewClient(Config{
		Dialer: func(ctx context.Context, network, addr string) (net.Conn, error) {
			go func(c net.Conn) {
				req, err := DecodeFrame(c)
				if err != nil {
					return
				}
				respBuf := new(bytes.Buffer)
				respBuf.Write([]byte{0x00, 0x04, 't', 'e', 's', 't'}) // topic
				respBuf.Write(make([]byte, 2+4+8+8+2+32))              // partition details
				respFrame := &Frame{
					ApiKey:        ApiKeyProduce,
					ApiVersion:    1,
					CorrelationID: req.CorrelationID,
					Payload:       respBuf.Bytes(),
				}
				encoded, _ := EncodeFrame(respFrame)
				c.Write(encoded)
			}(serverConn)
			return clientConn, nil
		},
	})
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	defer client.Close()

	event := NewGenAiEvent("trace-123", "span-456", "anthropic", "claude-3-7-sonnet")
	event.Prompt = "Verify flight recorder"
	event.SupervisorID = "sec-ops@vortex.io"

	resp, err := client.ProduceAgentEvent(context.Background(), "agent-audit", 0, []byte("agent-1"), event)
	if err != nil {
		t.Fatalf("ProduceAgentEvent failed: %v", err)
	}
	if resp.Topic != "test" {
		t.Errorf("expected topic 'test', got '%s'", resp.Topic)
	}
}
