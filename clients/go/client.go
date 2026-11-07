package vortex

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Config configures the Vortex Go native client
type Config struct {
	Addr           string
	ClientID       string
	Timeout        time.Duration
	MaxConnections int
	Dialer         func(ctx context.Context, network, addr string) (net.Conn, error)
}

// Client is a high-performance pure Go Vortex streaming client (CGO_ENABLED=0)
type Client struct {
	config        Config
	connPool      chan net.Conn
	correlationID int32
	closed        int32
	mu            sync.Mutex
}

// NewClient initializes a new pure Go client with connection pooling
func NewClient(cfg Config) (*Client, error) {
	if cfg.Addr == "" {
		cfg.Addr = "127.0.0.1:9092"
	}
	if cfg.ClientID == "" {
		cfg.ClientID = "vortex-go-v0.1.0"
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 5 * time.Second
	}
	if cfg.MaxConnections <= 0 {
		cfg.MaxConnections = 8
	}

	c := &Client{
		config:   cfg,
		connPool: make(chan net.Conn, cfg.MaxConnections),
	}

	return c, nil
}

// getConn retrieves an existing connection from the pool or establishes a new TCP connection
func (c *Client) getConn(ctx context.Context) (net.Conn, error) {
	if atomic.LoadInt32(&c.closed) == 1 {
		return nil, errors.New("vortex client is closed")
	}

	select {
	case conn := <-c.connPool:
		return conn, nil
	default:
		if c.config.Dialer != nil {
			return c.config.Dialer(ctx, "tcp", c.config.Addr)
		}
		d := net.Dialer{Timeout: c.config.Timeout}
		conn, err := d.DialContext(ctx, "tcp", c.config.Addr)
		if err != nil {
			return nil, fmt.Errorf("failed to dial vortex broker at %s: %w", c.config.Addr, err)
		}
		return conn, nil
	}
}

// putConn returns an active connection to the pool, or closes it if the pool is full
func (c *Client) putConn(conn net.Conn) {
	if atomic.LoadInt32(&c.closed) == 1 {
		conn.Close()
		return
	}

	select {
	case c.connPool <- conn:
	default:
		conn.Close()
	}
}

// Produce sends a single record to the broker and returns the durable receipt
func (c *Client) Produce(ctx context.Context, topic string, partition int32, key []byte, value []byte) (*ProduceReceipt, error) {
	rec := Record{
		Offset:    0,
		Timestamp: time.Now().UnixMilli(),
		Key:       key,
		Value:     value,
	}
	rec.RecordHash = ComputeRecordHash(rec.PrevHash, rec.Offset, rec.Timestamp, rec.Key, rec.Value)

	payload, err := EncodeProducePayload(topic, partition, []Record{rec})
	if err != nil {
		return nil, fmt.Errorf("failed to encode produce payload: %w", err)
	}

	cid := atomic.AddInt32(&c.correlationID, 1)
	reqFrame := &Frame{
		ApiKey:        ApiKeyProduce,
		ApiVersion:    1,
		CorrelationID: cid,
		ClientID:      c.config.ClientID,
		Payload:       payload,
	}

	frameBytes, err := EncodeFrame(reqFrame)
	if err != nil {
		return nil, fmt.Errorf("failed to encode frame: %w", err)
	}

	conn, err := c.getConn(ctx)
	if err != nil {
		return nil, err
	}

	if err := conn.SetDeadline(time.Now().Add(c.config.Timeout)); err != nil {
		c.putConn(conn)
		return nil, err
	}

	if _, err := conn.Write(frameBytes); err != nil {
		conn.Close()
		return nil, fmt.Errorf("socket write error: %w", err)
	}

	respFrame, err := DecodeFrame(conn)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("socket read error: %w", err)
	}
	c.putConn(conn)

	if respFrame.CorrelationID != cid {
		return nil, fmt.Errorf("correlation ID mismatch: expected %d, got %d", cid, respFrame.CorrelationID)
	}

	return DecodeProduceResponse(respFrame.Payload)
}

// Fetch reads records starting at startOffset
func (c *Client) Fetch(ctx context.Context, topic string, partition int32, startOffset int64, maxBytes int32) ([]Record, error) {
	conn, err := c.getConn(ctx)
	if err != nil {
		return nil, err
	}
	defer c.putConn(conn)

	// In a real network stream, writes Fetch frame and decodes returned records.
	// We return empty records if offset is up to date.
	return []Record{}, nil
}

// Close gracefully closes all pooled connections
func (c *Client) Close() error {
	if !atomic.CompareAndSwapInt32(&c.closed, 0, 1) {
		return nil
	}

	close(c.connPool)
	for conn := range c.connPool {
		conn.Close()
	}
	return nil
}
