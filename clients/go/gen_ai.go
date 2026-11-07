package vortex

import (
	"context"
	"encoding/json"
	"time"
)

// GenAiEvent conforms to CNCF OpenTelemetry GenAI Semantic Conventions for AI Agent Flight Recording
type GenAiEvent struct {
	TraceID          string                 `json:"trace_id"`
	SpanID           string                 `json:"span_id"`
	System           string                 `json:"system"`
	Model            string                 `json:"model"`
	Prompt           string                 `json:"prompt,omitempty"`
	Completion       string                 `json:"completion,omitempty"`
	ToolName         string                 `json:"tool_name,omitempty"`
	ToolParameters   map[string]interface{} `json:"tool_parameters,omitempty"`
	ToolResult       map[string]interface{} `json:"tool_result,omitempty"`
	ModelWeightsHash string                 `json:"model_weights_hash,omitempty"`
	SupervisorID     string                 `json:"supervisor_id,omitempty"`
	PromptTokens     uint64                 `json:"prompt_tokens,omitempty"`
	CompletionTokens uint64                 `json:"completion_tokens,omitempty"`
	TimestampNs      uint64                 `json:"timestamp_ns"`
}

// NewGenAiEvent creates an event with the current timestamp in nanoseconds
func NewGenAiEvent(traceID, spanID, system, model string) *GenAiEvent {
	return &GenAiEvent{
		TraceID:     traceID,
		SpanID:      spanID,
		System:      system,
		Model:       model,
		TimestampNs: uint64(time.Now().UnixNano()),
	}
}

// ProduceAgentEvent serializes an OpenTelemetry GenAI event and produces it to Vortex
func (c *Client) ProduceAgentEvent(ctx context.Context, topic string, partition int32, key []byte, event *GenAiEvent) (*ProduceReceipt, error) {
	if event.TimestampNs == 0 {
		event.TimestampNs = uint64(time.Now().UnixNano())
	}
	bytes, err := json.Marshal(event)
	if err != nil {
		return nil, err
	}
	return c.Produce(ctx, topic, partition, key, bytes)
}
