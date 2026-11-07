/**
 * OpenTelemetry GenAI Semantic Convention event for Vortex AI Agent Flight Recording
 */
class GenAiEvent {
  constructor({
    traceId,
    spanId,
    system,
    model,
    prompt,
    completion,
    toolName,
    toolParameters,
    toolResult,
    modelWeightsHash,
    supervisorId,
    promptTokens,
    completionTokens,
    timestampNs,
  }) {
    this.trace_id = traceId;
    this.span_id = spanId;
    this.system = system;
    this.model = model;
    this.prompt = prompt;
    this.completion = completion;
    this.tool_name = toolName;
    this.tool_parameters = toolParameters;
    this.tool_result = toolResult;
    this.model_weights_hash = modelWeightsHash;
    this.supervisor_id = supervisorId;
    this.prompt_tokens = promptTokens;
    this.completion_tokens = completionTokens;
    this.timestamp_ns = timestampNs || (BigInt(Date.now()) * 1000000n).toString();
  }

  toBytes() {
    const cleanObj = {};
    for (const [k, v] of Object.entries(this)) {
      if (v !== undefined) {
        cleanObj[k] = v;
      }
    }
    return Buffer.from(JSON.stringify(cleanObj), "utf-8");
  }

  static fromBytes(buf) {
    const obj = JSON.parse(buf.toString("utf-8"));
    return new GenAiEvent({
      traceId: obj.trace_id,
      spanId: obj.span_id,
      system: obj.system,
      model: obj.model,
      prompt: obj.prompt,
      completion: obj.completion,
      toolName: obj.tool_name,
      toolParameters: obj.tool_parameters,
      toolResult: obj.tool_result,
      modelWeightsHash: obj.model_weights_hash,
      supervisorId: obj.supervisor_id,
      promptTokens: obj.prompt_tokens,
      completionTokens: obj.completion_tokens,
      timestampNs: obj.timestamp_ns,
    });
  }
}

module.exports = { GenAiEvent };

