const assert = require('assert');
const {
  encodeFrame,
  decodeFrame,
  computeRecordHash,
  verifyHashChain,
  API_KEY_PRODUCE,
} = require('./index');

console.log('--- Testing Vortex TypeScript/Node.js SDK ---');

// Test 1: Frame Encoding & Decoding
const originalFrame = {
  apiKey: API_KEY_PRODUCE,
  apiVersion: 1,
  correlationId: 999,
  clientId: 'test-ts-client',
  payload: Buffer.from('hello-vortex-world-bytes'),
};

const encoded = encodeFrame(originalFrame);
const decoded = decodeFrame(encoded);

assert.strictEqual(decoded.apiKey, originalFrame.apiKey);
assert.strictEqual(decoded.apiVersion, originalFrame.apiVersion);
assert.strictEqual(decoded.correlationId, originalFrame.correlationId);
assert.strictEqual(decoded.clientId, originalFrame.clientId);
assert.deepStrictEqual(decoded.payload, originalFrame.payload);
console.log('✓ Frame serialization roundtrip passed');

// Test 2: Cryptographic Hash Chaining
const records = [];
let prev = Buffer.alloc(32);
for (let i = 0; i < 10; i++) {
  const key = Buffer.from('k');
  const value = Buffer.from(`record-payload-${i}`);
  const hash = computeRecordHash(prev, BigInt(i), 1700000000n + BigInt(i), key, value);
  records.push({
    offset: BigInt(i),
    timestamp: 1700000000n + BigInt(i),
    prevHash: prev,
    recordHash: hash,
    key,
    value,
  });
  prev = hash;
}

const verifyResult = verifyHashChain(records);
assert.strictEqual(verifyResult.valid, true);
assert.strictEqual(verifyResult.errorIndex, -1);
console.log('✓ 10-record hash chain verification passed');

// Test 3: Tamper Detection
records[4].value = Buffer.from('tampered-payload');
const tamperResult = verifyHashChain(records);
assert.strictEqual(tamperResult.valid, false);
assert.strictEqual(tamperResult.errorIndex, 4);
console.log('✓ Bit-rot / tamper detection at index 4 passed');

// Test 4: GenAiEvent Serialization
const { GenAiEvent } = require('./index');
const agentEvent = new GenAiEvent({
  traceId: 'trace-node-123',
  spanId: 'span-node-456',
  system: 'openai',
  model: 'gpt-4o',
  prompt: 'Execute automated deployment',
  toolName: 'k8s_apply',
  toolParameters: { replicas: 3 },
  supervisorId: 'devops-lead@enterprise.com',
});
const serialized = agentEvent.toBytes();
const deserialized = GenAiEvent.fromBytes(serialized);
assert.strictEqual(deserialized.trace_id, 'trace-node-123');
assert.strictEqual(deserialized.system, 'openai');
assert.strictEqual(deserialized.model, 'gpt-4o');
assert.strictEqual(deserialized.prompt, 'Execute automated deployment');
assert.deepStrictEqual(deserialized.tool_parameters, { replicas: 3 });
assert.strictEqual(deserialized.supervisor_id, 'devops-lead@enterprise.com');
console.log('✓ GenAiEvent serialization roundtrip passed');

console.log('All TypeScript / Node.js SDK tests passed successfully!');

