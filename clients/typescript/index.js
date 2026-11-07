const crypto = require('crypto');
const net = require('net');
const { GenAiEvent } = require('./gen_ai');

const API_KEY_PRODUCE = 0;
const API_KEY_FETCH = 1;

/**
 * Computes SHA-256 hash matching Vortex canonical record commitment
 */
function computeRecordHash(prevHash, offset, timestamp, key, value) {
  const hash = crypto.createHash('sha256');
  hash.update(prevHash.slice(0, 32));

  const numBuf = Buffer.alloc(16);
  numBuf.writeBigInt64BE(BigInt(offset), 0);
  numBuf.writeBigInt64BE(BigInt(timestamp), 8);
  hash.update(numBuf);

  const keyLenBuf = Buffer.alloc(4);
  keyLenBuf.writeInt32BE(key.length, 0);
  hash.update(keyLenBuf);
  hash.update(key);

  const valLenBuf = Buffer.alloc(4);
  valLenBuf.writeInt32BE(value.length, 0);
  hash.update(valLenBuf);
  hash.update(value);

  return hash.digest();
}

/**
 * Verifies that an array of records maintains an unbroken linear cryptographic hash chain
 */
function verifyHashChain(records, initialPrevHash = Buffer.alloc(32)) {
  let expectedPrev = initialPrevHash;
  for (let i = 0; i < records.length; i++) {
    const r = records[i];
    if (!r.prevHash.equals(expectedPrev)) {
      return { valid: false, errorIndex: i };
    }
    const computed = computeRecordHash(r.prevHash, r.offset, r.timestamp, r.key, r.value);
    if (!computed.equals(r.recordHash)) {
      return { valid: false, errorIndex: i };
    }
    expectedPrev = r.recordHash;
  }
  return { valid: true, errorIndex: -1 };
}

/**
 * Encodes a Frame into BigEndian binary wire format
 */
function encodeFrame(frame) {
  const clientBuf = Buffer.from(frame.clientId || 'vortex-node-v0.1.0', 'utf-8');
  const headerLen = 2 + 2 + 4 + 2 + clientBuf.length;
  const payloadLen = frame.payload.length;
  const totalBodyLen = headerLen + payloadLen;

  const buf = Buffer.alloc(4 + totalBodyLen);
  buf.writeUInt32BE(totalBodyLen, 0);
  buf.writeInt16BE(frame.apiKey, 4);
  buf.writeInt16BE(frame.apiVersion, 6);
  buf.writeInt32BE(frame.correlationId, 8);
  buf.writeInt16BE(clientBuf.length, 12);
  clientBuf.copy(buf, 14);
  frame.payload.copy(buf, 14 + clientBuf.length);

  return buf;
}

/**
 * Decodes a binary Frame
 */
function decodeFrame(rawBuf) {
  if (rawBuf.length < 4) {
    throw new Error('Buffer too small for frame length');
  }
  const totalLen = rawBuf.readUInt32BE(0);
  if (rawBuf.length < 4 + totalLen) {
    throw new Error('Incomplete frame buffer');
  }

  const apiKey = rawBuf.readInt16BE(4);
  const apiVersion = rawBuf.readInt16BE(6);
  const correlationId = rawBuf.readInt32BE(8);
  const clientIdLen = rawBuf.readInt16BE(12);

  let clientId = '';
  let offset = 14;
  if (clientIdLen > 0) {
    clientId = rawBuf.toString('utf-8', offset, offset + clientIdLen);
    offset += clientIdLen;
  }
  // If clientIdLen <= 0 (-1 in Kafka wire protocol for null), leave clientId as empty string cleanly

  const payload = rawBuf.subarray(offset, 4 + totalLen);

  return {
    apiKey,
    apiVersion,
    correlationId,
    clientId,
    payload,
  };
}

/**
 * High-performance Node.js / TypeScript Vortex streaming client
 */
class VortexClient {
  constructor(options = {}) {
    this.host = options.host || '127.0.0.1';
    this.port = options.port || 9092;
    this.clientId = options.clientId || 'vortex-node-v0.1.0';
    this.timeout = options.timeout || 5000;
    this.correlationId = 0;
    this.socket = null;
  }

  async connect() {
    if (this.socket && !this.socket.destroyed) {
      return;
    }
    return new Promise((resolve, reject) => {
      this.socket = net.createConnection({ host: this.host, port: this.port }, () => {
        resolve();
      });
      this.socket.on('error', (err) => {
        reject(err);
      });
    });
  }

  async produce(topic, value, key = Buffer.alloc(0), partition = 0) {
    await this.connect();
    this.correlationId += 1;
    const cid = this.correlationId;

    const valBuf = Buffer.isBuffer(value) ? value : Buffer.from(value);
    const keyBuf = Buffer.isBuffer(key) ? key : Buffer.from(key);
    const nowMs = BigInt(Date.now());
    const prevHash = Buffer.alloc(32);
    const recHash = computeRecordHash(prevHash, 0n, nowMs, keyBuf, valBuf);

    // Encode produce body
    const topicBuf = Buffer.from(topic, 'utf-8');
    const produceBuf = Buffer.alloc(2 + topicBuf.length + 4 + 4 + 8 + 8 + 32 + 32 + 4 + keyBuf.length + 4 + valBuf.length);
    let off = 0;
    produceBuf.writeInt16BE(topicBuf.length, off); off += 2;
    topicBuf.copy(produceBuf, off); off += topicBuf.length;
    produceBuf.writeInt32BE(partition, off); off += 4;
    produceBuf.writeInt32BE(1, off); off += 4; // 1 record
    produceBuf.writeBigInt64BE(0n, off); off += 8;
    produceBuf.writeBigInt64BE(nowMs, off); off += 8;
    prevHash.copy(produceBuf, off); off += 32;
    recHash.copy(produceBuf, off); off += 32;
    produceBuf.writeInt32BE(keyBuf.length, off); off += 4;
    keyBuf.copy(produceBuf, off); off += keyBuf.length;
    produceBuf.writeInt32BE(valBuf.length, off); off += 4;
    valBuf.copy(produceBuf, off); off += valBuf.length;

    const frame = encodeFrame({
      apiKey: API_KEY_PRODUCE,
      apiVersion: 1,
      correlationId: cid,
      clientId: this.clientId,
      payload: produceBuf,
    });

    return new Promise((resolve, reject) => {
      this.socket.write(frame, (err) => {
        if (err) return reject(err);
      });

      this.socket.once('data', (data) => {
        try {
          const resp = decodeFrame(data);
          resolve({
            topic,
            partition,
            correlationId: resp.correlationId,
            recordHash: recHash,
          });
        } catch (e) {
          reject(e);
        }
      });
    });
  }

  async produceAgentEvent(topic, event, key = '', partition = 0) {
    const value = event.toBytes();
    return this.produce(topic, value, key, partition);
  }

  async close() {
    if (this.socket) {
      this.socket.end();
      this.socket.destroy();
      this.socket = null;
    }
  }
}

module.exports = {
  VortexClient,
  GenAiEvent,
  computeRecordHash,
  verifyHashChain,
  encodeFrame,
  decodeFrame,
  API_KEY_PRODUCE,
  API_KEY_FETCH,
};
