/// <reference types="node" />

export interface Frame {
  apiKey: number;
  apiVersion: number;
  correlationId: number;
  clientId?: string;
  payload: Buffer;
}

export interface Record {
  offset: bigint;
  timestamp: bigint;
  prevHash: Buffer;
  recordHash: Buffer;
  key: Buffer;
  value: Buffer;
}

export interface ProduceReceipt {
  topic: string;
  partition: number;
  correlationId: number;
  recordHash: Buffer;
}

export interface ClientOptions {
  host?: string;
  port?: number;
  clientId?: string;
  timeout?: number;
}

export function computeRecordHash(
  prevHash: Buffer,
  offset: bigint,
  timestamp: bigint,
  key: Buffer,
  value: Buffer
): Buffer;

export function verifyHashChain(
  records: Record[],
  initialPrevHash?: Buffer
): { valid: boolean; errorIndex: number };

export function encodeFrame(frame: Frame): Buffer;
export function decodeFrame(rawBuf: Buffer): Frame;

export class VortexClient {
  constructor(options?: ClientOptions);
  connect(): Promise<void>;
  produce(topic: string, value: Buffer | string, key?: Buffer | string, partition?: number): Promise<ProduceReceipt>;
  close(): Promise<void>;
}

