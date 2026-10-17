// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

export type EntryKind = 'genesis' | 'event' | 'intent' | 'action' | 'heartbeat';

export interface Entry {
  format: 'qlog-entry/1';
  logId: string;
  seq: number;
  prev: string;
  time: string;
  kind: EntryKind;
  ref: number | null;
  after: string;
  digest: string;
  note: string;
}

export interface CheckpointStatement {
  logId: string;
  writerKeyId: string;
  seq: number;
  head: string;
  lastTime: string;
  sealedAt: string;
  note: string;
}

export interface Checkpoint {
  format: 'qlog/1';
  type: 'checkpoint';
  algorithm: 'ML-DSA-65';
  signer: { id: string; publicKey: string };
  statement: CheckpointStatement;
  signature: string;
  anchor?: unknown;
}

export interface KeyDescription {
  format: 'qlog-key/1';
  algorithm: 'ML-DSA-65';
  id: string;
  publicKey: string;
}

export interface CreateOptions {
  key: Uint8Array;
  time?: string;
  note?: string;
}

export interface AppendOptions {
  kind: 'event' | 'intent' | 'action' | 'heartbeat';
  payload?: Uint8Array;
  digest?: string;
  ref?: number | null;
  after?: string | Checkpoint;
  time?: string;
  note?: string;
}

export interface HeartbeatOptions {
  time?: string;
  note?: string;
}

export interface CheckpointOptions {
  key: Uint8Array;
  sealedAt?: string;
  note?: string;
}

export interface AnchorOptions {
  seed: Uint8Array;
  index: number;
  network?: 'testnet';
  rpc?: string | string[];
  client?: unknown;
  clients?: Array<string | unknown>;
  trustSingleEndpoint?: boolean;
  meter?: number;
  maxFee?: string | number;
  timeoutMs?: number;
  onPending?: (pending: unknown) => void | Promise<void>;
}

export interface PayloadCheck {
  seq: number;
  bytes: Uint8Array;
}

export interface VerifyOptions {
  writerKeyId?: string;
  writerPublicKey?: Uint8Array | string;
  checkpoints?: Checkpoint[];
  requireAnchor?: boolean;
  requireIntentFirst?: boolean;
  maxGapSeconds?: number;
  payloads?: PayloadCheck[];
  at?: string;
  rpc?: string | string[];
  client?: unknown;
  clients?: Array<string | unknown>;
  trustSingleEndpoint?: boolean;
  contract?: string;
  trustCustomContract?: boolean;
  maxAnchorDelay?: number;
}

export interface VerifyCheck {
  name: string;
  ok: boolean;
  detail: string;
  transport: boolean;
  indeterminate: boolean;
}

export interface VerifyResult {
  valid: boolean;
  status: 'valid' | 'invalid' | 'indeterminate';
  logId: string | null;
  writerKeyId: string;
  entries?: number;
  head?: string;
  signedThrough?: number;
  sealedThrough?: number;
  unsealed?: number;
  firstAnchoredAt?: string | null;
  lastAnchoredAt?: string | null;
  actions?: number;
  actionsIntentFirst?: number;
  payloadsChecked?: number;
  checks: VerifyCheck[];
  endpoints: string[];
  officialEndpoints: boolean | null;
}

export function generateKey(): Uint8Array;
export function publicKey(key: Uint8Array): Uint8Array;
export function keyId(key: Uint8Array): string;
export function describeKey(key: Uint8Array): KeyDescription;
export function create(options: CreateOptions): Entry;
export function append(log: Entry[], options: AppendOptions): Entry;
export function heartbeat(log: Entry[], options?: HeartbeatOptions): Entry;
export function checkpoint(log: Entry[], options: CheckpointOptions): Checkpoint;
export function anchor(checkpoints: Checkpoint | Checkpoint[], options: AnchorOptions): Promise<Checkpoint[]>;
export function complete(checkpoints: Checkpoint | Checkpoint[], pending: unknown, options?: { rpc?: string | string[]; client?: unknown; clients?: Array<string | unknown>; trustSingleEndpoint?: boolean; timeoutMs?: number }): Promise<Checkpoint[]>;
export function verify(log: Entry[] | string, options: VerifyOptions): Promise<VerifyResult>;
export function toJsonl(log: Entry[]): string;
export function fromJsonl(text: string): unknown[];
export function entryHash(entry: Entry): string;
export function anchorDigest(checkpoint: Checkpoint): string;
export const FORMAT: 'qlog/1';
export const ENTRY_FORMAT: 'qlog-entry/1';
export const ENTRY_FIELDS: readonly string[];
export const ALGORITHM: 'ML-DSA-65';
export const KINDS: readonly EntryKind[];
