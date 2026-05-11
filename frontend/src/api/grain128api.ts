/**
 * KriptoFlow Backend API Client
 * Grain-128AEAD · GIFT-COFB · ISAP · ASCON · XOODYAK
 * Base: /api/v1 (Vite proxy → http://127.0.0.1:8000)
 */

const API_BASE = '/api/v1';

// ── Shared input/output types ─────────────────────────────────────────────────

export type InputEncoding  = 'hex' | 'utf8' | 'base64' | 'bits';
export type OutputEncoding = 'hex' | 'base64' | 'bits' | 'utf8';

export interface EncodedValue {
  value: string;
  encoding: InputEncoding;
}

/** Full multi-format byte representation returned by the backend */
export interface NormalizedBytes {
  byte_length: number;
  bit_length:  number;
  hex:         string;
  base64:      string;
  bits:        string;
  bits_lsb_first: string;
  output:      string;
}

// ── NIST Core Input (Grain-128AEAD only) ─────────────────────────────────────

export interface CoreInputPreview {
  associated_data_length_bytes: number;
  plaintext_length_bytes:       number;
  encoded_ad_length:            NormalizedBytes;
  associated_data:              NormalizedBytes;
  plaintext:                    NormalizedBytes;
  padding_byte:                 NormalizedBytes;
  core_input_m0:                NormalizedBytes;
  mask_for_encrypted_region_bits: string;
  mask_for_encrypted_region_length_bits: number;
}

// ── Generic AEAD request / response ──────────────────────────────────────────

export interface AEADEncryptRequest {
  key:              EncodedValue;
  nonce:            EncodedValue;
  plaintext:        EncodedValue;
  associated_data:  EncodedValue;
  output_encoding:  OutputEncoding;
  include_normalized_inputs?: boolean;
  include_core_input_preview?: boolean;
}

export interface AEADEncryptResponse {
  implemented: boolean;
  message:     string;
  ciphertext:              NormalizedBytes;
  tag:                     NormalizedBytes;
  nist_ciphertext_with_tag: NormalizedBytes;
  core_input_preview?: CoreInputPreview | null;
  normalized_inputs?: unknown | null;
}

export interface AEADDecryptRequest {
  key:             EncodedValue;
  nonce:           EncodedValue;
  ciphertext:      EncodedValue;
  tag:             EncodedValue;
  associated_data: EncodedValue;
  output_encoding: OutputEncoding;
  include_core_input_preview?: boolean;
  include_normalized_inputs?: boolean;
}

export interface AEADDecryptResponse {
  implemented: boolean;
  message:     string;
  valid:       boolean;
  plaintext:   NormalizedBytes;
  core_input_preview?: CoreInputPreview | null;
  normalized_inputs?: unknown | null;
}

// ── Backward-compatible aliases (Grain-128AEAD) ───────────────────────────────

export type GrainEncryptRequest  = AEADEncryptRequest;
export type GrainEncryptResponse = AEADEncryptResponse;
export type GrainDecryptRequest  = AEADDecryptRequest;
export type GrainDecryptResponse = AEADDecryptResponse;

// ── Low-level fetch helper ────────────────────────────────────────────────────

async function post<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(
      Array.isArray(err.detail)
        ? err.detail.map((d: { msg: string }) => d.msg).join(', ')
        : (err.detail ?? `HTTP ${res.status}`)
    );
  }
  return res.json() as T;
}

async function get<T>(path: string): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json() as T;
}

// ── Encrypt / Decrypt per algorithm ──────────────────────────────────────────

/** Grain-128AEAD */
export const encryptGrain128 = (req: AEADEncryptRequest) =>
  post<AEADEncryptResponse>('/grain128aeadv2/encrypt', req);

export const decryptGrain128 = (req: AEADDecryptRequest) =>
  post<AEADDecryptResponse>('/grain128aeadv2/decrypt', req);

/** GIFT-COFB */
export const encryptGiftCofb = (req: AEADEncryptRequest) =>
  post<AEADEncryptResponse>('/gift-cofb/encrypt', req);

export const decryptGiftCofb = (req: AEADDecryptRequest) =>
  post<AEADDecryptResponse>('/gift-cofb/decrypt', req);

/** ISAP */
export const encryptIsap = (req: AEADEncryptRequest) =>
  post<AEADEncryptResponse>('/isap/encrypt', req);

export const decryptIsap = (req: AEADDecryptRequest) =>
  post<AEADDecryptResponse>('/isap/decrypt', req);

/** ASCON */
export const encryptAscon = (req: AEADEncryptRequest) =>
  post<AEADEncryptResponse>('/ascon/encrypt', req);

export const decryptAscon = (req: AEADDecryptRequest) =>
  post<AEADDecryptResponse>('/ascon/decrypt', req);

/** XOODYAK */
export const encryptXoodyak = (req: AEADEncryptRequest) =>
  post<AEADEncryptResponse>('/xoodyak/encrypt', req);

export const decryptXoodyak = (req: AEADDecryptRequest) =>
  post<AEADDecryptResponse>('/xoodyak/decrypt', req);

/** Generic — algoritma ID'ye göre doğru endpoint'i çağırır */
export function encryptAlgorithm(algoId: string, req: AEADEncryptRequest) {
  const path = algoId === 'grain128aead' ? '/grain128aeadv2/encrypt' : `/${algoId}/encrypt`;
  return post<AEADEncryptResponse>(path, req);
}

export function decryptAlgorithm(algoId: string, req: AEADDecryptRequest) {
  const path = algoId === 'grain128aead' ? '/grain128aeadv2/decrypt' : `/${algoId}/decrypt`;
  return post<AEADDecryptResponse>(path, req);
}

// ── Parameters & Health ───────────────────────────────────────────────────────

export interface AlgorithmParameters {
  algorithm:       string;
  key_bits:        number;
  nonce_bits:      number;
  tag_bits:        number;
  plaintext:       string;
  associated_data: string;
  nist_core_input?: string;
  nonce_rule?:     string;
}

export async function getAlgorithmParameters(algoId: string): Promise<AlgorithmParameters> {
  const path = algoId === 'grain128aead' ? '/grain128aeadv2/parameters' : `/${algoId}/parameters`;
  return get<AlgorithmParameters>(path);
}

export async function checkHealth(): Promise<{ status: string; algorithms: Record<string, { available: boolean; name: string }> }> {
  return get('/health');
}
