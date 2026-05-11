import type { NormalizedBytes, CoreInputPreview } from '../api/grain128api';
import type { AlgorithmId } from './algorithms';

export type { NormalizedBytes, CoreInputPreview };

export type PortType = 'plaintext' | 'key' | 'iv' | 'ciphertext' | 'tag' | 'ad';

export interface NodeBaseData {
  label: string;
  progress: number; // 0-100
  processed: boolean;
  error?: string;
}

export interface InputNodeData extends NodeBaseData {
  type: 'input';
  value: string;
  format: 'text' | 'hex';
  outputType: 'plaintext' | 'ad';
  padding: boolean;
}

export interface KeyNodeData extends NodeBaseData {
  type: 'key';
  keyBits: number;   // selected key size: 128 | 160 | 256
  ivBits: number;    // selected IV size: 0 | 64 | 96 | 128 | 256
  keyValue: string;
  ivValue: string;
}

export interface Grain128NodeData extends NodeBaseData {
  type: 'grain128';
  keyInput?: string;
  ivInput?: string;
  plaintextInput?: string;
  adInput?: string;
  ciphertextOutput?: string;
  tagOutput?: string;
  ciphertextBase64?: string;
  tagBase64?: string;
  nistCiphertextWithTag?: string;
  lfsrState?: number[];
  nfsrState?: number[];
  currentRound?: number;
  implemented?: boolean;
  apiMessage?: string;
  coreInputPreview?: CoreInputPreview | null;
}

/** Generic algorithm node — works for Grain-128 AEAD, GIFT-COFB, ISAP, ASCON */
export interface AlgorithmNodeData extends NodeBaseData {
  type: 'algorithm';
  algorithm: AlgorithmId;
  // Inputs (populated during pipeline execution)
  keyInput?: string;
  ivInput?: string;
  plaintextInput?: string;
  adInput?: string;
  // Outputs — hex
  ciphertextOutput?: string;
  tagOutput?: string;
  // Outputs — additional encodings
  ciphertextBase64?: string;
  tagBase64?: string;
  nistCiphertextWithTag?: string;
  // Grain-128 AEAD specific visualization
  lfsrState?: number[];
  nfsrState?: number[];
  currentRound?: number;
  coreInputPreview?: CoreInputPreview | null;
  // Hash-function specific
  hashInputBytes?: number;
  // API metadata
  implemented?: boolean;
  apiMessage?: string;
}

export interface OutputNodeData extends NodeBaseData {
  type: 'output';
  ciphertextInput?: string;
  ciphertextBase64?: string;
  tagInput?: string;
  tagBase64?: string;
  nistCiphertextWithTag?: string;
  implemented?: boolean;
  format: 'hex' | 'base64';
}

export type CryptoNodeData =
  | InputNodeData
  | KeyNodeData
  | Grain128NodeData
  | AlgorithmNodeData
  | OutputNodeData;

export type NodeType = 'inputNode' | 'adInputNode' | 'keyNode' | 'grain128Node' | 'algorithmNode' | 'outputNode';

export interface PaletteItem {
  nodeType: NodeType;
  label: string;
  description: string;
  icon: string;
  color: string;
  algorithmId?: AlgorithmId;
}
