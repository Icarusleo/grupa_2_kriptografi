import { AlgorithmDef, addDynamicAlgorithm } from '../types/algorithms';

const API_BASE = '/api/v1';

export interface HashAlgorithmInfo {
  name: string;
  description: string;
  digest_size: number;
}

export interface HashComputeRequest {
  algorithm_id: string;
  data: {
    value: string;
    encoding: string;
  };
  output_encoding?: string;
}

export interface HashComputeResponse {
  algorithm: string;
  digest_size: number;
  hash: {
    byte_length: number;
    hex: string;
    base64: string;
    bits: string;
    output: string;
  };
}

export async function fetchHashAlgorithms(): Promise<Record<string, HashAlgorithmInfo>> {
  try {
    const res = await fetch(`${API_BASE}/hash/algorithms`);
    if (!res.ok) throw new Error('Failed to fetch hash algorithms');
    const data = await res.json();
    
    // Register them dynamically
    Object.entries(data).forEach(([id, info]) => {
      const hashInfo = info as HashAlgorithmInfo;
      const algoDef: AlgorithmDef = {
        id,
        name: hashInfo.name,
        keyBits: 0,
        ivBits: 0,
        tagBits: 0,
        color: '#d8b4e2',
        accentColor: '#301040',
        icon: '🔑',
        description: hashInfo.description,
        category: 'Cryptography Hash Functions',
        group: 'Dynamic Hashes'
      };
      addDynamicAlgorithm(algoDef);
    });
    
    return data;
  } catch (error) {
    console.error("Error fetching hash algorithms:", error);
    return {};
  }
}

export async function computeHash(req: HashComputeRequest): Promise<HashComputeResponse> {
  const res = await fetch(`${API_BASE}/hash/compute`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(req),
  });
  
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail ?? `HTTP ${res.status}`);
  }
  return res.json();
}
