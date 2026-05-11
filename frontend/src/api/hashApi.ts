import { AlgorithmDef, addDynamicAlgorithm } from '../types/algorithms';

const API_BASE = '/api/v1';

export interface HashAlgorithmInfo {
  name: string;
  description: string;
  digest_size: number;
  group?: string;
  icon?: string;
  block_size?: number;
  rounds?: number;
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
    
    // Per-algorithm cosmetic styling (everything else falls back to the default).
    const STYLE: Record<string, { color: string; accentColor: string; icon: string }> = {
      md5:  { color: '#c4b5fd', accentColor: '#3b1d6e', icon: '#️⃣' },
      sha1: { color: '#86efac', accentColor: '#1f5132', icon: '🛡️' },
    };
    const DEFAULT_STYLE = { color: '#d8b4e2', accentColor: '#301040', icon: '🔢' };

    // Register them dynamically
    Object.entries(data).forEach(([id, info]) => {
      const hashInfo = info as HashAlgorithmInfo;
      const digestBits = hashInfo.digest_size * 8;
      const blockBits = (hashInfo.block_size ?? 64) * 8;
      const rounds = hashInfo.rounds ?? 0;
      const style = STYLE[id] ?? DEFAULT_STYLE;

      const descParts = ['Hash', `${digestBits}-bit özet`, `${blockBits}-bit blok`];
      if (rounds > 0) descParts.push(`${rounds} tur`);

      const algoDef: AlgorithmDef = {
        id,
        name: hashInfo.name,
        keyBits: 0,
        ivBits: 0,
        tagBits: 0,
        color: '#d8b4e2',
        accentColor: '#301040',
        icon: hashInfo.icon ?? '#',
        description: hashInfo.description,
        category: 'Cryptography Hash Functions',
        group: hashInfo.group ?? 'Dynamic Hashes',
        color: style.color,
        accentColor: style.accentColor,
        icon: style.icon,
        description: descParts.join(' · '),
        category: 'Cryptographic Hash Functions',
        isHash: true,
        digestBits,
        blockBits,
        rounds,
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
