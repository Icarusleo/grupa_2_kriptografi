export type AlgorithmId =
  | 'grain128aead'
  | 'gift-cofb'
  | 'isap'
  | 'ascon'
  | 'xoodyak'
  | 'rc4'
  | 'chacha20'
  | 'salsa20'
  | 'hc-128'
  | 'hc-256'
  | 'rabbit'
  | string;

export interface AlgorithmDef {
  id: AlgorithmId;
  name: string;
  keyBits: number;
  ivBits: number;
  tagBits: number;
  color: string;
  accentColor: string;
  icon: string;
  description: string;
  category: string;
  group?: string;
}

export const ALGORITHMS: AlgorithmDef[] = [
  // ── Lightweight AEAD ──────────────────────────────────────────────────────
  {
    id: 'grain128aead',
    name: 'Grain-128 AEAD',
    keyBits: 128,
    ivBits: 96,
    tagBits: 64,
    color: '#86efac',
    accentColor: '#4a5c28',
    icon: '⚙️',
    description: 'Stream cipher · 96-bit IV · 64-bit tag',
    category: 'Lightweight AEAD',
  },
  {
    id: 'gift-cofb',
    name: 'GIFT-COFB',
    keyBits: 128,
    ivBits: 128,
    tagBits: 128,
    color: '#93c5fd',
    accentColor: '#1e3a5a',
    icon: '🎁',
    description: 'Block cipher · 128-bit IV · 128-bit tag',
    category: 'Lightweight AEAD',
  },
  {
    id: 'isap',
    name: 'ISAP',
    keyBits: 128,
    ivBits: 128,
    tagBits: 128,
    color: '#fcd34d',
    accentColor: '#4a3a0a',
    icon: '🔒',
    description: 'Sponge-based · 128-bit IV · 128-bit tag',
    category: 'Lightweight AEAD',
  },
  {
    id: 'ascon',
    name: 'ASCON',
    keyBits: 128,
    ivBits: 128,
    tagBits: 128,
    color: '#f9a8d4',
    accentColor: '#4a1a3a',
    icon: '🌟',
    description: 'NIST lightweight · 128-bit IV · 128-bit tag',
    category: 'Lightweight AEAD',
  },
  {
    id: 'xoodyak',
    name: 'XOODYAK',
    keyBits: 128,
    ivBits: 128,
    tagBits: 128,
    color: '#fb923c',
    accentColor: '#4a2a0a',
    icon: '🌀',
    description: 'Xoodoo permutation · 128-bit IV · 128-bit tag',
    category: 'Lightweight AEAD',
  },

  // ── Hash Fonksiyonları > Software oriented stream ciphers ─────────────────
  {
    id: 'rc4',
    name: 'RC4',
    keyBits: 128,
    ivBits: 0,
    tagBits: 0,
    color: '#ff7675',
    accentColor: '#4a1a1a',
    icon: '🔴',
    description: 'Stream cipher · anahtar tabanlı · IV yok · tag yok',
    category: 'Hash Fonksiyonları',
    group: 'Software oriented stream ciphers',
  },
  {
    id: 'chacha20',
    name: 'ChaCha20',
    keyBits: 256,
    ivBits: 96,
    tagBits: 0,
    color: '#00cec9',
    accentColor: '#0a2a2a',
    icon: '🌊',
    description: 'Stream cipher · 256-bit key · 96-bit nonce',
    category: 'Hash Fonksiyonları',
    group: 'Software oriented stream ciphers',
  },
  {
    id: 'salsa20',
    name: 'Salsa20',
    keyBits: 256,
    ivBits: 64,
    tagBits: 0,
    color: '#74b9ff',
    accentColor: '#0a1a3a',
    icon: '💃',
    description: 'Stream cipher · 256-bit key · 64-bit nonce',
    category: 'Hash Fonksiyonları',
    group: 'Software oriented stream ciphers',
  },
  {
    id: 'hc-128',
    name: 'HC-128',
    keyBits: 128,
    ivBits: 128,
    tagBits: 0,
    color: '#fdcb6e',
    accentColor: '#3a2a0a',
    icon: '⚡',
    description: 'Stream cipher · yazılım odaklı · 128-bit key/IV',
    category: 'Hash Fonksiyonları',
    group: 'Software oriented stream ciphers',
  },
  {
    id: 'hc-256',
    name: 'HC-256',
    keyBits: 256,
    ivBits: 256,
    tagBits: 0,
    color: '#e17055',
    accentColor: '#3a1a0a',
    icon: '🔥',
    description: 'Stream cipher · yazılım odaklı · 256-bit key/IV',
    category: 'Hash Fonksiyonları',
    group: 'Software oriented stream ciphers',
  },
  {
    id: 'rabbit',
    name: 'Rabbit',
    keyBits: 128,
    ivBits: 64,
    tagBits: 0,
    color: '#a29bfe',
    accentColor: '#1a1a3a',
    icon: '🐇',
    description: 'Stream cipher · yüksek hızlı · 64-bit IV',
    category: 'Hash Fonksiyonları',
    group: 'Software oriented stream ciphers',
  },
];

export function getAlgorithm(id: AlgorithmId): AlgorithmDef {
  return ALGORITHMS.find((a) => a.id === id) ?? ALGORITHMS[0];
}

export function addDynamicAlgorithm(algo: AlgorithmDef) {
  if (!ALGORITHMS.find(a => a.id === algo.id)) {
    ALGORITHMS.push(algo);
  }
}
