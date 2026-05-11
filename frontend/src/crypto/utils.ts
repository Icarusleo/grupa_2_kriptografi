/** Convert hex string to Uint8Array */
export function hexToBytes(hex: string): Uint8Array {
  const clean = hex.replace(/\s/g, '');
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

/** Convert Uint8Array to hex string */
export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/** Convert text string to Uint8Array (UTF-8) */
export function textToBytes(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

/** Convert hex string to bit array (MSB first) */
export function hexToBits(hex: string, length: number): number[] {
  const bytes = hexToBytes(hex.padEnd(Math.ceil(length / 8) * 2, '0'));
  const bits: number[] = [];
  for (const byte of bytes) {
    for (let i = 7; i >= 0; i--) {
      bits.push((byte >> i) & 1);
    }
  }
  return bits.slice(0, length);
}

/** Validate hex string of expected byte length */
export function isValidHex(hex: string, expectedBytes: number): boolean {
  const clean = hex.replace(/\s/g, '');
  return /^[0-9a-fA-F]*$/.test(clean) && clean.length === expectedBytes * 2;
}

/** Generate random hex string of n bytes */
export function randomHex(bytes: number): string {
  const arr = new Uint8Array(bytes);
  crypto.getRandomValues(arr);
  return bytesToHex(arr);
}

/** XOR two Uint8Arrays (truncate to shorter length) */
export function xorBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
  const len = Math.min(a.length, b.length);
  const result = new Uint8Array(len);
  for (let i = 0; i < len; i++) result[i] = a[i] ^ b[i];
  return result;
}
