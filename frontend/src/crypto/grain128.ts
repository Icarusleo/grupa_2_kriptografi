/**
 * GRAIN-128 AEAD — Simplified Mock Implementation
 *
 * This is an educational/visualization mock of Grain-128AEAD.
 * It approximates the structure (LFSR + NFSR + filter function + AAD authentication)
 * but is NOT cryptographically correct. Backend will replace this.
 *
 * Reference: https://grain-128aead.github.io/
 */

import { hexToBytes, bytesToHex, xorBytes } from './utils';

export interface Grain128State {
  lfsr: number[]; // 128 bits
  nfsr: number[]; // 128 bits
  round: number;
}

export interface Grain128Result {
  ciphertext: string;      // hex
  tag: string;             // hex (32 chars = 128 bits)
  stateHistory: Grain128State[]; // snapshots for visualization
  rounds: number;
}

/** LFSR feedback polynomial: x^128 + x^7 + x^38 + x^70 + x^81 + x^96 + 1 */
function lfsrFeedback(s: number[]): number {
  return s[0] ^ s[7] ^ s[38] ^ s[70] ^ s[81] ^ s[96];
}

/** NFSR feedback (simplified nonlinear function) */
function nfsrFeedback(b: number[], s: number[]): number {
  return s[0] ^ b[0] ^ b[26] ^ b[56] ^ b[91] ^ b[96] ^
    (b[3] & b[67]) ^ (b[11] & b[13]) ^ (b[17] & b[18]) ^
    (b[27] & b[59]) ^ (b[40] & b[48]) ^ (b[61] & b[65]) ^ (b[68] & b[84]);
}

/** Output/filter function h(x) — simplified */
function hFunc(b: number[], s: number[]): number {
  const x0 = b[12], x1 = s[8], x2 = s[13], x3 = s[20], x4 = b[95];
  return (x1 & x4) ^ (x0 & x3) ^ (x2 & x4) ^ (x3 & x0) ^ x0;
}

/** Pre-output function zt */
function outputBit(b: number[], s: number[]): number {
  return hFunc(b, s) ^
    s[93] ^ b[2] ^ b[15] ^ b[36] ^ b[45] ^ b[64] ^ b[73] ^ b[89];
}

/** Shift register left, insert new bit at MSB position [127] */
function shiftIn(reg: number[], newBit: number): number[] {
  return [...reg.slice(1), newBit];
}

function initGrainState(keyHex: string, ivHex: string): Grain128State {
  const keyBytes = hexToBytes(keyHex.padEnd(32, '0'));
  const ivBytes = hexToBytes(ivHex.padEnd(24, '0'));

  // Build LFSR: IV[0..95] || 1 || 1...1 (padding)
  const lfsr: number[] = new Array(128).fill(0);
  for (let i = 0; i < 96; i++) {
    lfsr[i] = (ivBytes[Math.floor(i / 8)] >> (7 - (i % 8))) & 1;
  }
  for (let i = 96; i < 128; i++) lfsr[i] = 1;

  // Build NFSR: key bits
  const nfsr: number[] = new Array(128).fill(0);
  for (let i = 0; i < 128; i++) {
    nfsr[i] = (keyBytes[Math.floor(i / 8)] >> (7 - (i % 8))) & 1;
  }

  return { lfsr, nfsr, round: 0 };
}

function clockGrain(state: Grain128State, keyFeed = false): { state: Grain128State; outBit: number } {
  const { lfsr, nfsr } = state;
  const zBit = outputBit(nfsr, lfsr);
  let lNew = lfsrFeedback(lfsr);
  let nNew = nfsrFeedback(nfsr, lfsr);

  if (keyFeed) {
    const keyBit = nfsr[0];
    lNew ^= keyBit;
    nNew ^= keyBit;
  }

  return {
    state: {
      lfsr: shiftIn(lfsr, lNew ^ (keyFeed ? zBit : 0)),
      nfsr: shiftIn(nfsr, nNew),
      round: state.round + 1,
    },
    outBit: zBit,
  };
}

/**
 * Accumulate keystream bits into a 128-bit tag accumulator (simplified MAC).
 * In real Grain-128AEAD the accumulator is updated with every other keystream bit
 * during AD and ciphertext phases. Here we XOR full bytes for simplicity.
 */
function accumulateTag(acc: Uint8Array, keystreamByte: number, dataByte: number): void {
  for (let i = 0; i < 16; i++) {
    acc[i] ^= ((keystreamByte + dataByte + i) & 0xff);
  }
}

export function grain128Encrypt(
  keyHex: string,
  ivHex: string,
  plaintextHex: string,
  adHex = '',          // Associated Data (hex) — authenticated but not encrypted
): Grain128Result {
  let state = initGrainState(keyHex, ivHex);
  const stateHistory: Grain128State[] = [{ ...state, lfsr: [...state.lfsr], nfsr: [...state.nfsr] }];

  // Initialization: 256 clocks with key feedback
  for (let i = 0; i < 256; i++) {
    const { state: next } = clockGrain(state, true);
    state = next;
    if (i % 16 === 0) {
      stateHistory.push({ ...state, lfsr: [...state.lfsr], nfsr: [...state.nfsr] });
    }
  }

  // Tag accumulator (128 bits)
  const tagAcc = new Uint8Array(16);

  // --- Phase 1: Process Associated Data ---
  // AD is authenticated only (not encrypted).
  // For each AD byte we clock the cipher and mix into tag accumulator.
  const adBytes = adHex ? hexToBytes(adHex) : new Uint8Array(0);
  const adKeystream = new Uint8Array(adBytes.length);

  let bitBuffer = 0, bitCount = 0, byteIndex = 0;
  const totalADBits = adBytes.length * 8;

  for (let i = 0; i < totalADBits; i++) {
    const { state: next, outBit } = clockGrain(state, false);
    state = next;
    bitBuffer = (bitBuffer << 1) | outBit;
    bitCount++;
    if (bitCount === 8) {
      adKeystream[byteIndex] = bitBuffer & 0xff;
      accumulateTag(tagAcc, adKeystream[byteIndex], adBytes[byteIndex]);
      byteIndex++;
      bitBuffer = 0;
      bitCount = 0;
    }
  }

  // Domain separation: one extra clock between AD and plaintext phases
  if (adBytes.length > 0) {
    const { state: next } = clockGrain(state, false);
    state = next;
  }

  // --- Phase 2: Encrypt Plaintext & continue accumulating tag ---
  const ptBytes = hexToBytes(plaintextHex);
  const encKeystream = new Uint8Array(ptBytes.length + 16); // +16 for tag keystream

  bitBuffer = 0; bitCount = 0; byteIndex = 0;

  for (let i = 0; i < (ptBytes.length + 16) * 8; i++) {
    const { state: next, outBit } = clockGrain(state, false);
    state = next;
    bitBuffer = (bitBuffer << 1) | outBit;
    bitCount++;
    if (bitCount === 8) {
      encKeystream[byteIndex++] = bitBuffer & 0xff;
      bitBuffer = 0;
      bitCount = 0;
    }
  }

  const keystream = encKeystream.slice(0, ptBytes.length);
  const tagKeystream = encKeystream.slice(ptBytes.length, ptBytes.length + 16);

  const ciphertextBytes = xorBytes(ptBytes, keystream);

  // Accumulate ciphertext bytes into tag
  for (let i = 0; i < ciphertextBytes.length; i++) {
    accumulateTag(tagAcc, tagKeystream[i % 16], ciphertextBytes[i]);
  }

  // Final tag: XOR accumulator with tag keystream
  const tagBytes = new Uint8Array(16);
  for (let i = 0; i < 16; i++) {
    tagBytes[i] = tagAcc[i] ^ tagKeystream[i];
  }

  stateHistory.push({ ...state, lfsr: [...state.lfsr], nfsr: [...state.nfsr] });

  return {
    ciphertext: bytesToHex(ciphertextBytes),
    tag: bytesToHex(tagBytes),
    stateHistory,
    rounds: state.round,
  };
}
