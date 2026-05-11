import { Handle, Position, NodeProps } from '@xyflow/react';
import { Cpu } from 'lucide-react';
import { BaseNode } from './BaseNode';
import { Grain128NodeData } from '../../types/nodes';

function RegisterDisplay({ bits, label, color }: { bits: number[]; label: string; color: string }) {
  const show = bits.slice(0, 40);
  return (
    <div style={{ marginBottom: 10 }}>
      <div style={{ fontSize: 11, fontWeight: 700, color, marginBottom: 4, display: 'flex', alignItems: 'baseline', gap: 6 }}>
        {label}
        <span style={{ fontSize: 10, fontWeight: 400, color: '#6b8a6b' }}>128-bit — ilk 40 hane gösteriliyor</span>
      </div>
      <div style={{ display: 'flex', gap: 2, alignItems: 'center', flexWrap: 'nowrap', overflowX: 'auto', paddingBottom: 2 }}>
        {show.map((bit, i) => (
          <div
            key={i}
            style={{
              width: 18,
              height: 18,
              flexShrink: 0,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              fontSize: 9,
              fontWeight: 700,
              fontFamily: 'monospace',
              borderRadius: 3,
              background: bit ? color : '#1e2e1e',
              color: bit ? '#0a1a0a' : '#4a6a4a',
              border: `1px solid ${bit ? color + 'cc' : '#2a4a2a'}`,
              transition: 'background 0.3s, color 0.3s',
            }}
          >
            {bit}
          </div>
        ))}
        <span style={{ fontSize: 11, color: '#4a6a4a', marginLeft: 4, flexShrink: 0 }}>…</span>
      </div>
    </div>
  );
}

function HexField({ label, value, color }: { label: string; value?: string; color: string }) {
  if (!value) return null;
  return (
    <div style={{ marginTop: 8 }}>
      <div style={{ fontSize: 11, color, fontWeight: 700, marginBottom: 4 }}>{label}</div>
      <div style={{
        fontSize: 10,
        fontFamily: 'monospace',
        padding: '5px 8px',
        borderRadius: 5,
        background: '#181818',
        color,
        border: `1px solid ${color}44`,
        overflow: 'hidden',
        textOverflow: 'ellipsis',
        whiteSpace: 'nowrap',
      }}>
        {value.slice(0, 56)}{value.length > 56 ? '…' : ''}
      </div>
    </div>
  );
}

export function Grain128Node({ id, data, selected }: NodeProps) {
  const nodeData = data as unknown as Grain128NodeData;

  const hasKey = !!nodeData.keyInput;
  const hasIV = !!nodeData.ivInput;
  const hasPlaintext = !!nodeData.plaintextInput;
  const hasAD = !!nodeData.adInput;
  const ready = hasKey && hasIV && hasPlaintext;

  const lfsrBits = nodeData.lfsrState ?? new Array(128).fill(0);
  const nfsrBits = nodeData.nfsrState ?? new Array(128).fill(0);

  const cp = nodeData.coreInputPreview;

  return (
    <BaseNode
      id={id}
      title="GRAIN-128 AEAD"
      icon={<Cpu size={13} />}
      progress={nodeData.progress}
      processed={nodeData.processed}
      error={nodeData.error}
      selected={selected}
      accentColor="#4a5c28"
      minWidth={440}
      helpText="Grain-128AEADv2 stream şifreleme algoritması. Key ve IV bağlandıktan sonra plaintext'i şifreler, 64-bit authentication tag üretir. Associated Data (AD) isteğe bağlıdır — şifrelenmez, yalnızca tag'e dahil edilir."
    >
      {/* Implementation status banner */}
      {nodeData.processed && (
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: 6,
          padding: '4px 8px',
          borderRadius: 5,
          marginBottom: 8,
          background: nodeData.implemented ? '#1a2a1a' : '#2a1a0a',
          border: `1px solid ${nodeData.implemented ? '#4ade80' : '#f97316'}`,
          fontSize: 10,
          fontFamily: 'monospace',
          color: nodeData.implemented ? '#86efac' : '#fb923c',
        }}>
          <span style={{
            width: 7, height: 7, borderRadius: '50%', flexShrink: 0,
            background: nodeData.implemented ? '#4ade80' : '#f97316',
            display: 'inline-block',
          }} />
          {nodeData.apiMessage ?? (nodeData.implemented ? 'Gerçek implementasyon' : 'Stub — placeholder çıktı')}
        </div>
      )}

      {/* Input / output ports layout */}
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 10 }}>
        {/* Left: input port badges */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
          {[
            { label: 'Key',             ok: hasKey,       color: '#c4b5fd', optional: false },
            { label: 'IV / Nonce',      ok: hasIV,        color: '#93c5fd', optional: false },
            { label: 'Plaintext',       ok: hasPlaintext, color: '#d1d5db', optional: false },
            { label: 'Associated Data', ok: hasAD,        color: '#fde68a', optional: true  },
          ].map(({ label, ok, color, optional }) => (
            <div
              key={label}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 6,
                fontSize: 11,
                fontWeight: 600,
                fontFamily: 'monospace',
                padding: '3px 8px',
                borderRadius: 5,
                background: ok ? '#1a2a1a' : '#1e1818',
                border: `1px solid ${ok ? color + '80' : optional ? '#3a3a1a' : '#3a2a2a'}`,
                color: ok ? color : optional ? '#5a5a3a' : '#5a4a4a',
              }}
            >
              <span style={{ width: 7, height: 7, borderRadius: '50%', background: ok ? color : optional ? '#3a3a1a' : '#3a2a2a', flexShrink: 0, display: 'inline-block' }} />
              {label}
              {optional && !ok && <span style={{ fontSize: 9, color: '#6a6a3a', marginLeft: 2 }}>(isteğe bağlı)</span>}
            </div>
          ))}
        </div>

        {/* Right: output port labels */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 14, justifyContent: 'center', paddingRight: 18 }}>
          <span style={{ fontSize: 11, color: '#fca5a5', fontFamily: 'monospace', fontWeight: 600, textAlign: 'right' }}>ciphertext</span>
          <span style={{ fontSize: 11, color: '#c4b5fd', fontFamily: 'monospace', fontWeight: 600, textAlign: 'right' }}>tag</span>
        </div>
      </div>

      {/* NIST Core Input preview */}
      {cp && (
        <div style={{
          background: '#161e16',
          border: '1px solid #2a4a2a',
          borderRadius: 6,
          padding: '8px 10px',
          marginBottom: 10,
          fontSize: 10,
          fontFamily: 'monospace',
          color: '#6b9a6b',
        }}>
          <div style={{ fontWeight: 700, color: '#86efac', marginBottom: 6, fontSize: 11 }}>
            NIST Core Input  <span style={{ fontWeight: 400, color: '#4a7a4a' }}>m₀ = Encode(|ad|) ‖ ad ‖ plaintext ‖ 0x80</span>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
            <div><span style={{ color: '#fde68a' }}>Encode(|ad|):</span> {cp.encoded_ad_length.hex} <span style={{ color: '#4a6a4a' }}>({cp.associated_data_length_bytes} byte)</span></div>
            {cp.associated_data_length_bytes > 0 && (
              <div><span style={{ color: '#fde68a' }}>AD:</span> {cp.associated_data.hex.slice(0, 32)}{cp.associated_data.hex.length > 32 ? '…' : ''}</div>
            )}
            <div><span style={{ color: '#d1d5db' }}>Plaintext:</span> {cp.plaintext.hex.slice(0, 32)}{cp.plaintext.hex.length > 32 ? '…' : ''} <span style={{ color: '#4a6a4a' }}>({cp.plaintext_length_bytes} byte)</span></div>
            <div><span style={{ color: '#a0a0a0' }}>Pad:</span> {cp.padding_byte.hex}</div>
            <div style={{ borderTop: '1px solid #2a4a2a', marginTop: 4, paddingTop: 4 }}>
              <span style={{ color: '#86efac' }}>m₀:</span> {cp.core_input_m0.hex.slice(0, 40)}{cp.core_input_m0.hex.length > 40 ? '…' : ''}
              <span style={{ color: '#4a6a4a' }}> ({cp.core_input_m0.byte_length} byte)</span>
            </div>
          </div>
        </div>
      )}

      {/* Registers (only meaningful if local mock was used; show zeros otherwise) */}
      <RegisterDisplay bits={lfsrBits} label="LFSR" color="#86efac" />
      <RegisterDisplay bits={nfsrBits} label="NFSR" color="#fbbf24" />

      {/* Output previews */}
      <HexField label="Ciphertext" value={nodeData.ciphertextOutput} color="#fca5a5" />
      <HexField label="Auth Tag (64-bit)" value={nodeData.tagOutput} color="#c4b5fd" />
      {nodeData.nistCiphertextWithTag && (
        <HexField label="NIST: ciphertext ‖ tag" value={nodeData.nistCiphertextWithTag} color="#fbbf24" />
      )}

      {/* Not ready warning */}
      {!ready && (
        <p style={{ fontSize: 11, color: '#fbbf24', marginTop: 8 }}>
          Key, IV ve Plaintext bağlantılarını yap, ardından ▶ Run'a bas.
        </p>
      )}

      {/* Input handles */}
      <Handle type="target" position={Position.Left} id="key"
        style={{ left: -8, top: '26%', width: 14, height: 14, background: '#e9d5ff', borderColor: '#a78bfa', borderWidth: 2 }} />
      <Handle type="target" position={Position.Left} id="iv"
        style={{ left: -8, top: '38%', width: 14, height: 14, background: '#bfdbfe', borderColor: '#60a5fa', borderWidth: 2 }} />
      <Handle type="target" position={Position.Left} id="plaintext"
        style={{ left: -8, top: '50%', width: 14, height: 14, background: '#e5e7eb', borderColor: '#9ca3af', borderWidth: 2 }} />
      <Handle type="target" position={Position.Left} id="ad"
        style={{ left: -8, top: '62%', width: 14, height: 14, background: '#fef08a', borderColor: '#eab308', borderWidth: 2 }} />

      {/* Output handles */}
      <Handle type="source" position={Position.Right} id="ciphertext"
        style={{ right: -8, top: '25%', width: 14, height: 14, background: '#fee2e2', borderColor: '#f87171', borderWidth: 2 }} />
      <Handle type="source" position={Position.Right} id="tag"
        style={{ right: -8, top: '42%', width: 14, height: 14, background: '#e9d5ff', borderColor: '#a78bfa', borderWidth: 2 }} />
    </BaseNode>
  );
}
