import { Handle, Position, NodeProps, useReactFlow } from '@xyflow/react';
import { Monitor, Copy, Check } from 'lucide-react';
import { BaseNode } from './BaseNode';
import { OutputNodeData } from '../../types/nodes';
import { useState } from 'react';

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      onClick={async () => {
        await navigator.clipboard.writeText(text);
        setCopied(true);
        setTimeout(() => setCopied(false), 1500);
      }}
      title="Kopyala"
      style={{ background: 'none', border: 'none', cursor: 'pointer', padding: 2, color: copied ? '#22c55e' : '#6b9a8a', display: 'flex' }}
    >
      {copied ? <Check size={12} /> : <Copy size={12} />}
    </button>
  );
}

function OutputField({ label, value, color }: { label: string; value?: string; color: string }) {
  return (
    <div style={{ marginBottom: 10 }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 4 }}>
        <span style={{ fontSize: 11, fontWeight: 700, color }}>{label}</span>
        {value && <CopyButton text={value} />}
      </div>
      <div
        style={{
          fontSize: 11,
          fontFamily: 'monospace',
          padding: '6px 8px',
          borderRadius: 5,
          background: '#1a1a1a',
          color: value ? color : '#4a5a4a',
          border: `1px solid ${value ? color + '55' : '#2a3a2a'}`,
          minHeight: 38,
          maxHeight: 80,
          overflowY: 'auto',
          wordBreak: 'break-all',
          lineHeight: 1.5,
        }}
      >
        {value ?? <span style={{ opacity: 0.35 }}>—</span>}
      </div>
    </div>
  );
}

export function OutputNode({ id, data, selected }: NodeProps) {
  const nodeData = data as unknown as OutputNodeData;
  const { updateNodeData } = useReactFlow();

  const toggleFormat = (fmt: 'hex' | 'base64') => {
    if (fmt === nodeData.format) return;
    updateNodeData(id, { ...nodeData, format: fmt });
  };

  // Use the correct base64 value from API (not btoa on hex string)
  const cipherDisplay =
    nodeData.format === 'base64'
      ? nodeData.ciphertextBase64 ?? nodeData.ciphertextInput
      : nodeData.ciphertextInput;

  const tagDisplay =
    nodeData.format === 'base64'
      ? nodeData.tagBase64 ?? nodeData.tagInput
      : nodeData.tagInput;

  return (
    <BaseNode
      id={id}
      title="Output"
      icon={<Monitor size={13} />}
      progress={nodeData.progress}
      processed={nodeData.processed}
      error={nodeData.error}
      selected={selected}
      accentColor="#6a2a2a"
      helpText="Şifreli çıktıyı ve authentication tag'i gösterir. HEX veya Base64 formatında görüntülenebilir. Kopyala butonu ile panoya alınabilir."
    >
      {/* Implementation status */}
      {nodeData.processed && nodeData.implemented === false && (
        <div style={{
          fontSize: 10,
          fontFamily: 'monospace',
          color: '#fb923c',
          background: '#2a1a0a',
          border: '1px solid #f97316',
          borderRadius: 5,
          padding: '3px 8px',
          marginBottom: 8,
        }}>
          ⚠ Stub çıktı — gerçek implementasyon bağlı değil
        </div>
      )}

      {/* Input port labels */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: 6, marginBottom: 10, paddingLeft: 18 }}>
        <span style={{ fontSize: 11, color: '#fca5a5', fontFamily: 'monospace', fontWeight: 600 }}>ciphertext</span>
        <span style={{ fontSize: 11, color: '#c4b5fd', fontFamily: 'monospace', fontWeight: 600 }}>tag</span>
      </div>

      {/* Format toggle */}
      <div style={{ display: 'flex', gap: 6, marginBottom: 10 }}>
        {(['hex', 'base64'] as const).map((fmt) => (
          <button
            key={fmt}
            onClick={() => toggleFormat(fmt)}
            style={{
              fontSize: 11,
              fontWeight: 700,
              padding: '2px 10px',
              borderRadius: 5,
              border: '1px solid',
              cursor: 'pointer',
              background: nodeData.format === fmt ? '#6a2a2a' : '#1a1a1a',
              color: nodeData.format === fmt ? '#fca5a5' : '#6a4a4a',
              borderColor: nodeData.format === fmt ? '#f87171' : '#3a2a2a',
              transition: 'all 0.15s',
            }}
          >
            {fmt.toUpperCase()}
          </button>
        ))}
      </div>

      <OutputField label="Ciphertext" value={cipherDisplay} color="#f87171" />
      <OutputField label="Auth Tag" value={tagDisplay} color="#c4b5fd" />

      {/* NIST full output */}
      {nodeData.nistCiphertextWithTag && (
        <div style={{ marginTop: 4 }}>
          <div style={{ fontSize: 10, fontWeight: 700, color: '#fbbf24', marginBottom: 4 }}>
            NIST output  <span style={{ fontWeight: 400, color: '#6a5a3a' }}>ciphertext ‖ tag</span>
          </div>
          <div style={{
            fontSize: 10,
            fontFamily: 'monospace',
            padding: '5px 8px',
            borderRadius: 5,
            background: '#1a1a10',
            color: '#fbbf24',
            border: '1px solid #4a4a1a',
            wordBreak: 'break-all',
            lineHeight: 1.5,
          }}>
            {nodeData.nistCiphertextWithTag}
          </div>
        </div>
      )}

      {/* Input handles */}
      <Handle type="target" position={Position.Left} id="ciphertext"
        style={{ left: -8, top: '22%', width: 14, height: 14, background: '#fee2e2', borderColor: '#f87171', borderWidth: 2 }} />
      <Handle type="target" position={Position.Left} id="tag"
        style={{ left: -8, top: '36%', width: 14, height: 14, background: '#e9d5ff', borderColor: '#a78bfa', borderWidth: 2 }} />
    </BaseNode>
  );
}
