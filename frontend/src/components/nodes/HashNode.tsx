import { Handle, Position, NodeProps, useReactFlow } from '@xyflow/react';
import { Hash } from 'lucide-react';
import { BaseNode } from './BaseNode';
import { HashNodeData } from '../../types/nodes';
import { getAlgorithm } from '../../types/algorithms';

function HexField({ label, value, color }: { label: string; value?: string; color: string }) {
  if (!value) return null;
  return (
    <div style={{ marginTop: 8 }}>
      <div style={{ fontSize: 11, color, fontWeight: 700, marginBottom: 4 }}>{label}</div>
      <div
        style={{
          fontSize: 10,
          fontFamily: 'monospace',
          padding: '6px 8px',
          borderRadius: 5,
          background: '#181818',
          color,
          border: `1px solid ${color}44`,
          wordBreak: 'break-all',
          lineHeight: 1.5,
          maxHeight: 120,
          overflowY: 'auto',
        }}
      >
        {value}
      </div>
    </div>
  );
}

export function HashNode({ id, data, selected }: NodeProps) {
  const nodeData = data as unknown as HashNodeData;
  const algo = getAlgorithm(nodeData.algorithm ?? 'sha3-256');
  const { setNodes } = useReactFlow();

  const hasMessage = !!nodeData.messageInput;
  const isXof = !!algo.isXof;
  const outputLength = nodeData.outputLength ?? (isXof ? 32 : (algo.digestBits ?? 256) / 8);
  const digestBitsLabel = isXof ? `${outputLength * 8}-bit (özelleştirilebilir)` : `${algo.digestBits}-bit`;
  const isBlake2 = algo.id === 'blake2b' || algo.id === 'blake2s';
  const blake2MaxSalt = algo.id === 'blake2b' ? 16 : 8;
  const blake2MaxKey  = algo.id === 'blake2b' ? 64 : 32;

  const updateOutputLength = (value: number) => {
    setNodes((nds) =>
      nds.map((n) =>
        n.id === id
          ? { ...n, data: { ...n.data, outputLength: value } as Record<string, unknown> }
          : n
      )
    );
  };

  const updateBlake2Field = (field: 'blake2Key' | 'blake2Salt' | 'blake2Person', value: string) => {
    setNodes((nds) =>
      nds.map((n) =>
        n.id === id
          ? { ...n, data: { ...n.data, [field]: value } as Record<string, unknown> }
          : n
      )
    );
  };

  return (
    <BaseNode
      id={id}
      title={algo.name}
      icon={<Hash size={13} />}
      progress={nodeData.progress}
      processed={nodeData.processed}
      error={nodeData.error}
      selected={selected}
      accentColor={algo.accentColor}
      minWidth={420}
      helpText={
        isXof
          ? `${algo.name} XOF (extendable-output function). Mesaj bağlandıktan sonra istenen uzunlukta digest üretir.`
          : `${algo.name} hash fonksiyonu. Mesaj bağlandığında ${algo.digestBits}-bit sabit digest üretir. NIST FIPS 202 standardına uygundur.`
      }
    >
      {/* Status banner */}
      {nodeData.processed && (
        <div
          style={{
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
          }}
        >
          <span
            style={{
              width: 7,
              height: 7,
              borderRadius: '50%',
              flexShrink: 0,
              display: 'inline-block',
              background: nodeData.implemented ? '#4ade80' : '#f97316',
            }}
          />
          {nodeData.apiMessage ?? (nodeData.implemented ? 'Gerçek implementasyon (hashlib)' : 'Stub')}
        </div>
      )}

      {/* Input / output port layout */}
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 10 }}>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 6,
              fontSize: 11,
              fontWeight: 600,
              fontFamily: 'monospace',
              padding: '3px 8px',
              borderRadius: 5,
              background: hasMessage ? '#1a2a1a' : '#1e1818',
              border: `1px solid ${hasMessage ? '#d1d5db80' : '#3a2a2a'}`,
              color: hasMessage ? '#d1d5db' : '#5a4a4a',
            }}
          >
            <span
              style={{
                width: 7,
                height: 7,
                borderRadius: '50%',
                flexShrink: 0,
                display: 'inline-block',
                background: hasMessage ? '#d1d5db' : '#3a2a2a',
              }}
            />
            Message
          </div>
          <div
            style={{
              fontSize: 10,
              fontFamily: 'monospace',
              color: '#6a9a6a',
              padding: '2px 4px',
            }}
          >
            digest: {digestBitsLabel}
          </div>
        </div>

        <div
          style={{
            display: 'flex',
            flexDirection: 'column',
            gap: 14,
            justifyContent: 'center',
            paddingRight: 18,
          }}
        >
          <span
            style={{
              fontSize: 11,
              color: algo.color,
              fontFamily: 'monospace',
              fontWeight: 600,
              textAlign: 'right',
            }}
          >
            digest
          </span>
        </div>
      </div>

      {/* XOF: configurable output length */}
      {isXof && (
        <div
          style={{
            background: '#1a2a1a',
            border: '1px solid #2a4a2a',
            borderRadius: 6,
            padding: '8px 10px',
            marginBottom: 8,
            display: 'flex',
            alignItems: 'center',
            gap: 8,
            fontFamily: 'monospace',
          }}
        >
          <span style={{ fontSize: 11, color: '#86efac', fontWeight: 700 }}>Output bytes:</span>
          <input
            type="number"
            min={1}
            max={65536}
            value={outputLength}
            onChange={(e) => {
              const v = parseInt(e.target.value, 10);
              if (!isNaN(v) && v >= 1 && v <= 65536) updateOutputLength(v);
            }}
            className="nodrag"
            style={{
              width: 80,
              padding: '3px 6px',
              borderRadius: 4,
              border: '1px solid #3a5a3a',
              background: '#0e1a0e',
              color: '#d1d5db',
              fontSize: 11,
              fontFamily: 'monospace',
              outline: 'none',
            }}
          />
          <span style={{ fontSize: 10, color: '#6a9a6a' }}>= {outputLength * 8} bit</span>
        </div>
      )}

      {/* BLAKE2 parameter block (RFC 7693) — key / salt / person */}
      {isBlake2 && (
        <div
          style={{
            background: '#1a1530',
            border: '1px solid #3a2a5a',
            borderRadius: 6,
            padding: '8px 10px',
            marginBottom: 8,
            fontFamily: 'monospace',
          }}
        >
          <div style={{ fontSize: 10, color: '#a78bfa', fontWeight: 700, marginBottom: 6 }}>
            BLAKE2 parameter block (hex, opsiyonel)
          </div>
          {[
            { field: 'blake2Key' as const,    label: `Key (MAC, ≤${blake2MaxKey}B)`,  value: nodeData.blake2Key ?? '' },
            { field: 'blake2Salt' as const,   label: `Salt (≤${blake2MaxSalt}B)`,     value: nodeData.blake2Salt ?? '' },
            { field: 'blake2Person' as const, label: `Person (≤${blake2MaxSalt}B)`,   value: nodeData.blake2Person ?? '' },
          ].map(({ field, label, value }) => (
            <div key={field} style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 4 }}>
              <span style={{ fontSize: 10, color: '#c4b5fd', minWidth: 110 }}>{label}</span>
              <input
                type="text"
                value={value}
                placeholder="hex"
                onChange={(e) => updateBlake2Field(field, e.target.value.trim())}
                className="nodrag"
                style={{
                  flex: 1,
                  padding: '3px 6px',
                  borderRadius: 4,
                  border: '1px solid #4a3a7a',
                  background: '#0e0a1a',
                  color: '#e0d4ff',
                  fontSize: 10,
                  fontFamily: 'monospace',
                  outline: 'none',
                }}
              />
            </div>
          ))}
        </div>
      )}

      {/* Digest output */}
      <HexField label="Digest (hex)" value={nodeData.digestOutput} color={algo.color} />
      <HexField label="Digest (base64)" value={nodeData.digestBase64} color="#a7c4a7" />

      {!hasMessage && (
        <p style={{ fontSize: 11, color: '#fbbf24', marginTop: 8 }}>
          Plaintext Input'u Message handle'ına bağla ve ▶ Run'a bas.
        </p>
      )}

      {/* Input handle */}
      <Handle
        type="target"
        position={Position.Left}
        id="message"
        style={{
          left: -8,
          top: '40%',
          width: 14,
          height: 14,
          background: '#e5e7eb',
          borderColor: '#9ca3af',
          borderWidth: 2,
        }}
      />

      {/* Output handle */}
      <Handle
        type="source"
        position={Position.Right}
        id="digest"
        style={{
          right: -8,
          top: '40%',
          width: 14,
          height: 14,
          background: '#fef3c7',
          borderColor: '#f59e0b',
          borderWidth: 2,
        }}
      />
    </BaseNode>
  );
}
