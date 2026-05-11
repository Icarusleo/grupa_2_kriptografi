import { Handle, Position, NodeProps, useReactFlow } from '@xyflow/react';
import { Key } from 'lucide-react';
import { BaseNode } from './BaseNode';
import { KeyNodeData } from '../../types/nodes';
import { randomHex } from '../../crypto/utils';

const KEY_SIZES = [128, 160, 256] as const;
const IV_SIZES = [0, 64, 96, 128, 256] as const;

function SizeToggle({
  label,
  sizes,
  selected,
  color,
  onChange,
}: {
  label: string;
  sizes: readonly number[];
  selected: number;
  color: string;
  onChange: (v: number) => void;
}) {
  return (
    <div style={{ marginBottom: 4 }}>
      <p style={{ fontSize: 10, color, fontWeight: 700, margin: '0 0 4px' }}>{label}</p>
      <div style={{ display: 'flex', gap: 3, flexWrap: 'wrap' }}>
        {sizes.map((s) => {
          const active = s === selected;
          const displayLabel = s === 0 ? 'No IV' : `${s}-bit`;
          return (
            <button
              key={s}
              onClick={() => onChange(s)}
              style={{
                fontSize: 9,
                padding: '2px 7px',
                borderRadius: 4,
                border: `1px solid ${active ? color : '#2a3a2a'}`,
                background: active ? `${color}22` : '#1a2a1a',
                color: active ? color : '#4a6a4a',
                cursor: 'pointer',
                fontFamily: 'monospace',
                fontWeight: active ? 700 : 400,
                transition: 'all 0.15s',
              }}
            >
              {displayLabel}
            </button>
          );
        })}
      </div>
    </div>
  );
}

export function KeyNode({ id, data, selected }: NodeProps) {
  const nodeData = data as unknown as KeyNodeData;
  const { updateNodeData } = useReactFlow();

  const keyBits = nodeData.keyBits ?? 128;
  const ivBits = nodeData.ivBits ?? 96;
  const keyHexLen = keyBits / 4;
  const ivHexLen = ivBits / 4;

  const update = (patch: Partial<KeyNodeData>) => {
    updateNodeData(id, { ...nodeData, ...patch, processed: false, progress: 0 });
  };

  const handleKeyBitsChange = (bits: number) => {
    update({ keyBits: bits, keyValue: randomHex(bits / 8) });
  };

  const handleIvBitsChange = (bits: number) => {
    update({ ivBits: bits, ivValue: bits === 0 ? '' : randomHex(bits / 8) });
  };

  const keyValid = new RegExp(`^[0-9a-fA-F]{${keyHexLen}}$`).test(nodeData.keyValue);
  const ivValid = ivBits === 0 || new RegExp(`^[0-9a-fA-F]{${ivHexLen}}$`).test(nodeData.ivValue);

  return (
    <BaseNode
      id={id}
      title="Key / IV"
      icon={<Key size={13} />}
      progress={nodeData.progress}
      processed={nodeData.processed}
      error={nodeData.error}
      selected={selected}
      accentColor="#4c3a7a"
      helpText={`${keyBits}-bit key (${keyHexLen} hex karakter) ve ${ivBits > 0 ? `${ivBits}-bit IV/nonce (${ivHexLen} hex karakter)` : 'IV yok'}. Bit boyutunu algoritmanıza göre seçin.`}
    >
      {/* Key */}
      <div style={{ marginBottom: 12 }}>
        <SizeToggle
          label="Key boyutu"
          sizes={KEY_SIZES}
          selected={keyBits}
          color="#c4b5fd"
          onChange={handleKeyBitsChange}
        />
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4 }}>
          <label style={{ fontSize: 11, color: '#c4b5fd', fontWeight: 700 }}>
            Key ({keyBits}-bit)
          </label>
          <button
            onClick={() => update({ keyValue: randomHex(keyBits / 8) })}
            style={{ fontSize: 10, padding: '2px 8px', borderRadius: 4, background: '#3a2a6a', color: '#c4b5fd', border: '1px solid #6a5aaa', cursor: 'pointer' }}
          >
            Random
          </button>
        </div>
        <input
          style={{
            width: '100%',
            fontSize: 11,
            fontFamily: 'monospace',
            padding: '5px 8px',
            borderRadius: 5,
            border: `1px solid ${keyValid ? '#5a4a9a' : '#ef4444'}`,
            background: '#1a1a2a',
            color: keyValid ? '#c4b5fd' : '#f87171',
            outline: 'none',
            boxSizing: 'border-box',
            letterSpacing: '0.05em',
          }}
          placeholder={`${keyHexLen} hex chars (${keyBits} bits)`}
          value={nodeData.keyValue}
          onChange={(e) => update({ keyValue: e.target.value })}
          maxLength={keyHexLen}
          spellCheck={false}
        />
        {!keyValid && nodeData.keyValue && (
          <p style={{ color: '#f87171', fontSize: 10, marginTop: 2 }}>
            {keyHexLen} hex karakter gerekli ({keyBits} bit)
          </p>
        )}
      </div>

      {/* IV / Nonce */}
      <div>
        <SizeToggle
          label="IV / Nonce boyutu"
          sizes={IV_SIZES}
          selected={ivBits}
          color="#93c5fd"
          onChange={handleIvBitsChange}
        />

        {ivBits > 0 ? (
          <>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4 }}>
              <label style={{ fontSize: 11, color: '#93c5fd', fontWeight: 700 }}>
                IV / Nonce ({ivBits}-bit)
              </label>
              <button
                onClick={() => update({ ivValue: randomHex(ivBits / 8) })}
                style={{ fontSize: 10, padding: '2px 8px', borderRadius: 4, background: '#1a3040', color: '#93c5fd', border: '1px solid #2a5a7a', cursor: 'pointer' }}
              >
                Random
              </button>
            </div>
            <input
              style={{
                width: '100%',
                fontSize: 11,
                fontFamily: 'monospace',
                padding: '5px 8px',
                borderRadius: 5,
                border: `1px solid ${ivValid ? '#2a5a8a' : '#ef4444'}`,
                background: '#1a2030',
                color: ivValid ? '#93c5fd' : '#f87171',
                outline: 'none',
                boxSizing: 'border-box',
                letterSpacing: '0.05em',
              }}
              placeholder={`${ivHexLen} hex chars (${ivBits} bits)`}
              value={nodeData.ivValue}
              onChange={(e) => update({ ivValue: e.target.value })}
              maxLength={ivHexLen}
              spellCheck={false}
            />
            {!ivValid && nodeData.ivValue && (
              <p style={{ color: '#f87171', fontSize: 10, marginTop: 2 }}>
                {ivHexLen} hex karakter gerekli ({ivBits} bit)
              </p>
            )}
          </>
        ) : (
          <div style={{
            padding: '6px 10px',
            borderRadius: 5,
            background: '#1a1a1a',
            border: '1px solid #2a2a2a',
            marginTop: 4,
          }}>
            <p style={{ fontSize: 10, color: '#4a5a4a', fontFamily: 'monospace', margin: 0 }}>
              Bu algoritma IV kullanmıyor (ör. RC4)
            </p>
          </div>
        )}
      </div>

      {/* Port labels */}
      <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: 14, marginTop: 8, paddingRight: 18 }}>
        <span style={{ fontSize: 11, color: '#c4b5fd', fontFamily: 'monospace', fontWeight: 600 }}>key</span>
        {ivBits > 0 && (
          <span style={{ fontSize: 11, color: '#93c5fd', fontFamily: 'monospace', fontWeight: 600 }}>iv</span>
        )}
      </div>

      {/* Output handles */}
      <Handle
        type="source"
        position={Position.Right}
        id="key"
        style={{ right: -8, top: '42%', width: 14, height: 14, background: '#e9d5ff', borderColor: '#a78bfa', borderWidth: 2 }}
      />
      {ivBits > 0 && (
        <Handle
          type="source"
          position={Position.Right}
          id="iv"
          style={{ right: -8, top: '68%', width: 14, height: 14, background: '#bfdbfe', borderColor: '#60a5fa', borderWidth: 2 }}
        />
      )}
    </BaseNode>
  );
}
