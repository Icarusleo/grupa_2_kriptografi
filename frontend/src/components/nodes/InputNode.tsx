import { Handle, Position, NodeProps, useReactFlow } from '@xyflow/react';
import { FileText, Database } from 'lucide-react';
import { BaseNode } from './BaseNode';
import { InputNodeData } from '../../types/nodes';
import { textToBytes, bytesToHex } from '../../crypto/utils';

function getByteCount(nodeData: InputNodeData): number {
  if (!nodeData.value) return 0;
  if (nodeData.format === 'hex') {
    return Math.floor(nodeData.value.replace(/\s/g, '').length / 2);
  }
  return textToBytes(nodeData.value).length;
}

const ACCENT_PLAINTEXT = '#2d6a52';
const ACCENT_AD = '#6a5a1a';

const HANDLE_STYLE_PLAINTEXT = {
  width: 14, height: 14,
  background: '#d1fae5', borderColor: '#6ee7b7', borderWidth: 2, right: -8,
};

const HANDLE_STYLE_AD = {
  width: 14, height: 14,
  background: '#fef08a', borderColor: '#eab308', borderWidth: 2, right: -8,
};

export function InputNode({ id, data, selected }: NodeProps) {
  const nodeData = data as unknown as InputNodeData;
  const { updateNodeData } = useReactFlow();

  const isAD = nodeData.outputType === 'ad';
  const accentColor = isAD ? ACCENT_AD : ACCENT_PLAINTEXT;
  const handleStyle = isAD ? HANDLE_STYLE_AD : HANDLE_STYLE_PLAINTEXT;
  const portColor = isAD ? '#fde68a' : '#9ca3af';

  const update = (patch: Partial<InputNodeData>) => {
    updateNodeData(id, { ...nodeData, ...patch, processed: false, progress: 0 });
  };

  const byteCount = getByteCount(nodeData);
  const needsPadding = !isAD && byteCount > 0 && byteCount < 16;

  const hexPreview =
    nodeData.format === 'text' && nodeData.value
      ? bytesToHex(textToBytes(nodeData.value))
      : null;

  return (
    <BaseNode
      id={id}
      title={isAD ? 'AD Input' : 'Text Input'}
      icon={isAD ? <Database size={13} /> : <FileText size={13} />}
      progress={nodeData.progress}
      processed={nodeData.processed}
      error={nodeData.error}
      selected={selected}
      accentColor={accentColor}
      helpText={
        isAD
          ? 'Associated Data (İlişkili Veri) girişi. Şifrelenmez; yalnızca kimlik doğrulama tag\'ine dahil edilir. Paket başlıkları, IP adresleri gibi meta veriler için kullanılır.'
          : 'Plaintext veya hex formatında veri girişi. Text modunda girilen değer otomatik hex\'e çevrilir. Çıkış "plaintext" handle\'ından akar.'
      }
    >
      {/* Output type toggle: Plaintext | AD */}
      <div style={{ display: 'flex', gap: 4, marginBottom: 8 }}>
        {(['plaintext', 'ad'] as const).map((ot) => {
          const active = nodeData.outputType === ot;
          const color = ot === 'ad' ? '#fde68a' : '#86efac';
          return (
            <button
              key={ot}
              onClick={() => update({ outputType: ot })}
              style={{
                fontSize: 10,
                fontWeight: 700,
                padding: '2px 9px',
                borderRadius: 5,
                border: `1px solid ${active ? color : '#2a3a2a'}`,
                cursor: 'pointer',
                background: active ? (ot === 'ad' ? '#3a3a0a' : '#1a3a1a') : '#141e14',
                color: active ? color : '#4a6a4a',
                fontFamily: 'monospace',
                transition: 'all 0.15s',
              }}
            >
              {ot === 'ad' ? 'Associated Data' : 'Plaintext'}
            </button>
          );
        })}
      </div>

      {/* Format toggle: TEXT | HEX */}
      <div style={{ display: 'flex', gap: 6, marginBottom: 8 }}>
        {(['text', 'hex'] as const).map((fmt) => (
          <button
            key={fmt}
            onClick={() => update({ format: fmt })}
            style={{
              fontSize: 11,
              fontWeight: 600,
              padding: '2px 10px',
              borderRadius: 5,
              border: '1px solid',
              cursor: 'pointer',
              background: nodeData.format === fmt ? accentColor : '#1a2a1a',
              color: nodeData.format === fmt ? '#d1fae5' : '#6b9a8a',
              borderColor: nodeData.format === fmt ? (isAD ? '#eab308' : '#4ade80') : '#2a4a3a',
              transition: 'all 0.15s',
            }}
          >
            {fmt.toUpperCase()}
          </button>
        ))}
      </div>

      {/* Input area */}
      <textarea
        style={{
          width: '100%',
          fontSize: 11,
          fontFamily: 'monospace',
          padding: '6px 8px',
          borderRadius: 6,
          border: `1px solid ${isAD ? '#4a4a1a' : '#3a5a3a'}`,
          background: '#1a2a1a',
          color: isAD ? '#fde68a' : '#86efac',
          resize: 'vertical',
          outline: 'none',
          minHeight: 56,
          boxSizing: 'border-box',
          lineHeight: 1.5,
        }}
        placeholder={
          isAD
            ? nodeData.format === 'text'
              ? 'Enter associated data…'
              : 'Enter hex bytes for AD…'
            : nodeData.format === 'text'
            ? 'Enter plaintext…'
            : 'Enter hex bytes (e.g. deadbeef)'
        }
        value={nodeData.value}
        onChange={(e) => update({ value: e.target.value })}
        spellCheck={false}
      />

      {/* Byte counter */}
      {nodeData.value && (
        <div style={{
          fontSize: 10, fontFamily: 'monospace', marginTop: 3, marginBottom: 2,
          color: needsPadding ? '#fbbf24' : isAD ? '#a09040' : '#6b9a8a',
        }}>
          {byteCount} byte ({byteCount * 8} bit){needsPadding ? ' — 128 bitten az' : ''}
        </div>
      )}

      {/* Hex preview for text mode */}
      {hexPreview && (
        <div style={{
          fontSize: 10, fontFamily: 'monospace', marginBottom: 4,
          color: isAD ? '#7a7a30' : '#4a8a6a',
          overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
        }}>
          hex: {hexPreview.slice(0, 32)}{hexPreview.length > 32 ? '…' : ''}
        </div>
      )}

      {/* Padding checkbox — only for plaintext */}
      {!isAD && (
        <label style={{
          display: 'flex', alignItems: 'center', gap: 7, cursor: 'pointer',
          marginTop: 4, marginBottom: 2, userSelect: 'none',
        }}>
          <div
            onClick={() => update({ padding: !nodeData.padding })}
            style={{
              width: 16, height: 16, borderRadius: 4,
              border: `2px solid ${nodeData.padding ? '#4ade80' : '#3a5a3a'}`,
              background: nodeData.padding ? '#2d6a52' : '#1a2a1a',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              flexShrink: 0, transition: 'all 0.15s', cursor: 'pointer',
            }}
          >
            {nodeData.padding && (
              <svg width="10" height="10" viewBox="0 0 10 10" fill="none">
                <path d="M2 5l2.5 2.5L8 3" stroke="#86efac" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
              </svg>
            )}
          </div>
          <span style={{
            fontSize: 11, fontWeight: 600, fontFamily: 'monospace',
            color: nodeData.padding ? '#86efac' : '#6b9a8a',
          }}>
            Padding (sıfır-pad → 128 bit)
          </span>
        </label>
      )}

      {!isAD && nodeData.padding && needsPadding && (
        <div style={{ fontSize: 10, color: '#4ade80', fontFamily: 'monospace', marginBottom: 2 }}>
          {16 - byteCount} byte sıfır eklenecek → 16 byte
        </div>
      )}

      {/* AD info badge */}
      {isAD && (
        <div style={{
          fontSize: 9, color: '#a09040', fontFamily: 'monospace', marginTop: 4,
          padding: '2px 6px', borderRadius: 3, background: '#2a2a0a',
          border: '1px solid #3a3a1a', display: 'inline-block',
        }}>
          ℹ şifrelenmez · yalnızca tag'e dahil edilir
        </div>
      )}

      {/* Port label + handle */}
      <div style={{
        position: 'relative', marginTop: 6,
        display: 'flex', justifyContent: 'flex-end', alignItems: 'center', paddingRight: 18,
      }}>
        <span style={{ fontSize: 11, color: portColor, fontFamily: 'monospace', fontWeight: 600 }}>
          {isAD ? 'associated data' : 'plaintext'}
        </span>
      </div>

      <Handle
        type="source"
        position={Position.Right}
        id={nodeData.outputType}
        style={handleStyle}
      />
    </BaseNode>
  );
}
