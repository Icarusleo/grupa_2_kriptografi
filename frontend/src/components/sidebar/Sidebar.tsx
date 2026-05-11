import { ToolItem } from './ToolItem';
import type { PaletteItem } from '../../types/nodes';

const IO_ITEMS: PaletteItem[] = [
  {
    nodeType: 'inputNode',
    label: 'Plaintext Input',
    description: 'Şifrelenecek düz metin',
    icon: '📄',
    color: '#4a9a7a',
  },
  {
    nodeType: 'adInputNode',
    label: 'AD Input',
    description: 'Associated Data · şifrelenmez, tag\'e dahil edilir',
    icon: '🏷️',
    color: '#d97706',
  },
  {
    nodeType: 'outputNode',
    label: 'Output',
    description: 'Ciphertext & tag çıktısı',
    icon: '🖥️',
    color: '#f87171',
  },
];

const KEY_ITEM: PaletteItem = {
  nodeType: 'keyNode',
  label: 'Key / IV',
  description: '128-bit key + IV (size per algorithm)',
  icon: '🔑',
  color: '#a78bfa',
};

export function Sidebar() {
  return (
    <div
      className="flex flex-col h-full select-none"
      style={{
        width: 220,
        background: '#111611',
        borderRight: '1px solid #2a3a2a',
        flexShrink: 0,
      }}
    >
      {/* Header */}
      <div className="px-3 py-3 border-b" style={{ borderColor: '#2a3a2a' }}>
        <div className="flex items-center gap-2">
          <span className="text-green-400 text-lg">🔐</span>
          <div>
            <h1 className="text-white text-sm font-bold tracking-wide">KriptoFlow</h1>
            <p className="text-green-700 text-[10px]">Lightweight Crypto Editor</p>
          </div>
        </div>
      </div>

      {/* I/O nodes */}
      <div className="px-3 pt-3 pb-1">
        <p className="text-[10px] font-bold uppercase tracking-widest text-green-700 mb-2">
          I/O
        </p>
        <div className="flex flex-col gap-1.5">
          {IO_ITEMS.map((item) => (
            <ToolItem key={item.nodeType} item={item} />
          ))}
        </div>
      </div>

      <div className="mx-3 my-2" style={{ height: 1, background: '#2a3a2a' }} />

      {/* Crypto primitives */}
      <div className="px-3 pb-3">
        <p className="text-[10px] font-bold uppercase tracking-widest text-green-700 mb-2">
          Crypto Primitives
        </p>
        <div className="flex flex-col gap-1.5">
          <ToolItem item={KEY_ITEM} />
        </div>
      </div>

      <div className="mx-3" style={{ height: 1, background: '#2a3a2a' }} />

      {/* Usage hint */}
      <div className="px-3 py-3 mt-auto">
        <div className="rounded-lg p-2.5" style={{ background: '#1a2a1a', border: '1px solid #2a4a2a' }}>
          <p className="text-[10px] text-green-600 font-semibold mb-1">Nasıl kullanılır?</p>
          <ol className="text-[10px] text-green-800 space-y-0.5 list-decimal list-inside">
            <li>Sağdan algoritmayı sürükle</li>
            <li>Araçları canvas'a sürükle</li>
            <li>Handle'lara tıklayarak bağla</li>
            <li><strong className="text-green-600">▶ Run</strong> butonuna bas</li>
          </ol>
        </div>
      </div>
    </div>
  );
}
