import { useState } from 'react';
import { ChevronDown, Search } from 'lucide-react';
import { ALGORITHMS } from '../../types/algorithms';
import type { AlgorithmDef } from '../../types/algorithms';

function AccordionItem({ algo, isOpen, onToggle }: {
  algo: AlgorithmDef;
  isOpen: boolean;
  onToggle: () => void;
}) {
  const onDragStart = (event: React.DragEvent) => {
    event.dataTransfer.setData('application/reactflow', 'algorithmNode');
    event.dataTransfer.setData('application/algorithm-id', algo.id);
    event.dataTransfer.effectAllowed = 'move';
  };

  const badges = algo.isHash
    ? [
        `Digest: ${algo.digestBits ?? '?'}b`,
        `Block: ${algo.blockBits ?? '?'}b`,
        ...(algo.rounds ? [`${algo.rounds} tur`] : []),
        'Key yok · IV yok',
      ]
    : [
        `Key: ${algo.keyBits}b`,
        ...(algo.ivBits > 0 ? [`IV: ${algo.ivBits}b`] : ['No IV']),
        ...(algo.tagBits > 0 ? [`Tag: ${algo.tagBits}b`] : []),
      ];

  return (
    <div
      draggable
      onDragStart={onDragStart}
      style={{
        borderRadius: 8,
        border: `1.5px solid ${isOpen ? algo.color : '#2a3a2a'}`,
        background: isOpen ? `${algo.color}12` : '#141e14',
        transition: 'all 0.18s',
        cursor: 'grab',
        userSelect: 'none',
      }}
    >
      {/* Header */}
      <button
        onClick={onToggle}
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 7,
          width: '100%',
          padding: '9px 11px',
          background: 'transparent',
          border: 'none',
          cursor: 'pointer',
          textAlign: 'left',
        }}
      >
        <span style={{ fontSize: 15, flexShrink: 0 }}>{algo.icon}</span>
        <span style={{
          fontSize: 12,
          fontWeight: 700,
          fontFamily: 'monospace',
          color: isOpen ? algo.color : '#6a9a6a',
          flex: 1,
        }}>
          {algo.name}
        </span>
        <ChevronDown
          size={13}
          color={isOpen ? algo.color : '#4a6a4a'}
          style={{
            flexShrink: 0,
            transform: isOpen ? 'rotate(180deg)' : 'rotate(0deg)',
            transition: 'transform 0.18s',
          }}
        />
      </button>

      {/* Body */}
      {isOpen && (
        <div style={{ padding: '0 11px 10px' }}>
          <p style={{
            fontSize: 10,
            color: `${algo.color}cc`,
            margin: '0 0 7px',
            fontFamily: 'monospace',
            lineHeight: 1.4,
          }}>
            {algo.description}
          </p>
          <div style={{ display: 'flex', gap: 3, flexWrap: 'wrap' }}>
            {badges.map((label) => (
              <span
                key={label}
                style={{
                  fontSize: 9,
                  padding: '1px 5px',
                  borderRadius: 3,
                  background: '#1e2e1e',
                  color: `${algo.color}aa`,
                  border: `1px solid ${algo.color}30`,
                  fontFamily: 'monospace',
                }}
              >
                {label}
              </span>
            ))}
          </div>
          <p style={{
            fontSize: 9,
            color: '#3a5a3a',
            margin: '7px 0 0',
            fontStyle: 'italic',
          }}>
            ⠿ sürükle → canvas'a ekle
          </p>
        </div>
      )}
    </div>
  );
}

function CategoryHeader({ label }: { label: string }) {
  return (
    <div style={{
      padding: '6px 4px 4px',
      marginTop: 6,
      borderBottom: '1px solid #2a3a2a',
    }}>
      <p style={{
        fontSize: 10,
        fontWeight: 700,
        color: '#4a7a4a',
        textTransform: 'uppercase',
        letterSpacing: '0.1em',
        margin: 0,
      }}>
        {label}
      </p>
    </div>
  );
}

function GroupHeader({ label }: { label: string }) {
  return (
    <div style={{ padding: '5px 4px 2px' }}>
      <p style={{
        fontSize: 9,
        fontWeight: 700,
        color: '#3a5a5a',
        textTransform: 'uppercase',
        letterSpacing: '0.08em',
        margin: 0,
      }}>
        ↳ {label}
      </p>
    </div>
  );
}

type Grouped = {
  category: string;
  groups: { group: string; algos: AlgorithmDef[] }[];
}[];

function groupAlgorithms(algos: AlgorithmDef[]): Grouped {
  const categories = [...new Set(algos.map((a) => a.category))];
  return categories.map((category) => {
    const catAlgos = algos.filter((a) => a.category === category);
    const groups = [...new Set(catAlgos.map((a) => a.group ?? ''))];
    return {
      category,
      groups: groups.map((group) => ({
        group,
        algos: catAlgos.filter((a) => (a.group ?? '') === group),
      })),
    };
  });
}

export function AlgorithmSelector() {
  const [openId, setOpenId] = useState<string | null>(null);
  const [query, setQuery] = useState('');

  const filtered = ALGORITHMS.filter((a) => {
    const q = query.toLowerCase();
    return (
      a.name.toLowerCase().includes(q) ||
      a.description.toLowerCase().includes(q)
    );
  });

  const grouped = groupAlgorithms(filtered);

  return (
    <div
      style={{
        width: 220,
        background: '#0f1a0f',
        borderLeft: '1px solid #2a3a2a',
        flexShrink: 0,
        display: 'flex',
        flexDirection: 'column',
        height: '100%',
      }}
    >
      {/* Header */}
      <div style={{ padding: '12px 12px 10px', borderBottom: '1px solid #2a3a2a' }}>
        <p style={{
          fontSize: 10,
          fontWeight: 700,
          color: '#4a7a4a',
          textTransform: 'uppercase',
          letterSpacing: '0.1em',
          margin: '0 0 8px',
        }}>
          ⚙️ Algoritmalar
        </p>

        {/* Search */}
        <div style={{ position: 'relative' }}>
          <Search
            size={11}
            color="#3a5a3a"
            style={{ position: 'absolute', left: 8, top: '50%', transform: 'translateY(-50%)' }}
          />
          <input
            type="text"
            placeholder="Algoritma ara..."
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            style={{
              width: '100%',
              padding: '5px 8px 5px 24px',
              borderRadius: 6,
              border: '1px solid #2a3a2a',
              background: '#141e14',
              color: '#8aaa8a',
              fontSize: 11,
              fontFamily: 'monospace',
              outline: 'none',
              boxSizing: 'border-box',
            }}
          />
        </div>
      </div>

      {/* Grouped accordion list */}
      <div style={{ padding: '6px 10px 10px', display: 'flex', flexDirection: 'column', gap: 0, overflowY: 'auto', flex: 1 }}>
        {filtered.length === 0 ? (
          <p style={{ fontSize: 10, color: '#3a5a3a', textAlign: 'center', marginTop: 12, fontFamily: 'monospace' }}>
            Sonuç bulunamadı
          </p>
        ) : (
          grouped.map(({ category, groups }) => (
            <div key={category}>
              <CategoryHeader label={category} />
              {groups.map(({ group, algos }) => (
                <div key={group}>
                  {group && <GroupHeader label={group} />}
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 5, marginTop: 5, marginBottom: 4 }}>
                    {algos.map((algo) => (
                      <AccordionItem
                        key={algo.id}
                        algo={algo}
                        isOpen={openId === algo.id}
                        onToggle={() => setOpenId(openId === algo.id ? null : algo.id)}
                      />
                    ))}
                  </div>
                </div>
              ))}
            </div>
          ))
        )}
      </div>

      {/* Footer */}
      <div style={{ padding: '10px 12px', borderTop: '1px solid #2a3a2a' }}>
        <p style={{ fontSize: 9, color: '#3a5a3a', margin: 0, lineHeight: 1.5 }}>
          Algoritmayı sürükleyerek canvas'a ekle. Her düğüm kendi algoritmasını taşır.
        </p>
      </div>
    </div>
  );
}
