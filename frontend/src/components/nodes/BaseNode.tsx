import React, { useState } from 'react';
import { X, Minus, HelpCircle, ChevronDown } from 'lucide-react';
import { useReactFlow } from '@xyflow/react';

interface BaseNodeProps {
  id: string;
  title: string;
  icon: React.ReactNode;
  progress: number;
  processed: boolean;
  error?: string;
  selected?: boolean;
  accentColor?: string;
  helpText?: string;
  minWidth?: number;
  children: React.ReactNode;
}

export function BaseNode({
  id,
  title,
  icon,
  progress,
  processed,
  error,
  selected,
  accentColor = '#4a7a4a',
  helpText,
  minWidth = 260,
  children,
}: BaseNodeProps) {
  const { deleteElements } = useReactFlow();
  const [collapsed, setCollapsed] = useState(false);
  const [showHelp, setShowHelp] = useState(false);

  const progressColor = error ? '#ef4444' : processed ? '#22c55e' : '#3a5a3a';

  const handleDelete = () => {
    deleteElements({ nodes: [{ id }] });
  };

  return (
    <div
      style={{
        minWidth,
        background: '#263326',
        border: `2px solid ${selected ? '#86efac' : accentColor}`,
        borderRadius: 10,
        boxShadow: selected
          ? `0 0 0 1px #86efac, 0 8px 32px rgba(0,0,0,0.7)`
          : `0 4px 24px rgba(0,0,0,0.6)`,
        position: 'relative',
        overflow: 'visible',
      }}
    >
      {/* Header */}
      <div
        style={{
          background: accentColor,
          borderRadius: '8px 8px 0 0',
          minHeight: 34,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          padding: '0 8px',
          gap: 8,
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, minWidth: 0 }}>
          <span style={{ color: 'rgba(255,255,255,0.9)', flexShrink: 0, display: 'flex' }}>{icon}</span>
          <span style={{ color: '#fff', fontSize: 12, fontWeight: 700, letterSpacing: '0.05em', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
            {title}
          </span>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 2, flexShrink: 0 }}>
          <HeaderBtn title="Help" onClick={() => setShowHelp(v => !v)}>
            <HelpCircle size={12} />
          </HeaderBtn>
          <HeaderBtn title={collapsed ? 'Expand' : 'Minimize'} onClick={() => setCollapsed(v => !v)}>
            {collapsed ? <ChevronDown size={12} /> : <Minus size={12} />}
          </HeaderBtn>
          <HeaderBtn title="Delete node" onClick={handleDelete} danger>
            <X size={12} />
          </HeaderBtn>
        </div>
      </div>

      {/* Help tooltip */}
      {showHelp && (
        <div
          style={{
            position: 'absolute',
            top: 38,
            right: 0,
            zIndex: 50,
            minWidth: 220,
            maxWidth: 300,
            background: '#1a2a1a',
            border: `1px solid ${accentColor}`,
            borderRadius: 8,
            padding: '10px 12px',
            boxShadow: '0 8px 24px rgba(0,0,0,0.6)',
          }}
        >
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
            <span style={{ color: '#86efac', fontSize: 11, fontWeight: 700 }}>{title}</span>
            <button onClick={() => setShowHelp(false)} style={{ color: '#4a6a4a', background: 'none', border: 'none', cursor: 'pointer', padding: 0 }}>
              <X size={11} />
            </button>
          </div>
          <p style={{ color: '#a7c4a7', fontSize: 11, lineHeight: 1.6, margin: 0 }}>
            {helpText ?? 'Bu node hakkında bilgi mevcut değil.'}
          </p>
        </div>
      )}

      {/* Collapsible body */}
      {!collapsed && (
        <>
          <div style={{ padding: '10px 12px 6px' }}>{children}</div>

          {/* Progress bar */}
          <div style={{ padding: '4px 12px 10px' }}>
            {error && (
              <p style={{ color: '#f87171', fontSize: 10, marginBottom: 4, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                {error}
              </p>
            )}
            <div style={{ width: '100%', height: 16, borderRadius: 4, overflow: 'hidden', background: '#1a2a1a', border: '1px solid #3a5a3a' }}>
              <div
                style={{
                  width: `${progress}%`,
                  height: '100%',
                  background: progressColor,
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  color: '#fff',
                  fontSize: 10,
                  fontWeight: 700,
                  transition: 'width 0.5s ease',
                  minWidth: progress > 0 ? 28 : 0,
                }}
              >
                {progress > 15 ? `${progress}%` : ''}
              </div>
            </div>
          </div>
        </>
      )}

      {/* Collapsed: slim progress line */}
      {collapsed && (
        <div style={{ height: 3, background: progressColor, borderRadius: '0 0 8px 8px', opacity: 0.8 }} />
      )}
    </div>
  );
}

function HeaderBtn({ children, title, onClick, danger }: { children: React.ReactNode; title: string; onClick: () => void; danger?: boolean }) {
  const [hover, setHover] = useState(false);
  return (
    <button
      title={title}
      onClick={onClick}
      onMouseEnter={() => setHover(true)}
      onMouseLeave={() => setHover(false)}
      style={{
        background: hover ? (danger ? 'rgba(239,68,68,0.25)' : 'rgba(255,255,255,0.15)') : 'transparent',
        border: 'none',
        cursor: 'pointer',
        color: hover && danger ? '#fca5a5' : 'rgba(255,255,255,0.8)',
        padding: '3px 4px',
        borderRadius: 4,
        display: 'flex',
        alignItems: 'center',
        transition: 'background 0.15s, color 0.15s',
      }}
    >
      {children}
    </button>
  );
}
