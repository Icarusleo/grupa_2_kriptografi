import { ReactFlowProvider } from '@xyflow/react';
import { Sidebar } from './components/sidebar/Sidebar';
import { AlgorithmSelector } from './components/sidebar/AlgorithmSelector';
import { FlowCanvas } from './components/canvas/FlowCanvas';
import { useFlowStore } from './hooks/useFlowStore';

function PaddingWarningModal({ onConfirm }: { onConfirm: () => void }) {
  return (
    <div
      style={{
        position: 'fixed',
        inset: 0,
        zIndex: 1000,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        background: 'rgba(0,0,0,0.6)',
        backdropFilter: 'blur(2px)',
      }}
    >
      <div
        style={{
          background: '#1a2a1a',
          border: '1.5px solid #fbbf24',
          borderRadius: 12,
          padding: '28px 32px',
          maxWidth: 380,
          width: '90%',
          boxShadow: '0 8px 32px rgba(0,0,0,0.6)',
          textAlign: 'center',
        }}
      >
        <div style={{ fontSize: 32, marginBottom: 12 }}>⚠️</div>
        <div style={{
          fontSize: 14, fontWeight: 700, color: '#fbbf24',
          marginBottom: 10, fontFamily: 'monospace',
        }}>
          Plaintext 128 Bitten Az
        </div>
        <div style={{
          fontSize: 12, color: '#a0b0a0', marginBottom: 24, lineHeight: 1.6,
        }}>
          Girilen plaintext 128 bit (16 byte) altında.
          <br />
          Padding seçeneği kapalı — veri olduğu gibi kullanılacak.
          <br /><br />
          Yine de devam etmek istiyor musunuz?
        </div>
        <button
          onClick={onConfirm}
          style={{
            padding: '9px 36px',
            borderRadius: 8,
            border: '1.5px solid #4ade80',
            background: 'linear-gradient(135deg, #16a34a, #15803d)',
            color: '#fff',
            fontSize: 13, fontWeight: 700,
            cursor: 'pointer',
            fontFamily: 'monospace',
            boxShadow: '0 2px 8px rgba(22,163,74,0.35)',
          }}
        >
          Evet
        </button>
      </div>
    </div>
  );
}

function AppInner() {
  const {
    nodes,
    edges,
    onNodesChange,
    onEdgesChange,
    onConnect,
    runPipeline,
    confirmPaddingRun,
    showPaddingWarning,
    isRunning,
    clearAll,
    setNodes,
  } = useFlowStore();

  return (
    <div className="flex w-full h-full overflow-hidden" style={{ background: '#1a1f1a' }}>
      <Sidebar />
      <main className="flex-1 relative overflow-hidden">
        <FlowCanvas
          nodes={nodes}
          edges={edges}
          onNodesChange={onNodesChange}
          onEdgesChange={onEdgesChange}
          onConnect={onConnect}
          onAddNode={(node) => setNodes((nds) => nds.concat(node))}
          onRun={runPipeline}
          onClear={clearAll}
          isRunning={isRunning}
        />
      </main>
      <AlgorithmSelector />
      {showPaddingWarning && <PaddingWarningModal onConfirm={confirmPaddingRun} />}
    </div>
  );
}

export default function App() {
  return (
    <ReactFlowProvider>
      <AppInner />
    </ReactFlowProvider>
  );
}
