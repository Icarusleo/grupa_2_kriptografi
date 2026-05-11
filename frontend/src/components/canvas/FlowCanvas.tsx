import { useCallback, useRef } from 'react';
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  BackgroundVariant,
  ReactFlowInstance,
  Node,
  NodeChange,
  EdgeChange,
  Connection,
  Edge,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';

import { InputNode } from '../nodes/InputNode';
import { KeyNode } from '../nodes/KeyNode';
import { Grain128Node } from '../nodes/Grain128Node';
import { AlgorithmNode } from '../nodes/AlgorithmNode';
import { HashNode } from '../nodes/HashNode';
import { OutputNode } from '../nodes/OutputNode';
import { NodeType } from '../../types/nodes';
import { getAlgorithm } from '../../types/algorithms';
import type { AlgorithmId } from '../../types/algorithms';
import { randomHex } from '../../crypto/utils';

const nodeTypes = {
  inputNode: InputNode,
  adInputNode: InputNode,   // same component, default outputType:'ad'
  keyNode: KeyNode,
  grain128Node: Grain128Node,
  algorithmNode: AlgorithmNode,
  hashNode: HashNode,
  outputNode: OutputNode,
};

function makeDefaultData(type: NodeType, algorithmId: string) {
  switch (type) {
    case 'inputNode':
      return { label: 'Text Input', type: 'input', value: '', format: 'text', padding: false, progress: 0, processed: false, outputType: 'plaintext' };
    case 'adInputNode':
      return { label: 'AD Input', type: 'input', value: '', format: 'text', padding: false, progress: 0, processed: false, outputType: 'ad' };
    case 'keyNode':
      return { label: 'Key / IV', type: 'key', keyBits: 128, ivBits: 96, keyValue: randomHex(16), ivValue: randomHex(12), progress: 0, processed: false };
    case 'grain128Node':
      return { label: 'GRAIN-128 AEAD', type: 'grain128', progress: 0, processed: false, lfsrState: new Array(128).fill(0), nfsrState: new Array(128).fill(0), currentRound: 0 };
    case 'algorithmNode':
      return { label: algorithmId, type: 'algorithm', algorithm: algorithmId, progress: 0, processed: false, lfsrState: new Array(128).fill(0), nfsrState: new Array(128).fill(0), currentRound: 0 };
    case 'hashNode': {
      const algo = getAlgorithm(algorithmId as AlgorithmId);
      // XOF / değişken çıktı: digestBits varsa onu kullan (BLAKE2b=64B, BLAKE2s=32B), yoksa 32B
      const defaultLen = algo.isXof
        ? (algo.digestBits ? algo.digestBits / 8 : 32)
        : (algo.digestBits ?? 256) / 8;
      return {
        label: algo.name,
        type: 'hash',
        algorithm: algo.id,
        outputLength: defaultLen,
        blake2Key: '',
        blake2Salt: '',
        blake2Person: '',
        progress: 0,
        processed: false,
      };
    }
    case 'outputNode':
      return { label: 'Output', type: 'output', format: 'hex', progress: 0, processed: false };
  }
}

interface FlowCanvasProps {
  nodes: Node[];
  edges: Edge[];
  onNodesChange: (changes: NodeChange[]) => void;
  onEdgesChange: (changes: EdgeChange[]) => void;
  onConnect: (connection: Connection) => void;
  onAddNode: (node: Node) => void;
  onRun: () => void;
  onClear: () => void;
  isRunning?: boolean;
}

export function FlowCanvas({
  nodes,
  edges,
  onNodesChange,
  onEdgesChange,
  onConnect,
  onAddNode,
  onRun,
  onClear,
  isRunning = false,
}: FlowCanvasProps) {
  const rfInstanceRef = useRef<ReactFlowInstance | null>(null);

  const onDragOver = useCallback((event: React.DragEvent) => {
    event.preventDefault();
    event.dataTransfer.dropEffect = 'move';
  }, []);

  const onDrop = useCallback(
    (event: React.DragEvent) => {
      event.preventDefault();
      const nodeType = event.dataTransfer.getData('application/reactflow') as NodeType;
      const algorithmId = event.dataTransfer.getData('application/algorithm-id') || 'grain128aead';
      if (!nodeType || !rfInstanceRef.current) return;

      const position = rfInstanceRef.current.screenToFlowPosition({
        x: event.clientX,
        y: event.clientY,
      });

      const newNode: Node = {
        id: `${nodeType}-${Date.now()}`,
        type: nodeType,
        position,
        data: makeDefaultData(nodeType, algorithmId) as unknown as Record<string, unknown>,
      };

      onAddNode(newNode);
    },
    [onAddNode]
  );

  return (
    <div className="relative w-full h-full">
      {/* Toolbar */}
      <div className="absolute top-3 right-3 flex gap-2" style={{ zIndex: 10 }}>
        <button
          onClick={onRun}
          disabled={isRunning}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-sm font-semibold transition-all hover:brightness-110 active:scale-95"
          style={{
            background: isRunning
              ? 'linear-gradient(135deg, #166534, #14532d)'
              : 'linear-gradient(135deg, #16a34a, #15803d)',
            color: isRunning ? '#86efac88' : '#fff',
            border: '1px solid #4ade80',
            boxShadow: '0 2px 8px rgba(22,163,74,0.4)',
            cursor: isRunning ? 'not-allowed' : 'pointer',
            opacity: isRunning ? 0.7 : 1,
          }}
        >
          {isRunning ? '⏳ Running…' : '▶ Run'}
        </button>
        <button
          onClick={onClear}
          className="px-3 py-1.5 rounded-lg text-sm font-semibold transition-all hover:brightness-110 active:scale-95"
          style={{
            background: '#2a1a1a',
            color: '#f87171',
            border: '1px solid #7f1d1d',
          }}
        >
          Clear
        </button>
      </div>

      <ReactFlow
        nodes={nodes}
        edges={edges}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        onConnect={onConnect}
        onInit={(instance) => { rfInstanceRef.current = instance; }}
        onDrop={onDrop}
        onDragOver={onDragOver}
        nodeTypes={nodeTypes}
        fitView
        deleteKeyCode="Delete"
        multiSelectionKeyCode="Shift"
        style={{ background: '#1a1f1a' }}
        defaultEdgeOptions={{
          animated: true,
          style: { stroke: '#4a7a4a', strokeWidth: 2 },
        }}
      >
        <Background
          variant={BackgroundVariant.Dots}
          gap={20}
          size={1}
          color="#2a3a2a"
        />
        <Controls position="bottom-right" showInteractive={false} />
        <MiniMap
          position="bottom-left"
          nodeColor={(n) => {
            if (n.type === 'inputNode') return '#3a6a5a';
            if (n.type === 'adInputNode') return '#6a6a1a';
            if (n.type === 'keyNode') return '#5a4a8a';
            if (n.type === 'grain128Node') return '#5a6a3a';
            if (n.type === 'algorithmNode') return '#5a6a3a';
            if (n.type === 'hashNode') return '#6a5a1a';
            if (n.type === 'outputNode') return '#6a3a3a';
            return '#4a7a4a';
          }}
          maskColor="rgba(17, 22, 17, 0.7)"
        />
      </ReactFlow>

      {nodes.length === 0 && (
        <div
          className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none"
          style={{ zIndex: 5 }}
        >
          <div
            className="text-center p-6 rounded-xl"
            style={{
              background: 'rgba(42,58,42,0.6)',
              border: '2px dashed #4a7a4a',
              maxWidth: 320,
            }}
          >
            <p className="text-2xl mb-2">⚙️</p>
            <p className="text-green-300 font-semibold mb-1">Canvas Boş</p>
            <p className="text-green-600 text-sm">
              Sol paneldeki araçları buraya sürükle-bırak ile ekle ve birbirine bağla.
            </p>
          </div>
        </div>
      )}
    </div>
  );
}
