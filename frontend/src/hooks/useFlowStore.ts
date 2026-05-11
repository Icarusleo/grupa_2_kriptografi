import { useCallback, useState } from 'react';
import {
  useNodesState,
  useEdgesState,
  addEdge,
  Node,
  Edge,
  Connection,
} from '@xyflow/react';
import { encryptAlgorithm, hashAlgorithm } from '../api/grain128api';
import type { EncodedValue } from '../api/grain128api';
import { textToBytes, bytesToHex } from '../crypto/utils';
import {
  InputNodeData,
  KeyNodeData,
  Grain128NodeData,
  AlgorithmNodeData,
  HashNodeData,
  OutputNodeData,
} from '../types/nodes';
import { getAlgorithm } from '../types/algorithms';
import type { AlgorithmId } from '../types/algorithms';

const initialNodes: Node[] = [];
const initialEdges: Edge[] = [];

function zeroPadHex(hex: string, targetBytes: number): string {
  return hex.padEnd(targetBytes * 2, '0');
}

function buildEdgeMap(edges: Edge[]) {
  const map = new Map<string, { sourceHandle: string; targetHandle: string; sourceNodeId: string }[]>();
  for (const edge of edges) {
    if (!edge.target || !edge.targetHandle || !edge.sourceHandle) continue;
    const list = map.get(edge.target) ?? [];
    list.push({
      sourceHandle: edge.sourceHandle,
      targetHandle: edge.targetHandle,
      sourceNodeId: edge.source,
    });
    map.set(edge.target, list);
  }
  return map;
}

function inputNodeToEncoded(id: InputNodeData, applyPadding: boolean): EncodedValue {
  if (id.format === 'hex') {
    let hex = id.value.replace(/\s/g, '');
    if (applyPadding && Math.floor(hex.length / 2) < 16) {
      hex = zeroPadHex(hex, 16);
    }
    return { value: hex, encoding: 'hex' };
  }
  if (applyPadding) {
    const bytes = textToBytes(id.value);
    if (bytes.length < 16) {
      let hex = bytesToHex(bytes);
      hex = zeroPadHex(hex, 16);
      return { value: hex, encoding: 'hex' };
    }
  }
  return { value: id.value, encoding: 'utf8' };
}

/** Gather key/iv/plaintext/ad from incoming edges for any algorithm node */
function gatherAlgoInputs(
  nodeId: string,
  nodeMap: Map<string, Node>,
  edgesByTarget: Map<string, { sourceHandle: string; targetHandle: string; sourceNodeId: string }[]>
) {
  const incomingEdges = edgesByTarget.get(nodeId) ?? [];
  let keyInput: string | undefined;
  let ivInput: string | undefined;
  let plaintextEncoded: EncodedValue | undefined;
  let adEncoded: EncodedValue = { value: '', encoding: 'hex' };

  for (const edge of incomingEdges) {
    const sourceNode = nodeMap.get(edge.sourceNodeId);
    if (!sourceNode) continue;

    if (edge.targetHandle === 'key' && sourceNode.type === 'keyNode') {
      keyInput = (sourceNode.data as unknown as KeyNodeData).keyValue;
    }
    if (edge.targetHandle === 'iv' && sourceNode.type === 'keyNode') {
      ivInput = (sourceNode.data as unknown as KeyNodeData).ivValue;
    }
    const isInputSource = sourceNode.type === 'inputNode' || sourceNode.type === 'adInputNode';
    if (edge.targetHandle === 'plaintext' && isInputSource) {
      const id = sourceNode.data as unknown as InputNodeData;
      plaintextEncoded = inputNodeToEncoded(id, id.padding);
    }
    if (edge.targetHandle === 'ad' && isInputSource) {
      const id = sourceNode.data as unknown as InputNodeData;
      adEncoded = inputNodeToEncoded(id, false);
    }
  }

  return { keyInput, ivInput, plaintextEncoded, adEncoded };
}

export function useFlowStore() {
  const [nodes, setNodes, onNodesChange] = useNodesState(initialNodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(initialEdges);
  const [showPaddingWarning, setShowPaddingWarning] = useState(false);
  const [isRunning, setIsRunning] = useState(false);

  const onConnect = useCallback(
    (params: Connection) => setEdges((eds) => addEdge({ ...params, animated: true }, eds)),
    [setEdges]
  );

  /** Sync all algorithmNodes to a new algorithm selection */
  const syncAlgorithm = useCallback(
    (algorithmId: AlgorithmId) => {
      setNodes((nds) =>
        nds.map((n) =>
          n.type === 'algorithmNode'
            ? {
                ...n,
                data: {
                  ...n.data,
                  algorithm: algorithmId,
                  processed: false,
                  progress: 0,
                  error: undefined,
                  ciphertextOutput: undefined,
                  tagOutput: undefined,
                  ciphertextBase64: undefined,
                  tagBase64: undefined,
                  nistCiphertextWithTag: undefined,
                  coreInputPreview: null,
                  lfsrState: new Array(128).fill(0),
                  nfsrState: new Array(128).fill(0),
                },
              }
            : n
        )
      );
    },
    [setNodes]
  );

  const executePipeline = useCallback(async () => {
    setIsRunning(true);

    try {
      const nodeMap = new Map(nodes.map((n) => [n.id, n]));
      const edgesByTarget = buildEdgeMap(edges);
      const updatedNodes: Node[] = nodes.map((n) => ({ ...n }));

      for (let i = 0; i < updatedNodes.length; i++) {
        const node = updatedNodes[i];

        // ── InputNode / adInputNode / KeyNode ───────────────────────────────
        if (node.type === 'inputNode' || node.type === 'adInputNode' || node.type === 'keyNode') {
          updatedNodes[i] = {
            ...node,
            data: { ...node.data, progress: 100, processed: true, error: undefined } as Record<string, unknown>,
          };
          nodeMap.set(node.id, updatedNodes[i]);
          continue;
        }

        // ── Legacy Grain128Node ──────────────────────────────────────────────
        if (node.type === 'grain128Node') {
          const gData = node.data as unknown as Grain128NodeData;
          const { keyInput, ivInput, plaintextEncoded, adEncoded } = gatherAlgoInputs(node.id, nodeMap, edgesByTarget);

          if (!keyInput || !ivInput || !plaintextEncoded) {
            updatedNodes[i] = { ...node, data: { ...gData, error: 'Missing inputs. Connect Key, IV, and Plaintext.', progress: 0, processed: false } as unknown as Record<string, unknown> };
            nodeMap.set(node.id, updatedNodes[i]);
            continue;
          }
          if (!/^[0-9a-fA-F]{32}$/.test(keyInput)) {
            updatedNodes[i] = { ...node, data: { ...gData, error: 'Key must be 32 hex chars (128 bit)', progress: 0, processed: false } as unknown as Record<string, unknown> };
            nodeMap.set(node.id, updatedNodes[i]);
            continue;
          }
          if (!/^[0-9a-fA-F]{24}$/.test(ivInput)) {
            updatedNodes[i] = { ...node, data: { ...gData, error: 'IV must be 24 hex chars (96 bit)', progress: 0, processed: false } as unknown as Record<string, unknown> };
            nodeMap.set(node.id, updatedNodes[i]);
            continue;
          }

          try {
            const result = await encryptAlgorithm('grain128aead', {
              key: { value: keyInput, encoding: 'hex' },
              nonce: { value: ivInput, encoding: 'hex' },
              plaintext: plaintextEncoded,
              associated_data: adEncoded,
              output_encoding: 'hex',
              include_core_input_preview: true,
            });
            updatedNodes[i] = {
              ...node,
              data: {
                ...gData,
                keyInput, ivInput,
                plaintextInput: plaintextEncoded.value,
                adInput: adEncoded.value || undefined,
                ciphertextOutput: result.ciphertext.hex,
                ciphertextBase64: result.ciphertext.base64,
                tagOutput: result.tag.hex,
                tagBase64: result.tag.base64,
                nistCiphertextWithTag: result.nist_ciphertext_with_tag.hex,
                implemented: result.implemented,
                apiMessage: result.message,
                coreInputPreview: result.core_input_preview ?? null,
                lfsrState: new Array(128).fill(0),
                nfsrState: new Array(128).fill(0),
                currentRound: 0,
                progress: 100, processed: true, error: undefined,
              } as unknown as Record<string, unknown>,
            };
          } catch (e) {
            updatedNodes[i] = { ...node, data: { ...gData, error: `API Error: ${String(e)}`, progress: 0, processed: false } as unknown as Record<string, unknown> };
          }
          nodeMap.set(node.id, updatedNodes[i]);
          continue;
        }

        // ── AlgorithmNode (Grain-128 AEAD / GIFT-COFB / ISAP / ASCON) ───────
        if (node.type === 'algorithmNode') {
          const aData = node.data as unknown as AlgorithmNodeData;
          const algo = getAlgorithm(aData.algorithm ?? 'grain128aead');
          const { keyInput, ivInput, plaintextEncoded, adEncoded } = gatherAlgoInputs(node.id, nodeMap, edgesByTarget);

          if (!keyInput || !ivInput || !plaintextEncoded) {
            updatedNodes[i] = { ...node, data: { ...aData, error: 'Missing inputs. Connect Key, IV, and Plaintext.', progress: 0, processed: false } as unknown as Record<string, unknown> };
            nodeMap.set(node.id, updatedNodes[i]);
            continue;
          }

          const keyHexLen = algo.keyBits / 4;
          const keyPattern = new RegExp(`^[0-9a-fA-F]{${keyHexLen}}$`);
          if (!keyPattern.test(keyInput)) {
            updatedNodes[i] = { ...node, data: { ...aData, error: `Key must be ${keyHexLen} hex chars (${algo.keyBits} bit)`, progress: 0, processed: false } as unknown as Record<string, unknown> };
            nodeMap.set(node.id, updatedNodes[i]);
            continue;
          }

          const ivHexLen = algo.ivBits / 4;
          const ivPattern = new RegExp(`^[0-9a-fA-F]{${ivHexLen}}$`);
          if (!ivPattern.test(ivInput)) {
            updatedNodes[i] = { ...node, data: { ...aData, error: `IV must be ${ivHexLen} hex chars (${algo.ivBits} bit)`, progress: 0, processed: false } as unknown as Record<string, unknown> };
            nodeMap.set(node.id, updatedNodes[i]);
            continue;
          }

          try {
            const isGrain = algo.id === 'grain128aead';
            const result = await encryptAlgorithm(algo.id, {
              key: { value: keyInput, encoding: 'hex' },
              nonce: { value: ivInput, encoding: 'hex' },
              plaintext: plaintextEncoded,
              associated_data: adEncoded,
              output_encoding: 'hex',
              include_core_input_preview: isGrain,
            });
            updatedNodes[i] = {
              ...node,
              data: {
                ...aData,
                keyInput, ivInput,
                plaintextInput: plaintextEncoded.value,
                adInput: adEncoded.value || undefined,
                ciphertextOutput: result.ciphertext.hex,
                ciphertextBase64: result.ciphertext.base64,
                tagOutput: result.tag.hex,
                tagBase64: result.tag.base64,
                nistCiphertextWithTag: result.nist_ciphertext_with_tag.hex,
                implemented: result.implemented,
                apiMessage: result.message,
                coreInputPreview: isGrain ? (result.core_input_preview ?? null) : null,
                lfsrState: new Array(128).fill(0),
                nfsrState: new Array(128).fill(0),
                currentRound: 0,
                progress: 100, processed: true, error: undefined,
              } as unknown as Record<string, unknown>,
            };
          } catch (e) {
            updatedNodes[i] = { ...node, data: { ...aData, error: `API Error: ${String(e)}`, progress: 0, processed: false } as unknown as Record<string, unknown> };
          }
          nodeMap.set(node.id, updatedNodes[i]);
          continue;
        }

        // ── HashNode (SHA-3 family) ─────────────────────────────────────────
        if (node.type === 'hashNode') {
          const hData = node.data as unknown as HashNodeData;
          const incomingEdges = edgesByTarget.get(node.id) ?? [];

          let messageEncoded: EncodedValue | undefined;
          for (const edge of incomingEdges) {
            const sourceNode = nodeMap.get(edge.sourceNodeId);
            if (!sourceNode) continue;
            const isInputSource = sourceNode.type === 'inputNode' || sourceNode.type === 'adInputNode';
            if (edge.targetHandle === 'message' && isInputSource) {
              const id = sourceNode.data as unknown as InputNodeData;
              // Hash: do NOT zero-pad — preserve the exact message bytes
              messageEncoded = inputNodeToEncoded(id, false);
            }
          }

          if (!messageEncoded) {
            updatedNodes[i] = {
              ...node,
              data: { ...hData, error: 'Plaintext Input bağla (Message handle).', progress: 0, processed: false } as unknown as Record<string, unknown>,
            };
            nodeMap.set(node.id, updatedNodes[i]);
            continue;
          }

          try {
            const hashReq: Parameters<typeof hashAlgorithm>[1] = {
              message: messageEncoded,
              output_encoding: 'hex',
              output_length: hData.outputLength,
            };
            // BLAKE2 (RFC 7693) parameter block — sadece blake2b/blake2s için gönder
            if (hData.algorithm === 'blake2b' || hData.algorithm === 'blake2s') {
              if (hData.blake2Key)    hashReq.key    = { value: hData.blake2Key,    encoding: 'hex' };
              if (hData.blake2Salt)   hashReq.salt   = { value: hData.blake2Salt,   encoding: 'hex' };
              if (hData.blake2Person) hashReq.person = { value: hData.blake2Person, encoding: 'hex' };
            }
            const result = await hashAlgorithm(hData.algorithm, hashReq);
            updatedNodes[i] = {
              ...node,
              data: {
                ...hData,
                messageInput: messageEncoded.value,
                digestOutput: result.digest.hex,
                digestBase64: result.digest.base64,
                digestBits: result.digest.bit_length,
                implemented: result.implemented,
                apiMessage: result.message,
                progress: 100,
                processed: true,
                error: undefined,
              } as unknown as Record<string, unknown>,
            };
          } catch (e) {
            updatedNodes[i] = {
              ...node,
              data: { ...hData, error: `API Error: ${String(e)}`, progress: 0, processed: false } as unknown as Record<string, unknown>,
            };
          }
          nodeMap.set(node.id, updatedNodes[i]);
          continue;
        }

        // ── OutputNode ───────────────────────────────────────────────────────
        if (node.type === 'outputNode') {
          const oData = node.data as unknown as OutputNodeData;
          const incomingEdges = edgesByTarget.get(node.id) ?? [];

          let ciphertextInput: string | undefined;
          let ciphertextBase64: string | undefined;
          let tagInput: string | undefined;
          let tagBase64: string | undefined;
          let nistCiphertextWithTag: string | undefined;
          let implemented: boolean | undefined;

          for (const edge of incomingEdges) {
            const sourceNode = nodeMap.get(edge.sourceNodeId);
            if (!sourceNode) continue;

            const isAlgoSource =
              sourceNode.type === 'grain128Node' || sourceNode.type === 'algorithmNode';
            const isHashSource = sourceNode.type === 'hashNode';

            if (edge.targetHandle === 'ciphertext' && isAlgoSource) {
              const d = sourceNode.data as unknown as { ciphertextOutput?: string; ciphertextBase64?: string; nistCiphertextWithTag?: string; implemented?: boolean };
              ciphertextInput = d.ciphertextOutput;
              ciphertextBase64 = d.ciphertextBase64;
              nistCiphertextWithTag = d.nistCiphertextWithTag;
              implemented = d.implemented;
            }
            if (edge.targetHandle === 'tag' && isAlgoSource) {
              const d = sourceNode.data as unknown as { tagOutput?: string; tagBase64?: string };
              tagInput = d.tagOutput;
              tagBase64 = d.tagBase64;
            }
            // Hash digest can be routed into the Output node's "ciphertext" slot
            if (edge.targetHandle === 'ciphertext' && isHashSource) {
              const d = sourceNode.data as unknown as { digestOutput?: string; digestBase64?: string; implemented?: boolean };
              ciphertextInput = d.digestOutput;
              ciphertextBase64 = d.digestBase64;
              implemented = d.implemented;
            }
          }

          updatedNodes[i] = {
            ...node,
            data: {
              ...oData,
              ciphertextInput,
              ciphertextBase64,
              tagInput,
              tagBase64,
              nistCiphertextWithTag,
              implemented,
              progress: ciphertextInput ? 100 : 0,
              processed: !!ciphertextInput,
            } as unknown as Record<string, unknown>,
          };
          nodeMap.set(node.id, updatedNodes[i]);
        }
      }

      setNodes(updatedNodes);
    } finally {
      setIsRunning(false);
    }
  }, [nodes, edges, setNodes]);

  const runPipeline = useCallback(() => {
    for (const node of nodes) {
      if (node.type === 'inputNode') {
        const id = node.data as unknown as InputNodeData;
        // Only warn for plaintext nodes — AD has no minimum size requirement
        if (id.outputType !== 'plaintext') continue;
        if (!id.padding && id.value) {
          const rawHex =
            id.format === 'hex'
              ? id.value.replace(/\s/g, '')
              : bytesToHex(textToBytes(id.value));
          const byteLen = Math.floor(rawHex.length / 2);
          if (byteLen > 0 && byteLen < 16) {
            setShowPaddingWarning(true);
            return;
          }
        }
      }
    }
    executePipeline();
  }, [nodes, executePipeline]);

  const confirmPaddingRun = useCallback(() => {
    setShowPaddingWarning(false);
    executePipeline();
  }, [executePipeline]);

  const clearAll = useCallback(() => {
    setNodes([]);
    setEdges([]);
  }, [setNodes, setEdges]);

  return {
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
    syncAlgorithm,
  };
}
