import { createContext, useContext, useState, ReactNode } from 'react';
import type { AlgorithmId } from '../types/algorithms';

interface AlgorithmContextType {
  selectedAlgorithm: AlgorithmId;
  setSelectedAlgorithm: (id: AlgorithmId) => void;
}

const AlgorithmContext = createContext<AlgorithmContextType>({
  selectedAlgorithm: 'grain128aead',
  setSelectedAlgorithm: () => {},
});

export function AlgorithmProvider({ children }: { children: ReactNode }) {
  const [selectedAlgorithm, setSelectedAlgorithm] = useState<AlgorithmId>('grain128aead');
  return (
    <AlgorithmContext.Provider value={{ selectedAlgorithm, setSelectedAlgorithm }}>
      {children}
    </AlgorithmContext.Provider>
  );
}

export const useAlgorithm = () => useContext(AlgorithmContext);
