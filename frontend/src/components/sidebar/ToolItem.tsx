import { PaletteItem } from '../../types/nodes';

interface ToolItemProps {
  item: PaletteItem;
}

export function ToolItem({ item }: ToolItemProps) {
  const onDragStart = (event: React.DragEvent) => {
    event.dataTransfer.setData('application/reactflow', item.nodeType);
    if (item.algorithmId) {
      event.dataTransfer.setData('application/algorithm-id', item.algorithmId);
    }
    event.dataTransfer.effectAllowed = 'move';
  };

  return (
    <div
      draggable
      onDragStart={onDragStart}
      className="flex items-start gap-2.5 p-2.5 rounded-lg cursor-grab active:cursor-grabbing select-none transition-all hover:brightness-125 active:scale-95"
      style={{
        background: '#1a2a1a',
        border: `1px solid ${item.color}40`,
        borderLeft: `3px solid ${item.color}`,
      }}
      title={item.description}
    >
      <span className="text-lg leading-none mt-0.5">{item.icon}</span>
      <div className="min-w-0">
        <p className="text-xs font-semibold text-white leading-tight">{item.label}</p>
        <p className="text-[10px] text-gray-400 mt-0.5 leading-snug">{item.description}</p>
      </div>
    </div>
  );
}
