import React, { useMemo } from 'react';
import { SecurityGraph as GraphData } from '../types';

interface Props {
  graph: GraphData | null;
  height?: number;
}

export const SecurityGraphView: React.FC<Props> = ({ graph, height = 280 }) => {
  const width = 640;

  const layout = useMemo(() => {
    if (!graph || graph.nodes.length === 0) return null;

    const users = graph.nodes.filter(n => n.type === 'user');
    const ips = graph.nodes.filter(n => n.type === 'ip');
    const cx = width / 2;
    const cy = height / 2;

    const positions: Record<string, { x: number; y: number }> = {};

    // Left cluster: users, right cluster: IPs
    users.forEach((n, i) => {
      const spread = Math.min(users.length * 50, height - 60);
      const startY = cy - spread / 2;
      positions[n.id] = { x: 120 + Math.random() * 40, y: startY + (i / Math.max(users.length - 1, 1)) * spread };
    });

    ips.forEach((n, i) => {
      const spread = Math.min(ips.length * 50, height - 60);
      const startY = cy - spread / 2;
      positions[n.id] = { x: width - 120 - Math.random() * 40, y: startY + (i / Math.max(ips.length - 1, 1)) * spread };
    });

    return { positions, users, ips };
  }, [graph, height]);

  if (!layout || !graph) {
    return (
      <div className="w-full flex flex-col items-center justify-center opacity-20 py-12" style={{ minHeight: height }}>
        <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
          <circle cx="12" cy="12" r="10" />
          <line x1="12" y1="8" x2="12" y2="16" />
          <line x1="8" y1="12" x2="16" y2="12" />
        </svg>
        <p className="mt-3 text-xs font-medium tracking-wider uppercase">Run pipeline to populate graph</p>
      </div>
    );
  }

  return (
    <div className="w-full rounded-xl bg-bg-secondary/40 border border-border/40 relative overflow-hidden" style={{ minHeight: height }}>
      <svg width="100%" height={height} viewBox={`0 0 ${width} ${height}`} className="block">
        <defs>
          <linearGradient id="edgeGrad" x1="0%" y1="0%" x2="100%" y2="0%">
            <stop offset="0%" stopColor="#8AB4F8" stopOpacity="0.4" />
            <stop offset="100%" stopColor="#F28B82" stopOpacity="0.4" />
          </linearGradient>
          <filter id="nodeGlow">
            <feGaussianBlur stdDeviation="3" result="blur" />
            <feMerge><feMergeNode in="blur" /><feMergeNode in="SourceGraphic" /></feMerge>
          </filter>
        </defs>

        {/* Edges */}
        {graph.edges.map((edge, i) => {
          const s = layout.positions[edge.source];
          const t = layout.positions[edge.target];
          if (!s || !t) return null;
          const mx = (s.x + t.x) / 2;
          const my = (s.y + t.y) / 2 + (i % 2 === 0 ? -15 : 15);
          return (
            <path
              key={i}
              d={`M ${s.x} ${s.y} Q ${mx} ${my} ${t.x} ${t.y}`}
              stroke="url(#edgeGrad)"
              strokeWidth="1.2"
              fill="none"
              strokeDasharray={edge.status === 'FAILURE' ? '4 3' : 'none'}
            />
          );
        })}

        {/* User Nodes */}
        {layout.users.map((node) => {
          const pos = layout.positions[node.id];
          return (
            <g key={node.id} filter="url(#nodeGlow)">
              <circle cx={pos.x} cy={pos.y} r="8" fill="#8AB4F8" opacity="0.15" />
              <circle cx={pos.x} cy={pos.y} r="5" fill="#8AB4F8" />
              <text x={pos.x} y={pos.y - 12} textAnchor="middle" fill="#8AB4F8" fontSize="9" fontFamily="var(--font-mono)" fontWeight="700" opacity="0.8">
                {node.id}
              </text>
            </g>
          );
        })}

        {/* IP Nodes */}
        {layout.ips.map((node) => {
          const pos = layout.positions[node.id];
          return (
            <g key={node.id} filter="url(#nodeGlow)">
              <rect x={pos.x - 6} y={pos.y - 6} width="12" height="12" rx="3" fill="#F28B82" opacity="0.15" />
              <rect x={pos.x - 4} y={pos.y - 4} width="8" height="8" rx="2" fill="#F28B82" />
              <text x={pos.x} y={pos.y + 18} textAnchor="middle" fill="#F28B82" fontSize="8" fontFamily="var(--font-mono)" fontWeight="700" opacity="0.7">
                {node.id}
              </text>
            </g>
          );
        })}
      </svg>

      {/* Legend */}
      <div className="absolute bottom-3 left-3 flex gap-4 text-[9px] font-bold uppercase tracking-wider">
        <span className="flex items-center gap-1.5 text-accent">
          <span className="w-2 h-2 rounded-full bg-accent" /> Identities
        </span>
        <span className="flex items-center gap-1.5 text-danger">
          <span className="w-2 h-2 rounded bg-danger" /> Endpoints
        </span>
      </div>
    </div>
  );
};
