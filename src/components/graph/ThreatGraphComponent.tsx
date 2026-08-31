import React, { useEffect, useRef, useState } from 'react';
import cytoscape, { Core, NodeSingular } from 'cytoscape';
import { GraphData, GraphNode, NodeType } from '../../types/graph';
import { ThreatSeverity } from '../../types/threat';
import { SeverityBadge } from '../common/SeverityBadge';
import {
  ZoomIn,
  ZoomOut,
  Maximize2,
  RefreshCw,
  Search,
  Filter,
  X,
  ArrowRight,
  ExternalLink,
  Layers,
  Info,
} from 'lucide-react';
import { useNavigate } from 'react-router-dom';

interface ThreatGraphComponentProps {
  data: GraphData;
  onSelectNode?: (node: GraphNode | null) => void;
  className?: string;
}

export const ThreatGraphComponent: React.FC<ThreatGraphComponentProps> = ({
  data,
  onSelectNode,
  className,
}) => {
  const containerRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<Core | null>(null);
  const navigate = useNavigate();

  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [layoutName, setLayoutName] = useState<'cose' | 'concentric' | 'circle' | 'breadthfirst' | 'grid'>('cose');
  const [selectedTypes, setSelectedTypes] = useState<NodeType[]>([
    'case',
    'campaign',
    'email',
    'domain',
    'url',
    'ip',
  ]);

  // Color mapping by entity type
  const getTypeColor = (type: NodeType) => {
    switch (type) {
      case 'case':
        return '#8B5CF6'; // Purple
      case 'campaign':
        return '#EC4899'; // Pink
      case 'email':
        return '#3B82F6'; // Blue
      case 'domain':
        return '#10B981'; // Green
      case 'url':
        return '#F59E0B'; // Amber
      case 'ip':
        return '#EF4444'; // Red
      default:
        return '#64748B';
    }
  };

  const toggleTypeFilter = (type: NodeType) => {
    setSelectedTypes((prev) =>
      prev.includes(type) ? prev.filter((t) => t !== type) : [...prev, type]
    );
  };

  // Initialize Cytoscape
  useEffect(() => {
    if (!containerRef.current) return;

    // Filter nodes and edges
    const visibleNodes = data.nodes.filter((n) => {
      if (!selectedTypes.includes(n.type)) return false;
      if (searchTerm.trim() && !n.label.toLowerCase().includes(searchTerm.toLowerCase())) return false;
      return true;
    });

    const visibleNodeIds = new Set(visibleNodes.map((n) => n.id));
    const visibleEdges = data.edges.filter(
      (e) => visibleNodeIds.has(e.source) && visibleNodeIds.has(e.target)
    );

    const elements: cytoscape.ElementDefinition[] = [
      ...visibleNodes.map((n) => ({
        group: 'nodes' as const,
        data: {
          id: n.id,
          label: n.label,
          type: n.type,
          severity: n.severity,
          riskScore: n.riskScore,
          color: getTypeColor(n.type),
          rawNode: n,
        },
      })),
      ...visibleEdges.map((e) => ({
        group: 'edges' as const,
        data: {
          id: e.id,
          source: e.source,
          target: e.target,
          label: e.label.replace('_', ' '),
        },
      })),
    ];

    if (cyRef.current) {
      cyRef.current.destroy();
    }

    const cy = cytoscape({
      container: containerRef.current,
      elements,
      style: [
        {
          selector: 'node',
          style: {
            'background-color': 'data(color)',
            label: 'data(label)',
            color: '#E2E8F0',
            'font-family': 'JetBrains Mono, monospace',
            'font-size': '10px',
            'text-valign': 'bottom',
            'text-margin-y': 6,
            'text-background-color': '#0B1120',
            'text-background-opacity': 0.8,
            'text-background-padding': '3px',
            'text-background-shape': 'roundrectangle',
            width: 32,
            height: 32,
            'border-width': 2,
            'border-color': '#263244',
            'transition-property': 'background-color, border-color, width, height',
            'transition-duration': 0.2,
          },
        },
        {
          selector: 'node[type="case"]',
          style: {
            shape: 'diamond',
            width: 42,
            height: 42,
          },
        },
        {
          selector: 'node[type="campaign"]',
          style: {
            shape: 'hexagon',
            width: 38,
            height: 38,
          },
        },
        {
          selector: 'node[type="ip"]',
          style: {
            shape: 'rectangle',
            width: 34,
            height: 34,
          },
        },
        {
          selector: 'node:selected',
          style: {
            'border-color': '#60A5FA',
            'border-width': 4,
            'border-opacity': 1,
          },
        },
        {
          selector: 'edge',
          style: {
            width: 1.5,
            'line-color': '#263244',
            'target-arrow-color': '#3B82F6',
            'target-arrow-shape': 'triangle',
            'curve-style': 'bezier',
            label: 'data(label)',
            'font-family': 'JetBrains Mono, monospace',
            'font-size': '8px',
            color: '#94A3B8',
            'text-background-color': '#0B1120',
            'text-background-opacity': 0.85,
            'text-background-padding': '2px',
            'text-rotation': 'autorotate',
            'arrow-scale': 0.8,
          },
        },
        {
          selector: 'edge:selected',
          style: {
            'line-color': '#3B82F6',
            width: 2.5,
          },
        },
      ],
      layout: {
        name: layoutName,
        padding: 50,
        animate: true,
        animationDuration: 500,
      } as cytoscape.LayoutOptions,
    });

    cy.on('tap', 'node', (evt) => {
      const nodeSingular = evt.target as NodeSingular;
      const raw = nodeSingular.data('rawNode') as GraphNode;
      setSelectedNode(raw);
      if (onSelectNode) onSelectNode(raw);
    });

    cy.on('tap', (evt) => {
      if (evt.target === cy) {
        setSelectedNode(null);
        if (onSelectNode) onSelectNode(null);
      }
    });

    cyRef.current = cy;

    return () => {
      if (cyRef.current) {
        cyRef.current.destroy();
        cyRef.current = null;
      }
    };
  }, [data, selectedTypes, searchTerm, layoutName, onSelectNode]);

  const handleZoomIn = () => cyRef.current?.zoom(cyRef.current.zoom() * 1.25);
  const handleZoomOut = () => cyRef.current?.zoom(cyRef.current.zoom() * 0.8);
  const handleFit = () => cyRef.current?.fit(undefined, 40);
  const handleResetLayout = () => {
    cyRef.current?.layout({ name: layoutName, animate: true } as cytoscape.LayoutOptions).run();
  };

  return (
    <div className={`relative flex flex-col h-full w-full rounded-lg border border-[#263244] overflow-hidden bg-[#0B1120] ${className}`}>
      {/* Top Filter & Toolbar Bar */}
      <div className="bg-[#111827] border-b border-[#263244] p-3 flex flex-wrap items-center justify-between gap-3 z-10 font-mono">
        <div className="flex flex-wrap items-center gap-3">
          {/* Search Node */}
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-gray-400 absolute left-2.5 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Search graph nodes..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="bg-[#151E2E] border border-[#263244] text-gray-200 text-xs rounded pl-8 pr-2.5 py-1 focus:outline-none focus:border-blue-500 w-44"
            />
          </div>

          {/* Layout Selector */}
          <div className="flex items-center gap-1 text-xs">
            <span className="text-gray-400 text-2xs uppercase">Layout:</span>
            <select
              value={layoutName}
              onChange={(e) => setLayoutName(e.target.value as any)}
              className="bg-[#151E2E] border border-[#263244] text-gray-200 text-xs rounded px-2 py-1 focus:outline-none"
            >
              <option value="cose">Force Directed (CoSE)</option>
              <option value="concentric">Concentric Rings</option>
              <option value="circle">Circular</option>
              <option value="breadthfirst">Hierarchical Tree</option>
              <option value="grid">Grid Array</option>
            </select>
          </div>

          {/* Entity Type Toggles */}
          <div className="hidden lg:flex items-center gap-1">
            {(['case', 'campaign', 'email', 'domain', 'url', 'ip'] as NodeType[]).map((type) => {
              const active = selectedTypes.includes(type);
              const color = getTypeColor(type);
              return (
                <button
                  key={type}
                  onClick={() => toggleTypeFilter(type)}
                  className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase transition border ${
                    active
                      ? 'bg-[#151E2E] text-gray-100'
                      : 'bg-transparent text-gray-500 border-transparent line-through'
                  }`}
                  style={{ borderColor: active ? color : 'transparent' }}
                >
                  <span className="inline-block w-1.5 h-1.5 rounded-full mr-1" style={{ backgroundColor: color }} />
                  {type}
                </button>
              );
            })}
          </div>
        </div>

        {/* Graph Controls: Zoom & Reset */}
        <div className="flex items-center gap-1.5">
          <button
            onClick={handleZoomIn}
            className="p-1.5 rounded bg-[#151E2E] hover:bg-[#1E293B] border border-[#263244] text-gray-300 transition"
            title="Zoom In"
          >
            <ZoomIn className="w-3.5 h-3.5" />
          </button>
          <button
            onClick={handleZoomOut}
            className="p-1.5 rounded bg-[#151E2E] hover:bg-[#1E293B] border border-[#263244] text-gray-300 transition"
            title="Zoom Out"
          >
            <ZoomOut className="w-3.5 h-3.5" />
          </button>
          <button
            onClick={handleFit}
            className="p-1.5 rounded bg-[#151E2E] hover:bg-[#1E293B] border border-[#263244] text-gray-300 transition"
            title="Fit to Screen"
          >
            <Maximize2 className="w-3.5 h-3.5" />
          </button>
          <button
            onClick={handleResetLayout}
            className="p-1.5 rounded bg-[#151E2E] hover:bg-[#1E293B] border border-[#263244] text-gray-300 transition"
            title="Re-run Layout"
          >
            <RefreshCw className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* Graph Canvas & Side Inspector */}
      <div className="relative flex-1 min-h-[500px] w-full">
        <div ref={containerRef} className="absolute inset-0 w-full h-full" />

        {/* Selected Node Inspector Drawer */}
        {selectedNode && (
          <div className="absolute top-4 right-4 w-80 bg-[#151E2E]/95 backdrop-blur-md border border-[#263244] rounded-lg shadow-2xl p-4 z-10 animate-in fade-in slide-in-from-right-4 space-y-3 font-mono">
            <div className="flex items-start justify-between border-b border-[#263244] pb-2.5">
              <div className="space-y-0.5">
                <span className="text-[10px] uppercase tracking-wider text-gray-400 font-bold block">
                  Node Entity Inspector
                </span>
                <h4 className="text-xs font-bold text-gray-100 break-all">{selectedNode.label}</h4>
              </div>
              <button
                onClick={() => setSelectedNode(null)}
                className="text-gray-400 hover:text-gray-200 p-1"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="flex items-center justify-between">
              <span className="text-xs text-gray-400">Entity Type:</span>
              <span
                className="px-2 py-0.5 rounded text-2xs font-bold uppercase text-white"
                style={{ backgroundColor: `${getTypeColor(selectedNode.type)}44`, border: `1px solid ${getTypeColor(selectedNode.type)}` }}
              >
                {selectedNode.type}
              </span>
            </div>

            <div className="flex items-center justify-between">
              <span className="text-xs text-gray-400">Threat Severity:</span>
              <SeverityBadge severity={selectedNode.severity} size="sm" />
            </div>

            {selectedNode.riskScore !== undefined && (
              <div className="flex items-center justify-between">
                <span className="text-xs text-gray-400">Risk Assessment:</span>
                <span className="text-xs font-bold text-red-400">{selectedNode.riskScore}/100</span>
              </div>
            )}

            {selectedNode.metadata.details && (
              <div className="p-2.5 rounded bg-[#0B1120] border border-[#263244] text-xs text-gray-300 font-sans leading-relaxed">
                {selectedNode.metadata.details}
              </div>
            )}

            {/* Entity Specific Jump Action */}
            <div className="pt-2 border-t border-[#263244]">
              {selectedNode.type === 'email' && (
                <button
                  onClick={() => navigate(`/analyze/${selectedNode.id}`)}
                  className="w-full flex items-center justify-center gap-1.5 py-1.5 bg-blue-600 hover:bg-blue-500 text-white rounded text-xs font-semibold transition"
                >
                  <span>Open Email Forensic View</span>
                  <ExternalLink className="w-3.5 h-3.5" />
                </button>
              )}
              {selectedNode.type === 'case' && (
                <button
                  onClick={() => navigate(`/cases/${selectedNode.id}`)}
                  className="w-full flex items-center justify-center gap-1.5 py-1.5 bg-purple-600 hover:bg-purple-500 text-white rounded text-xs font-semibold transition"
                >
                  <span>Open Case Workspace</span>
                  <ExternalLink className="w-3.5 h-3.5" />
                </button>
              )}
              {selectedNode.type === 'ip' && (
                <button
                  onClick={() => navigate('/map')}
                  className="w-full flex items-center justify-center gap-1.5 py-1.5 bg-[#1E293B] hover:bg-[#263244] text-gray-200 border border-[#263244] rounded text-xs transition"
                >
                  <span>Locate On Threat Map</span>
                  <ExternalLink className="w-3.5 h-3.5 text-blue-400" />
                </button>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
