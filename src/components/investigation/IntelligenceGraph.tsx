import React, { useEffect, useRef, useState } from 'react';
import cytoscape, { Core } from 'cytoscape';
import {
  ZoomIn,
  ZoomOut,
  Maximize2,
  RefreshCw,
  Search,
  Filter,
  Layers,
  Info,
  Shield,
  FileCode,
  Link,
  Globe,
  Server,
  User,
  Mail,
  HardDrive,
} from 'lucide-react';
import { CytoscapeGraphData, CytoscapeNode, CytoscapeEdge, EntityType } from '../../types/investigation';

interface IntelligenceGraphProps {
  data: CytoscapeGraphData;
  highlightedNodeIds?: string[];
  highlightedEdgeIds?: string[];
  onSelectNode: (node: CytoscapeNode['data'] | null) => void;
  onSelectEdge: (edge: CytoscapeEdge['data'] | null) => void;
  className?: string;
}

export const IntelligenceGraph: React.FC<IntelligenceGraphProps> = ({
  data,
  highlightedNodeIds = [],
  highlightedEdgeIds = [],
  onSelectNode,
  onSelectEdge,
  className = '',
}) => {
  const containerRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<Core | null>(null);

  const [layoutName, setLayoutName] = useState<'cose' | 'concentric' | 'circle' | 'breadthfirst'>('cose');
  const [selectedTypes, setSelectedTypes] = useState<EntityType[]>([
    'Email',
    'EmailAddress',
    'Domain',
    'URL',
    'IP',
    'Attachment',
    'FileHash',
    'MailServer',
    'Person',
  ]);
  const [searchTerm, setSearchTerm] = useState('');

  const getTypeColor = (type: string) => {
    switch (type) {
      case 'Email':
        return '#8B5CF6'; // Purple
      case 'EmailAddress':
        return '#3B82F6'; // Blue
      case 'Domain':
        return '#10B981'; // Emerald
      case 'URL':
        return '#F59E0B'; // Amber
      case 'IP':
        return '#EF4444'; // Red
      case 'Attachment':
        return '#EC4899'; // Pink
      case 'FileHash':
        return '#6366F1'; // Indigo
      case 'MailServer':
        return '#06B6D4'; // Cyan
      case 'Person':
        return '#F97316'; // Orange
      default:
        return '#64748B'; // Slate
    }
  };

  const toggleTypeFilter = (type: EntityType) => {
    setSelectedTypes((prev) =>
      prev.includes(type) ? prev.filter((t) => t !== type) : [...prev, type]
    );
  };

  // Initialize and update Cytoscape
  useEffect(() => {
    if (!containerRef.current) return;

    // Filter nodes by enabled types and search
    const visibleNodes = data.nodes.filter((n) => {
      if (!selectedTypes.includes(n.data.type as EntityType)) return false;
      if (searchTerm.trim() && !n.data.label.toLowerCase().includes(searchTerm.toLowerCase())) {
        return false;
      }
      return true;
    });

    const visibleNodeIds = new Set(visibleNodes.map((n) => n.data.id));
    const visibleEdges = data.edges.filter(
      (e) => visibleNodeIds.has(e.data.source) && visibleNodeIds.has(e.data.target)
    );

    const elements: cytoscape.ElementDefinition[] = [
      ...visibleNodes.map((n) => ({
        group: 'nodes' as const,
        data: {
          ...n.data,
          color: getTypeColor(n.data.type),
        },
      })),
      ...visibleEdges.map((e) => ({
        group: 'edges' as const,
        data: {
          ...e.data,
        },
      })),
    ];

    const getLayoutConfig = (name: string) => {
      if (name === 'cose') {
        return {
          name: 'cose',
          animate: true,
          animationDuration: 500,
          padding: 50,
          nodeRepulsion: () => 8000,
          idealEdgeLength: () => 120,
          edgeElasticity: () => 100,
          gravity: 0.25,
          numIter: 1000,
          initialTemp: 200,
          coolingFactor: 0.95,
        };
      }
      return {
        name,
        animate: true,
        animationDuration: 400,
        padding: 40,
      };
    };

    if (!cyRef.current) {
      cyRef.current = cytoscape({
        container: containerRef.current,
        elements,
        style: [
          {
            selector: 'node',
            style: {
              'background-color': 'data(color)',
              label: 'data(label)',
              color: '#F3F4F6',
              'font-size': '11px',
              'font-family': 'JetBrains Mono, monospace',
              'text-valign': 'bottom',
              'text-margin-y': 8,
              'text-wrap': 'ellipsis',
              'text-max-width': '120px',
              'text-background-color': '#0F172A',
              'text-background-opacity': 0.9,
              'text-background-padding': '3px',
              'text-background-shape': 'roundrectangle',
              shape: 'ellipse',
              width: 48,
              height: 48,
              'border-width': 2,
              'border-color': '#1E293B',
              'transition-property': 'background-color, border-color, border-width, opacity',
              'transition-duration': 0.2,
            },
          },
          {
            selector: 'node[type = "Email"]',
            style: {
              shape: 'roundrectangle',
              width: 56,
              height: 56,
              'border-color': '#C084FC',
              'border-width': 3,
            },
          },
          {
            selector: 'node[type = "Domain"]',
            style: {
              shape: 'roundrectangle',
              width: 48,
              height: 48,
            },
          },
          {
            selector: 'node[type = "IP"], node[type = "IPAddress"]',
            style: {
              shape: 'roundrectangle',
              width: 46,
              height: 46,
            },
          },
          {
            selector: 'node[?is_suspicious]',
            style: {
              'border-color': '#EF4444',
              'border-width': 3,
            },
          },
          {
            selector: 'node[?is_origin]',
            style: {
              'border-color': '#F59E0B',
              'border-width': 3,
            },
          },
          {
            selector: 'edge',
            style: {
              width: 1.5,
              'line-color': '#334155',
              'target-arrow-color': '#334155',
              'target-arrow-shape': 'triangle',
              'curve-style': 'bezier',
              label: 'data(label)',
              'font-size': '8px',
              'font-family': 'monospace',
              color: '#94A3B8',
              'text-background-color': '#0F172A',
              'text-background-opacity': 0.9,
              'text-background-padding': '1px',
              'text-rotation': 'autorotate',
              'arrow-scale': 0.8,
            },
          },
          {
            selector: '.highlighted',
            style: {
              'border-color': '#A855F7',
              'border-width': 4,
              'line-color': '#A855F7',
              'target-arrow-color': '#A855F7',
              width: 3,
              opacity: 1.0,
            },
          },
          {
            selector: '.dimmed',
            style: {
              opacity: 0.2,
            },
          },
        ],
        layout: getLayoutConfig(layoutName) as any,
        minZoom: 0.2,
        maxZoom: 3.0,
      });

      // Bind node selection
      cyRef.current.on('tap', 'node', (evt) => {
        const node = evt.target;
        onSelectNode(node.data());
      });

      // Bind edge selection
      cyRef.current.on('tap', 'edge', (evt) => {
        const edge = evt.target;
        onSelectEdge(edge.data());
      });

      // Background click resets selection
      cyRef.current.on('tap', (evt) => {
        if (evt.target === cyRef.current) {
          onSelectNode(null);
          onSelectEdge(null);
        }
      });
    } else {
      // Sync elements
      const cy = cyRef.current;
      cy.elements().remove();
      cy.add(elements);
      cy.layout(getLayoutConfig(layoutName) as any).run();
    }
  }, [data, selectedTypes, layoutName, searchTerm]);

  // Apply finding / path highlights dynamically
  useEffect(() => {
    if (!cyRef.current) return;
    const cy = cyRef.current;

    cy.elements().removeClass('highlighted dimmed');

    const hasHighlight = highlightedNodeIds.length > 0 || highlightedEdgeIds.length > 0;
    if (hasHighlight) {
      cy.elements().addClass('dimmed');

      highlightedNodeIds.forEach((id) => {
        cy.getElementById(id).removeClass('dimmed').addClass('highlighted');
      });

      highlightedEdgeIds.forEach((id) => {
        cy.getElementById(id).removeClass('dimmed').addClass('highlighted');
      });
    }
  }, [highlightedNodeIds, highlightedEdgeIds]);

  const handleFit = () => {
    cyRef.current?.fit(undefined, 30);
  };

  const handleZoomIn = () => {
    if (!cyRef.current) return;
    cyRef.current.zoom(cyRef.current.zoom() * 1.25);
  };

  const handleZoomOut = () => {
    if (!cyRef.current) return;
    cyRef.current.zoom(cyRef.current.zoom() * 0.8);
  };

  const handleReset = () => {
    if (!cyRef.current) return;
    cyRef.current.elements().removeClass('highlighted dimmed');
    cyRef.current.reset();
    cyRef.current.fit(undefined, 30);
    onSelectNode(null);
    onSelectEdge(null);
  };

  const allEntityTypes: { type: EntityType; label: string; icon: any }[] = [
    { type: 'Email', label: 'Email', icon: Mail },
    { type: 'EmailAddress', label: 'Addresses', icon: User },
    { type: 'Domain', label: 'Domains', icon: Globe },
    { type: 'URL', label: 'URLs', icon: Link },
    { type: 'IP', label: 'IPs', icon: Server },
    { type: 'Attachment', label: 'Files', icon: HardDrive },
    { type: 'MailServer', label: 'Relays', icon: Layers },
  ];

  return (
    <div className={`bg-[#0D1117] border border-[#263244] rounded-lg flex flex-col overflow-hidden relative ${className}`}>
      {/* Top Toolbar */}
      <div className="bg-[#111827] border-b border-[#263244] px-3 py-2 flex flex-wrap items-center justify-between gap-3 text-xs font-mono">
        {/* Entity Type Toggle Chips */}
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="text-2xs uppercase text-gray-400 font-semibold mr-1 flex items-center gap-1">
            <Filter className="w-3 h-3" /> Filters:
          </span>
          {allEntityTypes.map(({ type, label }) => {
            const isSelected = selectedTypes.includes(type);
            const color = getTypeColor(type);
            return (
              <button
                key={type}
                onClick={() => toggleTypeFilter(type)}
                className={`px-2 py-0.5 rounded text-2xs transition flex items-center gap-1.5 border ${
                  isSelected
                    ? 'bg-[#151E2E] text-gray-200 border-[#263244]'
                    : 'bg-transparent text-gray-400 border-transparent opacity-40 hover:opacity-75'
                }`}
              >
                <span className="w-2 h-2 rounded-full" style={{ backgroundColor: color }} />
                <span>{label}</span>
              </button>
            );
          })}
        </div>

        {/* Layout & Zoom Controls */}
        <div className="flex items-center gap-2">
          {/* Layout Selector */}
          <select
            value={layoutName}
            onChange={(e) => setLayoutName(e.target.value as any)}
            className="bg-[#151E2E] border border-[#263244] text-gray-200 text-2xs rounded px-2 py-1 focus:outline-none focus:border-purple-500"
          >
            <option value="cose">Force-Directed (COSE)</option>
            <option value="concentric">Concentric</option>
            <option value="breadthfirst">Hierarchical</option>
            <option value="circle">Circular</option>
          </select>

          <div className="flex items-center border border-[#263244] rounded bg-[#151E2E]">
            <button
              onClick={handleZoomIn}
              className="p-1 hover:bg-[#1E293B] text-gray-300 transition"
              title="Zoom In"
            >
              <ZoomIn className="w-3.5 h-3.5" />
            </button>
            <button
              onClick={handleZoomOut}
              className="p-1 hover:bg-[#1E293B] text-gray-300 transition border-l border-[#263244]"
              title="Zoom Out"
            >
              <ZoomOut className="w-3.5 h-3.5" />
            </button>
            <button
              onClick={handleFit}
              className="p-1 hover:bg-[#1E293B] text-gray-300 transition border-l border-[#263244]"
              title="Fit Viewport"
            >
              <Maximize2 className="w-3.5 h-3.5" />
            </button>
            <button
              onClick={handleReset}
              className="p-1 hover:bg-[#1E293B] text-gray-300 transition border-l border-[#263244]"
              title="Reset Graph"
            >
              <RefreshCw className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      </div>

      {/* Main Cytoscape Canvas */}
      <div ref={containerRef} className="flex-1 w-full min-h-[420px] bg-[#0A0E17]" />

      {/* Bottom Graph Stats Footer */}
      <div className="bg-[#111827]/90 backdrop-blur border-t border-[#263244] px-3 py-1.5 flex items-center justify-between text-2xs font-mono text-gray-400">
        <div className="flex items-center gap-3">
          <span>Nodes: <strong className="text-gray-200">{data.node_count}</strong></span>
          <span>•</span>
          <span>Edges: <strong className="text-purple-300">{data.edge_count}</strong></span>
        </div>
        <div className="flex items-center gap-2 text-3xs text-gray-400">
          <span>Click node or edge to inspect evidentiary provenance</span>
        </div>
      </div>
    </div>
  );
};
