import React, { useEffect, useRef, useState } from 'react';
import cytoscape, { Core } from 'cytoscape';
import {
  ZoomIn,
  ZoomOut,
  Maximize2,
  RefreshCw,
  Search,
  Filter,
} from 'lucide-react';
import { CytoscapeGraphData, CytoscapeNode, CytoscapeEdge } from '../../types/investigation';

interface IntelligenceGraphProps {
  data: CytoscapeGraphData;
  highlightedNodeIds?: string[];
  highlightedEdgeIds?: string[];
  onSelectNode: (node: CytoscapeNode['data'] | null) => void;
  onSelectEdge: (edge: CytoscapeEdge['data'] | null) => void;
  className?: string;
}

export type GraphCategory = 'All' | 'Email Addresses' | 'Domains' | 'URLs' | 'IPs' | 'Files' | 'Relays';

const categories: { label: GraphCategory; color: string }[] = [
  { label: 'All', color: '#94A3B8' },
  { label: 'Email Addresses', color: '#3B82F6' },
  { label: 'Domains', color: '#10B981' },
  { label: 'URLs', color: '#F59E0B' },
  { label: 'IPs', color: '#EF4444' },
  { label: 'Files', color: '#EC4899' },
  { label: 'Relays', color: '#06B6D4' },
];

const isNodeMatchingCategory = (type: string, category: GraphCategory): boolean => {
  if (category === 'All') return true;
  const t = (type || '').toLowerCase();
  switch (category) {
    case 'Email Addresses':
      return t === 'email' || t === 'emailaddress' || t === 'person';
    case 'Domains':
      return t === 'domain';
    case 'URLs':
      return t === 'url';
    case 'IPs':
      return t === 'ip' || t === 'ipaddress';
    case 'Files':
      return t === 'attachment' || t === 'filehash' || t === 'file';
    case 'Relays':
      return t === 'mailserver' || t === 'relay' || t === 'server';
    default:
      return false;
  }
};

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
  const [activeCategory, setActiveCategory] = useState<GraphCategory>('All');
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

  // Initialize and update Cytoscape
  useEffect(() => {
    if (!containerRef.current) return;

    // Preserve all nodes to maintain force-directed graph topology; filter only by search term if active
    const visibleNodes = data.nodes.filter((n) => {
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
      ...visibleNodes.map((n) => {
        const isZeroDay =
          (n.data.type === 'Domain' || n.data.type === 'URL') &&
          (Boolean((n.data as any).is_zero_day) ||
            Boolean((n.data as any).is_lookalike) ||
            ((n.data as any).risk_score != null && (n.data as any).risk_score >= 70) ||
            /corp-bankofamerica|micros0ft|portal-verification|supplier-invoices/i.test(n.data.label));

        return {
          group: 'nodes' as const,
          data: {
            ...n.data,
            label: isZeroDay && n.data.type === 'Domain' ? `⚠️ [0-DAY DOMAIN]\n${n.data.label}` : n.data.label,
            is_zero_day: isZeroDay,
            color: isZeroDay ? '#DC2626' : getTypeColor(n.data.type),
          },
        };
      }),
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
              'text-wrap': 'wrap',
              'text-max-width': '130px',
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
            selector: 'node[?is_zero_day]',
            style: {
              'background-color': '#DC2626',
              'border-color': '#EF4444',
              'border-width': 4,
              'border-opacity': 1,
              color: '#FCA5A5',
              'font-weight': 'bold',
              'text-wrap': 'wrap',
              'text-max-width': '140px',
              'text-background-color': '#450A0A',
              'text-background-opacity': 0.95,
              'text-background-padding': '4px',
              width: 56,
              height: 56,
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
          {
            selector: '.filter-match',
            style: {
              opacity: 1.0,
              'border-width': 4,
              'border-color': '#38BDF8',
              'border-opacity': 1,
              events: 'yes',
            },
          },
          {
            selector: '.filter-context',
            style: {
              opacity: 0.65,
              events: 'yes',
            },
          },
          {
            selector: '.filter-dimmed',
            style: {
              opacity: 0.15,
              events: 'no',
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
  }, [data, layoutName, searchTerm, onSelectNode, onSelectEdge]);

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

  // Category filter isolation effect: matching (1.0), 1-hop connected (0.65), unrelated (0.15)
  useEffect(() => {
    if (!cyRef.current) return;
    const cy = cyRef.current;
    cy.elements().removeClass('filter-match filter-context filter-dimmed');

    if (activeCategory === 'All') {
      return;
    }

    const matchingNodes = cy.nodes().filter((node) => {
      const type = node.data('type') || '';
      return isNodeMatchingCategory(type, activeCategory);
    });

    if (matchingNodes.length === 0) return;

    const neighborhood = matchingNodes.neighborhood();
    const contextElements = neighborhood.difference(matchingNodes);
    const dimmedElements = cy.elements().difference(matchingNodes).difference(neighborhood);

    matchingNodes.addClass('filter-match');
    contextElements.addClass('filter-context');
    dimmedElements.addClass('filter-dimmed');
  }, [activeCategory, data, searchTerm]);

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
    setActiveCategory('All');
    cyRef.current.elements().removeClass('highlighted dimmed filter-match filter-context filter-dimmed');
    cyRef.current.reset();
    cyRef.current.fit(undefined, 30);
    onSelectNode(null);
    onSelectEdge(null);
  };

  return (
    <div className={`bg-[#0D1117] border border-[#263244] rounded-lg flex flex-col overflow-hidden relative ${className}`}>
      {/* Top Toolbar */}
      <div className="bg-[#111827] border-b border-[#263244] px-3 py-2 flex flex-wrap items-center justify-between gap-3 text-xs font-mono">
        {/* Entity Category Filter Chips */}
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="text-2xs uppercase text-gray-400 font-semibold mr-1 flex items-center gap-1">
            <Filter className="w-3 h-3" /> Filters:
          </span>
          {categories.map(({ label, color }) => {
            const isActive = activeCategory === label;
            return (
              <button
                key={label}
                onClick={() => setActiveCategory(label)}
                className={`px-2.5 py-1 rounded text-2xs font-mono font-semibold transition flex items-center gap-1.5 border ${
                  isActive
                    ? 'bg-[#1E293B] text-sky-300 border-sky-400 shadow-sm shadow-sky-500/25 ring-1 ring-sky-500/50'
                    : 'bg-[#151E2E] text-gray-400 border-[#263244] hover:text-gray-200 hover:border-gray-500'
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
          {/* Quick Search */}
          <div className="relative flex items-center">
            <Search className="w-3 h-3 text-gray-400 absolute left-2 pointer-events-none" />
            <input
              type="text"
              placeholder="Search..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="pl-6 pr-2 py-0.5 bg-[#151E2E] border border-[#263244] rounded text-2xs text-gray-200 placeholder-gray-500 focus:outline-none focus:border-purple-500 w-24 sm:w-28 font-mono"
            />
          </div>

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
