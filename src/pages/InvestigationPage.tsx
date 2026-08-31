import React, { useState, useEffect, useCallback } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import {
  InvestigationDetail,
  CytoscapeGraphData,
  CytoscapeNode,
  CytoscapeEdge,
  InvestigationFinding,
  ThreatPath,
} from '../types/investigation';
import { investigationService } from '../services/investigationService';
import { InvestigationHeader } from '../components/investigation/InvestigationHeader';
import { ThreatSummary } from '../components/investigation/ThreatSummary';
import { IntelligenceGraph } from '../components/investigation/IntelligenceGraph';
import { FindingsPanel } from '../components/investigation/FindingsPanel';
import { EntityDetailsDrawer } from '../components/investigation/EntityDetailsDrawer';
import { RelationshipDetailsDrawer } from '../components/investigation/RelationshipDetailsDrawer';
import { ThreatPathsSection } from '../components/investigation/ThreatPathsSection';
import { InvestigationTimeline } from '../components/investigation/InvestigationTimeline';
import { EntitySearchModal } from '../components/investigation/EntitySearchModal';
import { LoadingState } from '../components/common/LoadingState';
import { AlertTriangle, RefreshCw, GitFork } from 'lucide-react';

export const InvestigationPage: React.FC = () => {
  const { investigationId } = useParams<{ investigationId: string }>();
  const navigate = useNavigate();

  const [investigation, setInvestigation] = useState<InvestigationDetail | null>(null);
  const [graphData, setGraphData] = useState<CytoscapeGraphData | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Active Selections & Highlights
  const [selectedNode, setSelectedNode] = useState<CytoscapeNode['data'] | null>(null);
  const [selectedEdge, setSelectedEdge] = useState<CytoscapeEdge['data'] | null>(null);
  const [activeFinding, setActiveFinding] = useState<InvestigationFinding | null>(null);
  const [activePath, setActivePath] = useState<ThreatPath | null>(null);
  const [isSearchOpen, setIsSearchOpen] = useState(false);

  // Highlighted IDs on the Cytoscape graph
  const [highlightedNodeIds, setHighlightedNodeIds] = useState<string[]>([]);
  const [highlightedEdgeIds, setHighlightedEdgeIds] = useState<string[]>([]);

  const loadData = useCallback(async (force = false) => {
    if (!investigationId) return;

    try {
      if (force) {
        setRefreshing(true);
      } else {
        setLoading(true);
      }
      setError(null);

      // 1. Trigger or Fetch Investigation
      const invData = await investigationService.createInvestigation(
        investigationId,
        force,
        'direct'
      );
      setInvestigation(invData);

      // 2. Fetch Graph Data
      const gData = await investigationService.getInvestigationGraph(
        invData.investigation_id
      );
      setGraphData(gData);
    } catch (err: any) {
      console.error('Failed to load investigation:', err);
      setError(err.message || 'Unable to construct threat investigation graph.');
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, [investigationId]);

  useEffect(() => {
    loadData(false);
  }, [loadData]);

  // Synchronize Highlights when Finding is selected
  const handleSelectFinding = (finding: InvestigationFinding | null) => {
    setActiveFinding(finding);
    setActivePath(null);
    if (finding) {
      setHighlightedNodeIds(finding.entity_ids || []);
      setHighlightedEdgeIds(finding.relationship_ids || []);
    } else {
      setHighlightedNodeIds([]);
      setHighlightedEdgeIds([]);
    }
  };

  // Synchronize Highlights when Threat Path is selected
  const handleSelectPath = (path: ThreatPath | null) => {
    setActivePath(path);
    setActiveFinding(null);
    if (path) {
      setHighlightedNodeIds(path.node_ids || []);
      setHighlightedEdgeIds(path.edge_ids || []);
    } else {
      setHighlightedNodeIds([]);
      setHighlightedEdgeIds([]);
    }
  };

  // When node is clicked
  const handleSelectNode = (node: CytoscapeNode['data'] | null) => {
    setSelectedNode(node);
    if (node) {
      setSelectedEdge(null);
    }
  };

  // When edge is clicked
  const handleSelectEdge = (edge: CytoscapeEdge['data'] | null) => {
    setSelectedEdge(edge);
    if (edge) {
      setSelectedNode(null);
    }
  };

  // Select entity by ID (from drawer or finding badge)
  const handleSelectEntityById = (entityId: string) => {
    if (!graphData) return;
    const found = graphData.nodes.find((n) => n.data.id === entityId);
    if (found) {
      setSelectedNode(found.data);
      setSelectedEdge(null);
      setHighlightedNodeIds([entityId]);
    }
  };

  if (loading && !investigation) {
    return (
      <div className="space-y-4 max-w-7xl mx-auto py-6">
        <LoadingState message="Constructing multi-entity graph, calculating threat paths, and synthesizing findings..." />
        <div className="bg-[#111827] border border-[#263244] rounded-lg p-6 max-w-md mx-auto text-center font-mono">
          <div className="flex items-center justify-center gap-2 text-xs text-purple-400 mb-2">
            <RefreshCw className="w-4 h-4 animate-spin" />
            <span>Processing Stages:</span>
          </div>
          <div className="text-2xs text-gray-400 space-y-1 text-left px-4">
            <p className="text-emerald-400">✓ Loading Task 01 structured analysis record</p>
            <p className="text-emerald-400">✓ Normalizing email, domain, URL, IP & hash entities</p>
            <p className="text-emerald-400">✓ Generating provenance-rich typed relationships</p>
            <p className="text-purple-300 animate-pulse">► Synchronizing Neo4j intelligence graph</p>
            <p className="text-gray-500">○ Evaluating findings & security threat paths</p>
          </div>
        </div>
      </div>
    );
  }

  if (error || !investigation) {
    return (
      <div className="max-w-xl mx-auto py-12 text-center font-mono">
        <div className="bg-[#111827] border border-rose-800/60 rounded-xl p-8 shadow-xl">
          <AlertTriangle className="w-10 h-10 text-rose-400 mx-auto mb-3" />
          <h2 className="text-base font-bold text-gray-100">Investigation Unavailable</h2>
          <p className="text-xs text-gray-300 mt-2 font-sans">{error || 'Investigation record not found.'}</p>
          <div className="mt-6 flex items-center justify-center gap-3">
            <button
              onClick={() => navigate('/threats')}
              className="px-3 py-1.5 rounded bg-[#151E2E] border border-[#263244] text-gray-300 text-xs hover:bg-[#1E293B] transition"
            >
              Back to Threats Feed
            </button>
            <button
              onClick={() => loadData(true)}
              className="px-3 py-1.5 rounded bg-purple-600 hover:bg-purple-500 text-white text-xs font-semibold transition flex items-center gap-1.5"
            >
              <RefreshCw className="w-3.5 h-3.5" />
              <span>Retry Pipeline</span>
            </button>
          </div>
        </div>
      </div>
    );
  }

  const findings = investigation.summary?.top_findings || [];
  const paths = investigation.summary?.key_threat_paths || [];
  const timelineEvents = investigation.summary?.timeline || [];

  return (
    <div className="space-y-4 pb-12 max-w-[1600px] mx-auto">
      {/* Top Header Bar */}
      <InvestigationHeader
        investigation={investigation}
        onRefresh={() => loadData(true)}
        onOpenSearch={() => setIsSearchOpen(true)}
        isRefreshing={refreshing}
      />

      {/* Metric Summary Cards */}
      <ThreatSummary investigation={investigation} />

      {/* Main Split Console: Intelligence Graph + Findings */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4 items-stretch min-h-[560px]">
        {/* Left / Center: Cytoscape Graph Canvas */}
        <div className="lg:col-span-8 flex flex-col min-h-[500px]">
          {graphData && (
            <IntelligenceGraph
              data={graphData}
              highlightedNodeIds={highlightedNodeIds}
              highlightedEdgeIds={highlightedEdgeIds}
              onSelectNode={handleSelectNode}
              onSelectEdge={handleSelectEdge}
              className="flex-1 w-full h-full"
            />
          )}
        </div>

        {/* Right: Findings Panel */}
        <div className="lg:col-span-4 flex flex-col min-h-[500px]">
          <FindingsPanel
            findings={findings}
            activeFindingId={activeFinding?.finding_id || null}
            onSelectFinding={handleSelectFinding}
            onSelectEntityId={handleSelectEntityById}
          />
        </div>
      </div>

      {/* Threat Paths Section */}
      <ThreatPathsSection
        paths={paths}
        activePathId={activePath?.path_id || null}
        onSelectPath={handleSelectPath}
      />

      {/* Forensic Timeline */}
      <InvestigationTimeline events={timelineEvents} />

      {/* Slide-over Drawers */}
      <EntityDetailsDrawer
        investigationId={investigation.investigation_id}
        selectedNode={selectedNode}
        onClose={() => setSelectedNode(null)}
        onSelectEntityId={handleSelectEntityById}
      />

      <RelationshipDetailsDrawer
        selectedEdge={selectedEdge}
        onClose={() => setSelectedEdge(null)}
        onSelectEntityId={handleSelectEntityById}
      />

      {/* Entity Search Modal */}
      {graphData && (
        <EntitySearchModal
          nodes={graphData.nodes}
          isOpen={isSearchOpen}
          onClose={() => setIsSearchOpen(false)}
          onSelectEntity={(node) => {
            setSelectedNode(node);
            setHighlightedNodeIds([node.id]);
          }}
        />
      )}
    </div>
  );
};
