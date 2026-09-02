import React, { useState, useEffect } from 'react';
import { ThreatGraphComponent } from '../components/graph/ThreatGraphComponent';
import { graphService } from '../services/graphService';
import { GraphData } from '../types/graph';
import { LoadingState } from '../components/common/LoadingState';
import { GitFork } from 'lucide-react';

export const IntelligenceGraphPage: React.FC = () => {
  const [graphData, setGraphData] = useState<GraphData | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function fetchGraph() {
      setLoading(true);
      const data = await graphService.getGraphData();
      setGraphData(data);
      setLoading(false);
    }
    fetchGraph();
  }, []);

  if (loading || !graphData) {
    return <LoadingState message="Constructing entity relationship & correlation graph..." />;
  }

  return (
    <div className="space-y-4 flex flex-col h-[calc(100vh-8.5rem)]">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-[#263244] pb-3 flex-shrink-0">
        <div>
          <h1 className="text-xl font-bold text-gray-100 font-mono tracking-tight flex items-center gap-2">
            <GitFork className="w-5 h-5 text-purple-400" />
            Threat Intelligence Correlation Graph
          </h1>
          <p className="text-xs text-gray-400 font-mono mt-0.5">
            Multi-entity graph correlating Emails, Lookalike Domains, Extracted URLs, Origin IPs, Campaigns, and Cases.
          </p>
        </div>

        <div className="flex items-center gap-4 text-2xs font-mono text-gray-400">
          <span>Nodes: <strong className="text-gray-200">{graphData.nodes.length}</strong></span>
          <span>Relationships: <strong className="text-blue-400">{graphData.edges.length}</strong></span>
        </div>
      </div>

      {/* Main Graph Component */}
      <div className="flex-1 w-full min-h-0">
        <ThreatGraphComponent data={graphData} className="h-full" />
      </div>
    </div>
  );
};
