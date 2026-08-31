import { GraphData, GraphFilterOptions } from '../types/graph';
import { mockGraphData } from '../mock/mockGraphData';

class GraphService {
  private data: GraphData = { ...mockGraphData };

  async getGraphData(filters?: GraphFilterOptions): Promise<GraphData> {
    await new Promise((resolve) => setTimeout(resolve, 120));
    if (!filters) return this.data;

    let filteredNodes = [...this.data.nodes];

    if (filters.nodeTypes && filters.nodeTypes.length > 0) {
      filteredNodes = filteredNodes.filter((n) => filters.nodeTypes.includes(n.type));
    }

    if (filters.severities && filters.severities.length > 0) {
      filteredNodes = filteredNodes.filter((n) => filters.severities.includes(n.severity));
    }

    if (filters.searchTerm && filters.searchTerm.trim() !== '') {
      const q = filters.searchTerm.toLowerCase();
      filteredNodes = filteredNodes.filter(
        (n) =>
          n.label.toLowerCase().includes(q) ||
          n.id.toLowerCase().includes(q) ||
          (n.metadata.details && n.metadata.details.toLowerCase().includes(q))
      );
    }

    const nodeIds = new Set(filteredNodes.map((n) => n.id));
    const filteredEdges = this.data.edges.filter(
      (e) => nodeIds.has(e.source) && nodeIds.has(e.target)
    );

    return {
      nodes: filteredNodes,
      edges: filteredEdges,
    };
  }

  async getCaseGraph(caseId: string): Promise<GraphData> {
    await new Promise((resolve) => setTimeout(resolve, 100));
    // Filter nodes connected to this case
    return this.getGraphData({
      nodeTypes: ['case', 'campaign', 'email', 'domain', 'url', 'ip'],
      severities: ['critical', 'high', 'medium', 'low', 'clean'],
      searchTerm: caseId === 'CASE-001245' ? 'CASE-001245' : '',
      layout: 'cose',
    });
  }
}

export const graphService = new GraphService();
