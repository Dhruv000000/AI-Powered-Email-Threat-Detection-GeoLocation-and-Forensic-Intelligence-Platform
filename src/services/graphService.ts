import { GraphData, GraphFilterOptions, GraphNode, GraphEdge, NodeType, EdgeType } from '../types/graph';
import { ThreatSeverity } from '../types/threat';

class GraphService {
  private getHeaders(): HeadersInit {
    return {
      'Content-Type': 'application/json',
      Authorization: 'Bearer mock-jwt-token-analyst-001',
    };
  }

  async getGraphData(filters?: GraphFilterOptions): Promise<GraphData> {
    try {
      // 1. Fetch live investigations from backend
      const invRes = await fetch('/api/v1/investigations', { headers: this.getHeaders() });
      if (!invRes.ok) return { nodes: [], edges: [] };
      const investigations: any[] = await invRes.json();
      if (!investigations || investigations.length === 0) return { nodes: [], edges: [] };

      // 2. Fetch graph for top active investigations
      const allNodesMap: Record<string, GraphNode> = {};
      const allEdgesMap: Record<string, GraphEdge> = {};

      await Promise.all(
        investigations.slice(0, 5).map(async (inv) => {
          try {
            const graphRes = await fetch(`/api/v1/investigations/${inv.investigation_id}/graph?max_nodes=100&max_edges=200`, {
              headers: this.getHeaders(),
            });
            if (graphRes.ok) {
              const gData = await graphRes.json();
              if (gData && gData.nodes) {
                gData.nodes.forEach((n: any) => {
                  const nodeData = n.data || n;
                  const rawType = (nodeData.type || nodeData.entity_type || 'email').toLowerCase();
                  let mappedType: NodeType = 'email';
                  if (rawType.includes('domain')) mappedType = 'domain';
                  else if (rawType.includes('url')) mappedType = 'url';
                  else if (rawType.includes('ip')) mappedType = 'ip';
                  else if (rawType.includes('case')) mappedType = 'case';
                  else if (rawType.includes('campaign')) mappedType = 'campaign';

                  const sev = (nodeData.severity || 'medium').toLowerCase() as ThreatSeverity;

                  allNodesMap[nodeData.id] = {
                    id: nodeData.id,
                    label: nodeData.label || nodeData.name || nodeData.id,
                    type: mappedType,
                    subType: nodeData.sub_type,
                    severity: sev,
                    riskScore: nodeData.risk_score || nodeData.riskScore || 50,
                    metadata: {
                      ip: nodeData.ip,
                      domain: nodeData.domain,
                      url: nodeData.url,
                      subject: nodeData.subject,
                      sender: nodeData.sender,
                      details: nodeData.details || nodeData.description,
                      detectedDate: nodeData.created_at,
                    },
                  };
                });
              }

              if (gData && gData.edges) {
                gData.edges.forEach((e: any) => {
                  const edgeData = e.data || e;
                  allEdgesMap[edgeData.id] = {
                    id: edgeData.id,
                    source: edgeData.source,
                    target: edgeData.target,
                    label: (edgeData.label || edgeData.relationship_type || 'related_to').toLowerCase() as EdgeType,
                    confidence: edgeData.confidence || 0.9,
                  };
                });
              }
            }
          } catch {
            // Ignore single graph failure
          }
        })
      );

      let nodes = Object.values(allNodesMap);
      let edges = Object.values(allEdgesMap);

      if (!filters) {
        return { nodes, edges };
      }

      if (filters.nodeTypes && filters.nodeTypes.length > 0) {
        nodes = nodes.filter((n) => filters.nodeTypes.includes(n.type));
      }

      if (filters.severities && filters.severities.length > 0) {
        nodes = nodes.filter((n) => filters.severities.includes(n.severity));
      }

      if (filters.searchTerm && filters.searchTerm.trim() !== '') {
        const q = filters.searchTerm.toLowerCase();
        nodes = nodes.filter(
          (n) =>
            n.label.toLowerCase().includes(q) ||
            n.id.toLowerCase().includes(q) ||
            (n.metadata.details && n.metadata.details.toLowerCase().includes(q))
        );
      }

      const nodeIds = new Set(nodes.map((n) => n.id));
      edges = edges.filter((e) => nodeIds.has(e.source) && nodeIds.has(e.target));

      return { nodes, edges };
    } catch (err) {
      console.error('[GraphService] Failed to load live graph data:', err);
      return { nodes: [], edges: [] };
    }
  }

  async getCaseGraph(caseId: string): Promise<GraphData> {
    return this.getGraphData({
      nodeTypes: ['case', 'campaign', 'email', 'domain', 'url', 'ip'],
      severities: ['critical', 'high', 'medium', 'low', 'clean'],
      searchTerm: caseId,
      layout: 'cose',
    });
  }
}

export const graphService = new GraphService();
