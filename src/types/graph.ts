import { ThreatSeverity } from './threat';

export type NodeType = 'email' | 'domain' | 'url' | 'ip' | 'campaign' | 'case';
export type EdgeType = 'contains' | 'sent_from' | 'hosted_on' | 'related_to' | 'belongs_to' | 'resolves_to';

export interface GraphNode {
  id: string;
  label: string;
  type: NodeType;
  subType?: string;
  severity: ThreatSeverity;
  riskScore: number;
  metadata: {
    ip?: string;
    domain?: string;
    url?: string;
    subject?: string;
    sender?: string;
    location?: string;
    asn?: string;
    caseId?: string;
    campaignName?: string;
    detectedDate?: string;
    details?: string;
  };
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  label: EdgeType;
  confidence?: number;
}

export interface GraphData {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export interface GraphFilterOptions {
  nodeTypes: NodeType[];
  severities: ThreatSeverity[];
  searchTerm: string;
  layout: 'cose' | 'concentric' | 'circle' | 'breadthfirst' | 'grid';
}
