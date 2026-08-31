import { ThreatSeverity } from './threat';

export type InvestigationStatus = 'created' | 'processing' | 'completed' | 'failed';

export type InvestigationStage =
  | 'loading_analysis'
  | 'building_entities'
  | 'building_relationships'
  | 'syncing_graph'
  | 'generating_findings'
  | 'generating_paths'
  | 'generating_summary'
  | 'completed';

export interface InvestigationFinding {
  id?: string;
  finding_id: string;
  investigation_id: string;
  reason_code: string;
  title: string;
  severity: ThreatSeverity;
  description: string;
  confidence: number;
  evidence_references: string[];
  entity_ids: string[];
  relationship_ids: string[];
  created_at?: string;
}

export type EntityType =
  | 'Email'
  | 'Person'
  | 'EmailAddress'
  | 'Domain'
  | 'URL'
  | 'IP'
  | 'Attachment'
  | 'FileHash'
  | 'MailServer';

export interface CytoscapeNodeData {
  id: string;
  label: string;
  type: EntityType | string;
  severity?: ThreatSeverity;
  risk_score?: number;
  is_origin?: boolean;
  is_suspicious?: boolean;
  evidence_reference?: string;
  properties?: Record<string, any>;
  color?: string;
}

export interface CytoscapeNode {
  group: 'nodes';
  data: CytoscapeNodeData;
}

export interface CytoscapeEdgeData {
  id: string;
  source: string;
  target: string;
  label: string;
  provenance?: string;
  source_reference?: string;
  confidence: number;
  properties?: Record<string, any>;
}

export interface CytoscapeEdge {
  group: 'edges';
  data: CytoscapeEdgeData;
}

export interface CytoscapeGraphData {
  investigation_id: string;
  node_count: number;
  edge_count: number;
  nodes: CytoscapeNode[];
  edges: CytoscapeEdge[];
}

export interface RelatedEntitySummary {
  entity_id: string;
  entity_type: string;
  display_label: string;
  relationship_type: string;
  direction: 'outgoing' | 'incoming';
  confidence: number;
}

export interface EntityDetail {
  entity_id: string;
  investigation_id: string;
  entity_type: EntityType | string;
  display_label: string;
  normalized_value: string;
  risk_score?: number;
  severity?: ThreatSeverity;
  evidence_reference?: string;
  properties: Record<string, any>;
  risk_signals: string[];
  related_entities: RelatedEntitySummary[];
  evidence_references: string[];
}

export interface RelationshipDetail {
  relationship_id: string;
  investigation_id: string;
  relationship_type: string;
  source_entity_id: string;
  target_entity_id: string;
  source_label?: string;
  target_label?: string;
  provenance_source: string;
  source_reference?: string;
  confidence: number;
  properties: Record<string, any>;
}

export interface ThreatPath {
  path_id: string;
  path_type: string;
  title: string;
  description: string;
  severity: ThreatSeverity;
  confidence: number;
  steps: string[];
  node_ids: string[];
  edge_ids: string[];
}

export interface TimelineEvent {
  id: string;
  timestamp: string;
  title: string;
  event_type: string;
  description: string;
  source: string;
  evidence_reference?: string;
}

export interface InvestigationSummary {
  investigation_id: string;
  analysis_id: string;
  threat_type?: string;
  risk_score?: number;
  severity?: ThreatSeverity;
  ai_confidence?: number;
  investigation_confidence: number;
  entity_counts: Record<string, number>;
  finding_counts: Record<string, number>;
  top_findings: InvestigationFinding[];
  key_threat_paths: ThreatPath[];
  timeline: TimelineEvent[];
  executive_summary?: string;
}

export interface InvestigationDetail {
  investigation_id: string;
  analysis_id: string;
  status: InvestigationStatus;
  stage: InvestigationStage;
  progress: number;
  threat_type?: string;
  risk_score?: number;
  severity?: ThreatSeverity;
  ai_confidence?: number;
  investigation_confidence?: number;
  created_by: string;
  created_at: string;
  updated_at: string;
  completed_at?: string;
  error_code?: string;
  error_message_safe?: string;
  summary?: InvestigationSummary;
  entity_count: number;
  relationship_count: number;
  finding_count: number;
}

export interface InvestigationListItem {
  investigation_id: string;
  analysis_id: string;
  status: InvestigationStatus;
  threat_type?: string;
  risk_score?: number;
  severity?: ThreatSeverity;
  created_by: string;
  created_at: string;
  completed_at?: string;
  finding_count: number;
  entity_count: number;
}
