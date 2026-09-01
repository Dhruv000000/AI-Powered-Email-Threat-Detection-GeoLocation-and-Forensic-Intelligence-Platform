export interface MitreTechnique {
  technique_id: string;
  name: string;
  tactic: string;
  description: string;
  matched_indicators: string[];
  confidence: number;
  url: string;
}

export interface RemediationAction {
  action_id: string;
  priority: 'P0' | 'P1' | 'P2' | string;
  title: string;
  category: string;
  description: string;
  target_system: string;
  automated_action?: string | null;
}

export interface IoCItem {
  ioc_type: 'Domain' | 'URL' | 'IP' | 'EmailAddress' | 'SHA256' | 'FileHash' | string;
  value: string;
  threat_context: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info' | string;
  killchain_stage: string;
}

export interface ExecutiveSummary {
  verdict: string;
  classification: string;
  risk_score: number;
  severity: string;
  ai_confidence: number;
  narrative: string;
  key_takeaways: string[];
  attack_vector: string;
  potential_impact: string;
}

export interface DFIRReport {
  report_id: string;
  investigation_id: string;
  analysis_id: string;
  generated_at: string;
  generated_by: string;
  case_reference: string;
  email_metadata: {
    from_email?: string;
    from_name?: string | null;
    to_email?: string;
    reply_to?: string | null;
    subject?: string;
    date?: string | null;
    message_id?: string | null;
    filename?: string;
    sha256?: string;
    origin_ip?: string | null;
  };
  executive_summary: ExecutiveSummary;
  mitre_matrix: MitreTechnique[];
  remediation_plan: RemediationAction[];
  iocs: IoCItem[];
  evidentiary_findings: Array<{
    finding_id?: string;
    title?: string;
    reason_code?: string;
    severity?: string;
    description?: string;
    confidence?: number;
    [key: string]: any;
  }>;
  forensic_timeline: Array<{
    timestamp: string;
    title: string;
    event_type: string;
    description: string;
    source: string;
  }>;
  threat_paths: Array<{
    path_id?: string;
    name?: string;
    risk_level?: string;
    summary?: string;
    [key: string]: any;
  }>;
  transit_route_summary?: {
    total_distance_km?: number;
    hops?: any[];
    anomalies?: string[];
    [key: string]: any;
  } | null;
}

export interface ForensicReport {
  id: string;
  caseId: string;
  caseTitle: string;
  generatedAt: string;
  generatedBy: {
    name: string;
    role: string;
    agency: string;
  };
  classification: string;
  status: string;
  fileFormat: string;
  summary: string;
  primaryThreatType: string;
  riskScore: number;
  attributionAssessment: string;
  totalEmailsInvolved: number;
  totalIndicatorsExtracted: number;
  evidenceItemsCount: number;
  findings: string[];
  recommendedMitigations: string[];
}
