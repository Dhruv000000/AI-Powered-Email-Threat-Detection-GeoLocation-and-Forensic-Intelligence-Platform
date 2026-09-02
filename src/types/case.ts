export type CasePriority = 'critical' | 'high' | 'medium' | 'low';
export type CaseStatus = 'open' | 'under_investigation' | 'escalated' | 'mitigated' | 'closed';

export interface CaseTimelineEvent {
  id: string;
  timestamp: string;
  timeFormatted: string;
  title: string;
  description: string;
  actor: string;
  type: 'upload' | 'detection' | 'ip_identified' | 'domain_discovered' | 'case_created' | 'evidence_attached' | 'analyst_action';
  relatedEntityId?: string;
}

export interface CaseNote {
  id: string;
  author: string;
  authorRole: string;
  createdAt: string;
  content: string;
  isPinned?: boolean;
}

export interface CaseEvidenceItem {
  id: string;
  evidenceId: string;
  fileName: string;
  fileType: string;
  sha256: string;
  uploadedAt: string;
  uploadedBy: string;
  integrity: 'Verified' | 'Pending';
  description: string;
}

export interface InvestigationCase {
  id: string; // e.g. CASE-001245
  title: string;
  description: string;
  priority: CasePriority;
  status: CaseStatus;
  assignedAnalyst: {
    name: string;
    email: string;
    role: string;
    avatarInitials: string;
  };
  createdAt: string;
  updatedAt: string;
  
  // Aggregated Counts
  counts: {
    emails: number;
    domains: number;
    ips: number;
    urls: number;
    evidence: number;
  };
  
  emailIds: string[];
  indicatorIps: string[];
  indicatorDomains: string[];
  indicatorUrls: string[];
  
  timeline: CaseTimelineEvent[];
  notes: CaseNote[];
  evidenceList: CaseEvidenceItem[];
  
  campaignName?: string;
  estimatedImpact: string;
  attributionConfidence: number; // 0 - 100%
  recommendedAction: string;
}
