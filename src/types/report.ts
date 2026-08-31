import { CasePriority, CaseStatus } from './case';

export interface ForensicReport {
  id: string; // e.g. RPT-2026-089
  caseId: string;
  caseTitle: string;
  generatedAt: string;
  generatedBy: {
    name: string;
    role: string;
    agency: string;
  };
  classification: 'RESTRICTED / LAW ENFORCEMENT' | 'CONFIDENTIAL' | 'INTERNAL SECURITY USE ONLY';
  status: 'Ready' | 'Draft' | 'Archived';
  fileFormat: 'PDF' | 'JSON' | 'STIX-2.1';
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
