import { ThreatSeverity, ThreatType } from './threat';
import { IPIntelligence, DomainIntelligence } from './infrastructure';

export interface AuthenticationResults {
  spf: {
    status: 'PASS' | 'FAIL' | 'SOFTFAIL' | 'NEUTRAL' | 'NONE';
    domain: string;
    senderIp: string;
    details: string;
  };
  dkim: {
    status: 'PASS' | 'FAIL' | 'NONE';
    domain: string;
    selector?: string;
    details: string;
  };
  dmarc: {
    status: 'PASS' | 'FAIL' | 'SUSPICIOUS' | 'NONE';
    policy: 'none' | 'quarantine' | 'reject';
    alignment: boolean;
    details: string;
  };
}

export interface RelayHop {
  hopNumber: number;
  fromServer: string;
  byServer: string;
  ip: string;
  timestamp: string;
  delaySeconds: number;
  protocol: string;
  location?: string;
  isOriginNode: boolean;
  isAnomaly: boolean;
  anomalyReason?: string;
  rawHeader: string;
}

export interface ExtractedUrl {
  id: string;
  url: string;
  domain: string;
  protocol: string;
  riskScore: number;
  threatLevel: ThreatSeverity;
  reason: string;
  isLookalike: boolean;
  isShortened: boolean;
  isIpBased: boolean;
  hasRedirect: boolean;
  finalDestination?: string;
  keywords: string[];
}

export interface AttachmentRecord {
  id: string;
  fileName: string;
  fileSize: string;
  fileType: string;
  sha256: string;
  isMalicious: boolean;
  riskScore: number;
  detectedThreat?: string;
}

export interface FeatureContribution {
  feature: string;
  weight: number; // 0 to 100
  impact: 'High' | 'Medium' | 'Low';
  description: string;
  type: 'Authentication' | 'NLP/Linguistics' | 'Infrastructure' | 'URL/Domain' | 'Domain/URL' | 'Behavioral';
}

export interface AIAnalysisResult {
  classification: ThreatType;
  confidence: number; // 0 - 100
  riskScore: number; // 0 - 100
  urgencyScore: number; // 0 - 100
  impersonationLikelihood: number; // 0 - 100
  socialEngineeringPattern: string;
  humanExplanation: string;
  flaggedReasons: string[];
  featureContributions: FeatureContribution[];
  linguisticAnomalies: {
    urgentLanguageDetected: boolean;
    financialKeywords: string[];
    sentiment: 'Urgent/Coercive' | 'Manipulative' | 'Suspicious' | 'Neutral';
    executiveImpersonationScore: number;
  };
}

export interface ChainOfCustodyEvent {
  timestamp: string;
  actor: string;
  action: string;
  hashVerification: string;
  notes?: string;
}

export interface EvidenceRecord {
  evidenceId: string;
  originalFileName: string;
  fileSizeBytes: number;
  fileSizeFormatted: string;
  sha256: string;
  md5: string;
  sha1: string;
  uploadedAt: string;
  integrityStatus: 'Verified' | 'Compromised' | 'Pending';
  mimeType: string;
  chainOfCustody: ChainOfCustodyEvent[];
}

export interface EmailAnalysis {
  id: string;
  evidenceId: string;
  caseId?: string;
  
  // Headers & Metadata
  headers: {
    from: string;
    fromDisplayName: string;
    fromEmail: string;
    fromDomain: string;
    to: string[];
    cc: string[];
    replyTo: string;
    returnPath: string;
    subject: string;
    date: string;
    messageId: string;
    xMailer?: string;
    xOriginatingIp?: string;
  };
  
  rawBodyText: string;
  rawHtmlText?: string;
  
  // Core Forensic Components
  authentication: AuthenticationResults;
  relayPath: RelayHop[];
  extractedUrls: ExtractedUrl[];
  attachments: AttachmentRecord[];
  
  // Infrastructure Discovery
  probableOriginIp: IPIntelligence;
  senderDomainIntel: DomainIntelligence;
  
  // AI & Detection Engine
  aiAnalysis: AIAnalysisResult;
  
  // Forensic Preservation
  evidence: EvidenceRecord;
}
