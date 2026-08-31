export type ThreatSeverity = 'critical' | 'high' | 'medium' | 'low' | 'clean';

export type ThreatType =
  | 'Business Email Compromise'
  | 'Phishing'
  | 'Spoofing'
  | 'Fraud'
  | 'Malware'
  | 'Suspicious'
  | 'Legitimate';

export type ThreatStatus = 'active' | 'investigating' | 'mitigated' | 'false_positive';

export interface ThreatRecord {
  id: string;
  emailId: string;
  subject: string;
  sender: string;
  senderDomain: string;
  threatType: ThreatType;
  severity: ThreatSeverity;
  riskScore: number; // 0 - 100
  confidence: number; // 0 - 100
  status: ThreatStatus;
  detectedAt: string;
  probableOriginIp: string;
  probableOriginCountry: string;
  probableOriginCity: string;
  indicatorsCount: {
    urls: number;
    ips: number;
    domains: number;
    attachments: number;
  };
  caseId?: string;
  primaryReason: string;
}
