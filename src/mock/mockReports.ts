import { ForensicReport } from '../types/report';

export const mockReportsList: ForensicReport[] = [
  {
    id: 'RPT-2026-089',
    caseId: 'CASE-001245',
    caseTitle: 'Executive Wire Fraud & Banking Credential Campaign',
    generatedAt: '2026-08-29 18:50:00',
    generatedBy: {
      name: 'Dhruv Sharma',
      role: 'Lead Forensic Investigator',
      agency: 'Cyber Defense & Threat Intel Division',
    },
    classification: 'RESTRICTED / LAW ENFORCEMENT',
    status: 'Ready',
    fileFormat: 'PDF',
    summary:
      'Forensic analysis of spear-phishing incident involving CEO executive impersonation and $485,000 wire escrow diversion. Originating relay traces to FlokiNET Bulletproof hosting node in Frankfurt am Main with Tor routing.',
    primaryThreatType: 'Business Email Compromise (BEC)',
    riskScore: 96,
    attributionAssessment:
      'High confidence attribution to threat actor cluster TA-505 infrastructure based on matching domain registrar patterns, bulletproof hosting autonomous systems, and homograph styling.',
    totalEmailsInvolved: 4,
    totalIndicatorsExtracted: 12,
    evidenceItemsCount: 6,
    findings: [
      'SPF, DKIM, and DMARC authentication checks failed on all inbound vectors.',
      'Lookalike domain "corp-bankofamerica.xyz" registered on 2026-08-20 with privacy proxy.',
      'Earliest hop IP 185.220.101.54 confirmed active as Tor Exit Node with known malicious history.',
      'Extracted payload links to live credential harvesting portal "secure-bank-login.xyz".',
    ],
    recommendedMitigations: [
      'Sinkhole DNS resolution for corp-bankofamerica.xyz and secure-bank-login.xyz across internal recursive resolvers.',
      'Submit emergency domain takedown request to NameCheap abuse desk.',
      'Provide recipient finance team with immediate security awareness retraining.',
      'Coordinate with financial institution FinCEN liaison to flag beneficiary account JPMorgan Chase 8829-1029-4401.',
    ],
  },
  {
    id: 'RPT-2026-088',
    caseId: 'CASE-001246',
    caseTitle: 'Executive HR Payroll Diversion Cluster',
    generatedAt: '2026-08-29 15:00:00',
    generatedBy: {
      name: 'Vikram Singh',
      role: 'Incident Response Specialist',
      agency: 'Cyber Defense & Threat Intel Division',
    },
    classification: 'CONFIDENTIAL',
    status: 'Ready',
    fileFormat: 'PDF',
    summary:
      'Targeted HR executive impersonation attempting to redirect monthly salary deposits to fraudulent accounts via Russian datacenter IP space.',
    primaryThreatType: 'Business Email Compromise (BEC)',
    riskScore: 94,
    attributionAssessment:
      'Moderate confidence attribution to opportunistic financial fraud syndicate utilizing PIN SPB Datacenter infrastructure.',
    totalEmailsInvolved: 2,
    totalIndicatorsExtracted: 5,
    evidenceItemsCount: 2,
    findings: [
      'Executive display name spoofing of VP Human Resources.',
      'Reply-To redirected to external unauthenticated Gmail address.',
      'Originating SMTP server located in Saint Petersburg, Russia (AS44050).',
    ],
    recommendedMitigations: [
      'Require multi-factor telephone out-of-band verification for all direct deposit modifications.',
      'Block inbound messages from executive-portal-corp.com domain.',
    ],
  },
  {
    id: 'RPT-2026-087',
    caseId: 'CASE-001248',
    caseTitle: 'Supply Chain Invoice Fraud & Trojan Delivery',
    generatedAt: '2026-08-29 17:15:00',
    generatedBy: {
      name: 'Dhruv Sharma',
      role: 'Senior Digital Forensics Lead',
      agency: 'Cyber Defense & Threat Intel Division',
    },
    classification: 'INTERNAL SECURITY USE ONLY',
    status: 'Ready',
    fileFormat: 'PDF',
    summary:
      'Analysis of fake supplier invoice delivering dual-extension (.pdf.vbs) VBScript Trojan downloader originating from dynamic ISP pool in Lagos, Nigeria.',
    primaryThreatType: 'Malware Delivery / Supply Chain Fraud',
    riskScore: 88,
    attributionAssessment: 'Attributed to West African business email compromise (BEC) and malware distribution network.',
    totalEmailsInvolved: 1,
    totalIndicatorsExtracted: 4,
    evidenceItemsCount: 2,
    findings: [
      'Dual extension file attachment Invoice_INV_8819_Revised_Account.pdf.vbs identified.',
      'Obfuscated VBScript initiates outbound HTTPS beacon to download second-stage keylogger.',
      'Origin IP 197.210.55.13 belongs to MTN Nigeria broadband residential range.',
    ],
    recommendedMitigations: [
      'Update mail gateway rule to block all inbound files with compound extensions (.pdf.vbs, .doc.exe).',
      'Scan recipient workstation for unauthorized VBS execution traces.',
    ],
  },
];
