import { GraphData } from '../types/graph';

export const mockGraphData: GraphData = {
  nodes: [
    // Cases
    {
      id: 'CASE-001245',
      label: 'CASE-001245: Wire Fraud & BEC',
      type: 'case',
      severity: 'critical',
      riskScore: 96,
      metadata: {
        caseId: 'CASE-001245',
        details: 'High-profile corporate BEC investigation targeting $485k escrow',
      },
    },
    {
      id: 'CASE-001247',
      label: 'CASE-001247: Credential Phishing',
      type: 'case',
      severity: 'high',
      riskScore: 85,
      metadata: {
        caseId: 'CASE-001247',
        details: 'DocuSign and IRS SSO credential harvesting wave',
      },
    },

    // Campaigns
    {
      id: 'CAMP-VELVET',
      label: 'Campaign: Operation Velvet Mirage',
      type: 'campaign',
      severity: 'critical',
      riskScore: 95,
      metadata: {
        campaignName: 'Operation Velvet Mirage',
        details: 'Coordinated BEC campaign leveraging lookalike banking domains',
      },
    },
    {
      id: 'CAMP-PHISHSTORM',
      label: 'Campaign: PhishStorm DocuCloud',
      type: 'campaign',
      severity: 'high',
      riskScore: 84,
      metadata: {
        campaignName: 'PhishStorm-DocuCloud',
        details: 'Automated mass credential harvester',
      },
    },

    // Emails
    {
      id: 'EML-2026-001',
      label: 'Email: Urgent Escrow Wire (#ACQ-9921)',
      type: 'email',
      severity: 'critical',
      riskScore: 96,
      metadata: {
        subject: 'URGENT: Confidential Acquisition Escrow Wire Transfer (#ACQ-9921)',
        sender: 'ceo@corp-bankofamerica.xyz',
        detectedDate: '2026-08-29',
      },
    },
    {
      id: 'EML-2026-002',
      label: 'Email: M365 MFA Notice',
      type: 'email',
      severity: 'critical',
      riskScore: 92,
      metadata: {
        subject: 'ACTION REQUIRED: Multifactor Authentication (MFA) Session Expiring',
        sender: 'security-alerts@micros0ft-security-verify.com',
        detectedDate: '2026-08-29',
      },
    },
    {
      id: 'EML-2026-005',
      label: 'Email: DocuSign MSA Contract',
      type: 'email',
      severity: 'high',
      riskScore: 82,
      metadata: {
        subject: 'Please Review & Sign: Master Services Agreement Amendment #MSA-774',
        sender: 'dse@docusign-document-cloud.cc',
        detectedDate: '2026-08-29',
      },
    },
    {
      id: 'EML-2026-006',
      label: 'Email: IRS Tax Audit Notice',
      type: 'email',
      severity: 'high',
      riskScore: 76,
      metadata: {
        subject: 'MANDATORY: Corporate Tax Year Audit Discrepancy Notification (#TAX-994)',
        sender: 'compliance@irs-tax-audit-notice.info',
        detectedDate: '2026-08-29',
      },
    },

    // Domains
    {
      id: 'dom-corp-boa',
      label: 'corp-bankofamerica.xyz',
      type: 'domain',
      severity: 'critical',
      riskScore: 94,
      metadata: {
        domain: 'corp-bankofamerica.xyz',
        details: 'Lookalike domain registered 9 days ago on NameCheap',
      },
    },
    {
      id: 'dom-sec-login',
      label: 'secure-bank-login.xyz',
      type: 'domain',
      severity: 'critical',
      riskScore: 96,
      metadata: {
        domain: 'secure-bank-login.xyz',
        details: 'Banking credential harvesting portal',
      },
    },
    {
      id: 'dom-ms-verify',
      label: 'micros0ft-security-verify.com',
      type: 'domain',
      severity: 'critical',
      riskScore: 98,
      metadata: {
        domain: 'micros0ft-security-verify.com',
        details: 'Typosquatted domain imitating Microsoft 365',
      },
    },
    {
      id: 'dom-docusign',
      label: 'docusign-document-cloud.cc',
      type: 'domain',
      severity: 'high',
      riskScore: 86,
      metadata: {
        domain: 'docusign-document-cloud.cc',
        details: 'DocuSign lookalike domain',
      },
    },
    {
      id: 'dom-irs-tax',
      label: 'irs-tax-audit-notice.info',
      type: 'domain',
      severity: 'high',
      riskScore: 78,
      metadata: {
        domain: 'irs-tax-audit-notice.info',
        details: 'IRS impersonation portal on .info TLD',
      },
    },

    // URLs
    {
      id: 'url-bank-auth',
      label: 'https://secure-bank-login.xyz/...',
      type: 'url',
      severity: 'critical',
      riskScore: 96,
      metadata: {
        url: 'https://secure-bank-login.xyz/auth/verify?session=99281a',
        details: 'Phishing login form capturing corporate banking tokens',
      },
    },
    {
      id: 'url-ms-login',
      label: 'https://micros0ft-security-verify...',
      type: 'url',
      severity: 'critical',
      riskScore: 94,
      metadata: {
        url: 'https://micros0ft-security-verify.com/login.srf?tenant=enterprise-corp',
        details: 'Fake Microsoft SSO credential trap',
      },
    },
    {
      id: 'url-docusign-env',
      label: 'https://docusign-document-cloud.cc/...',
      type: 'url',
      severity: 'high',
      riskScore: 86,
      metadata: {
        url: 'https://docusign-document-cloud.cc/envelope/9A481B2C',
        details: 'DocuSign signature harvest link',
      },
    },

    // IPs
    {
      id: 'ip-185-220-101-54',
      label: '185.220.101.54 [Frankfurt, DE]',
      type: 'ip',
      severity: 'critical',
      riskScore: 92,
      metadata: {
        ip: '185.220.101.54',
        location: 'Frankfurt, Germany',
        asn: 'AS200651 (FlokiNET Bulletproof / Tor Exit)',
        details: 'Known Tor exit relay and bulletproof hosting node',
      },
    },
    {
      id: 'ip-91-240-118-172',
      label: '91.240.118.172 [Amsterdam, NL]',
      type: 'ip',
      severity: 'high',
      riskScore: 86,
      metadata: {
        ip: '91.240.118.172',
        location: 'Amsterdam, Netherlands',
        asn: 'AS49453 (Serverius Holding B.V.)',
        details: 'Hosting provider with multiple malicious phishing reports',
      },
    },
    {
      id: 'ip-103-145-13-22',
      label: '103.145.13.22 [Singapore, SG]',
      type: 'ip',
      severity: 'medium',
      riskScore: 74,
      metadata: {
        ip: '103.145.13.22',
        location: 'Singapore',
        asn: 'AS13335 (Cloudflare Proxy)',
        details: 'Reverse proxy concealing upstream origin host',
      },
    },
    {
      id: 'ip-45-142-195-10',
      label: '45.142.195.10 [Ashburn, US]',
      type: 'ip',
      severity: 'medium',
      riskScore: 68,
      metadata: {
        ip: '45.142.195.10',
        location: 'Ashburn, VA, United States',
        asn: 'AS396982 (Google Cloud Infrastructure)',
        details: 'Cloud hosting instance running IRS phishing site',
      },
    },
  ],
  edges: [
    // Case -> Campaign
    { id: 'e1', source: 'CAMP-VELVET', target: 'CASE-001245', label: 'belongs_to' },
    { id: 'e2', source: 'CAMP-PHISHSTORM', target: 'CASE-001247', label: 'belongs_to' },

    // Campaign -> Emails
    { id: 'e3', source: 'EML-2026-001', target: 'CAMP-VELVET', label: 'related_to' },
    { id: 'e4', source: 'EML-2026-002', target: 'CAMP-VELVET', label: 'related_to' },
    { id: 'e5', source: 'EML-2026-005', target: 'CAMP-PHISHSTORM', label: 'related_to' },
    { id: 'e6', source: 'EML-2026-006', target: 'CAMP-PHISHSTORM', label: 'related_to' },

    // Emails -> Sender Domains
    { id: 'e7', source: 'EML-2026-001', target: 'dom-corp-boa', label: 'sent_from' },
    { id: 'e8', source: 'EML-2026-002', target: 'dom-ms-verify', label: 'sent_from' },
    { id: 'e9', source: 'EML-2026-005', target: 'dom-docusign', label: 'sent_from' },
    { id: 'e10', source: 'EML-2026-006', target: 'dom-irs-tax', label: 'sent_from' },

    // Emails -> URLs
    { id: 'e11', source: 'EML-2026-001', target: 'url-bank-auth', label: 'contains' },
    { id: 'e12', source: 'EML-2026-002', target: 'url-ms-login', label: 'contains' },
    { id: 'e13', source: 'EML-2026-005', target: 'url-docusign-env', label: 'contains' },

    // URLs / Domains -> Hosted IPs
    { id: 'e14', source: 'dom-corp-boa', target: 'ip-185-220-101-54', label: 'hosted_on' },
    { id: 'e15', source: 'dom-sec-login', target: 'ip-185-220-101-54', label: 'hosted_on' },
    { id: 'e16', source: 'dom-ms-verify', target: 'ip-91-240-118-172', label: 'hosted_on' },
    { id: 'e17', source: 'dom-docusign', target: 'ip-103-145-13-22', label: 'hosted_on' },
    { id: 'e18', source: 'dom-irs-tax', target: 'ip-45-142-195-10', label: 'hosted_on' },

    // Cross-Correlation: Shared Infrastructure
    { id: 'e19', source: 'url-bank-auth', target: 'dom-sec-login', label: 'resolves_to' },
  ],
};
