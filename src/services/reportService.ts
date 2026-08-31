import { ForensicReport } from '../types/report';
import { mockReportsList } from '../mock/mockReports';

class ReportService {
  private reports: ForensicReport[] = [...mockReportsList];

  async getReports(): Promise<ForensicReport[]> {
    await new Promise((resolve) => setTimeout(resolve, 100));
    return [...this.reports];
  }

  async getReportById(id: string): Promise<ForensicReport | null> {
    await new Promise((resolve) => setTimeout(resolve, 80));
    const found = this.reports.find((r) => r.id === id || r.caseId === id);
    return found ? { ...found } : null;
  }

  async generateReport(caseId: string, caseTitle: string): Promise<ForensicReport> {
    await new Promise((resolve) => setTimeout(resolve, 200));
    const newReport: ForensicReport = {
      id: `RPT-2026-${String(this.reports.length + 90).padStart(3, '0')}`,
      caseId,
      caseTitle,
      generatedAt: new Date().toISOString().replace('T', ' ').slice(0, 19) + ' UTC',
      generatedBy: {
        name: 'Dhruv Sharma',
        role: 'Lead Forensic Investigator',
        agency: 'Cyber Defense & Threat Intel Division',
      },
      classification: 'RESTRICTED / LAW ENFORCEMENT',
      status: 'Ready',
      fileFormat: 'PDF',
      summary: `Automated forensic intelligence summary compiled for ${caseId} (${caseTitle}). Correlated multi-hop email relay anomalies and verified cryptographic integrity.`,
      primaryThreatType: 'Business Email Compromise (BEC)',
      riskScore: 95,
      attributionAssessment: 'High-confidence correlation with known adversary infrastructure clusters.',
      totalEmailsInvolved: 2,
      totalIndicatorsExtracted: 7,
      evidenceItemsCount: 3,
      findings: [
        'SPF/DKIM/DMARC authentication failed.',
        'Suspicious originating IP hop located in bulletproof hosting network.',
        'Urgent financial settlement cues detected via natural language processing.',
      ],
      recommendedMitigations: [
        'Enforce DNS block for discovered lookalike domains.',
        'Deploy gateway-level attachment quarantine rules for suspicious extensions.',
      ],
    };

    this.reports.unshift(newReport);
    return newReport;
  }
}

export const reportService = new ReportService();
