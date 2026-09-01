import { DFIRReport, ForensicReport } from '../types/report';
import { mockReportsList } from '../mock/mockReports';

const API_BASE = '/api/v1';

export const reportService = {
  /**
   * Fetch the complete structured DFIR executive report for an investigation or analysis.
   */
  async getInvestigationReport(targetId: string): Promise<DFIRReport> {
    const res = await fetch(`${API_BASE}/investigations/${targetId}/report`);
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail?.message || `Failed to fetch DFIR report for ID '${targetId}'`);
    }
    return res.json();
  },

  /**
   * Stream and trigger download of the official branded PDF report document.
   */
  async downloadReportPdf(targetId: string, customFilename?: string): Promise<void> {
    const res = await fetch(`${API_BASE}/investigations/${targetId}/export/pdf`);
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail?.message || `Failed to export PDF report for '${targetId}'`);
    }
    const blob = await res.blob();
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = customFilename || `AEGIS_DFIR_Report_${targetId.replace(/ /g, '_')}.pdf`;
    document.body.appendChild(a);
    a.click();
    window.URL.revokeObjectURL(url);
    document.body.removeChild(a);
  },

  /**
   * Export deduplicated Indicators of Compromise (IoC) in CSV format.
   */
  async downloadIocsCsv(targetId: string): Promise<void> {
    const res = await fetch(`${API_BASE}/investigations/${targetId}/export/iocs?format=csv`);
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail?.message || `Failed to export IoCs for '${targetId}'`);
    }
    const blob = await res.blob();
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `AEGIS_IoCs_${targetId.replace(/ /g, '_')}.csv`;
    document.body.appendChild(a);
    a.click();
    window.URL.revokeObjectURL(url);
    document.body.removeChild(a);
  },

  /**
   * Case-level reports methods for legacy / case views
   */
  async getReports(): Promise<ForensicReport[]> {
    return Promise.resolve([...mockReportsList]);
  },

  async getReportById(caseId: string): Promise<ForensicReport | undefined> {
    return Promise.resolve(mockReportsList.find((r) => r.caseId === caseId) || mockReportsList[0]);
  },

  async generateReport(caseId: string, title: string): Promise<ForensicReport> {
    const newReport: ForensicReport = {
      id: `RPT-2026-${Math.floor(100 + Math.random() * 900)}`,
      caseId,
      caseTitle: title,
      generatedAt: new Date().toISOString().replace('T', ' ').substring(0, 19),
      generatedBy: {
        name: 'Dhruv Sharma',
        role: 'Lead Forensic Investigator',
        agency: 'Cyber Defense & Threat Intel Division',
      },
      classification: 'RESTRICTED / LAW ENFORCEMENT',
      status: 'Ready',
      fileFormat: 'PDF',
      summary: `Automated DFIR intelligence dossier generated for case ${caseId}. Includes full entity graph triangulation, header hop routes, and MITRE ATT&CK technique mapping.`,
      primaryThreatType: 'Business Email Compromise (BEC)',
      riskScore: 92,
      attributionAssessment: 'High confidence forensic attribution from automated heuristics and hop telemetry.',
      totalEmailsInvolved: 3,
      totalIndicatorsExtracted: 8,
      evidenceItemsCount: 4,
      findings: [
        'DMARC & SPF authentication failed on primary originating MTA.',
        'High-risk lookalike hostname detected in outbound links.',
        'First public transit node matches active Tor relay address.',
      ],
      recommendedMitigations: [
        'Enforce tenant-wide domain transport rejection for origin IP.',
        'Reset user credentials and invalidate active OAuth tokens.',
        'Submit automated domain takedown notification.',
      ],
    };
    mockReportsList.unshift(newReport);
    return Promise.resolve(newReport);
  },
};
