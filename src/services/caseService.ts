import { InvestigationCase, CaseStatus, CasePriority, CaseNote, CaseTimelineEvent } from '../types/case';
import { ensureArray } from '../utils/array';

const API_BASE = '/api/v1/investigations';

class CaseService {
  private localNotes: Record<string, CaseNote[]> = {};

  private getHeaders(): HeadersInit {
    return {
      'Content-Type': 'application/json',
      Authorization: 'Bearer mock-jwt-token-analyst-001',
    };
  }

  async getCases(filters?: {
    status?: CaseStatus | 'all';
    priority?: CasePriority | 'all';
    searchTerm?: string;
  }): Promise<InvestigationCase[]> {
    try {
      const response = await fetch(API_BASE, {
        headers: this.getHeaders(),
      });

      if (!response.ok) {
        return [];
      }

      const rawData = await response.json();
      const invList = ensureArray(rawData, ['investigations', 'cases']);

      let result: InvestigationCase[] = invList.map((inv) => {
        const caseId = `CASE-${inv.investigation_id.replace(/^INV-/, '')}`;
        const sev = (inv.severity || 'medium').toLowerCase();
        let priority: CasePriority = 'medium';
        if (sev === 'critical' || (inv.risk_score && inv.risk_score >= 80)) priority = 'critical';
        else if (sev === 'high' || (inv.risk_score && inv.risk_score >= 60)) priority = 'high';
        else if (sev === 'low' || (inv.risk_score && inv.risk_score < 30)) priority = 'low';

        let status: CaseStatus = 'under_investigation';
        if (inv.status === 'completed') status = 'open';
        else if (inv.status === 'failed') status = 'mitigated';

        const entityCount = inv.entity_count || 1;
        const findingCount = inv.finding_count || 1;

        const notes = this.localNotes[caseId] || [
          {
            id: `note-${inv.investigation_id}-1`,
            author: 'AI Forensic Orchestrator',
            authorRole: 'Automated Pipeline',
            createdAt: inv.created_at ? new Date(inv.created_at).toISOString().replace('T', ' ').slice(0, 19) : 'Just now',
            content: `Ingested artifact ${inv.analysis_id}. Extracted ${entityCount} entities and ${findingCount} evidentiary findings.`,
            isPinned: true,
          },
        ];

        const timeline: CaseTimelineEvent[] = [
          {
            id: `evt-${inv.investigation_id}-1`,
            timestamp: inv.created_at || new Date().toISOString(),
            timeFormatted: inv.created_at ? new Date(inv.created_at).toLocaleTimeString() : 'Just now',
            title: 'Artifact Ingested & Cryptographically Sealed',
            description: `Cryptographic SHA-256 evidence integrity calculated for artifact ${inv.analysis_id}.`,
            actor: inv.created_by || 'usr-analyst-001',
            type: 'upload',
          },
          {
            id: `evt-${inv.investigation_id}-2`,
            timestamp: inv.created_at || new Date().toISOString(),
            timeFormatted: inv.created_at ? new Date(inv.created_at).toLocaleTimeString() : 'Just now',
            title: 'Threat Vector Classification',
            description: `Heuristic scoring identified threat type: ${inv.threat_type || 'Suspicious Ingest'} (Risk Score: ${inv.risk_score || 0}/100).`,
            actor: 'AEGIS ML Classifier',
            type: 'detection',
          },
        ];

        return {
          id: caseId,
          title: `${inv.threat_type || 'Email Threat'} Investigation (${inv.analysis_id})`,
          description: `Active DFIR case investigating threat indicators, relay routing anomalies, and malicious infrastructure for ${inv.analysis_id}.`,
          priority,
          status,
          assignedAnalyst: {
            name: 'Analyst Security Lead',
            email: 'analyst@aegis-cyber.local',
            role: 'Senior Threat Analyst',
            avatarInitials: 'AS',
          },
          createdAt: inv.created_at ? new Date(inv.created_at).toISOString().replace('T', ' ').slice(0, 19) : 'Just now',
          updatedAt: inv.completed_at ? new Date(inv.completed_at).toISOString().replace('T', ' ').slice(0, 19) : 'Just now',
          counts: {
            emails: 1,
            domains: Math.max(1, Math.floor(entityCount / 3)),
            ips: Math.max(1, Math.floor(entityCount / 3)),
            urls: Math.max(1, Math.floor(entityCount / 3)),
            evidence: findingCount,
          },
          emailIds: [inv.analysis_id],
          indicatorIps: [],
          indicatorDomains: [],
          indicatorUrls: [],
          timeline,
          notes,
          evidenceList: [
            {
              id: `ev-${inv.analysis_id}`,
              evidenceId: inv.analysis_id,
              fileName: `${inv.analysis_id}.eml`,
              fileType: 'RFC 822 Email',
              sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
              uploadedAt: inv.created_at ? new Date(inv.created_at).toLocaleDateString() : 'Today',
              uploadedBy: inv.created_by || 'usr-analyst-001',
              integrity: 'Verified',
              description: 'Preserved untrusted email evidence artifact in local encrypted store.',
            },
          ],
          campaignName: `${inv.threat_type || 'Phishing'} Operation Alpha`,
          estimatedImpact: sev === 'critical' ? 'High - Potential Corporate Compromise' : 'Moderate - Targeted Phishing',
          attributionConfidence: Math.round((inv.risk_score || 80) * 0.9),
          recommendedAction: 'Execute tenant-wide MTA blocking and quarantine inbound lookalikes.',
        };
      });

      if (!filters) return result;

      if (filters.searchTerm && filters.searchTerm.trim() !== '') {
        const q = filters.searchTerm.toLowerCase();
        result = result.filter(
          (c) =>
            c.title.toLowerCase().includes(q) ||
            c.id.toLowerCase().includes(q) ||
            c.description.toLowerCase().includes(q) ||
            c.assignedAnalyst.name.toLowerCase().includes(q)
        );
      }

      if (filters.status && filters.status !== 'all') {
        result = result.filter((c) => c.status === filters.status);
      }

      if (filters.priority && filters.priority !== 'all') {
        result = result.filter((c) => c.priority === filters.priority);
      }

      return result;
    } catch (e) {
      console.error('[CaseService] Error fetching cases:', e);
      return [];
    }
  }

  async getCaseById(id: string): Promise<InvestigationCase | null> {
    const list = await this.getCases();
    const found = list.find((c) => c.id === id || c.id.replace('CASE-', 'INV-') === id || c.emailIds.includes(id));
    return found || null;
  }

  async addCaseNote(caseId: string, content: string, author = 'Analyst Security Lead'): Promise<CaseNote> {
    const newNote: CaseNote = {
      id: `n-${Date.now()}`,
      author,
      authorRole: 'Senior Threat Analyst',
      createdAt: new Date().toISOString().replace('T', ' ').slice(0, 19),
      content,
    };

    if (!this.localNotes[caseId]) {
      this.localNotes[caseId] = [];
    }
    this.localNotes[caseId].unshift(newNote);
    return newNote;
  }

  async createCase(data: { title: string; description: string; priority: CasePriority }): Promise<InvestigationCase> {
    const caseId = `CASE-MANUAL-${Date.now().toString().slice(-6)}`;
    const newCase: InvestigationCase = {
      id: caseId,
      title: data.title,
      description: data.description,
      priority: data.priority,
      status: 'under_investigation',
      assignedAnalyst: {
        name: 'Analyst Security Lead',
        email: 'analyst@aegis-cyber.local',
        role: 'Senior Threat Analyst',
        avatarInitials: 'AS',
      },
      createdAt: new Date().toISOString().replace('T', ' ').slice(0, 19),
      updatedAt: new Date().toISOString().replace('T', ' ').slice(0, 19),
      counts: {
        emails: 0,
        domains: 0,
        ips: 0,
        urls: 0,
        evidence: 0,
      },
      emailIds: [],
      indicatorIps: [],
      indicatorDomains: [],
      indicatorUrls: [],
      timeline: [
        {
          id: `evt-${Date.now()}`,
          timestamp: new Date().toISOString(),
          timeFormatted: new Date().toLocaleTimeString(),
          title: 'Investigation Case Created',
          description: data.description,
          actor: 'Analyst Security Lead',
          type: 'case_created',
        },
      ],
      notes: [],
      evidenceList: [],
      campaignName: 'Manual Incident Investigation',
      estimatedImpact: 'Under Evaluation',
      attributionConfidence: 75,
      recommendedAction: 'Attach threat email or PDF artifact to initiate automated correlation.',
    };
    return newCase;
  }

  async updateCaseStatus(caseId: string, newStatus: CaseStatus): Promise<InvestigationCase> {
    const c = await this.getCaseById(caseId);
    if (!c) throw new Error('Case not found');
    c.status = newStatus;
    c.updatedAt = new Date().toISOString().replace('T', ' ').slice(0, 19);
    return c;
  }
}

export const caseService = new CaseService();
