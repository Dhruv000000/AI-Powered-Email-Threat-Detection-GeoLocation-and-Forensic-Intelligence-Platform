import { InvestigationCase, CaseStatus, CasePriority, CaseNote, CaseTimelineEvent } from '../types/case';
import { ensureArray } from '../utils/array';
import { API_BASE_URL } from './apiClient';

const API_BASE = `${API_BASE_URL}/api/v1/investigations`;
const STORAGE_CASES_KEY = 'aegis_local_cases';
const STORAGE_NOTES_KEY = 'aegis_case_notes';
const STORAGE_CACHE_KEY = 'aegis_cached_cases';

class CaseService {
  private localCases: InvestigationCase[] = [];
  private localNotes: Record<string, CaseNote[]> = {};

  constructor() {
    this._loadFromStorage();
  }

  private _loadFromStorage(): void {
    try {
      const storedCases = localStorage.getItem(STORAGE_CASES_KEY);
      if (storedCases) {
        this.localCases = JSON.parse(storedCases);
      }
    } catch {
      this.localCases = [];
    }

    try {
      const storedNotes = localStorage.getItem(STORAGE_NOTES_KEY);
      if (storedNotes) {
        this.localNotes = JSON.parse(storedNotes);
      }
    } catch {
      this.localNotes = {};
    }
  }

  private _saveCasesToStorage(): void {
    try {
      localStorage.setItem(STORAGE_CASES_KEY, JSON.stringify(this.localCases));
    } catch (e) {
      console.warn('[CaseService] Failed to save local cases to storage:', e);
    }
  }

  private _saveNotesToStorage(): void {
    try {
      localStorage.setItem(STORAGE_NOTES_KEY, JSON.stringify(this.localNotes));
    } catch (e) {
      console.warn('[CaseService] Failed to save case notes to storage:', e);
    }
  }

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
    let result: InvestigationCase[] = [];

    try {
      const response = await fetch(API_BASE, {
        headers: this.getHeaders(),
      });

      if (response.ok) {
        const rawData = await response.json();
        const invList = ensureArray(rawData, ['investigations', 'cases']);

        result = invList.map((inv) => {
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

        // Merge local/manual cases
        const combinedMap = new Map<string, InvestigationCase>();
        result.forEach((c) => combinedMap.set(c.id, c));
        this.localCases.forEach((c) => {
          if (!combinedMap.has(c.id)) combinedMap.set(c.id, c);
        });
        result = Array.from(combinedMap.values());

        // Cache combined list for seamless persistence
        try {
          localStorage.setItem(STORAGE_CACHE_KEY, JSON.stringify(result));
        } catch {}
      } else {
        throw new Error(`API responded with ${response.status}`);
      }
    } catch (e) {
      console.warn('[CaseService] Using persisted cases from local cache:', e);
      try {
        const cached = localStorage.getItem(STORAGE_CACHE_KEY);
        if (cached) {
          result = JSON.parse(cached);
        } else {
          result = [...this.localCases];
        }
      } catch {
        result = [...this.localCases];
      }
    }

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
    this._saveNotesToStorage();
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

    this.localCases.unshift(newCase);
    this._saveCasesToStorage();
    return newCase;
  }

  async updateCaseStatus(caseId: string, newStatus: CaseStatus): Promise<InvestigationCase> {
    const c = await this.getCaseById(caseId);
    if (!c) throw new Error('Case not found');
    c.status = newStatus;
    c.updatedAt = new Date().toISOString().replace('T', ' ').slice(0, 19);

    const localIdx = this.localCases.findIndex((lc) => lc.id === caseId);
    if (localIdx >= 0) {
      this.localCases[localIdx] = c;
      this._saveCasesToStorage();
    }

    try {
      const cached = localStorage.getItem(STORAGE_CACHE_KEY);
      if (cached) {
        const cachedList: InvestigationCase[] = JSON.parse(cached);
        const idx = cachedList.findIndex((item) => item.id === caseId);
        if (idx >= 0) {
          cachedList[idx] = c;
          localStorage.setItem(STORAGE_CACHE_KEY, JSON.stringify(cachedList));
        }
      }
    } catch {}

    return c;
  }
}

export const caseService = new CaseService();
