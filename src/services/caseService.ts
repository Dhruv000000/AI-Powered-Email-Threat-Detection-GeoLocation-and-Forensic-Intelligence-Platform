import { InvestigationCase, CaseStatus, CasePriority, CaseNote, CaseTimelineEvent } from '../types/case';
import { mockCasesList } from '../mock/mockCases';

class CaseService {
  private cases: InvestigationCase[] = [...mockCasesList];

  async getCases(filters?: {
    status?: CaseStatus | 'all';
    priority?: CasePriority | 'all';
    searchTerm?: string;
  }): Promise<InvestigationCase[]> {
    await new Promise((resolve) => setTimeout(resolve, 100));
    let result = [...this.cases];

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
    await new Promise((resolve) => setTimeout(resolve, 80));
    const found = this.cases.find((c) => c.id === id);
    return found ? { ...found } : null;
  }

  async addCaseNote(caseId: string, content: string, author = 'Dhruv Sharma'): Promise<CaseNote> {
    await new Promise((resolve) => setTimeout(resolve, 100));
    const targetCase = this.cases.find((c) => c.id === caseId);
    if (!targetCase) throw new Error('Case not found');

    const newNote: CaseNote = {
      id: `n-${Date.now()}`,
      author,
      authorRole: 'Digital Forensics Analyst',
      createdAt: new Date().toISOString().replace('T', ' ').slice(0, 19),
      content,
    };

    targetCase.notes.unshift(newNote);
    targetCase.updatedAt = new Date().toISOString().replace('T', ' ').slice(0, 19);
    return newNote;
  }

  async updateCaseStatus(caseId: string, newStatus: CaseStatus): Promise<InvestigationCase> {
    await new Promise((resolve) => setTimeout(resolve, 100));
    const targetCase = this.cases.find((c) => c.id === caseId);
    if (!targetCase) throw new Error('Case not found');

    targetCase.status = newStatus;
    targetCase.updatedAt = new Date().toISOString().replace('T', ' ').slice(0, 19);

    const statusEvent: CaseTimelineEvent = {
      id: `t-${Date.now()}`,
      timestamp: new Date().toISOString(),
      timeFormatted: new Date().toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', hour12: false }),
      title: `Status changed to ${newStatus.replace('_', ' ').toUpperCase()}`,
      description: `Investigation state transitioned by assigned analyst.`,
      actor: 'Dhruv Sharma',
      type: 'analyst_action',
    };
    targetCase.timeline.unshift(statusEvent);

    return { ...targetCase };
  }

  async createCase(caseData: Partial<InvestigationCase>): Promise<InvestigationCase> {
    await new Promise((resolve) => setTimeout(resolve, 150));
    const newId = `CASE-00${1249 + this.cases.length}`;
    const newCase: InvestigationCase = {
      id: newId,
      title: caseData.title || 'New Email Threat Investigation',
      description: caseData.description || 'Investigation initiated from suspicious email detection.',
      priority: caseData.priority || 'high',
      status: 'under_investigation',
      assignedAnalyst: caseData.assignedAnalyst || {
        name: 'Dhruv Sharma',
        email: 'dhruv.sharma@cyberdefense.gov.in',
        role: 'Senior Digital Forensics Lead',
        avatarInitials: 'DS',
      },
      createdAt: new Date().toISOString().replace('T', ' ').slice(0, 19),
      updatedAt: new Date().toISOString().replace('T', ' ').slice(0, 19),
      counts: {
        emails: caseData.emailIds?.length || 1,
        domains: 1,
        ips: 1,
        urls: 1,
        evidence: 1,
      },
      emailIds: caseData.emailIds || [],
      indicatorIps: caseData.indicatorIps || ['185.220.101.54'],
      indicatorDomains: caseData.indicatorDomains || ['corp-bankofamerica.xyz'],
      indicatorUrls: caseData.indicatorUrls || [],
      timeline: [
        {
          id: `t-${Date.now()}`,
          timestamp: new Date().toISOString(),
          timeFormatted: new Date().toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', hour12: false }),
          title: `Case ${newId} Created`,
          description: 'Case formally registered in investigation repository.',
          actor: 'Dhruv Sharma',
          type: 'case_created',
        },
      ],
      notes: [],
      evidenceList: [],
      estimatedImpact: caseData.estimatedImpact || 'Medium risk perimeter exposure',
      attributionConfidence: 80,
      recommendedAction: 'Coordinate with incident response team for IOC containment.',
    };

    this.cases.unshift(newCase);
    return newCase;
  }
}

export const caseService = new CaseService();
