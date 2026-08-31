import { ThreatRecord, ThreatSeverity, ThreatType, ThreatStatus } from '../types/threat';
import { mockThreatsList } from '../mock/mockThreats';

export interface ThreatFilterParams {
  searchTerm?: string;
  threatType?: ThreatType | 'all';
  severity?: ThreatSeverity | 'all';
  status?: ThreatStatus | 'all';
  dateRange?: '24h' | '7d' | '30d' | 'all';
}

class ThreatService {
  private threats: ThreatRecord[] = [...mockThreatsList];

  async getThreats(filters?: ThreatFilterParams): Promise<ThreatRecord[]> {
    await new Promise((resolve) => setTimeout(resolve, 100));
    let result = [...this.threats];

    if (!filters) return result;

    if (filters.searchTerm && filters.searchTerm.trim() !== '') {
      const q = filters.searchTerm.toLowerCase();
      result = result.filter(
        (t) =>
          t.subject.toLowerCase().includes(q) ||
          t.sender.toLowerCase().includes(q) ||
          t.id.toLowerCase().includes(q) ||
          t.probableOriginIp.includes(q) ||
          t.primaryReason.toLowerCase().includes(q)
      );
    }

    if (filters.threatType && filters.threatType !== 'all') {
      result = result.filter((t) => t.threatType === filters.threatType);
    }

    if (filters.severity && filters.severity !== 'all') {
      result = result.filter((t) => t.severity === filters.severity);
    }

    if (filters.status && filters.status !== 'all') {
      result = result.filter((t) => t.status === filters.status);
    }

    return result;
  }

  async getThreatById(id: string): Promise<ThreatRecord | null> {
    await new Promise((resolve) => setTimeout(resolve, 80));
    const threat = this.threats.find((t) => t.id === id || t.emailId === id);
    return threat ? { ...threat } : null;
  }

  async getThreatStats() {
    await new Promise((resolve) => setTimeout(resolve, 60));
    return {
      emailsAnalyzed: 1248,
      threatsDetected: 87,
      criticalThreats: 12,
      activeCases: 8,
      severityBreakdown: {
        critical: 12,
        high: 28,
        medium: 32,
        low: 15,
      },
      typeDistribution: [
        { name: 'Phishing', count: 34, percentage: 39 },
        { name: 'BEC', count: 22, percentage: 25 },
        { name: 'Spoofing', count: 14, percentage: 16 },
        { name: 'Malware', count: 9, percentage: 10 },
        { name: 'Fraud', count: 6, percentage: 7 },
        { name: 'Other', count: 2, percentage: 3 },
      ],
      timeSeriesActivity: [
        { time: '00:00', phishing: 2, bec: 1, spoofing: 0, suspicious: 1 },
        { time: '04:00', phishing: 1, bec: 0, spoofing: 1, suspicious: 0 },
        { time: '08:00', phishing: 6, bec: 4, spoofing: 3, suspicious: 2 },
        { time: '12:00', phishing: 9, bec: 7, spoofing: 4, suspicious: 3 },
        { time: '16:00', phishing: 11, bec: 6, spoofing: 5, suspicious: 4 },
        { time: '20:00', phishing: 5, bec: 4, spoofing: 1, suspicious: 2 },
      ],
    };
  }
}

export const threatService = new ThreatService();
