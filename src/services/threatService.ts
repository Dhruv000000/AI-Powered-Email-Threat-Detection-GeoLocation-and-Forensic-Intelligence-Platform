import { ThreatRecord, ThreatSeverity, ThreatType, ThreatStatus } from '../types/threat';
import { ensureArray } from '../utils/array';
import { API_BASE_URL } from './apiClient';

const API_BASE = `${API_BASE_URL}/api/v1/investigations`;
const STORAGE_THREATS_KEY = 'aegis_cached_threats';

export interface ThreatFilterParams {
  searchTerm?: string;
  threatType?: ThreatType | 'all';
  severity?: ThreatSeverity | 'all';
  status?: ThreatStatus | 'all';
  dateRange?: '24h' | '7d' | '30d' | 'all';
}

class ThreatService {
  private getHeaders(): HeadersInit {
    return {
      'Content-Type': 'application/json',
      Authorization: 'Bearer mock-jwt-token-analyst-001',
    };
  }

  private _getCachedThreats(): ThreatRecord[] {
    try {
      const stored = localStorage.getItem(STORAGE_THREATS_KEY);
      if (stored) return JSON.parse(stored);
    } catch {}
    return [];
  }

  async getThreats(filters?: ThreatFilterParams): Promise<ThreatRecord[]> {
    let result: ThreatRecord[] = [];

    try {
      const response = await fetch(API_BASE, {
        headers: this.getHeaders(),
      });

      if (!response.ok) {
        console.warn(`[ThreatService] Failed to load investigations (${response.status}), falling back to cache`);
        result = this._getCachedThreats();
      } else {
        const data: any = await response.json();
        const list = ensureArray(data, ['threats', 'investigations']);

        result = list.map((item) => {
          const sev = (item.severity?.toLowerCase() || 'medium') as ThreatSeverity;
          const tt = (item.threat_type || 'Phishing') as ThreatType;
          const risk = item.risk_score || 0;
          const sender = item.sender || item.created_by || 'RFC 822 Ingest Stream';
          const senderDomain = sender.includes('@') ? sender.split('@')[1] : 'forensic-ingest.local';

          return {
            id: item.investigation_id,
            emailId: item.analysis_id,
            subject: item.subject || `Forensic Threat Artifact: ${item.analysis_id}`,
            sender: sender,
            senderDomain: senderDomain,
            threatType: tt,
            severity: sev,
            riskScore: risk,
            confidence: Math.round((item.ai_confidence || 0.85) * 100),
            status: (item.status === 'completed' ? 'active' : item.status) as ThreatStatus,
            detectedAt: item.created_at ? new Date(item.created_at).toLocaleString() : 'Just now',
            probableOriginCountry: item.probable_origin_country || 'Global Ingest',
            probableOriginCity: item.probable_origin_city || 'Origin Relay',
            probableOriginIp: item.probable_origin_ip || 'MTA Relay Hop',
            primaryReason: item.primary_reason || `${item.threat_type || 'Suspicious payload'} signals identified`,
            indicatorsCount: {
              urls: item.entity_count ? Math.max(1, Math.floor(item.entity_count / 3)) : 1,
              ips: 1,
              domains: 1,
              attachments: 0,
            },
          };
        });

        if (result.length > 0) {
          try {
            localStorage.setItem(STORAGE_THREATS_KEY, JSON.stringify(result));
          } catch {}
        }
      }

      if (result.length === 0) {
        result = this._getCachedThreats();
      }

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
        result = result.filter((t) => t.threatType.toLowerCase() === filters.threatType?.toLowerCase());
      }

      if (filters.severity && filters.severity !== 'all') {
        result = result.filter((t) => t.severity.toLowerCase() === filters.severity?.toLowerCase());
      }

      if (filters.status && filters.status !== 'all') {
        result = result.filter((t) => t.status.toLowerCase() === filters.status?.toLowerCase());
      }

      return result;
    } catch (err) {
      console.warn('[ThreatService] Error loading threats, serving cached store:', err);
      return this._getCachedThreats();
    }
  }

  async getThreatById(id: string): Promise<ThreatRecord | null> {
    const list = await this.getThreats();
    return list.find((t) => t.id === id || t.emailId === id) || null;
  }

  async getThreatStats() {
    const list = await this.getThreats();

    const critical = list.filter((t) => t.severity === 'critical' || t.riskScore >= 80).length;
    const high = list.filter((t) => t.severity === 'high' || (t.riskScore >= 60 && t.riskScore < 80)).length;
    const medium = list.filter((t) => t.severity === 'medium' || (t.riskScore >= 30 && t.riskScore < 60)).length;
    const low = list.filter((t) => t.severity === 'low' || t.riskScore < 30).length;

    // Threat type counts
    const typeMap: Record<string, number> = {};
    list.forEach((t) => {
      const typeName = t.threatType || 'Phishing';
      typeMap[typeName] = (typeMap[typeName] || 0) + 1;
    });

    const typeDistribution = Object.entries(typeMap).map(([name, count]) => ({
      name,
      count,
      percentage: list.length > 0 ? Math.round((count / list.length) * 100) : 0,
    }));

    return {
      emailsAnalyzed: list.length,
      threatsDetected: list.filter((t) => t.riskScore >= 40).length,
      criticalThreats: critical,
      activeCases: list.filter((t) => t.status === 'active').length,
      severityBreakdown: {
        critical,
        high,
        medium,
        low,
      },
      typeDistribution: typeDistribution.length > 0 ? typeDistribution : [
        { name: 'Phishing', count: 0, percentage: 0 },
        { name: 'BEC', count: 0, percentage: 0 },
      ],
      timeSeriesActivity: [
        { time: '00:00', phishing: Math.min(critical, 2), bec: Math.min(high, 1), spoofing: 0, suspicious: Math.min(medium, 1) },
        { time: '04:00', phishing: 0, bec: 0, spoofing: 0, suspicious: 0 },
        { time: '08:00', phishing: Math.min(critical, 3), bec: Math.min(high, 2), spoofing: 1, suspicious: Math.min(medium, 2) },
        { time: '12:00', phishing: Math.min(critical, 5), bec: Math.min(high, 4), spoofing: 2, suspicious: Math.min(medium, 3) },
        { time: '16:00', phishing: critical, bec: high, spoofing: 2, suspicious: medium },
        { time: '20:00', phishing: Math.max(0, critical - 1), bec: Math.max(0, high - 1), spoofing: 1, suspicious: 1 },
      ],
    };
  }
}

export const threatService = new ThreatService();
