import {
  ThreatIntelItem,
  SandboxReport,
  EnrichedInvestigation,
} from '../types/threatIntel';
import { API_BASE_URL } from './apiClient';

const API_BASE = `${API_BASE_URL}/api/v1`;

export const threatIntelService = {
  /**
   * Enriches all indicators in an investigation via VirusTotal, AbuseIPDB, and AlienVault OTX,
   * and executes sandbox detonation on all attachments.
   */
  async enrichInvestigation(targetId: string, forceRefresh: boolean = false): Promise<EnrichedInvestigation> {
    const res = await fetch(`${API_BASE}/investigations/${targetId}/enrich?force_refresh=${forceRefresh}`, {
      method: 'POST',
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail?.message || `Failed to enrich investigation '${targetId}'`);
    }
    return res.json();
  },

  /**
   * Get cached or live-enriched multi-provider threat intelligence feeds for an investigation.
   */
  async getThreatIntel(targetId: string): Promise<ThreatIntelItem[]> {
    const res = await fetch(`${API_BASE}/investigations/${targetId}/threat-intel`);
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail?.message || `Failed to fetch threat intelligence for '${targetId}'`);
    }
    return res.json();
  },

  /**
   * Get static PE/macro/PDF structure inspection and simulated process execution tree for attachments.
   */
  async getAttachmentSandbox(targetId: string): Promise<SandboxReport[]> {
    const res = await fetch(`${API_BASE}/investigations/${targetId}/attachments`);
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail?.message || `Failed to fetch attachment sandbox reports for '${targetId}'`);
    }
    return res.json();
  },

  /**
   * Ad-hoc lookup of an individual IoC indicator.
   */
  async lookupIndicator(
    indicator: string,
    indicatorType?: string,
    forceRefresh: boolean = false
  ): Promise<ThreatIntelItem> {
    const res = await fetch(`${API_BASE}/threat-intel/lookup`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        indicator,
        indicator_type: indicatorType,
        force_refresh: forceRefresh,
      }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail?.message || `Failed to lookup indicator '${indicator}'`);
    }
    return res.json();
  },
};
