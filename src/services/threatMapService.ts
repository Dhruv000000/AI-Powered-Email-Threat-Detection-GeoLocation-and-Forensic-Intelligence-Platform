import { ThreatMapData, GeoLocation, GeoLookupResponse } from '../types/threatMap';
import { API_BASE_URL } from './apiClient';

const API_BASE = `${API_BASE_URL}/api/v1`;

export const threatMapService = {
  /**
   * Fetch the geographic relay hop transit route and threat anomalies for an investigation.
   */
  async getInvestigationThreatMap(investigationId: string): Promise<ThreatMapData> {
    const res = await fetch(`${API_BASE}/investigations/${investigationId}/threat-map`);
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail?.message || `Failed to fetch threat map for investigation ${investigationId}`);
    }
    return res.json();
  },

  /**
   * Batch resolve a list of IPv4 / IPv6 addresses to geographic telemetry.
   */
  async lookupIps(ips: string[]): Promise<GeoLocation[]> {
    const res = await fetch(`${API_BASE}/geo/lookup`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ips }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail?.message || 'Failed to lookup IP geolocation');
    }
    const data: GeoLookupResponse = await res.json();
    return data.results;
  },
};
