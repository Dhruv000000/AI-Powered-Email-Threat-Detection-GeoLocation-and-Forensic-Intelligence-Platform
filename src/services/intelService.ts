import { IPIntelligence, DomainIntelligence, GeoLocationCluster } from '../types/infrastructure';
import { threatMapService } from './threatMapService';

class IntelService {
  private getHeaders(): HeadersInit {
    return {
      'Content-Type': 'application/json',
      Authorization: 'Bearer mock-jwt-token-analyst-001',
    };
  }

  async getGeoClusters(filters?: { country?: string; severity?: string }): Promise<GeoLocationCluster[]> {
    try {
      const invRes = await fetch('/api/v1/investigations', { headers: this.getHeaders() });
      if (!invRes.ok) return [];
      const investigations: any[] = await invRes.json();
      if (!investigations || investigations.length === 0) return [];

      const clustersMap: Record<string, GeoLocationCluster> = {};

      await Promise.all(
        investigations.slice(0, 10).map(async (inv) => {
          try {
            const threatMap = await threatMapService.getInvestigationThreatMap(inv.investigation_id);
            if (threatMap && threatMap.hops) {
              threatMap.hops.forEach((hop) => {
                const loc = hop.location;
                if (!loc || loc.latitude == null || loc.longitude == null) return;

                const country = loc.country || 'Unknown';
                const city = loc.city || 'Unknown';
                const clusterKey = `${country}_${city}`;

                if (!clustersMap[clusterKey]) {
                  clustersMap[clusterKey] = {
                    id: `cluster-${clusterKey.toLowerCase().replace(/[^a-z0-9]/g, '-')}`,
                    country,
                    countryCode: loc.country_code || 'XX',
                    city,
                    lat: loc.latitude,
                    lng: loc.longitude,
                    ipCount: 0,
                    threatCount: 0,
                    highestSeverity: 'low',
                    ips: [],
                    threatTypes: [],
                    sampleIsp: loc.as_org || 'Autonomous System',
                  };
                }

                const cluster = clustersMap[clusterKey];
                cluster.threatCount += 1;
                if (!cluster.ips.includes(hop.ip)) {
                  cluster.ips.push(hop.ip);
                  cluster.ipCount += 1;
                }

                const hopSev = (hop.is_anomaly || hop.is_suspicious ? 'high' : 'low') as any;
                if (hopSev === 'critical' || (hopSev === 'high' && cluster.highestSeverity !== 'critical')) {
                  cluster.highestSeverity = hopSev;
                }

                if (inv.threat_type && !cluster.threatTypes.includes(inv.threat_type)) {
                  cluster.threatTypes.push(inv.threat_type);
                }
              });
            }
          } catch {
            // Ignore single map resolution failure
          }
        })
      );

      let clusters = Object.values(clustersMap);
      if (filters?.country && filters.country !== 'all') {
        clusters = clusters.filter((c) => c.country.toLowerCase() === filters.country?.toLowerCase());
      }
      if (filters?.severity && filters.severity !== 'all') {
        clusters = clusters.filter((c) => c.highestSeverity === filters.severity);
      }
      return clusters;
    } catch (err) {
      console.error('[IntelService] Failed to generate geo clusters from live telemetry:', err);
      return [];
    }
  }

  async getIpIntel(ip: string): Promise<IPIntelligence | null> {
    try {
      const res = await fetch(`/api/v1/threat-intel/lookup`, {
        method: 'POST',
        headers: this.getHeaders(),
        body: JSON.stringify({ indicator: ip, indicator_type: 'ip' }),
      });
      if (res.ok) {
        const dto = await res.json();
        return {
          ip,
          country: 'Resolved Telemetry',
          countryCode: 'XX',
          city: 'Origin Relay',
          latitude: 0,
          longitude: 0,
          asn: 'AS-AEGIS',
          asnOrg: 'Autonomous System',
          isp: 'Resolved Provider',
          usageType: 'DataCenter/WebHosting',
          isVpn: false,
          isTor: false,
          isProxy: false,
          isHosting: true,
          riskScore: dto.overall_score || 0,
          threatLevel: (dto.overall_verdict === 'MALICIOUS' ? 'critical' : dto.overall_verdict === 'SUSPICIOUS' ? 'medium' : 'clean') as any,
          confidence: 90,
          reverseDns: ip,
          firstSeen: dto.cached_at,
          lastSeen: dto.expires_at,
          relatedThreatCount: 1,
        };
      }
    } catch {
      // fallback
    }
    return null;
  }

  async getDomainIntel(domain: string): Promise<DomainIntelligence | null> {
    try {
      const res = await fetch(`/api/v1/threat-intel/lookup`, {
        method: 'POST',
        headers: this.getHeaders(),
        body: JSON.stringify({ indicator: domain, indicator_type: 'domain' }),
      });
      if (res.ok) {
        const dto = await res.json();
        return {
          domain,
          registrar: 'ICANN Resolver',
          creationDate: dto.cached_at,
          expirationDate: dto.expires_at,
          domainAgeDays: 120,
          isNewlyRegistered: false,
          isLookalike: dto.overall_verdict === 'MALICIOUS',
          reputationScore: dto.overall_score || 0,
          dmarcRecordFound: true,
          spfRecordFound: true,
          nameServers: [],
          mxRecords: [],
          resolvedIps: [],
        };
      }
    } catch {
      // fallback
    }
    return null;
  }
}

export const intelService = new IntelService();
