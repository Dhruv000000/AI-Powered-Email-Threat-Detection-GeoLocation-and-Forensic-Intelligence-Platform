import { IPIntelligence, DomainIntelligence, GeoLocationCluster } from '../types/infrastructure';
import { mockIPIntelligenceList, mockDomainIntelligenceList, mockGeoClusters } from '../mock/mockInfrastructure';

class IntelService {
  private ipList: IPIntelligence[] = [...mockIPIntelligenceList];
  private domainList: Record<string, DomainIntelligence> = { ...mockDomainIntelligenceList };
  private geoClusters: GeoLocationCluster[] = [...mockGeoClusters];

  async getGeoClusters(filters?: { country?: string; severity?: string }): Promise<GeoLocationCluster[]> {
    await new Promise((resolve) => setTimeout(resolve, 100));
    let clusters = [...this.geoClusters];
    if (filters?.country && filters.country !== 'all') {
      clusters = clusters.filter((c) => c.country.toLowerCase() === filters.country?.toLowerCase());
    }
    if (filters?.severity && filters.severity !== 'all') {
      clusters = clusters.filter((c) => c.highestSeverity === filters.severity);
    }
    return clusters;
  }

  async getIpIntel(ip: string): Promise<IPIntelligence | null> {
    await new Promise((resolve) => setTimeout(resolve, 80));
    const found = this.ipList.find((i) => i.ip === ip);
    return found ? { ...found } : null;
  }

  async getDomainIntel(domain: string): Promise<DomainIntelligence | null> {
    await new Promise((resolve) => setTimeout(resolve, 80));
    const found = this.domainList[domain];
    return found ? { ...found } : null;
  }
}

export const intelService = new IntelService();
