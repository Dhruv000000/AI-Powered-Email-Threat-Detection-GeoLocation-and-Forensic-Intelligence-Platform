import { ThreatSeverity } from './threat';

export interface IPIntelligence {
  ip: string;
  country: string;
  countryCode: string;
  city: string;
  latitude: number;
  longitude: number;
  asn: string;
  asnOrg: string;
  isp: string;
  usageType: 'DataCenter/WebHosting' | 'Commercial' | 'Residential' | 'VPN/Proxy' | 'TOR' | 'Botnet';
  isVpn: boolean;
  isTor: boolean;
  isProxy: boolean;
  isHosting: boolean;
  riskScore: number;
  threatLevel: ThreatSeverity;
  confidence: number;
  reverseDns?: string;
  firstSeen?: string;
  lastSeen?: string;
  relatedThreatCount: number;
}

export interface DomainIntelligence {
  domain: string;
  registrar: string;
  creationDate: string;
  expirationDate: string;
  domainAgeDays: number;
  isNewlyRegistered: boolean;
  isLookalike: boolean;
  targetLegitimateBrand?: string;
  mxRecords: string[];
  nameServers: string[];
  resolvedIps: string[];
  reputationScore: number;
  dmarcRecordFound: boolean;
  spfRecordFound: boolean;
}

export interface GeoLocationCluster {
  id: string;
  country: string;
  countryCode: string;
  city: string;
  lat: number;
  lng: number;
  ipCount: number;
  threatCount: number;
  highestSeverity: ThreatSeverity;
  ips: string[];
  threatTypes: string[];
  sampleIsp: string;
}
