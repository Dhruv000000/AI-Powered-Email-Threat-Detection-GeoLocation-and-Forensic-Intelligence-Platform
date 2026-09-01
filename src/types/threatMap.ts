export interface GeoLocation {
  ip: string;
  is_private: boolean;
  is_bogon: boolean;
  latitude?: number | null;
  longitude?: number | null;
  country?: string | null;
  country_name?: string | null;
  country_code?: string | null;
  city?: string | null;
  region?: string | null;
  postal_code?: string | null;
  formatted_address?: string | null;
  asn?: number | null;
  as_org?: string | null;
  is_datacenter_or_vpn: boolean;
  is_tor: boolean;
}

export interface ThreatMapHop {
  hop_number: number;
  ip: string;
  hostname?: string | null;
  by_host?: string | null;
  protocol?: string | null;
  timestamp?: string | null;
  delay_seconds?: number | null;
  location?: GeoLocation | null;
  is_origin: boolean;
  is_destination: boolean;
  is_suspicious: boolean;
  is_anomaly: boolean;
  anomaly_reason?: string | null;
}

export interface ThreatMapData {
  investigation_id: string;
  analysis_id: string;
  origin_ip?: GeoLocation | null;
  destination_ip?: GeoLocation | null;
  hops: ThreatMapHop[];
  total_distance_km: number;
  anomalies: string[];
  risk_score?: number | null;
  threat_type?: string | null;
}

export interface GeoLookupResponse {
  results: GeoLocation[];
  total_resolved: number;
}
