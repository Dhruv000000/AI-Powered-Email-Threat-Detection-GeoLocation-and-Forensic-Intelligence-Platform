export interface ThreatIntelProviderResult {
  provider: 'virustotal' | 'abuseipdb' | 'alienvault_otx' | 'offline_mock' | string;
  verdict: 'MALICIOUS' | 'SUSPICIOUS' | 'CLEAN' | 'UNKNOWN' | string;
  score: number;
  detection_ratio?: string | null;
  abuse_confidence?: number | null;
  pulses_count?: number | null;
  malware_families: string[];
  tags: string[];
  details: Record<string, any>;
}

export interface ThreatIntelItem {
  indicator: string;
  indicator_type: 'ip' | 'domain' | 'url' | 'hash' | 'email' | string;
  overall_verdict: 'MALICIOUS' | 'SUSPICIOUS' | 'CLEAN' | 'UNKNOWN' | string;
  overall_score: number;
  cached: boolean;
  cached_at: string;
  expires_at: string;
  providers: ThreatIntelProviderResult[];
}

export interface ProcessTreeNode {
  pid: number;
  parent_pid?: number | null;
  process_name: string;
  command_line: string;
  is_suspicious: boolean;
  children: ProcessTreeNode[];
}

export interface NetworkCallback {
  protocol: string;
  destination: string;
  port: number;
  behavior: string;
  is_threat: boolean;
}

export interface RegistryModification {
  key: string;
  value_name: string;
  action: string;
  data?: string | null;
  is_persistence: boolean;
}

export interface SandboxReport {
  sha256: string;
  md5: string;
  sha1: string;
  file_name: string;
  file_type: string;
  file_size_bytes: number;
  verdict: 'MALICIOUS' | 'SUSPICIOUS' | 'CLEAN' | 'UNKNOWN' | string;
  risk_score: number;
  magic_bytes: string;
  entropy: number;
  structural_flags: string[];
  macro_analysis?: {
    has_macros: boolean;
    auto_exec?: string[];
    suspicious_functions?: string[];
    [key: string]: any;
  } | null;
  pdf_analysis?: {
    version?: string;
    javascript_objects?: number;
    uri_actions?: string[];
    embedded_files?: number;
    [key: string]: any;
  } | null;
  process_tree: ProcessTreeNode[];
  network_callbacks: NetworkCallback[];
  registry_modifications: RegistryModification[];
  dropped_files: Array<{
    file_name: string;
    file_path?: string;
    sha256?: string;
    size_bytes?: number;
    threat_type?: string;
    [key: string]: any;
  }>;
  mitre_techniques: string[];
}

export interface EnrichedInvestigation {
  investigation_id: string;
  analysis_id: string;
  total_indicators: number;
  malicious_indicators_count: number;
  indicators: ThreatIntelItem[];
  attachments: SandboxReport[];
  enriched_at: string;
}
