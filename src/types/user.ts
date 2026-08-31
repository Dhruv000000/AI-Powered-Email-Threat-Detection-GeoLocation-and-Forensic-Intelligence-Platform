export interface UserProfile {
  id: string;
  name: string;
  email: string;
  role: string; // e.g. "Senior Forensic Analyst", "SOC Lead"
  organization: string;
  initials: string;
  badgeNumber?: string;
  twoFactorEnabled: boolean;
  preferences: {
    theme: 'dark';
    tableDensity: 'compact' | 'comfortable';
    soundAlerts: boolean;
    autoRefreshInterval: number; // in seconds
  };
}

export interface SystemNotification {
  id: string;
  title: string;
  description: string;
  timeAgo: string;
  timestamp: string;
  type: 'critical_threat' | 'case_assigned' | 'analysis_complete' | 'evidence_alert';
  read: boolean;
  linkTo?: string;
}

export interface SearchResultItem {
  id: string;
  title: string;
  subtitle: string;
  category: 'Email' | 'Case' | 'IP' | 'Domain' | 'URL' | 'Evidence';
  severity?: 'critical' | 'high' | 'medium' | 'low';
  linkTo: string;
}
