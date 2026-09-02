/**
 * Unified AEGIS Severity & Risk Score Categorization.
 * Harmonizes top chips, sub-headers, investigation cards, and threat map badges.
 */

export type SeverityLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

export interface SeverityMapping {
  level: SeverityLevel;
  label: string;
  color: 'red' | 'orange' | 'amber' | 'green';
  bgClass: string;
  borderClass: string;
  textClass: string;
  badgeClass: string;
}

export function getSeverityFromScore(score: number): SeverityMapping {
  if (score >= 80) {
    return {
      level: 'CRITICAL',
      label: 'CRITICAL THREAT',
      color: 'red',
      bgClass: 'bg-rose-500/20',
      borderClass: 'border-rose-500/40',
      textClass: 'text-rose-400',
      badgeClass:
        'bg-rose-500/20 text-rose-400 border border-rose-500/40 font-mono text-xs font-bold px-2.5 py-0.5 rounded shadow-sm shadow-rose-950/50',
    };
  }
  if (score >= 60) {
    return {
      level: 'HIGH',
      label: 'HIGH THREAT',
      color: 'orange',
      bgClass: 'bg-amber-500/20',
      borderClass: 'border-amber-500/40',
      textClass: 'text-amber-400',
      badgeClass:
        'bg-amber-500/20 text-amber-400 border border-amber-500/40 font-mono text-xs font-bold px-2.5 py-0.5 rounded shadow-sm shadow-amber-950/50',
    };
  }
  if (score >= 40) {
    return {
      level: 'MEDIUM',
      label: 'MEDIUM THREAT',
      color: 'amber',
      bgClass: 'bg-yellow-500/20',
      borderClass: 'border-yellow-500/40',
      textClass: 'text-yellow-400',
      badgeClass:
        'bg-yellow-500/20 text-yellow-400 border border-yellow-500/40 font-mono text-xs font-bold px-2.5 py-0.5 rounded',
    };
  }
  return {
    level: 'LOW',
    label: 'BENIGN / LOW THREAT',
    color: 'green',
    bgClass: 'bg-emerald-500/20',
    borderClass: 'border-emerald-500/40',
    textClass: 'text-emerald-400',
    badgeClass:
      'bg-emerald-500/20 text-emerald-400 border border-emerald-500/40 font-mono text-xs font-bold px-2.5 py-0.5 rounded',
  };
}

export function getSeverityBadgeProps(severityOrScore: string | number) {
  if (typeof severityOrScore === 'number') {
    return getSeverityFromScore(severityOrScore);
  }
  const s = String(severityOrScore).toLowerCase();
  if (s === 'critical') return getSeverityFromScore(85);
  if (s === 'high') return getSeverityFromScore(65);
  if (s === 'medium' || s === 'moderate') return getSeverityFromScore(45);
  return getSeverityFromScore(10);
}
