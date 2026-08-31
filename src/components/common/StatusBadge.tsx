import React from 'react';
import { ThreatStatus } from '../../types/threat';
import { CaseStatus, CasePriority } from '../../types/case';
import { cn } from '../../lib/utils';

interface StatusBadgeProps {
  status: ThreatStatus | CaseStatus | CasePriority | string;
  className?: string;
}

export const StatusBadge: React.FC<StatusBadgeProps> = ({ status, className }) => {
  const getStyles = (st: string) => {
    switch (st) {
      case 'active':
      case 'open':
        return 'bg-red-500/10 text-red-400 border-red-500/30';
      case 'under_investigation':
        return 'bg-amber-500/10 text-amber-400 border-amber-500/30';
      case 'escalated':
        return 'bg-purple-500/10 text-purple-400 border-purple-500/30';
      case 'mitigated':
      case 'closed':
        return 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30';
      case 'false_positive':
        return 'bg-gray-500/10 text-gray-400 border-gray-500/30';
      default:
        return 'bg-blue-500/10 text-blue-400 border-blue-500/30';
    }
  };

  const formattedLabel = status.replace(/_/g, ' ').toUpperCase();

  return (
    <span
      className={cn(
        'inline-flex items-center px-2 py-0.5 rounded text-2xs font-semibold uppercase tracking-wider border',
        getStyles(status),
        className
      )}
    >
      <span className="w-1.5 h-1.5 rounded-full bg-current mr-1.5 opacity-80" />
      {formattedLabel}
    </span>
  );
};
