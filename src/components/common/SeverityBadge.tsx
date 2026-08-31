import React from 'react';
import { ThreatSeverity } from '../../types/threat';
import { cn } from '../../lib/utils';
import { AlertOctagon, AlertTriangle, AlertCircle, CheckCircle, ShieldCheck } from 'lucide-react';

interface SeverityBadgeProps {
  severity: ThreatSeverity;
  size?: 'sm' | 'md' | 'lg';
  showIcon?: boolean;
  className?: string;
}

export const SeverityBadge: React.FC<SeverityBadgeProps> = ({
  severity,
  size = 'md',
  showIcon = true,
  className,
}) => {
  const config = {
    critical: {
      bg: 'bg-red-500/10',
      text: 'text-red-400',
      border: 'border-red-500/30',
      label: 'CRITICAL',
      icon: AlertOctagon,
    },
    high: {
      bg: 'bg-orange-500/10',
      text: 'text-orange-400',
      border: 'border-orange-500/30',
      label: 'HIGH',
      icon: AlertTriangle,
    },
    medium: {
      bg: 'bg-amber-500/10',
      text: 'text-amber-400',
      border: 'border-amber-500/30',
      label: 'MEDIUM',
      icon: AlertCircle,
    },
    low: {
      bg: 'bg-emerald-500/10',
      text: 'text-emerald-400',
      border: 'border-emerald-500/30',
      label: 'LOW',
      icon: CheckCircle,
    },
    clean: {
      bg: 'bg-blue-500/10',
      text: 'text-blue-400',
      border: 'border-blue-500/30',
      label: 'CLEAN',
      icon: ShieldCheck,
    },
  }[severity] || {
    bg: 'bg-gray-500/10',
    text: 'text-gray-400',
    border: 'border-gray-500/30',
    label: severity.toUpperCase(),
    icon: AlertCircle,
  };

  const Icon = config.icon;

  const sizeClasses = {
    sm: 'text-2xs px-1.5 py-0.5 font-medium gap-1',
    md: 'text-xs px-2 py-0.5 font-semibold gap-1.5',
    lg: 'text-sm px-2.5 py-1 font-bold gap-2',
  }[size];

  return (
    <span
      className={cn(
        'inline-flex items-center rounded border tracking-wider uppercase',
        config.bg,
        config.text,
        config.border,
        sizeClasses,
        className
      )}
    >
      {showIcon && <Icon className={size === 'sm' ? 'w-3 h-3' : size === 'lg' ? 'w-4 h-4' : 'w-3.5 h-3.5'} />}
      {config.label}
    </span>
  );
};
