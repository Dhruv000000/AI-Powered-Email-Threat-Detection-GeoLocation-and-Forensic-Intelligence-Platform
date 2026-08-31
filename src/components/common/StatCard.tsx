import React from 'react';
import { LucideIcon, TrendingUp, TrendingDown } from 'lucide-react';
import { cn } from '../../lib/utils';

interface StatCardProps {
  title: string;
  value: string | number;
  icon: LucideIcon;
  change?: {
    value: string;
    isIncrease: boolean;
    period: string;
    isGood?: boolean;
  };
  variant?: 'default' | 'critical' | 'warning' | 'success';
  className?: string;
  onClick?: () => void;
}

export const StatCard: React.FC<StatCardProps> = ({
  title,
  value,
  icon: Icon,
  change,
  variant = 'default',
  className,
  onClick,
}) => {
  const variantStyles = {
    default: {
      border: 'border-[#263244]',
      iconBg: 'bg-blue-500/10 text-blue-400 border-blue-500/20',
      valueColor: 'text-gray-100',
    },
    critical: {
      border: 'border-red-500/30',
      iconBg: 'bg-red-500/10 text-red-400 border-red-500/20',
      valueColor: 'text-red-400',
    },
    warning: {
      border: 'border-amber-500/30',
      iconBg: 'bg-amber-500/10 text-amber-400 border-amber-500/20',
      valueColor: 'text-amber-400',
    },
    success: {
      border: 'border-emerald-500/30',
      iconBg: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20',
      valueColor: 'text-emerald-400',
    },
  }[variant];

  return (
    <div
      onClick={onClick}
      className={cn(
        'bg-[#151E2E] rounded-lg border p-4 transition-all duration-150',
        variantStyles.border,
        onClick && 'cursor-pointer hover:border-blue-500/40 hover:bg-[#182337]',
        className
      )}
    >
      <div className="flex items-start justify-between">
        <div>
          <p className="text-2xs font-semibold uppercase tracking-wider text-gray-400">{title}</p>
          <p className={cn('text-2xl font-bold font-mono tracking-tight mt-1', variantStyles.valueColor)}>
            {typeof value === 'number' ? value.toLocaleString() : value}
          </p>
        </div>
        <div className={cn('p-2.5 rounded-lg border', variantStyles.iconBg)}>
          <Icon className="w-5 h-5" />
        </div>
      </div>

      {change && (
        <div className="mt-3 pt-2.5 border-t border-[#1E293B] flex items-center gap-1.5 text-xs">
          {change.isIncrease ? (
            <TrendingUp className={cn('w-3.5 h-3.5', change.isGood ? 'text-emerald-400' : 'text-red-400')} />
          ) : (
            <TrendingDown className={cn('w-3.5 h-3.5', change.isGood ? 'text-emerald-400' : 'text-emerald-400')} />
          )}
          <span className={cn('font-semibold font-mono', change.isGood ? 'text-emerald-400' : 'text-red-400')}>
            {change.value}
          </span>
          <span className="text-gray-400 text-2xs">{change.period}</span>
        </div>
      )}
    </div>
  );
};
