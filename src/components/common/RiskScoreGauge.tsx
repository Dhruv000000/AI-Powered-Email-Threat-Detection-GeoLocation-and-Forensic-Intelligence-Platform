import React from 'react';
import { cn } from '../../lib/utils';

interface RiskScoreGaugeProps {
  score: number; // 0 - 100
  size?: 'sm' | 'md' | 'lg';
  showLabel?: boolean;
  className?: string;
}

export const RiskScoreGauge: React.FC<RiskScoreGaugeProps> = ({
  score,
  size = 'md',
  showLabel = true,
  className,
}) => {
  const getScoreColor = (val: number) => {
    if (val >= 85) return { stroke: '#EF4444', text: 'text-red-400', bg: 'bg-red-500/10', label: 'CRITICAL' };
    if (val >= 70) return { stroke: '#F97316', text: 'text-orange-400', bg: 'bg-orange-500/10', label: 'HIGH' };
    if (val >= 40) return { stroke: '#F59E0B', text: 'text-amber-400', bg: 'bg-amber-500/10', label: 'MEDIUM' };
    return { stroke: '#10B981', text: 'text-emerald-400', bg: 'bg-emerald-500/10', label: 'LOW / CLEAN' };
  };

  const info = getScoreColor(score);

  const dimensions = {
    sm: { size: 48, strokeWidth: 4, radius: 20, fontSize: 'text-sm font-bold', subSize: 'text-2xs' },
    md: { size: 68, strokeWidth: 5, radius: 28, fontSize: 'text-lg font-bold', subSize: 'text-2xs' },
    lg: { size: 88, strokeWidth: 6, radius: 36, fontSize: 'text-2xl font-extrabold', subSize: 'text-xs' },
  }[size];

  const circumference = 2 * Math.PI * dimensions.radius;
  const strokeDashoffset = circumference - (score / 100) * circumference;

  return (
    <div className={cn('flex items-center gap-3', className)}>
      <div className="relative inline-flex items-center justify-center" style={{ width: dimensions.size, height: dimensions.size }}>
        <svg
          className="transform -rotate-90"
          width={dimensions.size}
          height={dimensions.size}
        >
          <circle
            cx={dimensions.size / 2}
            cy={dimensions.size / 2}
            r={dimensions.radius}
            stroke="#1E293B"
            strokeWidth={dimensions.strokeWidth}
            fill="transparent"
          />
          <circle
            cx={dimensions.size / 2}
            cy={dimensions.size / 2}
            r={dimensions.radius}
            stroke={info.stroke}
            strokeWidth={dimensions.strokeWidth}
            strokeDasharray={circumference}
            strokeDashoffset={strokeDashoffset}
            strokeLinecap="round"
            fill="transparent"
            className="transition-all duration-700 ease-out"
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
          <span className={cn('font-mono leading-none tracking-tight', dimensions.fontSize, info.text)}>
            {score}
          </span>
          <span className="text-[9px] text-gray-400 font-mono leading-none mt-0.5">/100</span>
        </div>
      </div>

      {showLabel && (
        <div className="flex flex-col">
          <span className="text-2xs font-semibold uppercase tracking-wider text-gray-400">Risk Score</span>
          <span className={cn('text-xs font-bold uppercase tracking-wide mt-0.5', info.text)}>
            {info.label}
          </span>
        </div>
      )}
    </div>
  );
};
