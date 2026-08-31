import React from 'react';
import { Loader2 } from 'lucide-react';
import { cn } from '../../lib/utils';

interface LoadingStateProps {
  message?: string;
  className?: string;
}

export const LoadingState: React.FC<LoadingStateProps> = ({
  message = 'Loading intelligence telemetry...',
  className,
}) => {
  return (
    <div
      className={cn(
        'flex flex-col items-center justify-center p-12 text-center rounded-lg border border-[#263244] bg-[#151E2E]/40',
        className
      )}
    >
      <Loader2 className="w-7 h-7 text-blue-500 animate-spin mb-3" />
      <p className="text-xs font-medium text-gray-300 font-mono tracking-wide">{message}</p>
    </div>
  );
};
