import React from 'react';
import {
  GitFork,
  ArrowRight,
  ShieldAlert,
  Layers,
  ChevronRight,
  Eye,
  CheckCircle,
} from 'lucide-react';
import { ThreatPath } from '../../types/investigation';
import { SeverityBadge } from '../common/SeverityBadge';

interface ThreatPathsSectionProps {
  paths: ThreatPath[];
  activePathId: string | null;
  onSelectPath: (path: ThreatPath | null) => void;
}

export const ThreatPathsSection: React.FC<ThreatPathsSectionProps> = ({
  paths,
  activePathId,
  onSelectPath,
}) => {
  if (!paths || paths.length === 0) {
    return (
      <div className="bg-[#111827] border border-[#263244] rounded-lg p-5 text-center text-gray-400 font-mono text-xs">
        <CheckCircle className="w-6 h-6 text-gray-500 mx-auto mb-1.5 opacity-70" />
        <p className="font-semibold text-gray-300">No Multi-Hop Threat Paths Identified</p>
        <p className="text-2xs text-gray-500 mt-0.5">
          Email does not exhibit complex external attack infrastructure chaining.
        </p>
      </div>
    );
  }

  return (
    <div className="bg-[#111827] border border-[#263244] rounded-lg overflow-hidden">
      {/* Header */}
      <div className="bg-[#151E2E] border-b border-[#263244] px-4 py-2.5 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <GitFork className="w-4 h-4 text-purple-400" />
          <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-gray-100">
            Threat Infrastructure Paths ({paths.length})
          </h3>
        </div>
        <span className="text-3xs font-mono text-gray-400">
          Click path to focus & highlight graph flow
        </span>
      </div>

      {/* Path Cards */}
      <div className="p-3.5 space-y-2.5">
        {paths.map((path) => {
          const isActive = activePathId === path.path_id;

          return (
            <div
              key={path.path_id}
              onClick={() => onSelectPath(isActive ? null : path)}
              className={`p-3 rounded-lg border transition cursor-pointer ${
                isActive
                  ? 'bg-[#1C1936] border-purple-500 shadow-md ring-1 ring-purple-500/40'
                  : 'bg-[#151E2E]/80 border-[#263244] hover:border-gray-600'
              }`}
            >
              {/* Top Row: Title, Severity, Action */}
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="flex items-center gap-2">
                  <h4 className="text-xs font-bold text-gray-100 font-sans">
                    {path.title}
                  </h4>
                  <SeverityBadge severity={path.severity} className="text-3xs" />
                  <span className="text-3xs font-mono text-gray-400">
                    Confidence: <strong className="text-emerald-400">{Math.round(path.confidence * 100)}%</strong>
                  </span>
                </div>

                <span
                  className={`text-2xs font-mono flex items-center gap-1 px-2 py-0.5 rounded ${
                    isActive
                      ? 'bg-purple-600 text-white font-semibold'
                      : 'bg-[#111827] text-purple-300 border border-purple-900/50'
                  }`}
                >
                  <Eye className="w-3 h-3" />
                  <span>{isActive ? 'Highlighted' : 'Highlight Path'}</span>
                </span>
              </div>

              {/* Description */}
              <p className="text-2xs text-gray-300 font-sans mt-1.5">
                {path.description}
              </p>

              {/* Breadcrumb Steps Chain */}
              <div className="mt-2.5 flex flex-wrap items-center gap-1.5 font-mono text-2xs">
                {path.steps.map((step, idx) => (
                  <React.Fragment key={idx}>
                    <span className="px-2 py-0.5 rounded bg-[#0D1117] text-gray-200 border border-[#1E293B] max-w-[260px] truncate">
                      {step}
                    </span>
                    {idx < path.steps.length - 1 && (
                      <ArrowRight className="w-3 h-3 text-purple-400 shrink-0" />
                    )}
                  </React.Fragment>
                ))}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
