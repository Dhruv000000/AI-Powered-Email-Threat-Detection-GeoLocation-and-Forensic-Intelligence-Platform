import React from 'react';
import {
  AlertTriangle,
  ShieldAlert,
  Sparkles,
  Link,
  Lock,
  ChevronRight,
  Eye,
  CheckCircle,
} from 'lucide-react';
import { InvestigationFinding } from '../../types/investigation';
import { SeverityBadge } from '../common/SeverityBadge';

interface FindingsPanelProps {
  findings: InvestigationFinding[];
  activeFindingId: string | null;
  onSelectFinding: (finding: InvestigationFinding | null) => void;
  onSelectEntityId: (entityId: string) => void;
}

export const FindingsPanel: React.FC<FindingsPanelProps> = ({
  findings,
  activeFindingId,
  onSelectFinding,
  onSelectEntityId,
}) => {
  if (!findings || findings.length === 0) {
    return (
      <div className="bg-[#111827] border border-[#263244] rounded-lg p-6 text-center text-gray-400 font-mono text-xs">
        <CheckCircle className="w-8 h-8 text-emerald-400 mx-auto mb-2 opacity-80" />
        <p className="font-semibold text-gray-200">No Threat Findings Identified</p>
        <p className="text-2xs text-gray-400 mt-1">
          Forensic analysis did not detect high-risk anomalies or deceptive indicators.
        </p>
      </div>
    );
  }

  return (
    <div className="bg-[#111827] border border-[#263244] rounded-lg flex flex-col h-full overflow-hidden">
      {/* Header */}
      <div className="bg-[#151E2E] border-b border-[#263244] px-3.5 py-2.5 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <ShieldAlert className="w-4 h-4 text-purple-400" />
          <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-gray-100">
            Evidentiary Findings ({findings.length})
          </h3>
        </div>
        <span className="text-3xs font-mono px-2 py-0.5 rounded bg-[#111827] text-gray-400 border border-[#263244]">
          Traceable
        </span>
      </div>

      {/* Findings List */}
      <div className="flex-1 overflow-y-auto p-3 space-y-2.5">
        {findings.map((finding) => {
          const isActive = activeFindingId === finding.finding_id;

          return (
            <div
              key={finding.finding_id}
              className={`p-3 rounded-lg border transition ${
                isActive
                  ? 'bg-[#1C1936] border-purple-500 shadow-md ring-1 ring-purple-500/40'
                  : 'bg-[#151E2E]/80 border-[#263244] hover:border-gray-600'
              }`}
            >
              {/* Finding Title & Severity */}
              <div className="flex items-start justify-between gap-2">
                <div>
                  <div className="flex items-center gap-2">
                    <span className="text-3xs font-mono px-1.5 py-0.5 rounded bg-[#0D1117] text-gray-400 border border-[#1E293B]">
                      {finding.reason_code}
                    </span>
                    <SeverityBadge severity={finding.severity} className="text-3xs" />
                  </div>
                  <h4 className="text-xs font-bold text-gray-100 font-sans mt-1.5">
                    {finding.title}
                  </h4>
                </div>

                <button
                  onClick={() => onSelectFinding(isActive ? null : finding)}
                  className={`px-2 py-1 rounded text-2xs font-mono transition flex items-center gap-1 shrink-0 ${
                    isActive
                      ? 'bg-purple-600 text-white font-semibold'
                      : 'bg-[#111827] text-purple-300 hover:bg-purple-950/60 border border-purple-900/50'
                  }`}
                  title="Highlight finding path in intelligence graph"
                >
                  <Eye className="w-3 h-3" />
                  <span>{isActive ? 'Active' : 'Highlight'}</span>
                </button>
              </div>

              {/* Description */}
              <p className="text-2xs text-gray-300 font-sans mt-2 leading-relaxed">
                {finding.description}
              </p>

              {/* Evidence References */}
              {finding.evidence_references && finding.evidence_references.length > 0 && (
                <div className="mt-2.5 pt-2 border-t border-[#1E293B] flex flex-wrap items-center gap-1.5 text-3xs font-mono text-gray-400">
                  <span className="flex items-center gap-1 text-gray-400">
                    <Lock className="w-2.5 h-2.5 text-emerald-400" /> Evidence:
                  </span>
                  {finding.evidence_references.map((ref, idx) => (
                    <span key={idx} className="px-1.5 py-0.5 rounded bg-[#0D1117] text-gray-300 border border-[#1E293B]">
                      {ref}
                    </span>
                  ))}
                </div>
              )}

              {/* Correlated Entity Links */}
              {finding.entity_ids && finding.entity_ids.length > 0 && (
                <div className="mt-2 flex flex-wrap items-center gap-1">
                  <span className="text-3xs font-mono text-gray-400 mr-1">Nodes:</span>
                  {finding.entity_ids.map((entId) => (
                    <button
                      key={entId}
                      onClick={() => onSelectEntityId(entId)}
                      className="px-1.5 py-0.5 rounded bg-[#111827] hover:bg-[#1E293B] border border-[#263244] text-3xs font-mono text-blue-300 transition"
                      title="Inspect entity details"
                    >
                      {entId.length > 24 ? `${entId.slice(0, 22)}...` : entId}
                    </button>
                  ))}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
};
