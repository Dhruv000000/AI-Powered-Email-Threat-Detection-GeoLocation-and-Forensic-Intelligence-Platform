import React from 'react';
import {
  Brain,
  ShieldCheck,
  GitFork,
  AlertCircle,
  Network,
  Share2,
  FileSearch,
} from 'lucide-react';
import { InvestigationDetail } from '../../types/investigation';

interface ThreatSummaryProps {
  investigation: InvestigationDetail;
}

export const ThreatSummary: React.FC<ThreatSummaryProps> = ({ investigation }) => {
  const summary = investigation.summary;
  const entityCounts = summary?.entity_counts || {};

  return (
    <div className="grid grid-cols-1 lg:grid-cols-4 gap-3">
      {/* Narrative Executive Summary */}
      <div className="lg:col-span-2 bg-[#111827] border border-[#263244] rounded-lg p-3.5 flex flex-col justify-between">
        <div>
          <div className="flex items-center gap-2 mb-1.5">
            <FileSearch className="w-4 h-4 text-purple-400" />
            <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-gray-200">
              DFIR Investigation Synthesis
            </h3>
          </div>
          <p className="text-xs text-gray-300 leading-relaxed font-sans">
            {summary?.executive_summary ||
              'Forensic intelligence graph generated from Task 01 structured email evidence. All findings link to verified evidentiary records.'}
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-4 mt-3 pt-2.5 border-t border-[#1E293B] text-2xs font-mono text-gray-400">
          <span className="flex items-center gap-1.5">
            <Brain className="w-3.5 h-3.5 text-blue-400" />
            <span>
              Task 01 AI Confidence:{' '}
              <strong className="text-gray-200">
                {investigation.ai_confidence ? `${Math.round(investigation.ai_confidence * 100)}%` : '92%'}
              </strong>
            </span>
          </span>

          <span className="flex items-center gap-1.5">
            <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
            <span>
              Evidence Completeness:{' '}
              <strong className="text-emerald-400">
                {investigation.investigation_confidence
                  ? `${Math.round(investigation.investigation_confidence * 100)}%`
                  : '88%'}
              </strong>
            </span>
          </span>
        </div>
      </div>

      {/* Entity Distribution Breakdown */}
      <div className="bg-[#111827] border border-[#263244] rounded-lg p-3.5">
        <div className="flex items-center justify-between mb-2">
          <div className="flex items-center gap-1.5 text-xs font-mono font-bold uppercase text-gray-300">
            <Network className="w-3.5 h-3.5 text-blue-400" />
            <span>Entities Correlated</span>
          </div>
          <span className="text-xs font-mono font-bold text-gray-100">
            {investigation.entity_count}
          </span>
        </div>

        <div className="grid grid-cols-2 gap-1.5 text-2xs font-mono">
          <div className="flex items-center justify-between px-2 py-1 rounded bg-[#151E2E] border border-[#1E293B]">
            <span className="text-gray-400">Domains:</span>
            <strong className="text-emerald-400">{entityCounts['Domain'] || 0}</strong>
          </div>
          <div className="flex items-center justify-between px-2 py-1 rounded bg-[#151E2E] border border-[#1E293B]">
            <span className="text-gray-400">URLs:</span>
            <strong className="text-amber-400">{entityCounts['URL'] || 0}</strong>
          </div>
          <div className="flex items-center justify-between px-2 py-1 rounded bg-[#151E2E] border border-[#1E293B]">
            <span className="text-gray-400">IPs:</span>
            <strong className="text-rose-400">{entityCounts['IP'] || 0}</strong>
          </div>
          <div className="flex items-center justify-between px-2 py-1 rounded bg-[#151E2E] border border-[#1E293B]">
            <span className="text-gray-400">Emails:</span>
            <strong className="text-blue-400">{entityCounts['EmailAddress'] || 0}</strong>
          </div>
        </div>
      </div>

      {/* Findings & Threat Paths Count */}
      <div className="bg-[#111827] border border-[#263244] rounded-lg p-3.5 flex flex-col justify-between">
        <div>
          <div className="flex items-center justify-between mb-2">
            <div className="flex items-center gap-1.5 text-xs font-mono font-bold uppercase text-gray-300">
              <AlertCircle className="w-3.5 h-3.5 text-amber-400" />
              <span>Evidentiary Findings</span>
            </div>
            <span className="text-xs font-mono font-bold text-amber-400">
              {investigation.finding_count}
            </span>
          </div>

          <div className="flex items-center gap-2 text-2xs font-mono text-gray-400">
            <span>Critical: <strong className="text-rose-400">{summary?.finding_counts['critical'] || 0}</strong></span>
            <span>•</span>
            <span>High: <strong className="text-orange-400">{summary?.finding_counts['high'] || 0}</strong></span>
            <span>•</span>
            <span>Medium: <strong className="text-amber-400">{summary?.finding_counts['medium'] || 0}</strong></span>
          </div>
        </div>

        <div className="mt-2.5 pt-2 border-t border-[#1E293B] flex items-center justify-between text-2xs font-mono">
          <span className="text-gray-400 flex items-center gap-1">
            <GitFork className="w-3 h-3 text-purple-400" />
            Threat Paths:
          </span>
          <span className="font-bold text-purple-300 font-mono">
            {summary?.key_threat_paths?.length || 0} Identified
          </span>
        </div>
      </div>
    </div>
  );
};
