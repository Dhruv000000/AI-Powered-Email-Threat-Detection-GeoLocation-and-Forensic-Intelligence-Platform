import React from 'react';
import { ExtractedUrl } from '../../types/email';
import { ShieldCheck, Link2, CornerDownRight } from 'lucide-react';
import { SeverityBadge } from '../common/SeverityBadge';
import { cn } from '../../lib/utils';

interface UrlAnalysisTableProps {
  urls: ExtractedUrl[];
}

export const UrlAnalysisTable: React.FC<UrlAnalysisTableProps> = ({ urls }) => {
  if (!urls || urls.length === 0) {
    return (
      <div className="p-8 text-center bg-[#111827] rounded-lg border border-[#263244] text-gray-400">
        <ShieldCheck className="w-8 h-8 mx-auto text-emerald-400 mb-2" />
        <p className="text-xs font-semibold text-gray-300">No embedded URLs detected in email body.</p>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h4 className="text-xs font-bold uppercase tracking-wider text-gray-400 flex items-center gap-2">
          <Link2 className="w-4 h-4 text-blue-400" />
          Extracted Links & Redirection Analysis ({urls.length})
        </h4>
      </div>

      <div className="overflow-x-auto rounded-lg border border-[#263244] bg-[#111827]">
        <table className="w-full text-left text-xs border-collapse">
          <thead>
            <tr className="bg-[#151E2E] border-b border-[#263244] text-2xs uppercase tracking-wider font-semibold text-gray-400 font-mono">
              <th className="py-2.5 px-3">Target URL & Domain</th>
              <th className="py-2.5 px-3">Protocol</th>
              <th className="py-2.5 px-3">Risk Assessment</th>
              <th className="py-2.5 px-3">Forensic Indicators</th>
              <th className="py-2.5 px-3">Detection Rationale</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[#1E293B] font-mono">
            {urls.map((item) => (
              <tr key={item.id} className="hover:bg-[#151E2E]/60 transition">
                {/* URL and Destination */}
                <td className="py-3 px-3">
                  <div className="space-y-1">
                    <span className="font-semibold text-gray-100 break-all flex items-center gap-1.5">
                      {item.url}
                    </span>
                    <span className="text-2xs text-gray-400 block font-normal">
                      Host: <strong className="text-gray-300">{item.domain}</strong>
                    </span>
                    {item.hasRedirect && item.finalDestination && (
                      <div className="flex items-center gap-1.5 text-2xs text-amber-400 bg-amber-500/10 p-1.5 rounded border border-amber-500/20 mt-1">
                        <CornerDownRight className="w-3 h-3 flex-shrink-0" />
                        <span className="truncate">Redirects to: {item.finalDestination}</span>
                      </div>
                    )}
                  </div>
                </td>

                {/* Protocol */}
                <td className="py-3 px-3">
                  <span className="px-2 py-0.5 rounded bg-[#151E2E] border border-[#263244] text-gray-300 text-2xs font-bold">
                    {item.protocol}
                  </span>
                </td>

                {/* Risk */}
                <td className="py-3 px-3 whitespace-nowrap">
                  <div className="flex flex-col gap-1">
                    <div className="flex items-center gap-2">
                      <span
                        className={cn(
                          'font-bold text-sm',
                          item.riskScore >= 80 ? 'text-red-400' : item.riskScore >= 50 ? 'text-amber-400' : 'text-emerald-400'
                        )}
                      >
                        {item.riskScore}/100
                      </span>
                      <SeverityBadge severity={item.threatLevel} size="sm" />
                    </div>
                  </div>
                </td>

                {/* Indicators */}
                <td className="py-3 px-3">
                  <div className="flex flex-wrap gap-1">
                    {item.isLookalike && (
                      <span className="px-1.5 py-0.5 rounded bg-red-500/20 text-red-400 border border-red-500/30 text-[10px] font-bold">
                        Lookalike
                      </span>
                    )}
                    {item.isShortened && (
                      <span className="px-1.5 py-0.5 rounded bg-orange-500/20 text-orange-400 border border-orange-500/30 text-[10px] font-bold">
                        Shortened
                      </span>
                    )}
                    {item.isIpBased && (
                      <span className="px-1.5 py-0.5 rounded bg-purple-500/20 text-purple-400 border border-purple-500/30 text-[10px] font-bold">
                        Direct IP
                      </span>
                    )}
                    {item.keywords.map((kw) => (
                      <span
                        key={kw}
                        className="px-1.5 py-0.5 rounded bg-[#1E293B] text-gray-300 border border-[#263244] text-[10px]"
                      >
                        {kw}
                      </span>
                    ))}
                  </div>
                </td>

                {/* Reason */}
                <td className="py-3 px-3 text-xs text-gray-300 max-w-xs font-sans">
                  {item.reason}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};
