import React, { useState } from 'react';
import { AuthenticationResults, RelayHop } from '../../types/email';
import { ShieldCheck, ShieldAlert, AlertTriangle, ChevronDown, ChevronRight, Server, Clock, Globe } from 'lucide-react';
import { cn } from '../../lib/utils';

interface HeaderRelayTimelineProps {
  headers: {
    from: string;
    to: string[];
    cc: string[];
    replyTo: string;
    returnPath: string;
    subject: string;
    date: string;
    messageId: string;
    xMailer?: string;
    xOriginatingIp?: string;
  };
  authentication: AuthenticationResults;
  relayPath: RelayHop[];
}

export const HeaderRelayTimeline: React.FC<HeaderRelayTimelineProps> = ({
  headers,
  authentication,
  relayPath,
}) => {
  const [expandedHops, setExpandedHops] = useState<Record<number, boolean>>({ 1: true });

  const toggleHop = (hopNum: number) => {
    setExpandedHops((prev) => ({ ...prev, [hopNum]: !prev[hopNum] }));
  };

  const getAuthBadge = (status: string, label: string) => {
    const isPass = status === 'PASS';
    const isFail = status === 'FAIL';
    return (
      <div
        className={cn(
          'flex flex-col p-3 rounded-lg border',
          isPass
            ? 'bg-emerald-500/10 border-emerald-500/30'
            : isFail
            ? 'bg-red-500/10 border-red-500/30'
            : 'bg-amber-500/10 border-amber-500/30'
        )}
      >
        <div className="flex items-center justify-between">
          <span className="text-xs font-bold text-gray-300 font-mono">{label}</span>
          <span
            className={cn(
              'px-2 py-0.5 rounded text-2xs font-bold font-mono tracking-wider',
              isPass
                ? 'bg-emerald-500/20 text-emerald-400'
                : isFail
                ? 'bg-red-500/20 text-red-400'
                : 'bg-amber-500/20 text-amber-400'
            )}
          >
            {status}
          </span>
        </div>
      </div>
    );
  };

  return (
    <div className="space-y-6">
      {/* Authentication Verification Section */}
      <div>
        <h4 className="text-xs font-bold uppercase tracking-wider text-gray-400 mb-3 flex items-center gap-2">
          <ShieldCheck className="w-4 h-4 text-blue-400" />
          Email Cryptographic Authentication Results
        </h4>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
          {getAuthBadge(authentication.spf.status, 'SPF (Sender Policy)')}
          {getAuthBadge(authentication.dkim.status, 'DKIM (Cryptographic Sign)')}
          {getAuthBadge(authentication.dmarc.status, 'DMARC (Domain Alignment)')}
        </div>
        <div className="mt-3 p-3 bg-[#111827] rounded border border-[#263244] text-xs font-mono text-gray-300 space-y-1">
          <p><span className="text-gray-400 font-semibold">SPF Diagnostic:</span> {authentication.spf.details}</p>
          <p><span className="text-gray-400 font-semibold">DKIM Diagnostic:</span> {authentication.dkim.details}</p>
          <p><span className="text-gray-400 font-semibold">DMARC Diagnostic:</span> {authentication.dmarc.details}</p>
        </div>
      </div>

      {/* Primary Key Forensic Headers */}
      <div>
        <h4 className="text-xs font-bold uppercase tracking-wider text-gray-400 mb-3">
          Key Envelope Headers
        </h4>
        <div className="bg-[#111827] rounded-lg border border-[#263244] divide-y divide-[#1E293B] text-xs font-mono">
          <div className="p-2.5 flex items-start gap-4">
            <span className="w-28 text-gray-400 font-semibold flex-shrink-0">From</span>
            <span className="text-gray-200 break-all">{headers.from}</span>
          </div>
          <div className="p-2.5 flex items-start gap-4">
            <span className="w-28 text-gray-400 font-semibold flex-shrink-0">Reply-To</span>
            <span className={cn('break-all', headers.replyTo !== headers.from ? 'text-amber-400 font-bold' : 'text-gray-200')}>
              {headers.replyTo} {headers.replyTo !== headers.from && '(MISMATCH DETECTED)'}
            </span>
          </div>
          <div className="p-2.5 flex items-start gap-4">
            <span className="w-28 text-gray-400 font-semibold flex-shrink-0">Return-Path</span>
            <span className="text-gray-300 break-all">{headers.returnPath}</span>
          </div>
          <div className="p-2.5 flex items-start gap-4">
            <span className="w-28 text-gray-400 font-semibold flex-shrink-0">Message-ID</span>
            <span className="text-gray-400 break-all">{headers.messageId}</span>
          </div>
          {headers.xOriginatingIp && (
            <div className="p-2.5 flex items-start gap-4 bg-red-950/20">
              <span className="w-28 text-red-400 font-semibold flex-shrink-0">X-Originating-IP</span>
              <span className="text-red-300 font-bold">{headers.xOriginatingIp}</span>
            </div>
          )}
        </div>
      </div>

      {/* Relay Path Hop-by-Hop Timeline */}
      <div>
        <div className="flex items-center justify-between mb-3">
          <h4 className="text-xs font-bold uppercase tracking-wider text-gray-400 flex items-center gap-2">
            <Server className="w-4 h-4 text-blue-400" />
            SMTP Relay Transmission Path (Earliest Hop First)
          </h4>
          <span className="text-2xs text-gray-400 font-mono">{relayPath.length} Identified Relay Hops</span>
        </div>

        <div className="space-y-3 relative before:absolute before:inset-0 before:left-3 before:w-0.5 before:bg-[#263244] before:z-0">
          {relayPath.map((hop) => {
            const isExpanded = !!expandedHops[hop.hopNumber];
            return (
              <div
                key={hop.hopNumber}
                className={cn(
                  'relative z-10 rounded-lg border bg-[#151E2E] transition-all',
                  hop.isAnomaly
                    ? 'border-red-500/40 bg-red-950/10'
                    : 'border-[#263244]'
                )}
              >
                {/* Hop Title Bar */}
                <div
                  onClick={() => toggleHop(hop.hopNumber)}
                  className="p-3 flex items-center justify-between cursor-pointer hover:bg-[#1B263B] rounded-t-lg transition"
                >
                  <div className="flex items-center gap-3">
                    <div
                      className={cn(
                        'w-6 h-6 rounded-full flex items-center justify-center font-mono font-bold text-2xs border',
                        hop.isOriginNode
                          ? 'bg-red-500/20 text-red-400 border-red-500/40'
                          : 'bg-blue-500/20 text-blue-400 border-blue-500/40'
                      )}
                    >
                      {hop.hopNumber}
                    </div>

                    <div>
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-bold text-gray-100 font-mono">
                          {hop.fromServer}
                        </span>
                        {hop.isOriginNode && (
                          <span className="px-1.5 py-0.2 rounded text-[10px] font-mono font-bold bg-red-500/20 text-red-400 border border-red-500/30">
                            PROBABLE ORIGIN
                          </span>
                        )}
                        {hop.isAnomaly && (
                          <span className="px-1.5 py-0.2 rounded text-[10px] font-mono font-bold bg-amber-500/20 text-amber-400 border border-amber-500/30">
                            ANOMALY
                          </span>
                        )}
                      </div>
                      <div className="flex items-center gap-3 text-2xs text-gray-400 font-mono mt-0.5">
                        <span className="flex items-center gap-1">
                          <Globe className="w-3 h-3 text-gray-400" />
                          {hop.location || 'Unknown Location'} ({hop.ip})
                        </span>
                        <span className="flex items-center gap-1">
                          <Clock className="w-3 h-3 text-gray-400" />
                          Delay: +{hop.delaySeconds}s
                        </span>
                      </div>
                    </div>
                  </div>

                  <div className="flex items-center gap-2">
                    <span className="text-2xs font-mono text-gray-400">{hop.protocol}</span>
                    {isExpanded ? (
                      <ChevronDown className="w-4 h-4 text-gray-400" />
                    ) : (
                      <ChevronRight className="w-4 h-4 text-gray-400" />
                    )}
                  </div>
                </div>

                {/* Expanded Raw Received Header Content */}
                {isExpanded && (
                  <div className="px-3 pb-3 pt-1 border-t border-[#1E293B] space-y-2 text-xs font-mono">
                    {hop.anomalyReason && (
                      <div className="p-2 rounded bg-red-500/10 border border-red-500/30 text-red-400 text-2xs flex items-center gap-2">
                        <AlertTriangle className="w-3.5 h-3.5 flex-shrink-0" />
                        <span>{hop.anomalyReason}</span>
                      </div>
                    )}
                    <div>
                      <span className="text-2xs uppercase text-gray-400 font-semibold block mb-1">Raw Received Header:</span>
                      <pre className="p-2 rounded bg-[#0B1120] border border-[#263244] text-[11px] text-gray-300 whitespace-pre-wrap break-all leading-relaxed">
                        {hop.rawHeader}
                      </pre>
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};
