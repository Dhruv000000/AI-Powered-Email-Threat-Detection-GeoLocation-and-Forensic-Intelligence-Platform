import React from 'react';
import {
  Clock,
  Mail,
  Server,
  ShieldCheck,
  GitFork,
  CheckCircle2,
  Lock,
} from 'lucide-react';
import { TimelineEvent } from '../../types/investigation';

interface InvestigationTimelineProps {
  events: TimelineEvent[];
}

export const InvestigationTimeline: React.FC<InvestigationTimelineProps> = ({ events }) => {
  if (!events || events.length === 0) {
    return null;
  }

  const getEventIcon = (type: string) => {
    switch (type) {
      case 'email_received':
        return <Mail className="w-3.5 h-3.5 text-blue-400" />;
      case 'header_observed':
        return <Server className="w-3.5 h-3.5 text-cyan-400" />;
      case 'analysis_completed':
        return <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />;
      case 'investigation_started':
        return <GitFork className="w-3.5 h-3.5 text-purple-400" />;
      default:
        return <Clock className="w-3.5 h-3.5 text-gray-400" />;
    }
  };

  return (
    <div className="bg-[#111827] border border-[#263244] rounded-lg overflow-hidden">
      {/* Header */}
      <div className="bg-[#151E2E] border-b border-[#263244] px-4 py-2.5 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Clock className="w-4 h-4 text-blue-400" />
          <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-gray-100">
            Forensic Evidentiary Timeline ({events.length})
          </h3>
        </div>
        <span className="text-3xs font-mono text-gray-400 flex items-center gap-1">
          <Lock className="w-2.5 h-2.5 text-emerald-400" />
          Strict Timestamp Evidence
        </span>
      </div>

      {/* Timeline Stream */}
      <div className="p-4 relative">
        <div className="absolute left-7 top-4 bottom-4 w-0.5 bg-[#1E293B]" />

        <div className="space-y-4 relative">
          {events.map((evt, idx) => (
            <div key={evt.id || idx} className="flex items-start gap-3.5 group">
              {/* Event Icon Point */}
              <div className="w-6 h-6 rounded-full bg-[#151E2E] border border-[#263244] flex items-center justify-center shrink-0 z-10 group-hover:border-purple-500 transition">
                {getEventIcon(evt.event_type)}
              </div>

              {/* Event Card */}
              <div className="flex-1 bg-[#151E2E]/80 border border-[#263244] rounded-lg p-2.5 font-mono text-xs">
                <div className="flex flex-wrap items-center justify-between gap-1 mb-1">
                  <h4 className="text-xs font-bold text-gray-100 font-sans">
                    {evt.title}
                  </h4>
                  <span className="text-3xs text-gray-400 bg-[#0D1117] px-1.5 py-0.5 rounded border border-[#1E293B]">
                    {evt.timestamp}
                  </span>
                </div>

                <p className="text-2xs text-gray-300 font-sans leading-relaxed">
                  {evt.description}
                </p>

                <div className="mt-1.5 pt-1.5 border-t border-[#1E293B] flex items-center justify-between text-3xs text-gray-400">
                  <span>Source: <strong className="text-gray-300">{evt.source}</strong></span>
                  {evt.evidence_reference && (
                    <span className="text-emerald-400">{evt.evidence_reference}</span>
                  )}
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
