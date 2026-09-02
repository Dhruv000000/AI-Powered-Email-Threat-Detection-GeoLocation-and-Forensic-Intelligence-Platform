import React from 'react';
import { CaseTimelineEvent } from '../../types/case';
import { Clock, ShieldAlert, Upload, Server, Globe, Briefcase, FileCheck, User } from 'lucide-react';

interface CaseTimelineProps {
  events: CaseTimelineEvent[];
}

export const CaseTimeline: React.FC<CaseTimelineProps> = ({ events }) => {
  const getEventIcon = (type: string) => {
    switch (type) {
      case 'upload':
        return Upload;
      case 'detection':
        return ShieldAlert;
      case 'ip_identified':
        return Server;
      case 'domain_discovered':
        return Globe;
      case 'case_created':
        return Briefcase;
      case 'evidence_attached':
        return FileCheck;
      default:
        return User;
    }
  };

  if (!events || events.length === 0) {
    return (
      <div className="p-8 text-center bg-[#111827] rounded-lg border border-[#263244] text-gray-400 font-mono text-xs">
        No chronological timeline events logged yet.
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between mb-4">
        <h4 className="text-xs font-bold uppercase tracking-wider text-gray-400 font-mono flex items-center gap-2">
          <Clock className="w-4 h-4 text-blue-400" />
          Chronological Investigation Event Timeline
        </h4>
        <span className="text-2xs text-gray-400 font-mono">{events.length} Events Recorded</span>
      </div>

      <div className="space-y-4 relative before:absolute before:inset-0 before:left-3 before:w-0.5 before:bg-[#263244] before:z-0">
        {events.map((evt) => {
          const Icon = getEventIcon(evt.type);
          return (
            <div
              key={evt.id}
              className="relative z-10 flex items-start gap-4 pl-1 group"
            >
              <div className="w-6 h-6 rounded-full bg-[#151E2E] border border-blue-500/40 text-blue-400 flex items-center justify-center flex-shrink-0 mt-0.5 shadow-sm group-hover:border-blue-400 group-hover:scale-110 transition">
                <Icon className="w-3.5 h-3.5" />
              </div>

              <div className="flex-1 p-3 rounded-lg border border-[#263244] bg-[#151E2E] space-y-1">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-gray-100 font-mono">{evt.title}</span>
                  <span className="text-2xs text-gray-400 font-mono">{evt.timeFormatted || evt.timestamp}</span>
                </div>
                <p className="text-xs text-gray-300 font-sans leading-relaxed">{evt.description}</p>
                <div className="pt-1 flex items-center gap-2 text-2xs text-gray-400 font-mono">
                  <span>Actor / Origin: <strong className="text-gray-300">{evt.actor}</strong></span>
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
