import React from 'react';
import { IPIntelligence, DomainIntelligence } from '../../types/infrastructure';
import { Server, Globe, ShieldAlert, ArrowUpRight, CheckCircle2, AlertOctagon, HelpCircle } from 'lucide-react';
import { SeverityBadge } from '../common/SeverityBadge';
import { useNavigate } from 'react-router-dom';

interface IPIntelligenceCardProps {
  ipIntel: IPIntelligence;
  domainIntel: DomainIntelligence;
}

export const IPIntelligenceCard: React.FC<IPIntelligenceCardProps> = ({
  ipIntel,
  domainIntel,
}) => {
  const navigate = useNavigate();

  return (
    <div className="space-y-6">
      {/* Probable Infrastructure Origin Banner */}
      <div className="p-4 rounded-lg bg-blue-950/20 border border-blue-500/30 flex items-start gap-3">
        <HelpCircle className="w-5 h-5 text-blue-400 flex-shrink-0 mt-0.5" />
        <div className="text-xs text-gray-300 space-y-1">
          <p className="font-semibold text-gray-100 uppercase tracking-wide">
            Forensic Origin Disclaimer & Methodology
          </p>
          <p className="text-gray-400 leading-relaxed">
            Geographic references indicate the <strong>Probable Infrastructure Origin</strong> (the hosting server, proxy, or relay node executing the SMTP handshake). They do not represent the verified physical location of the human adversary.
          </p>
        </div>
      </div>

      {/* Main Grid: IP Intelligence & Domain WHOIS */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Originating IP Intelligence Card */}
        <div className="p-5 rounded-lg bg-[#111827] border border-[#263244] space-y-4">
          <div className="flex items-center justify-between border-b border-[#263244] pb-3">
            <div className="flex items-center gap-2">
              <Server className="w-4 h-4 text-blue-400" />
              <h4 className="text-xs font-bold uppercase tracking-wider text-gray-200 font-mono">
                Probable Infrastructure Origin (Earliest Relay Node)
              </h4>
            </div>
            <SeverityBadge severity={ipIntel.threatLevel} size="sm" />
          </div>

          <div className="grid grid-cols-2 gap-4 text-xs font-mono">
            <div>
              <span className="text-2xs uppercase text-gray-400 font-semibold block">IP Address</span>
              <span className="text-sm font-bold text-gray-100 mt-0.5 block">{ipIntel.ip}</span>
            </div>
            <div>
              <span className="text-2xs uppercase text-gray-400 font-semibold block">Estimated Geolocation</span>
              <span className="text-xs font-medium text-gray-200 mt-0.5 block">
                {ipIntel.city}, {ipIntel.country} ({ipIntel.countryCode})
              </span>
            </div>
            <div>
              <span className="text-2xs uppercase text-gray-400 font-semibold block">Autonomous System (ASN)</span>
              <span className="text-xs text-gray-200 mt-0.5 block">{ipIntel.asn}</span>
              <span className="text-2xs text-gray-400 block">{ipIntel.asnOrg}</span>
            </div>
            <div>
              <span className="text-2xs uppercase text-gray-400 font-semibold block">Internet Service Provider</span>
              <span className="text-xs text-gray-200 mt-0.5 block">{ipIntel.isp}</span>
            </div>
            <div>
              <span className="text-2xs uppercase text-gray-400 font-semibold block">Infrastructure Type</span>
              <span className="text-xs text-gray-200 mt-0.5 block">{ipIntel.usageType}</span>
            </div>
            <div>
              <span className="text-2xs uppercase text-gray-400 font-semibold block">Attribution Confidence</span>
              <span className="text-xs font-bold text-blue-400 mt-0.5 block">{ipIntel.confidence}%</span>
            </div>
          </div>

          {/* Infrastructure Threat Tags */}
          <div className="pt-2 border-t border-[#1E293B] flex flex-wrap gap-2">
            {ipIntel.isTor && (
              <span className="px-2 py-0.5 rounded bg-red-500/20 text-red-400 border border-red-500/30 text-2xs font-mono font-bold">
                TOR Exit Node
              </span>
            )}
            {ipIntel.isVpn && (
              <span className="px-2 py-0.5 rounded bg-amber-500/20 text-amber-400 border border-amber-500/30 text-2xs font-mono font-bold">
                Commercial VPN
              </span>
            )}
            {ipIntel.isProxy && (
              <span className="px-2 py-0.5 rounded bg-purple-500/20 text-purple-400 border border-purple-500/30 text-2xs font-mono font-bold">
                Anonymizing Proxy
              </span>
            )}
            {ipIntel.isHosting && (
              <span className="px-2 py-0.5 rounded bg-blue-500/20 text-blue-400 border border-blue-500/30 text-2xs font-mono font-bold">
                Bulletproof / Cloud Datacenter
              </span>
            )}
          </div>

          <div className="pt-3 flex justify-end">
            <button
              onClick={() => navigate('/map')}
              className="flex items-center gap-1.5 text-xs text-blue-400 hover:text-blue-300 font-medium font-mono"
            >
              <span>View On Global Threat Map</span>
              <ArrowUpRight className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>

        {/* Sender Domain WHOIS & DNS Intelligence */}
        <div className="p-5 rounded-lg bg-[#111827] border border-[#263244] space-y-4">
          <div className="flex items-center justify-between border-b border-[#263244] pb-3">
            <div className="flex items-center gap-2">
              <Globe className="w-4 h-4 text-blue-400" />
              <h4 className="text-xs font-bold uppercase tracking-wider text-gray-200 font-mono">
                Domain Registration & DNS Intelligence
              </h4>
            </div>
            {domainIntel.isNewlyRegistered && (
              <span className="px-2 py-0.5 rounded bg-red-500/20 text-red-400 border border-red-500/30 text-2xs font-mono font-bold">
                NEWLY REGISTERED (&lt;14 DAYS)
              </span>
            )}
          </div>

          <div className="grid grid-cols-2 gap-4 text-xs font-mono">
            <div>
              <span className="text-2xs uppercase text-gray-400 font-semibold block">Domain Name</span>
              <span className="text-xs font-bold text-gray-100 mt-0.5 block">{domainIntel.domain}</span>
            </div>
            <div>
              <span className="text-2xs uppercase text-gray-400 font-semibold block">Registrar</span>
              <span className="text-xs text-gray-200 mt-0.5 block">{domainIntel.registrar}</span>
            </div>
            <div>
              <span className="text-2xs uppercase text-gray-400 font-semibold block">Registration Date</span>
              <span className="text-xs text-gray-200 mt-0.5 block">
                {domainIntel.creationDate} ({domainIntel.domainAgeDays} days old)
              </span>
            </div>
            <div>
              <span className="text-2xs uppercase text-gray-400 font-semibold block">Domain Reputation Score</span>
              <span className="text-xs font-bold text-red-400 mt-0.5 block">
                {domainIntel.reputationScore}/100 (HIGH RISK)
              </span>
            </div>
          </div>

          {/* DNS / MX Records */}
          <div className="space-y-2 pt-2 border-t border-[#1E293B] text-xs font-mono">
            <div>
              <span className="text-2xs uppercase text-gray-400 font-semibold block mb-1">Authoritative Name Servers:</span>
              <div className="p-2 rounded bg-[#0B1120] border border-[#263244] text-gray-300 text-2xs space-y-0.5">
                {domainIntel.nameServers.map((ns) => (
                  <div key={ns}>{ns}</div>
                ))}
              </div>
            </div>
            <div>
              <span className="text-2xs uppercase text-gray-400 font-semibold block mb-1">MX Mail Exchangers:</span>
              <div className="p-2 rounded bg-[#0B1120] border border-[#263244] text-gray-300 text-2xs space-y-0.5">
                {domainIntel.mxRecords.map((mx) => (
                  <div key={mx}>{mx}</div>
                ))}
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
