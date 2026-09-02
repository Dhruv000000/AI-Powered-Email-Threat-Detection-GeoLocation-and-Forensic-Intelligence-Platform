import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  ShieldAlert,
  Search,
  Download,
  GitFork,
  MapPin,
  FileDown,
  Server,
} from 'lucide-react';
import { threatService } from '../services/threatService';
import { ThreatRecord, ThreatSeverity, ThreatType, ThreatStatus } from '../types/threat';
import { SeverityBadge } from '../components/common/SeverityBadge';
import { LoadingState } from '../components/common/LoadingState';
import { EmptyState } from '../components/common/EmptyState';
import { ThreatMapModal } from '../components/investigation/ThreatMapModal';
import { DFIRReportModal } from '../components/investigation/DFIRReportModal';
import { ThreatIntelModal } from '../components/investigation/ThreatIntelModal';

export const ThreatsPage: React.FC = () => {
  const navigate = useNavigate();
  const [threats, setThreats] = useState<ThreatRecord[]>([]);
  const [loading, setLoading] = useState(true);

  // Filters State
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedSeverity, setSelectedSeverity] = useState<ThreatSeverity | 'all'>('all');
  const [selectedType, setSelectedType] = useState<ThreatType | 'all'>('all');
  const [selectedStatus, setSelectedStatus] = useState<ThreatStatus | 'all'>('all');

  // Active Modals
  const [activeModal, setActiveModal] = useState<{
    type: 'map' | 'report' | 'intel' | null;
    targetId: string | null;
  }>({ type: null, targetId: null });

  useEffect(() => {
    let isMounted = true;
    async function loadThreats() {
      const data = await threatService.getThreats({
        searchTerm,
        severity: selectedSeverity,
        threatType: selectedType,
        status: selectedStatus,
      });
      if (isMounted) {
        setThreats(data);
        setLoading(false);
      }
    }
    loadThreats();
    return () => {
      isMounted = false;
    };
  }, [searchTerm, selectedSeverity, selectedType, selectedStatus]);

  const handleExportCsv = () => {
    const headers = ['Threat ID', 'Email ID', 'Subject', 'Sender', 'Type', 'Severity', 'Risk Score', 'Origin IP', 'Status'];
    const rows = threats.map((t) => [
      t.id,
      t.emailId,
      `"${t.subject.replace(/"/g, '""')}"`,
      t.sender,
      t.threatType,
      t.severity,
      t.riskScore,
      t.probableOriginIp,
      t.status,
    ]);

    const csvContent = 'data:text/csv;charset=utf-8,' + [headers.join(','), ...rows.map((e) => e.join(','))].join('\n');
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement('a');
    link.setAttribute('href', encodedUri);
    link.setAttribute('download', 'aegis-threat-telemetry.csv');
    document.body.appendChild(link);
    link.click();
    link.remove();
  };

  const getMitreTags = (threatType: string) => {
    const t = threatType.toLowerCase();
    if (t.includes('bec') || t.includes('impersonation')) {
      return ['T1586.002', 'T1656'];
    }
    if (t.includes('malware') || t.includes('payload') || t.includes('trojan')) {
      return ['T1204.002', 'T1059.001'];
    }
    if (t.includes('credential') || t.includes('harvester')) {
      return ['T1566.002', 'T1071.001'];
    }
    return ['T1566.002', 'T1204.001'];
  };

  return (
    <div className="space-y-6">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-[#263244] pb-4">
        <div>
          <h1 className="text-xl font-bold text-gray-100 font-mono tracking-tight flex items-center gap-2">
            <ShieldAlert className="w-5 h-5 text-red-400" />
            Global Threat Intelligence Telemetry & Telemetry Feed
          </h1>
          <p className="text-xs text-gray-400 font-mono mt-1">
            Aggregated threat events across organizational mail relays, honeypots, and gateways with one-click forensic pivots.
          </p>
        </div>

        <div className="flex items-center gap-2 font-mono text-xs">
          <button
            onClick={handleExportCsv}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-[#151E2E] hover:bg-[#1E293B] text-gray-200 border border-[#263244] rounded transition shadow-sm"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Export CSV</span>
          </button>
        </div>
      </div>

      {/* Filter Toolbar */}
      <div className="p-4 rounded-lg bg-[#151E2E] border border-[#263244] space-y-3 font-mono">
        <div className="flex flex-wrap items-center gap-3">
          {/* Search Input */}
          <div className="relative flex-1 min-w-[240px]">
            <Search className="w-4 h-4 text-gray-400 absolute left-3 top-2.5" />
            <input
              type="text"
              placeholder="Search threat subject, sender, indicators..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full pl-9 pr-3 py-1.5 bg-[#0B1120] border border-[#263244] rounded text-xs text-gray-200 placeholder-gray-500 focus:outline-none focus:border-blue-500"
            />
          </div>

          {/* Severity Filter */}
          <select
            value={selectedSeverity}
            onChange={(e) => setSelectedSeverity(e.target.value as any)}
            className="bg-[#0B1120] border border-[#263244] rounded px-3 py-1.5 text-xs text-gray-200 focus:outline-none focus:border-blue-500"
          >
            <option value="all">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>

          {/* Threat Type Filter */}
          <select
            value={selectedType}
            onChange={(e) => setSelectedType(e.target.value as any)}
            className="bg-[#0B1120] border border-[#263244] rounded px-3 py-1.5 text-xs text-gray-200 focus:outline-none focus:border-blue-500"
          >
            <option value="all">All Threat Types</option>
            <option value="phishing">Phishing</option>
            <option value="credential_harvesting">Credential Harvesting</option>
            <option value="malware_delivery">Malware Delivery</option>
            <option value="bec">BEC / Fraud</option>
            <option value="spam">Spam</option>
          </select>
        </div>
      </div>

      {/* Main Table */}
      {loading ? (
        <LoadingState message="Loading threat intelligence events..." />
      ) : threats.length === 0 ? (
        <EmptyState
          title="No Threats Found"
          description="No threat events matched your current search filters."
          actionLabel="Reset Search Filters"
          onAction={() => {
            setSearchTerm('');
            setSelectedSeverity('all');
            setSelectedType('all');
            setSelectedStatus('all');
          }}
        />
      ) : (
        <div className="overflow-x-auto rounded-lg border border-[#263244] bg-[#111827]">
          <table className="w-full text-left text-xs border-collapse font-mono">
            <thead>
              <tr className="bg-[#151E2E] border-b border-[#263244] text-2xs uppercase tracking-wider text-gray-400 font-semibold">
                <th className="py-3 px-3.5">Severity</th>
                <th className="py-3 px-3.5">Threat Subject & MITRE ATT&CK</th>
                <th className="py-3 px-3.5">Sender Identity</th>
                <th className="py-3 px-3.5">Classification</th>
                <th className="py-3 px-3.5">Risk</th>
                <th className="py-3 px-3.5">Origin Infrastructure</th>
                <th className="py-3 px-3.5 text-right">Quick Forensic Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1E293B]">
              {threats.map((item) => {
                const mitreTags = getMitreTags(item.threatType);
                return (
                  <tr
                    key={item.id}
                    className="hover:bg-[#151E2E]/80 transition group"
                  >
                    {/* Severity */}
                    <td className="py-3 px-3.5 whitespace-nowrap">
                      <SeverityBadge severity={item.severity} size="sm" />
                    </td>

                    {/* Subject & MITRE Tags */}
                    <td className="py-3 px-3.5 max-w-sm">
                      <div className="space-y-1">
                        <span
                          onClick={() => navigate(`/analyze/${item.emailId}`)}
                          className="font-semibold text-gray-100 font-sans hover:text-blue-400 cursor-pointer transition block truncate"
                          title={item.subject}
                        >
                          {item.subject}
                        </span>
                        <div className="flex items-center gap-1.5 flex-wrap">
                          {mitreTags.map((tag) => (
                            <span
                              key={tag}
                              className="text-3xs px-1.5 py-0.2 rounded bg-blue-950/70 text-blue-300 border border-blue-800/50"
                            >
                              {tag}
                            </span>
                          ))}
                          <span className="text-3xs text-gray-500 font-sans truncate max-w-[160px]">
                            {item.primaryReason}
                          </span>
                        </div>
                      </div>
                    </td>

                    {/* Sender */}
                    <td className="py-3 px-3.5 max-w-[180px] truncate text-gray-300">
                      {item.sender}
                    </td>

                    {/* Threat Type */}
                    <td className="py-3 px-3.5 whitespace-nowrap">
                      <span className="px-2 py-0.5 rounded bg-[#151E2E] text-gray-300 border border-[#263244] text-2xs font-semibold">
                        {item.threatType}
                      </span>
                    </td>

                    {/* Risk Score */}
                    <td className="py-3 px-3.5 whitespace-nowrap">
                      <span
                        className={`font-bold ${
                          item.riskScore >= 80 ? 'text-red-400' : item.riskScore >= 50 ? 'text-amber-400' : 'text-emerald-400'
                        }`}
                      >
                        {item.riskScore}/100
                      </span>
                    </td>

                    {/* Origin */}
                    <td className="py-3 px-3.5 whitespace-nowrap text-2xs text-gray-300">
                      <div>{item.probableOriginCity}, {item.probableOriginCountry}</div>
                      <div className="text-gray-400 text-[10px]">{item.probableOriginIp}</div>
                    </td>

                    {/* Quick Forensic Action Toolbar */}
                    <td className="py-3 px-3.5 text-right whitespace-nowrap">
                      <div className="flex items-center justify-end gap-1.5 font-mono">
                        {/* Threat Graph */}
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            navigate(`/investigations/${item.emailId}`);
                          }}
                          className="px-2 py-1 bg-[#1E293B] hover:bg-purple-900/60 text-purple-300 hover:text-white rounded text-3xs border border-[#263244] transition flex items-center gap-1 shadow-sm"
                          title="Open Interactive Cytoscape Threat Graph"
                        >
                          <GitFork className="w-3 h-3 text-purple-400" />
                          <span>Graph</span>
                        </button>

                        {/* Threat Map */}
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            setActiveModal({ type: 'map', targetId: item.emailId });
                          }}
                          className="px-2 py-1 bg-[#1E293B] hover:bg-blue-900/60 text-blue-300 hover:text-white rounded text-3xs border border-[#263244] transition flex items-center gap-1 shadow-sm"
                          title="Open Geographic Relay Transit Map"
                        >
                          <MapPin className="w-3 h-3 text-blue-400" />
                          <span>Map</span>
                        </button>

                        {/* DFIR Report */}
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            setActiveModal({ type: 'report', targetId: item.emailId });
                          }}
                          className="px-2 py-1 bg-[#1E293B] hover:bg-blue-600 hover:text-white text-gray-300 rounded text-3xs border border-[#263244] transition flex items-center gap-1 shadow-sm"
                          title="Open DFIR Executive Report & PDF Export"
                        >
                          <FileDown className="w-3 h-3" />
                          <span>Report</span>
                        </button>

                        {/* Threat Intel & Sandbox */}
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            setActiveModal({ type: 'intel', targetId: item.emailId });
                          }}
                          className="px-2 py-1 bg-[#1E293B] hover:bg-purple-600 hover:text-white text-gray-300 rounded text-3xs border border-[#263244] transition flex items-center gap-1 shadow-sm"
                          title="Open Live Threat Intel Feeds & Malware Sandbox"
                        >
                          <Server className="w-3 h-3 text-purple-400" />
                          <span>Intel</span>
                        </button>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {/* Global Modals for Quick Pivot Actions */}
      {activeModal.targetId && (
        <>
          <ThreatMapModal
            investigationId={activeModal.targetId}
            isOpen={activeModal.type === 'map'}
            onClose={() => setActiveModal({ type: null, targetId: null })}
          />

          <DFIRReportModal
            investigationId={activeModal.targetId}
            isOpen={activeModal.type === 'report'}
            onClose={() => setActiveModal({ type: null, targetId: null })}
          />

          <ThreatIntelModal
            investigationId={activeModal.targetId}
            isOpen={activeModal.type === 'intel'}
            onClose={() => setActiveModal({ type: null, targetId: null })}
          />
        </>
      )}
    </div>
  );
};
