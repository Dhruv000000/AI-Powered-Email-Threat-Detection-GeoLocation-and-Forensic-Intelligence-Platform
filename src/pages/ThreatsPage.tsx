import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  ShieldAlert,
  Search,
  Filter,
  ArrowUpDown,
  ExternalLink,
  RefreshCw,
  Clock,
  Download,
} from 'lucide-react';
import { threatService, ThreatFilterParams } from '../services/threatService';
import { ThreatRecord, ThreatSeverity, ThreatType, ThreatStatus } from '../types/threat';
import { SeverityBadge } from '../components/common/SeverityBadge';
import { StatusBadge } from '../components/common/StatusBadge';
import { LoadingState } from '../components/common/LoadingState';
import { EmptyState } from '../components/common/EmptyState';

export const ThreatsPage: React.FC = () => {
  const navigate = useNavigate();
  const [threats, setThreats] = useState<ThreatRecord[]>([]);
  const [loading, setLoading] = useState(true);

  // Filters State
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedSeverity, setSelectedSeverity] = useState<ThreatSeverity | 'all'>('all');
  const [selectedType, setSelectedType] = useState<ThreatType | 'all'>('all');
  const [selectedStatus, setSelectedStatus] = useState<ThreatStatus | 'all'>('all');

  const fetchThreats = async () => {
    setLoading(true);
    const data = await threatService.getThreats({
      searchTerm,
      severity: selectedSeverity,
      threatType: selectedType,
      status: selectedStatus,
    });
    setThreats(data);
    setLoading(false);
  };

  useEffect(() => {
    fetchThreats();
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

  return (
    <div className="space-y-6">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-[#263244] pb-4">
        <div>
          <h1 className="text-xl font-bold text-gray-100 font-mono tracking-tight flex items-center gap-2">
            <ShieldAlert className="w-5 h-5 text-red-400" />
            Global Threat Intelligence Telemetry
          </h1>
          <p className="text-xs text-gray-400 font-mono mt-1">
            Aggregated threat events across organizational mail relays, honeypots, and gateways.
          </p>
        </div>

        <div className="flex items-center gap-2 font-mono text-xs">
          <button
            onClick={handleExportCsv}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-[#151E2E] hover:bg-[#1E293B] text-gray-200 border border-[#263244] rounded transition"
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
            <Search className="w-4 h-4 text-gray-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Search by subject, sender, IP, threat reason..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full bg-[#0B1120] border border-[#263244] rounded pl-9 pr-3 py-1.5 text-xs text-gray-100 placeholder-gray-500 focus:outline-none focus:border-blue-500 font-sans"
            />
          </div>

          {/* Severity Filter */}
          <select
            value={selectedSeverity}
            onChange={(e) => setSelectedSeverity(e.target.value as any)}
            className="bg-[#0B1120] border border-[#263244] text-gray-200 text-xs rounded px-3 py-1.5 focus:outline-none"
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
            className="bg-[#0B1120] border border-[#263244] text-gray-200 text-xs rounded px-3 py-1.5 focus:outline-none"
          >
            <option value="all">All Threat Types</option>
            <option value="Business Email Compromise">Business Email Compromise (BEC)</option>
            <option value="Phishing">Phishing</option>
            <option value="Malware">Malware</option>
            <option value="Fraud">Fraud</option>
            <option value="Suspicious">Suspicious</option>
          </select>

          {/* Status Filter */}
          <select
            value={selectedStatus}
            onChange={(e) => setSelectedStatus(e.target.value as any)}
            className="bg-[#0B1120] border border-[#263244] text-gray-200 text-xs rounded px-3 py-1.5 focus:outline-none"
          >
            <option value="all">All Statuses</option>
            <option value="active">Active</option>
            <option value="investigating">Under Investigation</option>
            <option value="mitigated">Mitigated</option>
          </select>

          {/* Reset Filters */}
          {(searchTerm || selectedSeverity !== 'all' || selectedType !== 'all' || selectedStatus !== 'all') && (
            <button
              onClick={() => {
                setSearchTerm('');
                setSelectedSeverity('all');
                setSelectedType('all');
                setSelectedStatus('all');
              }}
              className="text-xs text-blue-400 hover:underline px-2 py-1"
            >
              Reset Filters
            </button>
          )}
        </div>

        <div className="flex items-center justify-between text-2xs text-gray-400 pt-1 border-t border-[#1E293B]">
          <span>Displaying <strong className="text-gray-200">{threats.length}</strong> threat incidents</span>
          <span>Gateway Sync Active</span>
        </div>
      </div>

      {/* Threats Table */}
      {loading ? (
        <LoadingState message="Loading threat telemetry..." />
      ) : threats.length === 0 ? (
        <EmptyState
          icon={ShieldAlert}
          title="No Threat Telemetry Found"
          description="No incidents match the active search filters or severity criteria."
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
                <th className="py-3 px-3.5">Threat Subject & Reason</th>
                <th className="py-3 px-3.5">Sender Identity</th>
                <th className="py-3 px-3.5">Classification</th>
                <th className="py-3 px-3.5">Risk</th>
                <th className="py-3 px-3.5">Origin Infrastructure</th>
                <th className="py-3 px-3.5">Status</th>
                <th className="py-3 px-3.5 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1E293B]">
              {threats.map((item) => (
                <tr
                  key={item.id}
                  onClick={() => navigate(`/analyze/${item.emailId}`)}
                  className="hover:bg-[#151E2E]/80 transition cursor-pointer group"
                >
                  {/* Severity */}
                  <td className="py-3 px-3.5 whitespace-nowrap">
                    <SeverityBadge severity={item.severity} size="sm" />
                  </td>

                  {/* Subject & Reason */}
                  <td className="py-3 px-3.5 max-w-sm">
                    <div className="space-y-0.5">
                      <span className="font-semibold text-gray-100 font-sans group-hover:text-blue-400 transition block truncate">
                        {item.subject}
                      </span>
                      <span className="text-2xs text-gray-400 block truncate font-sans">
                        {item.primaryReason}
                      </span>
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

                  {/* Status */}
                  <td className="py-3 px-3.5 whitespace-nowrap">
                    <StatusBadge status={item.status} />
                  </td>

                  {/* Action */}
                  <td className="py-3 px-3.5 text-right whitespace-nowrap">
                    <button className="px-2.5 py-1 bg-[#1E293B] hover:bg-blue-600 hover:text-white rounded text-2xs text-gray-300 border border-[#263244] transition">
                      Investigate
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};
