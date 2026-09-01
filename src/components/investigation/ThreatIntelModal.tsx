import React, { useEffect, useState } from 'react';
import {
  ThreatIntelItem,
  SandboxReport,
  EnrichedInvestigation,
  ProcessTreeNode,
} from '../../types/threatIntel';
import { threatIntelService } from '../../services/threatIntelService';
import { LoadingState } from '../common/LoadingState';
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  ExternalLink,
  Copy,
  Check,
  X,
  Layers,
  Search,
  RefreshCw,
  Cpu,
  Globe,
  Radio,
  FileCode,
  Terminal,
  Network,
  Database,
  Tag,
  Zap,
} from 'lucide-react';

interface ThreatIntelModalProps {
  investigationId: string;
  isOpen: boolean;
  onClose: () => void;
}

type TabType = 'intel' | 'sandbox';

export const ThreatIntelModal: React.FC<ThreatIntelModalProps> = ({
  investigationId,
  isOpen,
  onClose,
}) => {
  const [data, setData] = useState<EnrichedInvestigation | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<TabType>('intel');

  // Filters & State
  const [indicatorTypeFilter, setIndicatorTypeFilter] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [copiedText, setCopiedText] = useState<string | null>(null);
  const [selectedAttachmentIdx, setSelectedAttachmentIdx] = useState<number>(0);

  useEffect(() => {
    if (!isOpen || !investigationId) return;

    let isMounted = true;
    async function loadData(force = false) {
      if (force) setRefreshing(true);
      else setLoading(true);
      setError(null);

      try {
        const enriched = await threatIntelService.enrichInvestigation(investigationId, force);
        if (isMounted) {
          setData(enriched);
        }
      } catch (err: any) {
        if (isMounted) {
          setError(err.message || 'Failed to load threat intelligence');
        }
      } finally {
        if (isMounted) {
          setLoading(false);
          setRefreshing(false);
        }
      }
    }

    loadData();

    return () => {
      isMounted = false;
    };
  }, [isOpen, investigationId]);

  const handleRefresh = async () => {
    if (refreshing || !investigationId) return;
    setRefreshing(true);
    setError(null);
    try {
      const enriched = await threatIntelService.enrichInvestigation(investigationId, true);
      setData(enriched);
    } catch (err: any) {
      alert(`Refresh error: ${err.message}`);
    } finally {
      setRefreshing(false);
    }
  };

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedText(text);
    setTimeout(() => setCopiedText(null), 2000);
  };

  const renderProcessNode = (node: ProcessTreeNode, depth: number = 0) => {
    return (
      <div key={node.pid} className="space-y-1.5 font-mono text-2xs">
        <div
          className={`p-2 rounded border flex flex-col gap-1 transition-all ${
            node.is_suspicious
              ? 'bg-rose-950/30 border-rose-600/50 text-rose-200'
              : 'bg-[#111C30] border-[#1F2E47] text-gray-300'
          }`}
          style={{ marginLeft: `${depth * 18}px` }}
        >
          <div className="flex items-center justify-between gap-2">
            <div className="flex items-center gap-2">
              <Terminal className={`w-3.5 h-3.5 ${node.is_suspicious ? 'text-rose-400' : 'text-blue-400'}`} />
              <span className="font-bold text-gray-100">{node.process_name}</span>
              <span className="text-3xs px-1.5 py-0.2 bg-[#0B1120] rounded text-gray-400 border border-[#202E45]">
                PID: {node.pid} {node.parent_pid ? `(PPID: ${node.parent_pid})` : ''}
              </span>
            </div>
            {node.is_suspicious && (
              <span className="text-3xs font-bold px-1.5 py-0.5 rounded bg-rose-900/60 text-rose-300 border border-rose-700/50 flex items-center gap-1">
                <AlertTriangle className="w-2.5 h-2.5" />
                SUSPICIOUS BEHAVIOR
              </span>
            )}
          </div>
          <div className="text-3xs text-gray-400 font-mono bg-[#080D1A] p-1.5 rounded truncate border border-[#162238]" title={node.command_line}>
            {node.command_line}
          </div>
        </div>

        {node.children && node.children.map((child) => renderProcessNode(child, depth + 1))}
      </div>
    );
  };

  if (!isOpen) return null;

  const currentAttachment = data?.attachments && data.attachments[selectedAttachmentIdx];

  return (
    <div className="fixed inset-0 z-[9999] flex items-center justify-center bg-black/85 backdrop-blur-sm p-3 sm:p-5 animate-fade-in">
      <div className="bg-[#0B1120] border border-[#263244] rounded-xl w-full max-w-6xl h-[90vh] flex flex-col shadow-2xl overflow-hidden font-sans text-gray-200">
        {/* Modal Top Header */}
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between px-5 py-3.5 border-b border-[#263244] bg-[#0D1525] gap-3">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-purple-500/10 rounded-lg border border-purple-500/20 text-purple-400">
              <Globe className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-base font-bold text-gray-100 font-mono tracking-tight">
                  AEGIS Threat Intel Enrichment & Malware Sandbox
                </h2>
                <span className="text-3xs font-mono px-2 py-0.5 rounded bg-purple-900/40 text-purple-300 border border-purple-700/50">
                  LIVE CTI ENGINE
                </span>
              </div>
              <p className="text-2xs text-gray-400 font-mono">
                Target ID: <span className="text-purple-400 font-semibold">{investigationId}</span> • Aggregators:{' '}
                <span className="text-gray-300">VirusTotal • AbuseIPDB • AlienVault OTX</span>
              </p>
            </div>
          </div>

          {/* Header Action Buttons */}
          <div className="flex items-center gap-2 self-end sm:self-auto">
            <button
              onClick={handleRefresh}
              disabled={refreshing || loading}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-[#15233D] hover:bg-[#1C2F52] text-xs font-mono text-purple-300 border border-purple-500/30 rounded-lg transition-all disabled:opacity-50 shadow-sm"
              title="Bypass 24h cache and query live threat feeds"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${refreshing ? 'animate-spin' : 'text-purple-400'}`} />
              <span>{refreshing ? 'Refreshing Intel...' : 'Refresh Live Feeds'}</span>
            </button>

            <button
              onClick={onClose}
              className="p-1.5 text-gray-400 hover:text-gray-100 hover:bg-[#1A2538] rounded-lg transition-all"
              title="Close Intel Modal"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Navigation Tabs */}
        <div className="flex items-center px-5 border-b border-[#263244] bg-[#0A0F1D] gap-1 overflow-x-auto">
          <button
            onClick={() => setActiveTab('intel')}
            className={`flex items-center gap-2 py-3 px-4 border-b-2 text-xs font-mono font-semibold transition-all whitespace-nowrap ${
              activeTab === 'intel'
                ? 'border-purple-500 text-purple-400 bg-purple-500/5'
                : 'border-transparent text-gray-400 hover:text-gray-200'
            }`}
          >
            <Radio className={`w-3.5 h-3.5 ${activeTab === 'intel' ? 'text-purple-400' : 'text-gray-400'}`} />
            <span>Threat Intelligence Feeds</span>
            {data && (
              <span className="px-1.5 py-0.2 rounded-full text-3xs bg-purple-900/60 text-purple-300">
                {data.indicators.length}
              </span>
            )}
          </button>

          <button
            onClick={() => setActiveTab('sandbox')}
            className={`flex items-center gap-2 py-3 px-4 border-b-2 text-xs font-mono font-semibold transition-all whitespace-nowrap ${
              activeTab === 'sandbox'
                ? 'border-purple-500 text-purple-400 bg-purple-500/5'
                : 'border-transparent text-gray-400 hover:text-gray-200'
            }`}
          >
            <Cpu className={`w-3.5 h-3.5 ${activeTab === 'sandbox' ? 'text-purple-400' : 'text-gray-400'}`} />
            <span>Malware Sandbox Detonation</span>
            {data && data.attachments.length > 0 && (
              <span className="px-1.5 py-0.2 rounded-full text-3xs bg-rose-900/60 text-rose-300">
                {data.attachments.length}
              </span>
            )}
          </button>
        </div>

        {/* Content Body Area */}
        <div className="flex-1 overflow-y-auto p-5 scrollbar-thin scrollbar-thumb-slate-700">
          {loading ? (
            <div className="flex flex-col items-center justify-center h-full gap-3 py-16">
              <LoadingState message="Aggregating External CTI & Detonating Attachments..." />
            </div>
          ) : error ? (
            <div className="p-6 bg-red-950/30 border border-red-800/40 rounded-xl text-center space-y-3 max-w-lg mx-auto mt-12">
              <AlertTriangle className="w-8 h-8 text-rose-400 mx-auto" />
              <h3 className="text-sm font-bold text-rose-200 font-mono">Threat Intelligence Query Failed</h3>
              <p className="text-xs text-rose-300">{error}</p>
            </div>
          ) : !data ? null : (
            <>
              {/* TAB 1: THREAT INTEL FEEDS */}
              {activeTab === 'intel' && (
                <div className="space-y-4 animate-fade-in max-w-5xl mx-auto font-mono">
                  {/* Intel Scorecards Summary */}
                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                    <div className="bg-[#0D1525] border border-[#263244] rounded-lg p-3.5 flex items-center justify-between">
                      <div>
                        <span className="text-3xs text-gray-400 block uppercase">VirusTotal Detections</span>
                        <h4 className="text-lg font-black text-gray-100">Multi-Engine</h4>
                        <span className="text-3xs text-blue-400">72 AV Heuristics</span>
                      </div>
                      <div className="p-2.5 rounded-lg bg-blue-950/50 border border-blue-800/40 text-blue-400">
                        <Radio className="w-5 h-5" />
                      </div>
                    </div>

                    <div className="bg-[#0D1525] border border-[#263244] rounded-lg p-3.5 flex items-center justify-between">
                      <div>
                        <span className="text-3xs text-gray-400 block uppercase">AbuseIPDB Confidence</span>
                        <h4 className="text-lg font-black text-gray-100">IP Blacklist</h4>
                        <span className="text-3xs text-amber-400">Tor & Proxy Detection</span>
                      </div>
                      <div className="p-2.5 rounded-lg bg-amber-950/50 border border-amber-800/40 text-amber-400">
                        <Globe className="w-5 h-5" />
                      </div>
                    </div>

                    <div className="bg-[#0D1525] border border-[#263244] rounded-lg p-3.5 flex items-center justify-between">
                      <div>
                        <span className="text-3xs text-gray-400 block uppercase">AlienVault OTX</span>
                        <h4 className="text-lg font-black text-gray-100">Threat Pulses</h4>
                        <span className="text-3xs text-purple-400">Adversary Attribution</span>
                      </div>
                      <div className="p-2.5 rounded-lg bg-purple-950/50 border border-purple-800/40 text-purple-400">
                        <Zap className="w-5 h-5" />
                      </div>
                    </div>
                  </div>

                  {/* Indicator Filter Bar */}
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-2 border-b border-[#263244]">
                    {/* Indicator Type Filters */}
                    <div className="flex items-center gap-1 text-2xs bg-[#0D1525] p-1 rounded border border-[#263244] overflow-x-auto">
                      {(['ALL', 'url', 'domain', 'ip', 'hash', 'email'] as const).map((t) => (
                        <button
                          key={t}
                          onClick={() => setIndicatorTypeFilter(t)}
                          className={`px-2.5 py-1 rounded transition-all font-bold uppercase ${
                            indicatorTypeFilter === t
                              ? 'bg-purple-600 text-white'
                              : 'text-gray-400 hover:text-gray-200'
                          }`}
                        >
                          {t === 'ALL' ? 'All Types' : t}
                        </button>
                      ))}
                    </div>

                    {/* Search */}
                    <div className="relative">
                      <Search className="w-3.5 h-3.5 text-gray-400 absolute left-2.5 top-2.5" />
                      <input
                        type="text"
                        placeholder="Filter indicators..."
                        value={searchQuery}
                        onChange={(e) => setSearchQuery(e.target.value)}
                        className="pl-8 pr-3 py-1 bg-[#0D1525] border border-[#263244] rounded text-2xs text-gray-200 placeholder-gray-500 focus:outline-none focus:border-purple-500"
                      />
                    </div>
                  </div>

                  {/* Enriched Indicator Cards */}
                  <div className="space-y-3">
                    {data.indicators
                      .filter(
                        (i) =>
                          (indicatorTypeFilter === 'ALL' || i.indicator_type === indicatorTypeFilter) &&
                          (!searchQuery || i.indicator.toLowerCase().includes(searchQuery.toLowerCase()))
                      )
                      .map((item, idx) => {
                        const isMalicious = item.overall_verdict === 'MALICIOUS';
                        const isSuspicious = item.overall_verdict === 'SUSPICIOUS';

                        return (
                          <div
                            key={idx}
                            className={`p-4 rounded-lg border transition-all ${
                              isMalicious
                                ? 'bg-[#150D18] border-rose-600/50 shadow-md shadow-rose-950/20'
                                : isSuspicious
                                ? 'bg-[#15120D] border-amber-600/50'
                                : 'bg-[#0D1525] border-[#263244]'
                            }`}
                          >
                            <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2 pb-2 mb-2 border-b border-[#1E293B]">
                              <div className="flex items-center gap-2 flex-wrap">
                                <span
                                  className={`px-2 py-0.5 text-3xs font-bold rounded uppercase ${
                                    isMalicious
                                      ? 'bg-rose-950 text-rose-400 border border-rose-800/60'
                                      : isSuspicious
                                      ? 'bg-amber-950 text-amber-400 border border-amber-800/60'
                                      : 'bg-emerald-950 text-emerald-400 border border-emerald-800/60'
                                  }`}
                                >
                                  {item.overall_verdict}
                                </span>
                                <span className="text-3xs text-purple-300 bg-purple-950/60 px-2 py-0.5 rounded border border-purple-800/40 uppercase">
                                  {item.indicator_type}
                                </span>
                                <h4 className="text-xs font-bold text-gray-100 truncate max-w-md" title={item.indicator}>
                                  {item.indicator}
                                </h4>
                              </div>

                              <div className="flex items-center gap-2 self-end sm:self-auto">
                                <span className="text-3xs text-gray-400">
                                  Score: <strong className={isMalicious ? 'text-rose-400' : 'text-emerald-400'}>{item.overall_score}/100</strong>
                                </span>
                                <button
                                  onClick={() => handleCopy(item.indicator)}
                                  className="p-1 text-gray-400 hover:text-white rounded transition-all"
                                  title="Copy indicator value"
                                >
                                  {copiedText === item.indicator ? (
                                    <Check className="w-3.5 h-3.5 text-emerald-400" />
                                  ) : (
                                    <Copy className="w-3.5 h-3.5" />
                                  )}
                                </button>
                              </div>
                            </div>

                            {/* Providers Breakdown */}
                            <div className="grid grid-cols-1 md:grid-cols-3 gap-2.5 pt-1">
                              {item.providers.map((p, pIdx) => (
                                <div key={pIdx} className="bg-[#080D1A] p-2.5 rounded border border-[#18263D] text-3xs space-y-1.5">
                                  <div className="flex items-center justify-between">
                                    <span className="font-bold text-purple-300 uppercase">{p.provider}</span>
                                    <span
                                      className={`px-1.5 py-0.2 rounded font-bold ${
                                        p.verdict === 'MALICIOUS'
                                          ? 'text-rose-400 bg-rose-950'
                                          : p.verdict === 'SUSPICIOUS'
                                          ? 'text-amber-400 bg-amber-950'
                                          : 'text-emerald-400 bg-emerald-950'
                                      }`}
                                    >
                                      {p.verdict}
                                    </span>
                                  </div>

                                  {p.detection_ratio && (
                                    <div className="text-gray-300">
                                      Detection: <strong className="text-rose-400">{p.detection_ratio}</strong>
                                    </div>
                                  )}
                                  {p.abuse_confidence !== undefined && p.abuse_confidence !== null && (
                                    <div className="text-gray-300">
                                      Abuse Confidence: <strong className="text-amber-400">{p.abuse_confidence}%</strong>
                                    </div>
                                  )}
                                  {p.pulses_count !== undefined && p.pulses_count !== null && (
                                    <div className="text-gray-300">
                                      OTX Pulses: <strong className="text-purple-400">{p.pulses_count} Pulses</strong>
                                    </div>
                                  )}

                                  {p.malware_families && p.malware_families.length > 0 && (
                                    <div className="text-gray-400 truncate">
                                      Family: <span className="text-rose-300">{p.malware_families.join(', ')}</span>
                                    </div>
                                  )}

                                  {p.tags && p.tags.length > 0 && (
                                    <div className="flex flex-wrap gap-1 pt-1">
                                      {p.tags.map((tg, tIdx) => (
                                        <span key={tIdx} className="text-4xs px-1.5 py-0.2 rounded bg-[#10192A] text-gray-400 border border-[#1D2B44]">
                                          #{tg}
                                        </span>
                                      ))}
                                    </div>
                                  )}
                                </div>
                              ))}
                            </div>
                          </div>
                        );
                      })}
                  </div>
                </div>
              )}

              {/* TAB 2: ATTACHMENT SANDBOX DETONATION */}
              {activeTab === 'sandbox' && (
                <div className="space-y-5 animate-fade-in max-w-5xl mx-auto font-mono">
                  {data.attachments.length === 0 ? (
                    <div className="p-8 text-center bg-[#0D1525] border border-[#263244] rounded-lg text-gray-400 text-xs">
                      No attachments extracted from this email payload.
                    </div>
                  ) : (
                    <>
                      {/* Attachment Selector Bar */}
                      <div className="flex items-center gap-2 overflow-x-auto pb-2 border-b border-[#263244]">
                        {data.attachments.map((att, idx) => (
                          <button
                            key={idx}
                            onClick={() => setSelectedAttachmentIdx(idx)}
                            className={`flex items-center gap-2 px-3 py-1.5 rounded-lg border text-xs transition-all ${
                              selectedAttachmentIdx === idx
                                ? 'bg-purple-900/40 border-purple-500 text-purple-200'
                                : 'bg-[#0D1525] border-[#263244] text-gray-400 hover:text-gray-200'
                            }`}
                          >
                            <FileCode className="w-3.5 h-3.5 text-purple-400" />
                            <span className="truncate max-w-xs">{att.file_name}</span>
                            <span
                              className={`px-1.5 py-0.2 text-3xs font-bold rounded ${
                                att.verdict === 'MALICIOUS' ? 'bg-rose-950 text-rose-400' : 'bg-emerald-950 text-emerald-400'
                              }`}
                            >
                              {att.verdict}
                            </span>
                          </button>
                        ))}
                      </div>

                      {currentAttachment && (
                        <div className="space-y-4">
                          {/* Top File Summary Box */}
                          <div className="bg-[#0D1525] border border-[#263244] rounded-lg p-4 space-y-3">
                            <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2 pb-2 border-b border-[#1E293B]">
                              <div>
                                <h3 className="text-sm font-bold text-gray-100">{currentAttachment.file_name}</h3>
                                <p className="text-3xs text-gray-400">{currentAttachment.file_type}</p>
                              </div>
                              <div className="flex items-center gap-2">
                                <span className="text-3xs text-gray-400 bg-[#111C30] px-2 py-0.5 rounded border border-[#202C3F]">
                                  Magic: <strong className="text-gray-300">{currentAttachment.magic_bytes}</strong>
                                </span>
                                <span className="text-3xs text-gray-400 bg-[#111C30] px-2 py-0.5 rounded border border-[#202C3F]">
                                  Entropy: <strong className="text-amber-400">{currentAttachment.entropy} / 8.0</strong>
                                </span>
                                <span className="text-xs font-bold text-rose-400 bg-rose-950/60 px-2 py-0.5 rounded border border-rose-700/50">
                                  Risk: {currentAttachment.risk_score}/100
                                </span>
                              </div>
                            </div>

                            {/* Hash Row */}
                            <div className="p-2.5 bg-[#080D1A] rounded border border-[#162238] text-3xs space-y-1">
                              <div className="flex items-center justify-between">
                                <span className="text-gray-400">
                                  SHA256: <strong className="text-blue-400">{currentAttachment.sha256}</strong>
                                </span>
                                <button
                                  onClick={() => handleCopy(currentAttachment.sha256)}
                                  className="text-gray-400 hover:text-white"
                                >
                                  {copiedText === currentAttachment.sha256 ? (
                                    <Check className="w-3 h-3 text-emerald-400" />
                                  ) : (
                                    <Copy className="w-3 h-3" />
                                  )}
                                </button>
                              </div>
                            </div>

                            {/* Structural Flags */}
                            {currentAttachment.structural_flags.length > 0 && (
                              <div>
                                <span className="text-3xs text-gray-400 block uppercase font-bold mb-1.5">
                                  Static Structural Anomalies:
                                </span>
                                <div className="flex flex-wrap gap-1.5">
                                  {currentAttachment.structural_flags.map((flag, fIdx) => (
                                    <span
                                      key={fIdx}
                                      className="text-3xs px-2 py-0.5 rounded bg-rose-950/40 text-rose-300 border border-rose-800/40 flex items-center gap-1"
                                    >
                                      <AlertTriangle className="w-3 h-3 text-rose-400" />
                                      <span>{flag}</span>
                                    </span>
                                  ))}
                                </div>
                              </div>
                            )}
                          </div>

                          {/* Process Execution Tree */}
                          {currentAttachment.process_tree.length > 0 && (
                            <div className="bg-[#0D1525] border border-[#263244] rounded-lg p-4 space-y-3">
                              <h4 className="text-xs font-bold text-gray-200 uppercase tracking-wider flex items-center gap-2">
                                <Terminal className="w-4 h-4 text-purple-400" />
                                Simulated Process Execution Hierarchy
                              </h4>
                              <div className="space-y-2">
                                {currentAttachment.process_tree.map((rootNode) => renderProcessNode(rootNode, 0))}
                              </div>
                            </div>
                          )}

                          {/* Network Detonation Callbacks */}
                          {currentAttachment.network_callbacks.length > 0 && (
                            <div className="bg-[#0D1525] border border-[#263244] rounded-lg p-4 space-y-2.5">
                              <h4 className="text-xs font-bold text-gray-200 uppercase tracking-wider flex items-center gap-2">
                                <Network className="w-4 h-4 text-blue-400" />
                                Outbound Detonation Network Activity
                              </h4>
                              <div className="divide-y divide-[#1A2538]">
                                {currentAttachment.network_callbacks.map((net, nIdx) => (
                                  <div key={nIdx} className="py-2 flex items-center justify-between text-2xs">
                                    <div className="flex items-center gap-2">
                                      <span className="px-1.5 py-0.2 rounded bg-blue-950 text-blue-400 font-bold border border-blue-800/40">
                                        {net.protocol}
                                      </span>
                                      <span className="text-gray-200 font-bold">{net.destination}:{net.port}</span>
                                    </div>
                                    <span className="text-3xs text-rose-400 font-sans">{net.behavior}</span>
                                  </div>
                                ))}
                              </div>
                            </div>
                          )}

                          {/* Registry Persistence */}
                          {currentAttachment.registry_modifications.length > 0 && (
                            <div className="bg-[#0D1525] border border-[#263244] rounded-lg p-4 space-y-2.5">
                              <h4 className="text-xs font-bold text-gray-200 uppercase tracking-wider flex items-center gap-2">
                                <Database className="w-4 h-4 text-amber-400" />
                                Registry Autostart Persistence Hooks
                              </h4>
                              <div className="divide-y divide-[#1A2538]">
                                {currentAttachment.registry_modifications.map((reg, rIdx) => (
                                  <div key={rIdx} className="py-2 text-2xs space-y-0.5">
                                    <div className="flex items-center justify-between">
                                      <span className="text-amber-400 font-bold">{reg.key}</span>
                                      <span className="text-3xs px-1.5 py-0.2 rounded bg-amber-950 text-amber-300 border border-amber-800/40">
                                        {reg.action}
                                      </span>
                                    </div>
                                    <div className="text-3xs text-gray-400 truncate">
                                      Value: <strong>{reg.value_name}</strong> • Data: <code>{reg.data}</code>
                                    </div>
                                  </div>
                                ))}
                              </div>
                            </div>
                          )}
                        </div>
                      )}
                    </>
                  )}
                </div>
              )}
            </>
          )}
        </div>

        {/* Modal Footer */}
        <div className="flex items-center justify-between px-5 py-3 border-t border-[#263244] bg-[#0D1525] text-2xs font-mono text-gray-400">
          <div>
            <span>CTI Status: <strong className="text-purple-400">ENRICHED & ACTIVE</strong></span>
          </div>
          <div className="flex items-center gap-3">
            <span>AEGIS Sandbox Virtualization v2.4</span>
            <button
              onClick={onClose}
              className="px-3 py-1 bg-[#1A2538] hover:bg-[#22324D] text-gray-200 rounded transition-all font-semibold"
            >
              Close
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
