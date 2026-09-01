import React, { useEffect, useState } from 'react';
import { DFIRReport, MitreTechnique, RemediationAction, IoCItem } from '../../types/report';
import { reportService } from '../../services/reportService';
import { remediationService } from '../../services/remediationService';
import { RemediationExecutionLog } from '../../types/remediation';
import { LoadingState } from '../common/LoadingState';
import {
  FileText,
  Download,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  ExternalLink,
  CheckCircle2,
  Copy,
  Check,
  X,
  Layers,
  ListFilter,
  Flame,
  Search,
  Clock,
  Crosshair,
  Server,
  Share2,
  Play,
  RotateCcw,
  Zap,
  Activity,
} from 'lucide-react';

interface DFIRReportModalProps {
  investigationId: string;
  isOpen: boolean;
  onClose: () => void;
}

type TabType = 'summary' | 'mitre' | 'remediation' | 'iocs' | 'timeline';

export const DFIRReportModal: React.FC<DFIRReportModalProps> = ({
  investigationId,
  isOpen,
  onClose,
}) => {
  const [report, setReport] = useState<DFIRReport | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<TabType>('summary');
  const [downloadingPdf, setDownloadingPdf] = useState(false);
  const [downloadingCsv, setDownloadingCsv] = useState(false);
  const [downloadingStix, setDownloadingStix] = useState(false);

  // Remediation Execution States
  const [executionMap, setExecutionMap] = useState<Record<string, RemediationExecutionLog>>({});
  const [executingActionId, setExecutingActionId] = useState<string | null>(null);
  const [executingBatch, setExecutingBatch] = useState(false);
  const [rollingBackLogId, setRollingBackLogId] = useState<string | null>(null);
  const [remediationFeedback, setRemediationFeedback] = useState<string | null>(null);

  // Filters & State
  const [priorityFilter, setPriorityFilter] = useState<'ALL' | 'P0' | 'P1' | 'P2'>('ALL');
  const [iocSearch, setIocSearch] = useState('');
  const [copiedIoc, setCopiedIoc] = useState<string | null>(null);
  const [checkedActions, setCheckedActions] = useState<Record<string, boolean>>({});

  useEffect(() => {
    if (!isOpen || !investigationId) return;

    let isMounted = true;
    async function loadData() {
      setLoading(true);
      setError(null);
      try {
        const [reportData, historyData] = await Promise.all([
          reportService.getInvestigationReport(investigationId),
          remediationService.getExecutionHistory(investigationId).catch(() => ({ logs: [] })),
        ]);

        if (isMounted) {
          setReport(reportData);

          // Build quick lookup map by action_id
          const logMap: Record<string, RemediationExecutionLog> = {};
          if (historyData && historyData.logs) {
            historyData.logs.forEach((log: RemediationExecutionLog) => {
              // Store latest log per action_id
              if (!logMap[log.action_id] || new Date(log.executed_at) > new Date(logMap[log.action_id].executed_at)) {
                logMap[log.action_id] = log;
              }
            });
          }
          setExecutionMap(logMap);
        }
      } catch (err: any) {
        if (isMounted) {
          setError(err.message || 'Failed to load DFIR report');
        }
      } finally {
        if (isMounted) {
          setLoading(false);
        }
      }
    }

    loadData();

    return () => {
      isMounted = false;
    };
  }, [isOpen, investigationId]);

  const handleDownloadPdf = async () => {
    if (!investigationId || downloadingPdf) return;
    setDownloadingPdf(true);
    try {
      await reportService.downloadReportPdf(investigationId);
    } catch (err: any) {
      alert(`Error exporting PDF: ${err.message}`);
    } finally {
      setDownloadingPdf(false);
    }
  };

  const handleDownloadCsv = async () => {
    if (!investigationId || downloadingCsv) return;
    setDownloadingCsv(true);
    try {
      await reportService.downloadIocsCsv(investigationId);
    } catch (err: any) {
      alert(`Error exporting IoCs: ${err.message}`);
    } finally {
      setDownloadingCsv(false);
    }
  };

  const handleDownloadStix = async () => {
    if (!investigationId || downloadingStix) return;
    setDownloadingStix(true);
    try {
      await remediationService.downloadStixBundle(investigationId);
    } catch (err: any) {
      alert(`Error exporting STIX 2.1 bundle: ${err.message}`);
    } finally {
      setDownloadingStix(false);
    }
  };

  const handleExecuteSingle = async (actionId: string, e: React.MouseEvent) => {
    e.stopPropagation();
    if (executingActionId || !investigationId) return;

    setExecutingActionId(actionId);
    setRemediationFeedback(null);
    try {
      const res = await remediationService.executeAction(investigationId, actionId, false);
      setExecutionMap((prev) => ({ ...prev, [actionId]: res }));
      setCheckedActions((prev) => ({ ...prev, [actionId]: true }));
      setRemediationFeedback(`Action ${actionId} successfully enforced across ${res.target_system}.`);
      setTimeout(() => setRemediationFeedback(null), 4000);
    } catch (err: any) {
      alert(`Failed to execute action: ${err.message}`);
    } finally {
      setExecutingActionId(null);
    }
  };

  const handleExecuteBatchP0 = async () => {
    if (executingBatch || !investigationId) return;

    setExecutingBatch(true);
    setRemediationFeedback(null);
    try {
      const results = await remediationService.executeBatch(investigationId, 'P0', undefined, false);
      setExecutionMap((prev) => {
        const updated = { ...prev };
        results.forEach((r) => {
          updated[r.action_id] = r;
        });
        return updated;
      });
      setCheckedActions((prev) => {
        const updated = { ...prev };
        results.forEach((r) => {
          updated[r.action_id] = true;
        });
        return updated;
      });
      setRemediationFeedback(`Enforced ${results.length} P0 perimeter containment rules simultaneously.`);
      setTimeout(() => setRemediationFeedback(null), 5000);
    } catch (err: any) {
      alert(`Failed to execute batch containment: ${err.message}`);
    } finally {
      setExecutingBatch(false);
    }
  };

  const handleRollback = async (actionId: string, logId: string, e: React.MouseEvent) => {
    e.stopPropagation();
    if (rollingBackLogId || !investigationId) return;

    setRollingBackLogId(logId);
    setRemediationFeedback(null);
    try {
      const res = await remediationService.rollbackAction(investigationId, logId);
      setExecutionMap((prev) => ({ ...prev, [actionId]: res }));
      setCheckedActions((prev) => ({ ...prev, [actionId]: false }));
      setRemediationFeedback(`Rule ${actionId} successfully rolled back & perimeter ACL deactivated.`);
      setTimeout(() => setRemediationFeedback(null), 4000);
    } catch (err: any) {
      alert(`Failed to rollback action: ${err.message}`);
    } finally {
      setRollingBackLogId(null);
    }
  };

  const handleCopyIoc = (value: string) => {
    navigator.clipboard.writeText(value);
    setCopiedIoc(value);
    setTimeout(() => setCopiedIoc(null), 2000);
  };

  const toggleAction = (id: string) => {
    setCheckedActions((prev) => ({ ...prev, [id]: !prev[id] }));
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-[9999] flex items-center justify-center bg-black/85 backdrop-blur-sm p-3 sm:p-5 animate-fade-in">
      <div className="bg-[#0B1120] border border-[#263244] rounded-xl w-full max-w-6xl h-[90vh] flex flex-col shadow-2xl overflow-hidden font-sans text-gray-200">
        {/* Modal Top Header */}
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between px-5 py-3.5 border-b border-[#263244] bg-[#0D1525] gap-3">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-blue-500/10 rounded-lg border border-blue-500/20 text-blue-400">
              <FileText className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-base font-bold text-gray-100 font-mono tracking-tight">
                  AEGIS DFIR Executive Report & Incident Playbook
                </h2>
                <span className="text-3xs font-mono px-2 py-0.5 rounded bg-blue-900/40 text-blue-300 border border-blue-700/50">
                  TLP:AMBER
                </span>
              </div>
              <p className="text-2xs text-gray-400 font-mono">
                Case ID: <span className="text-blue-400 font-semibold">{report?.case_reference || investigationId}</span> • Report ID:{' '}
                <span className="text-gray-300">{report?.report_id || 'RPT-PENDING'}</span>
              </p>
            </div>
          </div>

          {/* Action Buttons */}
          <div className="flex items-center gap-2 self-end sm:self-auto flex-wrap">
            {/* STIX 2.1 CTI Export Button */}
            <button
              onClick={handleDownloadStix}
              disabled={downloadingStix || !report}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-[#15233D] hover:bg-[#1C2F52] text-xs font-mono text-emerald-300 border border-emerald-500/30 rounded-lg transition-all disabled:opacity-50 shadow-sm"
              title="Export standard STIX 2.1 CTI JSON bundle"
            >
              <Share2 className={`w-3.5 h-3.5 ${downloadingStix ? 'animate-spin' : 'text-emerald-400'}`} />
              <span>{downloadingStix ? 'Exporting...' : 'Export STIX 2.1'}</span>
            </button>

            {/* CSV IoC Export */}
            <button
              onClick={handleDownloadCsv}
              disabled={downloadingCsv || !report}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-[#15233D] hover:bg-[#1C2F52] text-xs font-mono text-blue-300 border border-blue-500/30 rounded-lg transition-all disabled:opacity-50 shadow-sm"
              title="Download IoC indicators as CSV"
            >
              <Download className={`w-3.5 h-3.5 ${downloadingCsv ? 'animate-spin' : ''}`} />
              <span>{downloadingCsv ? 'Exporting...' : 'Export IoCs'}</span>
            </button>

            {/* PDF Report Export */}
            <button
              onClick={handleDownloadPdf}
              disabled={downloadingPdf || !report}
              className="flex items-center gap-1.5 px-3.5 py-1.5 bg-blue-600 hover:bg-blue-500 text-xs font-mono font-semibold text-white rounded-lg transition-all disabled:opacity-50 shadow-md shadow-blue-900/30"
              title="Download full forensic executive report PDF"
            >
              <Download className={`w-3.5 h-3.5 ${downloadingPdf ? 'animate-spin' : ''}`} />
              <span>{downloadingPdf ? 'Generating PDF...' : 'Download PDF Report'}</span>
            </button>

            <button
              onClick={onClose}
              className="p-1.5 text-gray-400 hover:text-gray-100 hover:bg-[#1A2538] rounded-lg transition-all"
              title="Close Report Modal"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Global Feedback Banner */}
        {remediationFeedback && (
          <div className="bg-emerald-950/80 border-b border-emerald-600/40 px-5 py-2 text-xs font-mono text-emerald-200 flex items-center gap-2 animate-fade-in">
            <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
            <span>{remediationFeedback}</span>
          </div>
        )}

        {/* Navigation Tabs */}
        <div className="flex items-center px-5 border-b border-[#263244] bg-[#0A0F1D] gap-1 overflow-x-auto">
          {[
            { id: 'summary', label: 'Executive Summary', icon: ShieldAlert },
            { id: 'mitre', label: 'MITRE ATT&CK Matrix', icon: Layers },
            { id: 'remediation', label: 'SOC Remediation Playbook', icon: ShieldCheck },
            { id: 'iocs', label: 'IoC Indicators', icon: Crosshair },
            { id: 'timeline', label: 'Forensic Timeline', icon: Clock },
          ].map((tab) => {
            const Icon = tab.icon;
            const isActive = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id as TabType)}
                className={`flex items-center gap-2 py-3 px-3.5 border-b-2 text-xs font-mono font-semibold transition-all whitespace-nowrap ${
                  isActive
                    ? 'border-blue-500 text-blue-400 bg-blue-500/5'
                    : 'border-transparent text-gray-400 hover:text-gray-200 hover:bg-slate-800/30'
                }`}
              >
                <Icon className={`w-3.5 h-3.5 ${isActive ? 'text-blue-400' : 'text-gray-400'}`} />
                <span>{tab.label}</span>
                {tab.id === 'remediation' && report?.remediation_plan && (
                  <span className="px-1.5 py-0.2 rounded-full text-3xs bg-blue-900/60 text-blue-300">
                    {report.remediation_plan.length}
                  </span>
                )}
                {tab.id === 'iocs' && report?.iocs && (
                  <span className="px-1.5 py-0.2 rounded-full text-3xs bg-slate-800 text-gray-300">
                    {report.iocs.length}
                  </span>
                )}
              </button>
            );
          })}
        </div>

        {/* Content Body Area */}
        <div className="flex-1 overflow-y-auto p-5 scrollbar-thin scrollbar-thumb-slate-700">
          {loading ? (
            <div className="flex flex-col items-center justify-center h-full gap-3 py-16">
              <LoadingState message="Synthesizing DFIR Report & MITRE Matrix..." />
            </div>
          ) : error ? (
            <div className="p-6 bg-red-950/30 border border-red-800/40 rounded-xl text-center space-y-3 max-w-lg mx-auto mt-12">
              <AlertTriangle className="w-8 h-8 text-rose-400 mx-auto" />
              <h3 className="text-sm font-bold text-rose-200 font-mono">Failed to Generate DFIR Report</h3>
              <p className="text-xs text-rose-300">{error}</p>
            </div>
          ) : !report ? null : (
            <>
              {/* TAB 1: EXECUTIVE SUMMARY */}
              {activeTab === 'summary' && (
                <div className="space-y-5 animate-fade-in max-w-5xl mx-auto">
                  {/* Verdict Banner */}
                  <div
                    className={`p-4 rounded-xl border flex flex-col md:flex-row items-start md:items-center justify-between gap-4 ${
                      report.executive_summary.risk_score >= 80
                        ? 'bg-rose-950/20 border-rose-800/40'
                        : report.executive_summary.risk_score >= 50
                        ? 'bg-amber-950/20 border-amber-800/40'
                        : 'bg-emerald-950/20 border-emerald-800/40'
                    }`}
                  >
                    <div className="space-y-1">
                      <div className="flex items-center gap-2 font-mono">
                        <span className="text-xs font-bold text-gray-400 uppercase tracking-wider">
                          Primary Forensic Verdict:
                        </span>
                        <span
                          className={`text-sm font-black uppercase ${
                            report.executive_summary.risk_score >= 80
                              ? 'text-rose-400'
                              : report.executive_summary.risk_score >= 50
                              ? 'text-amber-400'
                              : 'text-emerald-400'
                          }`}
                        >
                          {report.executive_summary.verdict}
                        </span>
                      </div>
                      <p className="text-xs text-gray-300 font-mono">
                        Classification:{' '}
                        <strong className="text-white">{report.executive_summary.classification}</strong> • AI Confidence:{' '}
                        <strong className="text-blue-400">
                          {(report.executive_summary.ai_confidence * 100).toFixed(1)}%
                        </strong>
                      </p>
                    </div>

                    <div className="flex items-center gap-3 font-mono self-end md:self-auto">
                      <div className="text-right">
                        <span className="text-3xs text-gray-400 block uppercase">Composite Risk</span>
                        <span className="text-2xl font-black text-rose-400">
                          {report.executive_summary.risk_score}
                          <span className="text-xs text-gray-500">/100</span>
                        </span>
                      </div>
                    </div>
                  </div>

                  {/* Executive Narrative */}
                  <div className="bg-[#0D1525] border border-[#263244] rounded-lg p-4 space-y-2">
                    <h3 className="text-xs font-mono font-bold text-gray-300 uppercase tracking-wider flex items-center gap-2">
                      <ShieldAlert className="w-4 h-4 text-blue-400" />
                      Executive Threat Synthesis Narrative
                    </h3>
                    <p className="text-xs text-gray-300 leading-relaxed font-sans">
                      {report.executive_summary.narrative}
                    </p>
                  </div>

                  {/* Key Takeaways & Potential Impact */}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div className="bg-[#0D1525] border border-[#263244] rounded-lg p-4 space-y-2.5">
                      <h3 className="text-xs font-mono font-bold text-gray-300 uppercase tracking-wider flex items-center gap-2">
                        <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                        Key Investigation Takeaways
                      </h3>
                      <ul className="space-y-1.5 text-xs text-gray-300">
                        {report.executive_summary.key_takeaways.map((t, idx) => (
                          <li key={idx} className="flex items-start gap-2">
                            <span className="text-blue-400 font-bold">•</span>
                            <span>{t}</span>
                          </li>
                        ))}
                      </ul>
                    </div>

                    <div className="bg-[#0D1525] border border-[#263244] rounded-lg p-4 space-y-2.5 font-mono">
                      <h3 className="text-xs font-bold text-gray-300 uppercase tracking-wider flex items-center gap-2">
                        <Flame className="w-4 h-4 text-amber-400" />
                        Attack Vector & Impact Analysis
                      </h3>
                      <div className="space-y-2 text-xs">
                        <div className="p-2.5 bg-[#111C30] rounded border border-[#202C3F]">
                          <span className="text-3xs text-gray-400 block uppercase">Primary Vector</span>
                          <span className="text-gray-200 font-semibold">{report.executive_summary.attack_vector}</span>
                        </div>
                        <div className="p-2.5 bg-[#111C30] rounded border border-[#202C3F]">
                          <span className="text-3xs text-gray-400 block uppercase">Potential Business Impact</span>
                          <span className="text-gray-300">{report.executive_summary.potential_impact}</span>
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* Target Email Metadata Quickview */}
                  <div className="bg-[#0D1525] border border-[#263244] rounded-lg p-4 space-y-2 font-mono text-xs">
                    <h3 className="text-xs font-bold text-gray-300 uppercase tracking-wider flex items-center gap-2 mb-2">
                      <Server className="w-4 h-4 text-blue-400" />
                      Evidentiary Message Parameters
                    </h3>
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-2xs">
                      <div className="bg-[#111C30] p-2 rounded">
                        <strong className="text-gray-400">From:</strong>{' '}
                        <span className="text-gray-200">
                          {report.email_metadata.from_name ? `"${report.email_metadata.from_name}" ` : ''}
                          &lt;{report.email_metadata.from_email}&gt;
                        </span>
                      </div>
                      <div className="bg-[#111C30] p-2 rounded">
                        <strong className="text-gray-400">To:</strong>{' '}
                        <span className="text-gray-200">{report.email_metadata.to_email || 'N/A'}</span>
                      </div>
                      <div className="bg-[#111C30] p-2 rounded">
                        <strong className="text-gray-400">Subject:</strong>{' '}
                        <span className="text-gray-200">{report.email_metadata.subject || 'N/A'}</span>
                      </div>
                      <div className="bg-[#111C30] p-2 rounded">
                        <strong className="text-gray-400">Reply-To:</strong>{' '}
                        <span className="text-gray-200">{report.email_metadata.reply_to || 'None'}</span>
                      </div>
                      <div className="bg-[#111C30] p-2 rounded sm:col-span-2">
                        <strong className="text-gray-400">File SHA256:</strong>{' '}
                        <span className="text-blue-400">{report.email_metadata.sha256 || 'N/A'}</span>
                      </div>
                    </div>
                  </div>
                </div>
              )}

              {/* TAB 2: MITRE ATT&CK MATRIX */}
              {activeTab === 'mitre' && (
                <div className="space-y-4 animate-fade-in max-w-5xl mx-auto font-mono">
                  <div className="flex items-center justify-between pb-2 border-b border-[#263244]">
                    <div>
                      <h3 className="text-sm font-bold text-gray-200">
                        Mapped MITRE ATT&CK Enterprise Matrix Techniques ({report.mitre_matrix.length})
                      </h3>
                      <p className="text-2xs text-gray-400">
                        Deterministic tactical alignment derived from header signals, URLs, and transmission hops.
                      </p>
                    </div>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3.5">
                    {report.mitre_matrix.map((tech) => (
                      <div
                        key={tech.technique_id}
                        className="bg-[#0D1525] border border-[#263244] rounded-lg p-4 space-y-2.5 hover:border-blue-500/50 transition-all shadow-sm"
                      >
                        <div className="flex items-start justify-between gap-2">
                          <div className="flex items-center gap-2">
                            <span className="px-2 py-0.5 rounded bg-blue-900/50 text-blue-300 font-bold text-xs border border-blue-700/50">
                              {tech.technique_id}
                            </span>
                            <h4 className="text-xs font-bold text-gray-100">{tech.name}</h4>
                          </div>
                          <span className="text-3xs px-2 py-0.5 rounded bg-[#1A263D] text-gray-300 border border-[#2A3B5A]">
                            {tech.tactic}
                          </span>
                        </div>

                        <p className="text-2xs text-gray-300 font-sans leading-relaxed">
                          {tech.description}
                        </p>

                        {/* Matched Indicators */}
                        {tech.matched_indicators && tech.matched_indicators.length > 0 && (
                          <div className="pt-2 border-t border-[#1E293B]">
                            <span className="text-3xs text-gray-400 block mb-1 uppercase font-bold">
                              Evidentiary Context:
                            </span>
                            <div className="space-y-1">
                              {tech.matched_indicators.map((ind, i) => (
                                <div
                                  key={i}
                                  className="text-3xs bg-[#111C30] p-1.5 rounded text-gray-300 truncate border border-[#1C2C45]"
                                >
                                  {ind}
                                </div>
                              ))}
                            </div>
                          </div>
                        )}

                        <div className="flex items-center justify-between pt-1">
                          <span className="text-3xs text-gray-400">
                            Confidence: <strong className="text-blue-400">{(tech.confidence * 100).toFixed(0)}%</strong>
                          </span>
                          <a
                            href={tech.url}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="text-3xs text-blue-400 hover:text-blue-300 flex items-center gap-1 hover:underline"
                          >
                            <span>MITRE Doc</span>
                            <ExternalLink className="w-2.5 h-2.5" />
                          </a>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* TAB 3: REMEDIATION PLAYBOOK WITH LIVE EXECUTION & ROLLBACK */}
              {activeTab === 'remediation' && (
                <div className="space-y-4 animate-fade-in max-w-5xl mx-auto font-mono">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-2 border-b border-[#263244] gap-2">
                    <div>
                      <h3 className="text-sm font-bold text-gray-200 flex items-center gap-2">
                        <span>Prioritized SOC Incident Containment Playbook</span>
                        <span className="px-2 py-0.5 text-3xs font-bold rounded bg-blue-900/40 text-blue-300 border border-blue-700/40">
                          Automated Integrations Active
                        </span>
                      </h3>
                      <p className="text-2xs text-gray-400">
                        Enforce perimeter rules (DNS sinkholing, MTA blacklists, Exchange purge, EDR host isolation) with real-time audit logs.
                      </p>
                    </div>

                    <div className="flex items-center gap-2 flex-wrap">
                      {/* Execute All P0 Button */}
                      <button
                        onClick={handleExecuteBatchP0}
                        disabled={executingBatch}
                        className="flex items-center gap-1.5 px-3 py-1.5 bg-rose-600 hover:bg-rose-500 text-white text-xs font-bold rounded-lg transition-all shadow-md shadow-rose-950/40 disabled:opacity-50"
                        title="Enforce all P0 emergency containment rules simultaneously"
                      >
                        <Zap className={`w-3.5 h-3.5 ${executingBatch ? 'animate-spin' : 'text-yellow-300'}`} />
                        <span>{executingBatch ? 'Enforcing P0...' : 'Execute All P0 (Containment)'}</span>
                      </button>

                      {/* Priority Filter */}
                      <div className="flex items-center gap-1 text-2xs bg-[#0D1525] p-1 rounded border border-[#263244]">
                        {(['ALL', 'P0', 'P1', 'P2'] as const).map((p) => (
                          <button
                            key={p}
                            onClick={() => setPriorityFilter(p)}
                            className={`px-2.5 py-1 rounded transition-all font-bold ${
                              priorityFilter === p
                                ? p === 'P0'
                                  ? 'bg-rose-600 text-white'
                                  : p === 'P1'
                                  ? 'bg-amber-600 text-white'
                                  : p === 'P2'
                                  ? 'bg-blue-600 text-white'
                                  : 'bg-gray-700 text-white'
                                : 'text-gray-400 hover:text-gray-200'
                            }`}
                          >
                            {p === 'ALL' ? 'All Priorities' : p}
                          </button>
                        ))}
                      </div>
                    </div>
                  </div>

                  {/* Playbook Cards */}
                  <div className="space-y-3">
                    {report.remediation_plan
                      .filter((act) => priorityFilter === 'ALL' || act.priority === priorityFilter)
                      .map((act) => {
                        const execution = executionMap[act.action_id];
                        const isEnforced = execution && execution.status === 'SUCCESS';
                        const isReverted = execution && execution.status === 'REVERTED';
                        const isExecuting = executingActionId === act.action_id;
                        const isRollingBack = rollingBackLogId === execution?.log_id;

                        return (
                          <div
                            key={act.action_id}
                            className={`p-4 rounded-lg border transition-all ${
                              isEnforced
                                ? 'bg-[#0A1A14] border-emerald-600/60 shadow-md shadow-emerald-950/20'
                                : isReverted
                                ? 'bg-[#151520] border-gray-700/50 opacity-80'
                                : 'bg-[#0D1525] border-[#263244] hover:border-gray-500'
                            }`}
                          >
                            <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2 pb-2 mb-2 border-b border-[#1E293B]">
                              <div className="flex items-center gap-2 flex-wrap">
                                <span
                                  className={`px-2 py-0.5 text-3xs font-bold rounded ${
                                    act.priority === 'P0'
                                      ? 'bg-rose-500/20 text-rose-400 border border-rose-500/40'
                                      : act.priority === 'P1'
                                      ? 'bg-amber-500/20 text-amber-400 border border-amber-500/40'
                                      : 'bg-blue-500/20 text-blue-400 border border-blue-500/40'
                                  }`}
                                >
                                  {act.priority} • {act.category}
                                </span>
                                <h4 className="text-xs font-bold text-gray-100">{act.title}</h4>
                              </div>

                              <div className="flex items-center gap-2 self-end sm:self-auto">
                                <span className="text-3xs text-gray-400 bg-[#111C30] px-2 py-0.5 rounded border border-[#202C3F]">
                                  Target: <strong className="text-gray-200">{act.target_system}</strong>
                                </span>

                                {/* Execution Status Tag */}
                                {isEnforced ? (
                                  <span className="flex items-center gap-1 text-3xs font-bold px-2 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-500/50 animate-pulse">
                                    <CheckCircle2 className="w-3 h-3 text-emerald-400" />
                                    <span>ENFORCED ON PERIMETER</span>
                                  </span>
                                ) : isReverted ? (
                                  <span className="flex items-center gap-1 text-3xs font-bold px-2 py-0.5 rounded bg-gray-800 text-gray-400 border border-gray-600">
                                    <RotateCcw className="w-3 h-3 text-gray-400" />
                                    <span>RULE REVERTED</span>
                                  </span>
                                ) : (
                                  <span className="text-3xs text-gray-500 bg-[#101726] px-2 py-0.5 rounded border border-[#1E293B]">
                                    READY FOR DISPATCH
                                  </span>
                                )}
                              </div>
                            </div>

                            <p className="text-2xs text-gray-300 font-sans leading-relaxed mb-3">
                              {act.description}
                            </p>

                            {/* Execution Telemetry Box (If executed) */}
                            {execution && (
                              <div className="p-2.5 mb-3 bg-[#080D1A] rounded border border-[#1C2C45] text-3xs space-y-1">
                                <div className="flex items-center justify-between text-gray-400">
                                  <span>
                                    Audit Confirmation ID:{' '}
                                    <strong className="text-blue-400 font-mono">
                                      {execution.execution_result.confirmation_id || execution.log_id.substring(0, 8)}
                                    </strong>
                                  </span>
                                  <span>Executed by: <strong className="text-gray-300">{execution.executed_by}</strong></span>
                                </div>
                                {execution.affected_indicators && execution.affected_indicators.length > 0 && (
                                  <div className="text-gray-400 truncate">
                                    Target Indicators ({execution.affected_indicators.length}):{' '}
                                    <span className="text-gray-200">{execution.affected_indicators.join(', ')}</span>
                                  </div>
                                )}
                              </div>
                            )}

                            {/* Interactive Action Bar */}
                            <div className="flex items-center justify-between pt-1">
                              <div className="flex items-center gap-2">
                                {act.automated_action && (
                                  <span className="text-3xs text-blue-400 px-2 py-0.5 rounded bg-blue-950/60 border border-blue-800/40 font-mono">
                                    Connector: {act.automated_action}
                                  </span>
                                )}
                              </div>

                              <div className="flex items-center gap-2">
                                {/* Revert / Rollback Button */}
                                {isEnforced && execution.rollback_supported && (
                                  <button
                                    onClick={(e) => handleRollback(act.action_id, execution.log_id, e)}
                                    disabled={isRollingBack}
                                    className="flex items-center gap-1 px-2.5 py-1 bg-amber-950/40 hover:bg-amber-900/60 text-amber-300 text-3xs font-bold rounded border border-amber-600/40 transition-all disabled:opacity-50"
                                    title="Deactivate this rule from the perimeter firewall"
                                  >
                                    <RotateCcw className={`w-3 h-3 ${isRollingBack ? 'animate-spin' : ''}`} />
                                    <span>{isRollingBack ? 'Reverting...' : 'Rollback Rule'}</span>
                                  </button>
                                )}

                                {/* Trigger Action Button */}
                                <button
                                  onClick={(e) => handleExecuteSingle(act.action_id, e)}
                                  disabled={isExecuting || isEnforced}
                                  className={`flex items-center gap-1.5 px-3 py-1 text-xs font-bold rounded transition-all shadow-sm ${
                                    isEnforced
                                      ? 'bg-emerald-900/40 text-emerald-300 border border-emerald-600/40 cursor-default'
                                      : 'bg-blue-600 hover:bg-blue-500 text-white shadow-blue-900/40'
                                  }`}
                                >
                                  {isExecuting ? (
                                    <Activity className="w-3.5 h-3.5 animate-spin" />
                                  ) : isEnforced ? (
                                    <Check className="w-3.5 h-3.5 text-emerald-400" />
                                  ) : (
                                    <Play className="w-3.5 h-3.5" />
                                  )}
                                  <span>
                                    {isExecuting ? 'Enforcing...' : isEnforced ? 'Action Active' : 'Execute Action'}
                                  </span>
                                </button>
                              </div>
                            </div>
                          </div>
                        );
                      })}
                  </div>
                </div>
              )}

              {/* TAB 4: IOC APPENDIX */}
              {activeTab === 'iocs' && (
                <div className="space-y-4 animate-fade-in max-w-5xl mx-auto font-mono">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-2 border-b border-[#263244] gap-2">
                    <div>
                      <h3 className="text-sm font-bold text-gray-200">
                        Indicators of Compromise (IoCs) ({report.iocs.length})
                      </h3>
                      <p className="text-2xs text-gray-400">
                        Deduplicated artifact values formatted for SIEM / EDR blocklist ingestion.
                      </p>
                    </div>

                    <div className="flex items-center gap-2">
                      {/* Search */}
                      <div className="relative">
                        <Search className="w-3.5 h-3.5 text-gray-400 absolute left-2.5 top-2.5" />
                        <input
                          type="text"
                          placeholder="Search IoC value..."
                          value={iocSearch}
                          onChange={(e) => setIocSearch(e.target.value)}
                          className="pl-8 pr-3 py-1 bg-[#0D1525] border border-[#263244] rounded text-2xs text-gray-200 placeholder-gray-500 focus:outline-none focus:border-blue-500"
                        />
                      </div>
                    </div>
                  </div>

                  {/* IoC Table */}
                  <div className="bg-[#0D1525] border border-[#263244] rounded-lg overflow-hidden">
                    <table className="w-full text-left text-xs">
                      <thead className="bg-[#111C30] border-b border-[#263244] text-gray-400 text-3xs uppercase tracking-wider">
                        <tr>
                          <th className="py-2.5 px-3">Type</th>
                          <th className="py-2.5 px-3">Indicator Value</th>
                          <th className="py-2.5 px-3">Severity</th>
                          <th className="py-2.5 px-3">Killchain Stage</th>
                          <th className="py-2.5 px-3">Threat Context</th>
                          <th className="py-2.5 px-3 text-right">Copy</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-[#1A2538] text-2xs">
                        {report.iocs
                          .filter((ioc) => !iocSearch || ioc.value.toLowerCase().includes(iocSearch.toLowerCase()))
                          .map((ioc, idx) => (
                            <tr key={idx} className="hover:bg-[#152033] transition-colors">
                              <td className="py-2.5 px-3 font-bold text-blue-400">{ioc.ioc_type}</td>
                              <td className="py-2.5 px-3 font-mono text-gray-200 max-w-xs truncate" title={ioc.value}>
                                {ioc.value}
                              </td>
                              <td className="py-2.5 px-3">
                                <span
                                  className={`px-1.5 py-0.5 text-3xs font-bold rounded ${
                                    ioc.severity === 'critical'
                                      ? 'bg-rose-950 text-rose-400 border border-rose-800/60'
                                      : ioc.severity === 'high'
                                      ? 'bg-amber-950 text-amber-400 border border-amber-800/60'
                                      : 'bg-slate-800 text-gray-300'
                                  }`}
                                >
                                  {ioc.severity.toUpperCase()}
                                </span>
                              </td>
                              <td className="py-2.5 px-3 text-gray-300">{ioc.killchain_stage}</td>
                              <td className="py-2.5 px-3 text-gray-400 font-sans">{ioc.threat_context}</td>
                              <td className="py-2.5 px-3 text-right">
                                <button
                                  onClick={() => handleCopyIoc(ioc.value)}
                                  className="p-1 text-gray-400 hover:text-white rounded transition-all"
                                  title="Copy to clipboard"
                                >
                                  {copiedIoc === ioc.value ? (
                                    <Check className="w-3.5 h-3.5 text-emerald-400" />
                                  ) : (
                                    <Copy className="w-3.5 h-3.5" />
                                  )}
                                </button>
                              </td>
                            </tr>
                          ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}

              {/* TAB 5: FORENSIC TIMELINE */}
              {activeTab === 'timeline' && (
                <div className="space-y-4 animate-fade-in max-w-4xl mx-auto font-mono">
                  <div className="pb-2 border-b border-[#263244]">
                    <h3 className="text-sm font-bold text-gray-200">
                      RFC 5322 Received Relay Hop Transmission Timeline
                    </h3>
                    <p className="text-2xs text-gray-400">
                      Chronological reconstruction of message transit across mail transfer agents.
                    </p>
                  </div>

                  <div className="relative border-l-2 border-blue-500/40 ml-4 pl-6 space-y-6 my-4">
                    {report.forensic_timeline.map((event, idx) => (
                      <div key={idx} className="relative group">
                        {/* Dot on timeline */}
                        <div className="absolute -left-[31px] top-1 w-3.5 h-3.5 rounded-full bg-blue-600 border-2 border-[#0B1120] group-hover:bg-blue-400 transition-all shadow-md shadow-blue-500/50" />

                        <div className="bg-[#0D1525] border border-[#263244] rounded-lg p-3.5 space-y-1.5 group-hover:border-blue-500/50 transition-all">
                          <div className="flex items-center justify-between text-2xs text-gray-400">
                            <span className="font-bold text-blue-400">{event.event_type}</span>
                            <span>{event.timestamp || 'Time Header Unspecified'}</span>
                          </div>
                          <h4 className="text-xs font-bold text-gray-200">{event.title || (event as any).summary}</h4>
                          {(event.description || (event as any).details) && (
                            <p className="text-2xs text-gray-400 font-sans">{event.description || (event as any).details}</p>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </>
          )}
        </div>

        {/* Modal Footer */}
        <div className="flex items-center justify-between px-5 py-3 border-t border-[#263244] bg-[#0D1525] text-2xs font-mono text-gray-400">
          <div>
            <span>Status: <strong className="text-emerald-400">REPORT COMPLETE</strong></span>
          </div>
          <div className="flex items-center gap-3">
            <span>Powered by AEGIS CTI Engine</span>
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
