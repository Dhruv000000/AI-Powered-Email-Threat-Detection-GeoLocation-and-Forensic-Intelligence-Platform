import React, { useEffect, useState } from 'react';
import { DFIRReport, MitreTechnique, RemediationAction, IoCItem } from '../../types/report';
import { reportService } from '../../services/reportService';
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

  // Filters & State
  const [priorityFilter, setPriorityFilter] = useState<'ALL' | 'P0' | 'P1' | 'P2'>('ALL');
  const [iocSearch, setIocSearch] = useState('');
  const [iocTypeFilter, setIocTypeFilter] = useState('ALL');
  const [copiedIoc, setCopiedIoc] = useState<string | null>(null);
  const [checkedActions, setCheckedActions] = useState<Record<string, boolean>>({});

  useEffect(() => {
    if (!isOpen || !investigationId) return;

    let isMounted = true;
    async function loadReport() {
      setLoading(true);
      setError(null);
      try {
        const data = await reportService.getInvestigationReport(investigationId);
        if (isMounted) {
          setReport(data);
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

    loadReport();

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
          <div className="flex items-center gap-2 self-end sm:self-auto">
            <button
              onClick={handleDownloadCsv}
              disabled={downloadingCsv || !report}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-[#15233D] hover:bg-[#1C2F52] text-xs font-mono text-blue-300 border border-blue-500/30 rounded-lg transition-all disabled:opacity-50 shadow-sm"
              title="Download IoC indicators as CSV"
            >
              <Share2 className="w-3.5 h-3.5" />
              <span>{downloadingCsv ? 'Exporting...' : 'Export IoCs'}</span>
            </button>

            <button
              onClick={handleDownloadPdf}
              disabled={downloadingPdf || !report}
              className="flex items-center gap-1.5 px-3.5 py-1.5 bg-blue-600 hover:bg-blue-500 text-xs font-mono font-bold text-white rounded-lg transition-all shadow-md shadow-blue-900/40 disabled:opacity-50"
              title="Download official PDF forensic report"
            >
              <Download className="w-3.5 h-3.5" />
              <span>{downloadingPdf ? 'Generating PDF...' : 'Download PDF Report'}</span>
            </button>

            <button
              onClick={onClose}
              className="p-1.5 text-gray-400 hover:text-gray-200 hover:bg-[#1E293B] rounded-lg transition-colors ml-1"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Tab Navigation */}
        <div className="flex items-center gap-1 px-5 border-b border-[#263244] bg-[#0A101D] overflow-x-auto">
          <button
            onClick={() => setActiveTab('summary')}
            className={`px-4 py-2.5 text-xs font-mono font-medium border-b-2 transition-colors flex items-center gap-2 whitespace-nowrap ${
              activeTab === 'summary'
                ? 'border-blue-500 text-blue-400 bg-blue-500/5'
                : 'border-transparent text-gray-400 hover:text-gray-200'
            }`}
          >
            <ShieldAlert className="w-4 h-4" />
            <span>Executive Summary</span>
          </button>

          <button
            onClick={() => setActiveTab('mitre')}
            className={`px-4 py-2.5 text-xs font-mono font-medium border-b-2 transition-colors flex items-center gap-2 whitespace-nowrap ${
              activeTab === 'mitre'
                ? 'border-blue-500 text-blue-400 bg-blue-500/5'
                : 'border-transparent text-gray-400 hover:text-gray-200'
            }`}
          >
            <Crosshair className="w-4 h-4" />
            <span>MITRE ATT&CK Matrix</span>
            {report && (
              <span className="text-3xs px-1.5 py-0.2 rounded-full bg-[#1E293B] text-gray-300">
                {report.mitre_matrix.length}
              </span>
            )}
          </button>

          <button
            onClick={() => setActiveTab('remediation')}
            className={`px-4 py-2.5 text-xs font-mono font-medium border-b-2 transition-colors flex items-center gap-2 whitespace-nowrap ${
              activeTab === 'remediation'
                ? 'border-blue-500 text-blue-400 bg-blue-500/5'
                : 'border-transparent text-gray-400 hover:text-gray-200'
            }`}
          >
            <CheckCircle2 className="w-4 h-4" />
            <span>SOC Remediation Playbook</span>
            {report && (
              <span className="text-3xs px-1.5 py-0.2 rounded-full bg-[#1E293B] text-gray-300">
                {report.remediation_plan.length}
              </span>
            )}
          </button>

          <button
            onClick={() => setActiveTab('iocs')}
            className={`px-4 py-2.5 text-xs font-mono font-medium border-b-2 transition-colors flex items-center gap-2 whitespace-nowrap ${
              activeTab === 'iocs'
                ? 'border-blue-500 text-blue-400 bg-blue-500/5'
                : 'border-transparent text-gray-400 hover:text-gray-200'
            }`}
          >
            <ListFilter className="w-4 h-4" />
            <span>IoC Appendix</span>
            {report && (
              <span className="text-3xs px-1.5 py-0.2 rounded-full bg-[#1E293B] text-gray-300">
                {report.iocs.length}
              </span>
            )}
          </button>

          <button
            onClick={() => setActiveTab('timeline')}
            className={`px-4 py-2.5 text-xs font-mono font-medium border-b-2 transition-colors flex items-center gap-2 whitespace-nowrap ${
              activeTab === 'timeline'
                ? 'border-blue-500 text-blue-400 bg-blue-500/5'
                : 'border-transparent text-gray-400 hover:text-gray-200'
            }`}
          >
            <Clock className="w-4 h-4" />
            <span>Forensic Timeline</span>
          </button>
        </div>

        {/* Modal Content Body */}
        <div className="flex-1 p-5 min-h-0 bg-[#0B1120] overflow-y-auto scrollbar-thin scrollbar-thumb-slate-700 scrollbar-track-transparent">
          {loading ? (
            <div className="h-full flex items-center justify-center">
              <LoadingState message="Synthesizing DFIR report, MITRE matrix mapping, and evidence correlation..." />
            </div>
          ) : error ? (
            <div className="h-full flex flex-col items-center justify-center p-8 text-center">
              <AlertTriangle className="w-12 h-12 text-red-400 mb-3" />
              <h3 className="text-sm font-bold font-mono text-gray-200 mb-1">
                Unable to Generate DFIR Report
              </h3>
              <p className="text-xs font-mono text-gray-400 max-w-md mb-4">{error}</p>
              <button
                onClick={onClose}
                className="px-4 py-1.5 bg-[#1E293B] hover:bg-[#2A3B52] text-xs font-mono text-gray-200 rounded border border-[#263244]"
              >
                Close Window
              </button>
            </div>
          ) : report ? (
            <>
              {/* TAB 1: EXECUTIVE SUMMARY */}
              {activeTab === 'summary' && (
                <div className="space-y-5 animate-fade-in max-w-5xl mx-auto">
                  {/* Top Verdict Banner */}
                  <div className="grid grid-cols-1 md:grid-cols-4 gap-3 font-mono">
                    <div className="bg-[#0D1525] border border-[#263244] p-3.5 rounded-lg">
                      <span className="text-2xs text-gray-400 block mb-1">THREAT VERDICT</span>
                      <div className="flex items-center gap-2">
                        <span
                          className={`text-lg font-bold ${
                            report.executive_summary.verdict === 'MALICIOUS'
                              ? 'text-rose-400'
                              : report.executive_summary.verdict === 'SUSPICIOUS'
                              ? 'text-amber-400'
                              : 'text-emerald-400'
                          }`}
                        >
                          {report.executive_summary.verdict}
                        </span>
                      </div>
                      <span className="text-3xs text-gray-500 block mt-0.5">
                        Classification: {report.executive_summary.classification}
                      </span>
                    </div>

                    <div className="bg-[#0D1525] border border-[#263244] p-3.5 rounded-lg">
                      <span className="text-2xs text-gray-400 block mb-1">RISK SCORE</span>
                      <div className="flex items-baseline gap-1">
                        <span
                          className={`text-2xl font-bold ${
                            report.executive_summary.risk_score >= 80
                              ? 'text-rose-400'
                              : report.executive_summary.risk_score >= 50
                              ? 'text-amber-400'
                              : 'text-emerald-400'
                          }`}
                        >
                          {report.executive_summary.risk_score}
                        </span>
                        <span className="text-xs text-gray-500">/100</span>
                      </div>
                      <span className="text-3xs text-gray-400 block mt-0.5">
                        Severity Level: {report.executive_summary.severity}
                      </span>
                    </div>

                    <div className="bg-[#0D1525] border border-[#263244] p-3.5 rounded-lg">
                      <span className="text-2xs text-gray-400 block mb-1">AI CONFIDENCE</span>
                      <span className="text-2xl font-bold text-blue-400">
                        {(report.executive_summary.ai_confidence * 100).toFixed(1)}%
                      </span>
                      <span className="text-3xs text-gray-500 block mt-0.5">
                        Authoritative Evidence Completeness
                      </span>
                    </div>

                    <div className="bg-[#0D1525] border border-[#263244] p-3.5 rounded-lg">
                      <span className="text-2xs text-gray-400 block mb-1">CORRELATED FINDINGS</span>
                      <span className="text-2xl font-bold text-gray-100">
                        {report.evidentiary_findings.length}
                      </span>
                      <span className="text-3xs text-gray-500 block mt-0.5">
                        Across {report.threat_paths.length} Threat Paths
                      </span>
                    </div>
                  </div>

                  {/* Narrative Synthesis */}
                  <div className="bg-[#0D1525] border border-[#263244] rounded-lg p-4 space-y-2.5">
                    <h3 className="text-xs font-mono font-bold text-gray-300 uppercase tracking-wider flex items-center gap-2">
                      <FileText className="w-4 h-4 text-blue-400" />
                      Executive Threat Assessment
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

              {/* TAB 3: REMEDIATION PLAYBOOK */}
              {activeTab === 'remediation' && (
                <div className="space-y-4 animate-fade-in max-w-5xl mx-auto font-mono">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-2 border-b border-[#263244] gap-2">
                    <div>
                      <h3 className="text-sm font-bold text-gray-200">
                        Prioritized SOC Incident Containment Playbook
                      </h3>
                      <p className="text-2xs text-gray-400">
                        Follow sequential actions to contain, eradicate, and harden tenant defenses.
                      </p>
                    </div>

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

                  <div className="space-y-2.5">
                    {report.remediation_plan
                      .filter((act) => priorityFilter === 'ALL' || act.priority === priorityFilter)
                      .map((act) => {
                        const isDone = !!checkedActions[act.action_id];
                        return (
                          <div
                            key={act.action_id}
                            onClick={() => toggleAction(act.action_id)}
                            className={`p-3.5 rounded-lg border transition-all cursor-pointer ${
                              isDone
                                ? 'bg-[#0F1C18] border-emerald-700/50 opacity-75'
                                : 'bg-[#0D1525] border-[#263244] hover:border-gray-500'
                            }`}
                          >
                            <div className="flex items-start gap-3">
                              <input
                                type="checkbox"
                                checked={isDone}
                                onChange={() => {}}
                                className="mt-1 w-4 h-4 rounded text-blue-500 bg-[#1E293B] border-gray-600 focus:ring-blue-500 cursor-pointer"
                              />

                              <div className="flex-1 space-y-1">
                                <div className="flex flex-wrap items-center justify-between gap-2">
                                  <div className="flex items-center gap-2">
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
                                    <h4
                                      className={`text-xs font-bold ${
                                        isDone ? 'line-through text-gray-400' : 'text-gray-100'
                                      }`}
                                    >
                                      {act.title}
                                    </h4>
                                  </div>

                                  <span className="text-3xs text-gray-400 bg-[#111C30] px-2 py-0.5 rounded border border-[#202C3F]">
                                    Target: <strong className="text-gray-300">{act.target_system}</strong>
                                  </span>
                                </div>

                                <p className="text-2xs text-gray-300 font-sans leading-relaxed">
                                  {act.description}
                                </p>

                                {act.automated_action && (
                                  <div className="pt-1 flex items-center gap-2 text-3xs text-blue-400">
                                    <span className="px-1.5 py-0.5 rounded bg-blue-950/60 border border-blue-800/40 font-mono">
                                      API: {act.automated_action}
                                    </span>
                                  </div>
                                )}
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
                            <tr key={idx} className="hover:bg-[#121E36] transition-colors">
                              <td className="py-2 px-3 text-blue-400 font-bold">{ioc.ioc_type}</td>
                              <td className="py-2 px-3 text-gray-200 font-mono max-w-xs truncate" title={ioc.value}>
                                {ioc.value}
                              </td>
                              <td className="py-2 px-3">
                                <span
                                  className={`px-1.5 py-0.5 rounded text-3xs font-bold uppercase ${
                                    ioc.severity === 'critical'
                                      ? 'bg-rose-500/20 text-rose-400 border border-rose-500/40'
                                      : ioc.severity === 'high'
                                      ? 'bg-amber-500/20 text-amber-400 border border-amber-500/40'
                                      : 'bg-blue-500/20 text-blue-400 border border-blue-500/40'
                                  }`}
                                >
                                  {ioc.severity}
                                </span>
                              </td>
                              <td className="py-2 px-3 text-gray-400">{ioc.killchain_stage}</td>
                              <td className="py-2 px-3 text-gray-300 font-sans max-w-sm truncate" title={ioc.threat_context}>
                                {ioc.threat_context}
                              </td>
                              <td className="py-2 px-3 text-right">
                                <button
                                  onClick={() => handleCopyIoc(ioc.value)}
                                  className="p-1 hover:bg-[#1E2E4A] rounded text-gray-400 hover:text-blue-300 transition-colors"
                                  title="Copy indicator value"
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
                      Authoritative Chronological Forensic Timeline
                    </h3>
                    <p className="text-2xs text-gray-400">
                      Evidentiary events reconstructed from RFC 5322 Received headers and cryptographic analysis seals.
                    </p>
                  </div>

                  <div className="relative pl-6 space-y-4 before:absolute before:left-2 before:top-2 before:bottom-2 before:w-0.5 before:bg-[#263244]">
                    {report.forensic_timeline.map((evt, idx) => (
                      <div key={idx} className="relative group">
                        <span className="absolute -left-6 top-1.5 w-3 h-3 rounded-full bg-blue-500 border-2 border-[#0B1120] ring-2 ring-blue-500/30 group-hover:scale-110 transition-transform" />
                        <div className="bg-[#0D1525] border border-[#263244] rounded-lg p-3 space-y-1">
                          <div className="flex items-center justify-between gap-2">
                            <h4 className="text-xs font-bold text-gray-200">{evt.title}</h4>
                            <span className="text-3xs text-gray-400 bg-[#111C30] px-2 py-0.5 rounded">
                              {evt.source}
                            </span>
                          </div>
                          <p className="text-2xs text-gray-300 font-sans">{evt.description}</p>
                          <span className="text-3xs text-blue-400 block pt-0.5">Timestamp: {evt.timestamp}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </>
          ) : null}
        </div>
      </div>
    </div>
  );
};
