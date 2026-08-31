import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import {
  Briefcase,
  ArrowLeft,
  Shield,
  FileText,
  Mail,
  Server,
  Globe,
  Link2,
  Clock,
  MessageSquare,
  FileCheck,
  Download,
  Plus,
  Edit,
  CheckCircle2,
  GitFork,
  ExternalLink,
} from 'lucide-react';
import { caseService } from '../services/caseService';
import { graphService } from '../services/graphService';
import { reportService } from '../services/reportService';
import { InvestigationCase, CaseStatus } from '../types/case';
import { GraphData } from '../types/graph';
import { ForensicReport } from '../types/report';
import { SeverityBadge } from '../components/common/SeverityBadge';
import { StatusBadge } from '../components/common/StatusBadge';
import { CaseTimeline } from '../components/cases/CaseTimeline';
import { CaseNotesSection } from '../components/cases/CaseNotesSection';
import { CaseReportModal } from '../components/cases/CaseReportModal';
import { ThreatGraphComponent } from '../components/graph/ThreatGraphComponent';
import { LoadingState } from '../components/common/LoadingState';

export const CaseDetailsPage: React.FC = () => {
  const { caseId } = useParams<{ caseId: string }>();
  const navigate = useNavigate();

  const [caseItem, setCaseItem] = useState<InvestigationCase | null>(null);
  const [graphData, setGraphData] = useState<GraphData | null>(null);
  const [report, setReport] = useState<ForensicReport | null>(null);
  const [loading, setLoading] = useState(true);
  const [isReportModalOpen, setIsReportModalOpen] = useState(false);

  const [activeTab, setActiveTab] = useState<
    'overview' | 'emails' | 'indicators' | 'graph' | 'timeline' | 'evidence' | 'notes' | 'report'
  >('overview');

  useEffect(() => {
    async function loadCaseData() {
      setLoading(true);
      const targetId = caseId || 'CASE-001245';
      const [c, g, r] = await Promise.all([
        caseService.getCaseById(targetId),
        graphService.getCaseGraph(targetId),
        reportService.getReportById(targetId),
      ]);
      setCaseItem(c);
      setGraphData(g);
      setReport(r);
      setLoading(false);
    }
    loadCaseData();
  }, [caseId]);

  if (loading || !caseItem) {
    return <LoadingState message="Loading investigation workspace & telemetry..." />;
  }

  const handleAddNote = async (content: string) => {
    await caseService.addCaseNote(caseItem.id, content);
    const updated = await caseService.getCaseById(caseItem.id);
    if (updated) setCaseItem(updated);
  };

  const handleChangeStatus = async (newStatus: CaseStatus) => {
    const updated = await caseService.updateCaseStatus(caseItem.id, newStatus);
    setCaseItem(updated);
  };

  const handleGenerateReport = async () => {
    const newReport = await reportService.generateReport(caseItem.id, caseItem.title);
    setReport(newReport);
    setIsReportModalOpen(true);
  };

  const tabs = [
    { id: 'overview', label: '1. Overview', icon: FileText },
    { id: 'emails', label: `2. Emails (${caseItem.counts.emails})`, icon: Mail },
    { id: 'indicators', label: `3. IoCs (${caseItem.counts.domains + caseItem.counts.ips})`, icon: Server },
    { id: 'graph', label: '4. Case Graph', icon: GitFork },
    { id: 'timeline', label: `5. Timeline (${caseItem.timeline.length})`, icon: Clock },
    { id: 'evidence', label: `6. Evidence (${caseItem.counts.evidence})`, icon: FileCheck },
    { id: 'notes', label: `7. Field Notes (${caseItem.notes.length})`, icon: MessageSquare },
    { id: 'report', label: '8. Forensic Report', icon: Download },
  ];

  return (
    <div className="space-y-6">
      {/* Header Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-[#263244] pb-4">
        <div className="flex items-center gap-3">
          <button
            onClick={() => navigate('/cases')}
            className="p-1.5 rounded bg-[#151E2E] hover:bg-[#1E293B] border border-[#263244] text-gray-300 transition"
            title="Back to Cases"
          >
            <ArrowLeft className="w-4 h-4" />
          </button>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-xs font-bold text-blue-400 font-mono">{caseItem.id}</span>
              <SeverityBadge severity={caseItem.priority} size="sm" />
              <StatusBadge status={caseItem.status} />
            </div>
            <h1 className="text-lg font-bold text-gray-100 font-sans mt-0.5 tracking-tight">
              {caseItem.title}
            </h1>
          </div>
        </div>

        {/* Action Controls */}
        <div className="flex flex-wrap items-center gap-2 font-mono text-xs">
          <select
            value={caseItem.status}
            onChange={(e) => handleChangeStatus(e.target.value as CaseStatus)}
            className="bg-[#151E2E] border border-[#263244] text-gray-200 text-xs rounded px-2.5 py-1.5 focus:outline-none focus:border-blue-500"
          >
            <option value="under_investigation">Status: Under Investigation</option>
            <option value="open">Status: Open</option>
            <option value="escalated">Status: Escalated</option>
            <option value="mitigated">Status: Mitigated</option>
            <option value="closed">Status: Closed</option>
          </select>

          <button
            onClick={() => navigate('/analyze')}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-[#151E2E] hover:bg-[#1E293B] text-gray-200 border border-[#263244] rounded transition"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>Attach Email</span>
          </button>

          <button
            onClick={handleGenerateReport}
            className="flex items-center gap-1.5 px-4 py-1.5 bg-blue-600 hover:bg-blue-500 text-white rounded font-semibold shadow transition"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Generate Forensic Report</span>
          </button>
        </div>
      </div>

      {/* Summary KPI Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-5 gap-3 font-mono">
        <div className="p-3.5 rounded-lg bg-[#151E2E] border border-[#263244]">
          <span className="text-2xs text-gray-400 uppercase font-semibold block">Attached Emails</span>
          <span className="text-xl font-bold text-gray-100 mt-1 block">{caseItem.counts.emails}</span>
        </div>
        <div className="p-3.5 rounded-lg bg-[#151E2E] border border-[#263244]">
          <span className="text-2xs text-gray-400 uppercase font-semibold block">Discovered Domains</span>
          <span className="text-xl font-bold text-amber-400 mt-1 block">{caseItem.counts.domains}</span>
        </div>
        <div className="p-3.5 rounded-lg bg-[#151E2E] border border-[#263244]">
          <span className="text-2xs text-gray-400 uppercase font-semibold block">Origin IPs</span>
          <span className="text-xl font-bold text-red-400 mt-1 block">{caseItem.counts.ips}</span>
        </div>
        <div className="p-3.5 rounded-lg bg-[#151E2E] border border-[#263244]">
          <span className="text-2xs text-gray-400 uppercase font-semibold block">Payload URLs</span>
          <span className="text-xl font-bold text-blue-400 mt-1 block">{caseItem.counts.urls}</span>
        </div>
        <div className="p-3.5 rounded-lg bg-[#151E2E] border border-[#263244] col-span-2 sm:col-span-1">
          <span className="text-2xs text-gray-400 uppercase font-semibold block">Preserved Evidence</span>
          <span className="text-xl font-bold text-emerald-400 mt-1 block">{caseItem.counts.evidence}</span>
        </div>
      </div>

      {/* Workspace Tabs Navigation */}
      <div className="border-b border-[#263244] flex items-center gap-1 overflow-x-auto font-mono text-xs">
        {tabs.map((tab) => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id as any)}
              className={`px-3.5 py-2 font-semibold border-b-2 whitespace-nowrap transition flex items-center gap-2 ${
                isActive
                  ? 'border-blue-500 text-blue-400 bg-blue-950/20'
                  : 'border-transparent text-gray-400 hover:text-gray-200 hover:bg-[#151E2E]'
              }`}
            >
              <Icon className="w-3.5 h-3.5" />
              <span>{tab.label}</span>
            </button>
          );
        })}
      </div>

      {/* Tab Panels */}
      <div className="min-h-[400px]">
        {/* Tab 1: Overview */}
        {activeTab === 'overview' && (
          <div className="space-y-6">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              <div className="md:col-span-2 p-5 rounded-lg bg-[#111827] border border-[#263244] space-y-4">
                <h3 className="text-xs font-bold uppercase tracking-wider text-gray-300 font-mono border-b border-[#263244] pb-2">
                  Executive Investigation Summary
                </h3>
                <p className="text-xs text-gray-200 leading-relaxed font-sans">{caseItem.description}</p>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-2 font-mono text-xs">
                  <div className="p-3 bg-[#0B1120] rounded border border-[#263244]">
                    <span className="text-2xs text-gray-400 uppercase font-semibold block">Campaign Affiliation</span>
                    <span className="text-xs font-bold text-purple-400 mt-1 block">{caseItem.campaignName || 'Unassigned Campaign'}</span>
                  </div>
                  <div className="p-3 bg-[#0B1120] rounded border border-[#263244]">
                    <span className="text-2xs text-gray-400 uppercase font-semibold block">Potential Organizational Impact</span>
                    <span className="text-xs font-bold text-red-400 mt-1 block">{caseItem.estimatedImpact}</span>
                  </div>
                </div>

                <div className="p-3.5 bg-blue-950/20 rounded-lg border border-blue-500/30 text-xs text-gray-300 space-y-1">
                  <span className="text-2xs font-mono uppercase font-bold text-blue-400 block">Recommended SOC Action:</span>
                  <p className="font-sans">{caseItem.recommendedAction}</p>
                </div>
              </div>

              {/* Assigned Analyst & Attribution */}
              <div className="p-5 rounded-lg bg-[#111827] border border-[#263244] space-y-4 font-mono text-xs">
                <h3 className="text-xs font-bold uppercase tracking-wider text-gray-300 border-b border-[#263244] pb-2">
                  Investigation Lead
                </h3>

                <div className="flex items-center gap-3">
                  <div className="w-10 h-10 rounded-full bg-blue-900/60 border border-blue-500/40 text-blue-300 flex items-center justify-center font-bold text-sm">
                    {caseItem.assignedAnalyst.avatarInitials}
                  </div>
                  <div>
                    <span className="font-bold text-gray-100 block">{caseItem.assignedAnalyst.name}</span>
                    <span className="text-2xs text-gray-400 block">{caseItem.assignedAnalyst.role}</span>
                    <span className="text-2xs text-blue-400 block">{caseItem.assignedAnalyst.email}</span>
                  </div>
                </div>

                <div className="pt-3 border-t border-[#263244] space-y-2">
                  <span className="text-2xs text-gray-400 uppercase font-semibold block">Attribution Confidence</span>
                  <div className="flex items-center justify-between">
                    <div className="h-2 flex-1 bg-[#0B1120] rounded-full overflow-hidden border border-[#263244] mr-3">
                      <div className="h-full bg-blue-500 rounded-full" style={{ width: `${caseItem.attributionConfidence}%` }} />
                    </div>
                    <span className="font-bold text-blue-400">{caseItem.attributionConfidence}%</span>
                  </div>
                  <p className="text-2xs text-gray-400 font-sans">
                    Correlated with known TA-505 bulletproof hosting ASN footprints.
                  </p>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Tab 2: Attached Emails */}
        {activeTab === 'emails' && (
          <div className="space-y-4">
            <h3 className="text-xs font-bold uppercase tracking-wider text-gray-400 font-mono">
              Suspicious Emails Linked to this Case ({caseItem.emailIds.length})
            </h3>
            <div className="space-y-3 font-mono text-xs">
              {caseItem.emailIds.map((eId) => (
                <div
                  key={eId}
                  onClick={() => navigate(`/analyze/${eId}`)}
                  className="p-4 rounded-lg bg-[#151E2E] border border-[#263244] hover:border-blue-500/50 hover:bg-[#1B263B] transition cursor-pointer flex items-center justify-between group"
                >
                  <div className="flex items-center gap-3">
                    <div className="p-2 rounded bg-blue-500/10 text-blue-400 border border-blue-500/20">
                      <Mail className="w-4 h-4" />
                    </div>
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="font-bold text-gray-100 group-hover:text-blue-300 font-sans">{eId}</span>
                        <SeverityBadge severity="critical" size="sm" />
                      </div>
                      <p className="text-2xs text-gray-400 mt-0.5">Click to inspect complete technical forensic result</p>
                    </div>
                  </div>

                  <span className="flex items-center gap-1 text-2xs text-blue-400 group-hover:underline">
                    <span>Inspect Forensic Result</span>
                    <ExternalLink className="w-3.5 h-3.5" />
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Tab 3: Indicators */}
        {activeTab === 'indicators' && (
          <div className="space-y-6">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              {/* Origin IPs */}
              <div className="p-5 rounded-lg bg-[#111827] border border-[#263244] space-y-3 font-mono text-xs">
                <h3 className="text-xs font-bold uppercase tracking-wider text-gray-300 border-b border-[#263244] pb-2 flex items-center gap-2">
                  <Server className="w-4 h-4 text-red-400" />
                  Originating IPs & Relays ({caseItem.indicatorIps.length})
                </h3>
                <div className="space-y-2">
                  {caseItem.indicatorIps.map((ip) => (
                    <div key={ip} className="p-2.5 rounded bg-[#151E2E] border border-[#263244] flex items-center justify-between">
                      <span className="font-bold text-red-400">{ip}</span>
                      <button onClick={() => navigate('/map')} className="text-2xs text-blue-400 hover:underline">
                        Trace on Map
                      </button>
                    </div>
                  ))}
                </div>
              </div>

              {/* Domains */}
              <div className="p-5 rounded-lg bg-[#111827] border border-[#263244] space-y-3 font-mono text-xs">
                <h3 className="text-xs font-bold uppercase tracking-wider text-gray-300 border-b border-[#263244] pb-2 flex items-center gap-2">
                  <Globe className="w-4 h-4 text-amber-400" />
                  Lookalike Domains ({caseItem.indicatorDomains.length})
                </h3>
                <div className="space-y-2">
                  {caseItem.indicatorDomains.map((dom) => (
                    <div key={dom} className="p-2.5 rounded bg-[#151E2E] border border-[#263244] flex items-center justify-between">
                      <span className="font-bold text-amber-400">{dom}</span>
                      <span className="text-2xs text-gray-400">DNS Sinkhole Pending</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Tab 4: Graph */}
        {activeTab === 'graph' && graphData && (
          <div className="h-[500px]">
            <ThreatGraphComponent data={graphData} />
          </div>
        )}

        {/* Tab 5: Timeline */}
        {activeTab === 'timeline' && <CaseTimeline events={caseItem.timeline} />}

        {/* Tab 6: Evidence */}
        {activeTab === 'evidence' && (
          <div className="space-y-4 font-mono text-xs">
            <h3 className="text-xs font-bold uppercase tracking-wider text-gray-400">
              Attached Evidentiary Objects ({caseItem.evidenceList.length})
            </h3>
            <div className="space-y-3">
              {caseItem.evidenceList.map((ev) => (
                <div key={ev.id} className="p-4 rounded-lg bg-[#151E2E] border border-[#263244] space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-gray-100">{ev.evidenceId}: {ev.fileName}</span>
                    <span className="px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-400 text-2xs font-bold">
                      {ev.integrity}
                    </span>
                  </div>
                  <p className="text-2xs text-gray-400 font-sans">{ev.description}</p>
                  <div className="p-2 rounded bg-[#0B1120] border border-[#263244] text-[11px] text-blue-300 break-all select-all">
                    SHA-256: {ev.sha256}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Tab 7: Notes */}
        {activeTab === 'notes' && <CaseNotesSection notes={caseItem.notes} onAddNote={handleAddNote} />}

        {/* Tab 8: Report */}
        {activeTab === 'report' && (
          <div className="p-6 rounded-lg bg-[#151E2E] border border-[#263244] space-y-4 font-mono text-center">
            <Shield className="w-10 h-10 text-blue-400 mx-auto" />
            <h3 className="text-sm font-bold text-gray-100">Forensic Incident Intelligence Report Ready</h3>
            <p className="text-xs text-gray-400 max-w-md mx-auto font-sans">
              Compiled formal documentation formatted for law enforcement liaison, cyber incident response, and institutional security review.
            </p>
            <div className="pt-2">
              <button
                onClick={() => setIsReportModalOpen(true)}
                className="px-5 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded text-xs font-semibold shadow transition"
              >
                Open Official Report Viewer
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Report Modal */}
      <CaseReportModal
        isOpen={isReportModalOpen}
        onClose={() => setIsReportModalOpen(false)}
        caseItem={caseItem}
        report={report || undefined}
      />
    </div>
  );
};
