import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import {
  ArrowLeft,
  Briefcase,
  Lock,
  AlertTriangle,
  FileText,
  Server,
  Link2,
  Brain,
  ShieldCheck,
  MapPin,
  GitFork,
  FileDown,
  ExternalLink,
  ChevronRight,
  HelpCircle,
  Copy,
  Check,
} from 'lucide-react';
import { emailService } from '../services/emailService';
import { EmailAnalysis } from '../types/email';
import { RiskScoreGauge } from '../components/common/RiskScoreGauge';
import { SeverityBadge } from '../components/common/SeverityBadge';
import { HeaderRelayTimeline } from '../components/analysis/HeaderRelayTimeline';
import { UrlAnalysisTable } from '../components/analysis/UrlAnalysisTable';
import { IPIntelligenceCard } from '../components/analysis/IPIntelligenceCard';
import { FeatureContributionBar } from '../components/analysis/FeatureContributionBar';
import { EvidenceLocker } from '../components/analysis/EvidenceLocker';
import { ThreatMapModal } from '../components/investigation/ThreatMapModal';
import { DFIRReportModal } from '../components/investigation/DFIRReportModal';
import { LoadingState } from '../components/common/LoadingState';

export const AnalysisResultPage: React.FC = () => {
  const { emailId } = useParams<{ emailId: string }>();
  const navigate = useNavigate();

  const [email, setEmail] = useState<EmailAnalysis | null>(null);
  const [loading, setLoading] = useState(true);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<'overview' | 'headers' | 'urls' | 'infrastructure' | 'ai' | 'evidence'>('overview');
  const [isMapModalOpen, setIsMapModalOpen] = useState(false);
  const [isReportModalOpen, setIsReportModalOpen] = useState(false);

  useEffect(() => {
    async function fetchEmail() {
      if (!emailId) {
        setErrorMessage('No email analysis identifier provided.');
        setLoading(false);
        return;
      }

      setLoading(true);
      setErrorMessage(null);
      try {
        const data = await emailService.getEmailById(emailId);
        if (!data) {
          setErrorMessage(`No forensic analysis record found for ID '${emailId}'.`);
        } else {
          setEmail(data);
        }
      } catch (err: any) {
        setErrorMessage(err.message || 'Failed to retrieve forensic record.');
      } finally {
        setLoading(false);
      }
    }
    fetchEmail();
  }, [emailId]);

  if (loading) {
    return <LoadingState message="Retrieving forensic email container & telemetry..." />;
  }

  if (errorMessage || !email) {
    return (
      <div className="bg-[#151E2E] border border-red-500/30 rounded-lg p-8 max-w-xl mx-auto text-center space-y-4 font-mono mt-10">
        <div className="p-3 rounded-full bg-red-500/10 text-red-400 w-fit mx-auto border border-red-500/20">
          <AlertTriangle className="w-8 h-8" />
        </div>
        <h2 className="text-base font-bold text-gray-100">Analysis Record Not Found</h2>
        <p className="text-xs text-gray-400">
          {errorMessage || `Unable to locate analysis record '${emailId}'. Please verify the ID or run a new forensic analysis.`}
        </p>
        <div className="pt-2 flex justify-center gap-3">
          <button
            onClick={() => navigate('/analyze')}
            className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded text-xs font-semibold shadow transition"
          >
            Analyze New Email
          </button>
          <button
            onClick={() => navigate('/threats')}
            className="px-4 py-2 bg-[#1E293B] hover:bg-[#2A374D] text-gray-200 border border-[#263244] rounded text-xs transition"
          >
            Back to Threats
          </button>
        </div>
      </div>
    );
  }

  const tabs = [
    { id: 'overview', label: '1. Overview', icon: FileText },
    { id: 'headers', label: '2. Headers & Relay', icon: Server },
    { id: 'urls', label: `3. URLs (${email.extractedUrls.length})`, icon: Link2 },
    { id: 'infrastructure', label: '4. Infrastructure', icon: MapPin },
    { id: 'ai', label: '5. AI Analysis', icon: Brain },
    { id: 'evidence', label: '6. Evidence Locker', icon: Lock },
  ];

  return (
    <div className="space-y-6">
      {/* Top Breadcrumb & Actions Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-[#263244] pb-4">
        <div className="flex items-center gap-3">
          <button
            onClick={() => navigate('/threats')}
            className="p-1.5 rounded bg-[#151E2E] hover:bg-[#1E293B] border border-[#263244] text-gray-300 transition"
            title="Back to Threats Feed"
          >
            <ArrowLeft className="w-4 h-4" />
          </button>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-lg font-bold text-gray-100 font-mono tracking-tight">
                Email Threat Investigation
              </h1>
              <span className="text-2xs font-mono px-2 py-0.5 rounded bg-[#151E2E] text-gray-300 border border-[#263244]">
                {email.id}
              </span>
            </div>
            <div className="flex items-center gap-3 text-2xs text-gray-400 font-mono mt-0.5">
              {email.caseId ? (
                <button
                  onClick={() => navigate(`/cases/${email.caseId}`)}
                  className="text-blue-400 hover:underline flex items-center gap-1 font-semibold"
                >
                  <Briefcase className="w-3 h-3" />
                  <span>Linked Case: {email.caseId}</span>
                </button>
              ) : (
                <span>Standalone Telemetry</span>
              )}
              <span>•</span>
              <span className="flex items-center gap-1">
                <Lock className="w-3 h-3 text-emerald-400" />
                Evidence ID: {email.evidenceId}
              </span>
            </div>
          </div>
        </div>

        {/* Pivot actions */}
        <div className="flex items-center gap-2 font-mono text-xs">
          <button
            onClick={() => setIsReportModalOpen(true)}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-blue-600 hover:bg-blue-500 text-white rounded transition font-bold shadow-md shadow-blue-900/30"
            title="Open DFIR Executive Report, MITRE Matrix & PDF Exporter"
          >
            <FileDown className="w-3.5 h-3.5" />
            <span>DFIR Report</span>
          </button>
          <button
            onClick={() => navigate(`/investigations/${email.id}`)}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-purple-950/80 hover:bg-purple-900 text-purple-200 border border-purple-800 rounded transition font-bold shadow-sm"
            title="Launch Task 02 Threat Investigation Engine"
          >
            <GitFork className="w-3.5 h-3.5 text-purple-400" />
            <span>Investigate Threat Graph</span>
          </button>
          <button
            onClick={() => setIsMapModalOpen(true)}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-blue-950/80 hover:bg-blue-900 text-blue-200 border border-blue-800 rounded transition font-bold shadow-sm"
            title="Trace Geographic Relay Transit & Origin Map"
          >
            <MapPin className="w-3.5 h-3.5 text-blue-400" />
            <span>Trace Origin Map</span>
          </button>
        </div>
      </div>

      {/* Top Banner: Forensic Assessment & Flagged Rationale */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Risk Score Summary Banner (1 col) */}
        <div className="p-5 rounded-lg bg-[#151E2E] border border-[#263244] flex flex-col justify-between space-y-4">
          <div className="flex items-center justify-between border-b border-[#263244] pb-3">
            <span className="text-2xs font-bold uppercase tracking-wider text-gray-400 font-mono">
              Composite Risk Score
            </span>
            <SeverityBadge
              severity={
                email.aiAnalysis.riskScore >= 85
                  ? 'critical'
                  : email.aiAnalysis.riskScore >= 70
                  ? 'high'
                  : email.aiAnalysis.riskScore >= 40
                  ? 'medium'
                  : 'clean'
              }
              size="sm"
            />
          </div>

          <div className="flex items-center gap-4">
            <RiskScoreGauge score={email.aiAnalysis.riskScore} size="lg" showLabel={false} />
            <div className="space-y-1 font-mono">
              <span className="text-xs font-bold text-red-400 block uppercase tracking-wide">
                {email.aiAnalysis.riskScore >= 85 ? 'CRITICAL THREAT' : 'HIGH THREAT'}
              </span>
              <p className="text-sm font-bold text-gray-100 font-sans">{email.aiAnalysis.classification}</p>
              <span className="text-2xs text-blue-400 block">AI Confidence: {email.aiAnalysis.confidence}%</span>
            </div>
          </div>

          <div className="pt-3 border-t border-[#263244] text-2xs font-mono text-gray-400 flex items-center justify-between">
            <span>Authentication: <strong className={email.authentication.spf.status === 'FAIL' ? 'text-red-400' : 'text-emerald-400'}>{email.authentication.spf.status}</strong></span>
            <span>Origin: <strong className="text-gray-200">{email.probableOriginIp.country}</strong></span>
          </div>
        </div>

        {/* Why was this email flagged? (2 cols) */}
        <div className="lg:col-span-2 p-5 rounded-lg bg-[#151E2E] border border-[#263244] space-y-3 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between border-b border-[#263244] pb-2.5 mb-2.5">
              <h2 className="text-xs font-bold uppercase tracking-wider text-gray-200 font-mono flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 text-amber-400" />
                Why was this email flagged?
              </h2>
              <span className="text-2xs text-gray-400 font-mono">
                {email.aiAnalysis.flaggedReasons.length} Forensic Anomalies
              </span>
            </div>

            {/* Bulleted Forensic Flags */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs font-mono">
              {email.aiAnalysis.flaggedReasons.map((reason, idx) => (
                <div key={idx} className="flex items-start gap-2 text-gray-300">
                  <span className="text-amber-400 font-bold">⚠</span>
                  <span className="leading-snug">{reason}</span>
                </div>
              ))}
            </div>
          </div>

          {/* AI Human Explanation */}
          <div className="p-3 bg-[#0B1120] rounded border border-[#263244] text-xs leading-relaxed text-gray-300">
            <span className="text-2xs font-mono font-bold uppercase text-blue-400 block mb-1">
              AI Summary & Behavioral Intent:
            </span>
            <p className="font-sans">{email.aiAnalysis.humanExplanation}</p>
          </div>
        </div>
      </div>

      {/* 6 Tabs Navigation */}
      <div className="border-b border-[#263244] flex items-center gap-1 overflow-x-auto font-mono text-xs">
        {tabs.map((tab) => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id as any)}
              className={`px-4 py-2.5 font-semibold border-b-2 whitespace-nowrap transition flex items-center gap-2 ${
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
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              {/* Email Envelope Summary */}
              <div className="p-5 rounded-lg bg-[#111827] border border-[#263244] space-y-3 font-mono text-xs">
                <h3 className="text-xs font-bold uppercase tracking-wider text-gray-300 border-b border-[#263244] pb-2">
                  Email Message Envelope Details
                </h3>
                <div className="space-y-2">
                  <div>
                    <span className="text-2xs uppercase text-gray-400 block">From Address:</span>
                    <span className="text-gray-100 font-bold">{email.headers.from}</span>
                  </div>
                  <div>
                    <span className="text-2xs uppercase text-gray-400 block">To Recipient:</span>
                    <span className="text-gray-300">{email.headers.to.join(', ')}</span>
                  </div>
                  {email.headers.cc.length > 0 && (
                    <div>
                      <span className="text-2xs uppercase text-gray-400 block">CC:</span>
                      <span className="text-gray-300">{email.headers.cc.join(', ')}</span>
                    </div>
                  )}
                  <div>
                    <span className="text-2xs uppercase text-gray-400 block">Reply-To:</span>
                    <span className={email.headers.replyTo !== email.headers.from ? 'text-amber-400 font-bold' : 'text-gray-300'}>
                      {email.headers.replyTo}
                    </span>
                  </div>
                  <div>
                    <span className="text-2xs uppercase text-gray-400 block">Subject:</span>
                    <span className="text-gray-100 font-sans font-semibold text-sm">{email.headers.subject}</span>
                  </div>
                  <div>
                    <span className="text-2xs uppercase text-gray-400 block">Date Header:</span>
                    <span className="text-gray-400">{email.headers.date}</span>
                  </div>
                </div>
              </div>

              {/* Threat Indicators Summary */}
              <div className="p-5 rounded-lg bg-[#111827] border border-[#263244] space-y-4 font-mono text-xs">
                <h3 className="text-xs font-bold uppercase tracking-wider text-gray-300 border-b border-[#263244] pb-2">
                  Extracted Indicators of Compromise (IoCs)
                </h3>
                <div className="grid grid-cols-2 gap-3">
                  <div className="p-3 rounded bg-[#151E2E] border border-[#263244]">
                    <span className="text-2xs uppercase text-gray-400 block">Probable Origin IP</span>
                    <span className="text-sm font-bold text-red-400 mt-0.5 block">{email.probableOriginIp.ip}</span>
                    <span className="text-2xs text-gray-400">{email.probableOriginIp.city}, {email.probableOriginIp.country}</span>
                  </div>
                  <div className="p-3 rounded bg-[#151E2E] border border-[#263244]">
                    <span className="text-2xs uppercase text-gray-400 block">Sender Domain</span>
                    <span className="text-sm font-bold text-amber-400 mt-0.5 block truncate">{email.headers.fromDomain}</span>
                    <span className="text-2xs text-gray-400">Age: {email.senderDomainIntel.domainAgeDays} days</span>
                  </div>
                  <div className="p-3 rounded bg-[#151E2E] border border-[#263244]">
                    <span className="text-2xs uppercase text-gray-400 block">Extracted Links</span>
                    <span className="text-sm font-bold text-blue-400 mt-0.5 block">{email.extractedUrls.length} URLs</span>
                    <span className="text-2xs text-gray-400">{email.extractedUrls.filter((u) => u.riskScore > 70).length} High Risk</span>
                  </div>
                  <div className="p-3 rounded bg-[#151E2E] border border-[#263244]">
                    <span className="text-2xs uppercase text-gray-400 block">Attachments</span>
                    <span className="text-sm font-bold text-purple-400 mt-0.5 block">{email.attachments.length} files</span>
                    <span className="text-2xs text-gray-400">{email.attachments.filter((a) => a.isMalicious).length} Malicious</span>
                  </div>
                </div>

                <div className="pt-2">
                  <span className="text-2xs uppercase text-gray-400 block mb-1">Social Engineering Pattern:</span>
                  <div className="p-2.5 rounded bg-[#151E2E] border border-[#263244] text-xs text-gray-200 font-sans">
                    {email.aiAnalysis.socialEngineeringPattern}
                  </div>
                </div>
              </div>
            </div>

            {/* Raw Email Body View */}
            <div className="p-5 rounded-lg bg-[#111827] border border-[#263244] space-y-3 font-mono text-xs">
              <h3 className="text-xs font-bold uppercase tracking-wider text-gray-300 border-b border-[#263244] pb-2">
                Decoded Email Text Body
              </h3>
              <pre className="p-4 rounded bg-[#0B1120] border border-[#263244] text-xs text-gray-300 whitespace-pre-wrap font-sans leading-relaxed">
                {email.rawBodyText}
              </pre>
            </div>
          </div>
        )}

        {/* Tab 2: Headers & Relay */}
        {activeTab === 'headers' && (
          <HeaderRelayTimeline
            headers={email.headers}
            authentication={email.authentication}
            relayPath={email.relayPath}
          />
        )}

        {/* Tab 3: URLs */}
        {activeTab === 'urls' && <UrlAnalysisTable urls={email.extractedUrls} />}

        {/* Tab 4: Infrastructure */}
        {activeTab === 'infrastructure' && (
          <IPIntelligenceCard
            ipIntel={email.probableOriginIp}
            domainIntel={email.senderDomainIntel}
          />
        )}

        {/* Tab 5: AI Analysis */}
        {activeTab === 'ai' && (
          <FeatureContributionBar
            contributions={email.aiAnalysis.featureContributions}
            classification={email.aiAnalysis.classification}
            confidence={email.aiAnalysis.confidence}
            explanation={email.aiAnalysis.humanExplanation}
            linguistics={email.aiAnalysis.linguisticAnomalies}
          />
        )}

        {/* Tab 6: Evidence Locker */}
        {activeTab === 'evidence' && (
          <EvidenceLocker evidence={email.evidence} caseId={email.caseId} />
        )}
      </div>

      {/* Trace Origin & Threat Route Map Modal */}
      <ThreatMapModal
        investigationId={email.id}
        isOpen={isMapModalOpen}
        onClose={() => setIsMapModalOpen(false)}
      />

      {/* DFIR Executive Report & Playbook Modal */}
      <DFIRReportModal
        investigationId={email.id}
        isOpen={isReportModalOpen}
        onClose={() => setIsReportModalOpen(false)}
      />
    </div>
  );
};
