import {
  ShieldAlert,
  ArrowLeft,
  RefreshCw,
  Search,
  FileDown,
  Layers,
  CheckCircle2,
  AlertTriangle,
  Clock,
  ExternalLink,
  MapPin,
} from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { InvestigationDetail } from '../../types/investigation';
import { SeverityBadge } from '../common/SeverityBadge';
import { RiskScoreGauge } from '../common/RiskScoreGauge';

interface InvestigationHeaderProps {
  investigation: InvestigationDetail;
  onRefresh: () => void;
  onOpenSearch: () => void;
  onOpenThreatMap?: () => void;
  onOpenReport?: () => void;
  isRefreshing?: boolean;
}

export const InvestigationHeader: React.FC<InvestigationHeaderProps> = ({
  investigation,
  onRefresh,
  onOpenSearch,
  onOpenThreatMap,
  onOpenReport,
  isRefreshing = false,
}) => {
  const navigate = useNavigate();

  const getStatusBadge = () => {
    switch (investigation.status) {
      case 'completed':
        return (
          <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded bg-emerald-950/80 text-emerald-400 border border-emerald-800/60 text-2xs font-mono font-medium">
            <CheckCircle2 className="w-3 h-3" />
            COMPLETED
          </span>
        );
      case 'processing':
        return (
          <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded bg-blue-950/80 text-blue-400 border border-blue-800/60 text-2xs font-mono font-medium animate-pulse">
            <RefreshCw className="w-3 h-3 animate-spin" />
            PROCESSING
          </span>
        );
      case 'failed':
        return (
          <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded bg-rose-950/80 text-rose-400 border border-rose-800/60 text-2xs font-mono font-medium">
            <AlertTriangle className="w-3 h-3" />
            FAILED
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded bg-gray-800 text-gray-300 border border-gray-700 text-2xs font-mono font-medium">
            <Clock className="w-3 h-3" />
            CREATED
          </span>
        );
    }
  };

  return (
    <div className="bg-[#111827] border border-[#263244] rounded-lg p-4 shadow-sm">
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
        {/* Left ID & Metadata info */}
        <div className="flex items-start sm:items-center gap-3">
          <button
            onClick={() => navigate(-1)}
            className="p-1.5 rounded bg-[#151E2E] hover:bg-[#1E293B] border border-[#263244] text-gray-300 transition shrink-0"
            title="Back to Previous View"
          >
            <ArrowLeft className="w-4 h-4" />
          </button>

          <div>
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-xs font-mono px-2 py-0.5 rounded bg-[#151E2E] text-purple-300 border border-purple-900/50 font-bold">
                {investigation.investigation_id}
              </span>
              {getStatusBadge()}
              {investigation.severity && (
                <SeverityBadge severity={investigation.severity} className="text-2xs" />
              )}
            </div>

            <div className="flex flex-wrap items-center gap-2.5 text-2xs text-gray-400 font-mono mt-1.5">
              <span>
                Task 01 Source:{' '}
                <button
                  onClick={() => navigate(`/analyze/${investigation.analysis_id}`)}
                  className="text-blue-400 hover:underline inline-flex items-center gap-0.5 font-semibold"
                >
                  <span>{investigation.analysis_id}</span>
                  <ExternalLink className="w-2.5 h-2.5" />
                </button>
              </span>
              <span>•</span>
              <span>
                Threat Classification:{' '}
                <strong className="text-gray-200 uppercase">
                  {(investigation.threat_type || 'Unknown').replace(/_/g, ' ')}
                </strong>
              </span>
              <span>•</span>
              <span>
                Investigator: <strong className="text-gray-300">{investigation.created_by}</strong>
              </span>
            </div>
          </div>
        </div>

        {/* Right Side Stats & Actions */}
        <div className="flex flex-wrap items-center gap-4">
          {/* Risk Score Gauge Mini */}
          {investigation.risk_score !== undefined && investigation.risk_score !== null && (
            <div className="flex items-center gap-2 pl-3 border-l border-[#263244]">
              <div className="text-right">
                <span className="block text-3xs font-mono text-gray-400 uppercase tracking-wider">
                  Threat Risk
                </span>
                <span className="text-base font-mono font-bold text-gray-100">
                  {investigation.risk_score}
                  <span className="text-xs text-gray-400">/100</span>
                </span>
              </div>
              <RiskScoreGauge score={investigation.risk_score} size="sm" showLabel={false} />
            </div>
          )}

          {/* Action Toolbar */}
          <div className="flex items-center gap-2">
            {onOpenThreatMap && (
              <button
                onClick={onOpenThreatMap}
                className="flex items-center gap-1.5 px-2.5 py-1.5 rounded bg-blue-950/80 hover:bg-blue-900 border border-blue-800 text-blue-200 text-xs font-mono font-bold transition shadow-sm"
                title="View Geographic Relay Transit Threat Map"
              >
                <MapPin className="w-3.5 h-3.5 text-blue-400" />
                <span>Threat Map</span>
              </button>
            )}

            <button
              onClick={onOpenSearch}
              className="flex items-center gap-1.5 px-2.5 py-1.5 rounded bg-[#151E2E] hover:bg-[#1E293B] border border-[#263244] text-gray-200 text-xs font-mono transition"
              title="Search entities in graph"
            >
              <Search className="w-3.5 h-3.5 text-gray-400" />
              <span>Search Entity</span>
            </button>

            <button
              onClick={onRefresh}
              disabled={isRefreshing}
              className="flex items-center gap-1.5 px-2.5 py-1.5 rounded bg-[#151E2E] hover:bg-[#1E293B] border border-[#263244] text-gray-200 text-xs font-mono transition disabled:opacity-50"
              title="Re-run investigation pipeline"
            >
              <RefreshCw className={`w-3.5 h-3.5 text-gray-400 ${isRefreshing ? 'animate-spin' : ''}`} />
              <span>Re-Investigate</span>
            </button>

            <button
              onClick={() => {
                if (onOpenReport) {
                  onOpenReport();
                } else {
                  const jsonStr = `data:text/json;charset=utf-8,${encodeURIComponent(
                    JSON.stringify(investigation, null, 2)
                  )}`;
                  const a = document.createElement('a');
                  a.href = jsonStr;
                  a.download = `${investigation.investigation_id}-evidence-report.json`;
                  a.click();
                }
              }}
              className="flex items-center gap-1.5 px-2.5 py-1.5 rounded bg-purple-950/60 hover:bg-purple-900/60 border border-purple-800/50 text-purple-300 text-xs font-mono font-bold transition shadow-sm"
              title="Open DFIR Report & Export PDF/IoCs"
            >
              <FileDown className="w-3.5 h-3.5" />
              <span>DFIR Report</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
