import React, { useEffect, useState } from 'react';
import { CheckCircle2, Loader2, Circle, ArrowRight, ShieldAlert } from 'lucide-react';

interface AnalysisStep {
  id: string;
  label: string;
  durationMs: number;
}

const ANALYSIS_STEPS: AnalysisStep[] = [
  { id: 'validate', label: 'File cryptographic signature & structure validated', durationMs: 400 },
  { id: 'metadata', label: 'Extracting email metadata & RFC 822 parameters', durationMs: 500 },
  { id: 'headers', label: 'Parsing SPF, DKIM, DMARC & multi-hop Received headers', durationMs: 650 },
  { id: 'urls', label: 'Extracting URLs, resolving redirects & homoglyph checks', durationMs: 600 },
  { id: 'ai', label: 'Running NLP social engineering & BEC machine learning models', durationMs: 800 },
  { id: 'infra', label: 'Tracing probable infrastructure origin & ASN threat score', durationMs: 650 },
  { id: 'graph', label: 'Correlating threat intelligence & campaign relationship cluster', durationMs: 600 },
  { id: 'risk', label: 'Generating comprehensive forensic risk assessment & IoC table', durationMs: 500 },
];

interface AnalysisProgressProps {
  fileName: string;
  isReady?: boolean;
  onComplete: () => void;
}

export const AnalysisProgress: React.FC<AnalysisProgressProps> = ({ fileName, isReady = true, onComplete }) => {
  const [currentStepIndex, setCurrentStepIndex] = useState(0);
  const isDone = currentStepIndex >= ANALYSIS_STEPS.length;

  useEffect(() => {
    if (currentStepIndex < ANALYSIS_STEPS.length) {
      const step = ANALYSIS_STEPS[currentStepIndex];
      const timeoutId = setTimeout(() => {
        setCurrentStepIndex((prev) => prev + 1);
      }, step.durationMs);
      return () => clearTimeout(timeoutId);
    }
  }, [currentStepIndex]);

  return (
    <div className="bg-[#151E2E] border border-[#263244] rounded-lg p-6 max-w-2xl mx-auto shadow-xl">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-[#263244] pb-4 mb-5">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded bg-blue-600/10 border border-blue-500/30 text-blue-400">
            <ShieldAlert className="w-5 h-5" />
          </div>
          <div>
            <h3 className="text-sm font-bold text-gray-100">Forensic Threat Ingestion Pipeline</h3>
            <p className="text-xs text-gray-400 font-mono mt-0.5">Target Evidence: {fileName}</p>
          </div>
        </div>
        <div className="text-right font-mono">
          <span className="text-xs font-bold text-blue-400">
            {Math.min(100, Math.round((currentStepIndex / ANALYSIS_STEPS.length) * 100))}%
          </span>
          <p className="text-[10px] text-gray-400 uppercase">Analysis Progress</p>
        </div>
      </div>

      {/* Steps List */}
      <div className="space-y-3 font-mono">
        {ANALYSIS_STEPS.map((step, idx) => {
          const isCompleted = idx < currentStepIndex;
          const isCurrent = idx === currentStepIndex;

          return (
            <div
              key={step.id}
              className={`flex items-center gap-3 text-xs transition-opacity duration-200 ${
                isCompleted
                  ? 'text-gray-200'
                  : isCurrent
                  ? 'text-blue-400 font-semibold'
                  : 'text-gray-400 opacity-60'
              }`}
            >
              <div className="flex-shrink-0">
                {isCompleted ? (
                  <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                ) : isCurrent ? (
                  <Loader2 className="w-4 h-4 text-blue-400 animate-spin" />
                ) : (
                  <Circle className="w-4 h-4 text-gray-400" />
                )}
              </div>
              <span className="tracking-tight">{step.label}</span>
            </div>
          );
        })}
      </div>

      {/* Completion CTA */}
      {isDone && (
        <div className="mt-6 pt-5 border-t border-[#263244] flex items-center justify-between animate-in fade-in">
          <div className="flex items-center gap-2 text-xs text-emerald-400 font-medium font-mono">
            <CheckCircle2 className="w-4 h-4" />
            <span>Forensic pipeline execution complete.</span>
          </div>
          <button
            onClick={onComplete}
            disabled={!isReady}
            className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white rounded text-xs font-semibold shadow transition"
          >
            {!isReady ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin" />
                <span>Finalizing Report...</span>
              </>
            ) : (
              <>
                <span>View Full Investigation</span>
                <ArrowRight className="w-4 h-4" />
              </>
            )}
          </button>
        </div>
      )}
    </div>
  );
};
