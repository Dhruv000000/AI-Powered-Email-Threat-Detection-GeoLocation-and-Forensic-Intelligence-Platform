import React from 'react';
import { FeatureContribution } from '../../types/email';
import { Brain, Sparkles, MessageSquare, AlertCircle } from 'lucide-react';
import { cn } from '../../lib/utils';

interface FeatureContributionProps {
  contributions: FeatureContribution[];
  classification: string;
  confidence: number;
  explanation: string;
  linguistics?: {
    urgentLanguageDetected: boolean;
    financialKeywords: string[];
    sentiment: string;
    executiveImpersonationScore: number;
  };
}

export const FeatureContributionBar: React.FC<FeatureContributionProps> = ({
  contributions,
  classification,
  confidence,
  explanation,
  linguistics,
}) => {
  const getImpactColor = (impact: string) => {
    switch (impact) {
      case 'High':
        return { bar: 'bg-red-500', text: 'text-red-400', badge: 'bg-red-500/20 text-red-400 border-red-500/30' };
      case 'Medium':
        return { bar: 'bg-amber-500', text: 'text-amber-400', badge: 'bg-amber-500/20 text-amber-400 border-amber-500/30' };
      default:
        return { bar: 'bg-blue-500', text: 'text-blue-400', badge: 'bg-blue-500/20 text-blue-400 border-blue-500/30' };
    }
  };

  return (
    <div className="space-y-6">
      {/* AI Model Assessment Card */}
      <div className="p-5 rounded-lg bg-[#111827] border border-[#263244] space-y-3">
        <div className="flex items-center justify-between border-b border-[#263244] pb-3">
          <div className="flex items-center gap-2">
            <Brain className="w-5 h-5 text-blue-400" />
            <div>
              <h4 className="text-xs font-bold uppercase tracking-wider text-gray-200 font-mono">
                AI Threat Classification Engine
              </h4>
              <p className="text-2xs text-gray-400">Multi-Model Ensemble: NLP + Header Graph + RF Classifier</p>
            </div>
          </div>
          <div className="text-right">
            <span className="text-sm font-bold text-blue-400 font-mono">{confidence}% Confidence</span>
            <p className="text-[10px] text-gray-400 uppercase font-mono">Statistical Certainty</p>
          </div>
        </div>

        <div>
          <span className="text-2xs font-mono uppercase text-gray-400 font-semibold block mb-1">
            Primary Model Classification:
          </span>
          <p className="text-base font-bold text-red-400 font-mono">{classification}</p>
        </div>

        <div className="p-3 bg-[#0B1120] rounded border border-[#263244]">
          <span className="text-2xs font-mono uppercase text-gray-400 font-semibold block mb-1">
            Human-Readable Explanatory Rationale:
          </span>
          <p className="text-xs text-gray-200 leading-relaxed">{explanation}</p>
        </div>
      </div>

      {/* Feature Contributions Section */}
      <div className="p-5 rounded-lg bg-[#111827] border border-[#263244] space-y-4">
        <div className="flex items-center justify-between border-b border-[#263244] pb-3">
          <h4 className="text-xs font-bold uppercase tracking-wider text-gray-200 font-mono flex items-center gap-2">
            <Sparkles className="w-4 h-4 text-blue-400" />
            Model Feature Importance & Weight Contributions (SHAP Values)
          </h4>
          <span className="text-2xs text-gray-400 font-mono">Normalized Importance</span>
        </div>

        <div className="space-y-4">
          {contributions.map((feat) => {
            const colors = getImpactColor(feat.impact);
            return (
              <div key={feat.feature} className="space-y-1.5 font-mono">
                <div className="flex items-center justify-between text-xs">
                  <div className="flex items-center gap-2">
                    <span className="font-semibold text-gray-200">{feat.feature}</span>
                    <span className={cn('px-1.5 py-0.2 rounded text-[10px] font-bold border', colors.badge)}>
                      {feat.impact} Impact
                    </span>
                  </div>
                  <span className={cn('font-bold', colors.text)}>{feat.weight}%</span>
                </div>

                {/* Progress Bar */}
                <div className="h-2 w-full bg-[#0B1120] rounded-full overflow-hidden border border-[#263244]">
                  <div
                    className={cn('h-full transition-all duration-500 rounded-full', colors.bar)}
                    style={{ width: `${feat.weight}%` }}
                  />
                </div>

                <p className="text-2xs text-gray-400 font-sans">{feat.description}</p>
              </div>
            );
          })}
        </div>
      </div>

      {/* Linguistic & Social Engineering Analysis */}
      {linguistics && (
        <div className="p-5 rounded-lg bg-[#111827] border border-[#263244] space-y-4">
          <h4 className="text-xs font-bold uppercase tracking-wider text-gray-200 font-mono flex items-center gap-2">
            <MessageSquare className="w-4 h-4 text-blue-400" />
            Natural Language Processing & Behavioral Indicators
          </h4>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 font-mono text-xs">
            <div className="p-3 bg-[#0B1120] rounded border border-[#263244]">
              <span className="text-2xs text-gray-400 uppercase font-semibold block">Detected Sentiment</span>
              <span className="text-sm font-bold text-amber-400 mt-1 block">{linguistics.sentiment}</span>
            </div>
            <div className="p-3 bg-[#0B1120] rounded border border-[#263244]">
              <span className="text-2xs text-gray-400 uppercase font-semibold block">Executive Impersonation</span>
              <span className="text-sm font-bold text-red-400 mt-1 block">
                {linguistics.executiveImpersonationScore}/100
              </span>
            </div>
            <div className="p-3 bg-[#0B1120] rounded border border-[#263244]">
              <span className="text-2xs text-gray-400 uppercase font-semibold block">Urgency Cue Status</span>
              <span className="text-sm font-bold text-red-400 mt-1 block">
                {linguistics.urgentLanguageDetected ? 'HIGH URGENCY DETECTED' : 'STANDARD'}
              </span>
            </div>
          </div>

          {linguistics.financialKeywords.length > 0 && (
            <div>
              <span className="text-2xs uppercase text-gray-400 font-semibold block mb-2 font-mono">
                Identified High-Risk Financial & Escrow Keywords:
              </span>
              <div className="flex flex-wrap gap-1.5 font-mono">
                {linguistics.financialKeywords.map((kw) => (
                  <span
                    key={kw}
                    className="px-2 py-1 rounded bg-red-500/10 text-red-300 border border-red-500/20 text-xs"
                  >
                    {kw}
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
