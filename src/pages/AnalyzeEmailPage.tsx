import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  UploadCloud,
  FileCode,
  Sparkles,
  Trash2,
  Play,
  FileText,
  ArrowRight,
  AlertCircle,
  RefreshCw,
} from 'lucide-react';
import { sampleEmailScenarios, SampleEmailScenario } from '../mock/sampleEmlFiles';
import { AnalysisProgress } from '../components/analysis/AnalysisProgress';
import { emailService } from '../services/emailService';

async function computeSha256(textOrBytes: string | ArrayBuffer): Promise<string> {
  const data = typeof textOrBytes === 'string' ? new TextEncoder().encode(textOrBytes) : textOrBytes;
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
}

interface SelectedFileState {
  name: string;
  size: string;
  sha256: string;
  content: string;
  fileObj?: File;
}

export const AnalyzeEmailPage: React.FC = () => {
  const navigate = useNavigate();

  const [activeTab, setActiveTab] = useState<'upload' | 'paste'>('upload');
  const [selectedFile, setSelectedFile] = useState<SelectedFileState | null>(null);
  const [rawText, setRawText] = useState('');
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [analyzedTargetId, setAnalyzedTargetId] = useState<string | null>(null);
  const [analysisError, setAnalysisError] = useState<string | null>(null);

  // Handle drag and drop or manual file selection
  const handleFileSelect = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setAnalysisError(null);

    try {
      const buffer = await file.arrayBuffer();
      const hash = await computeSha256(buffer);
      let content = '';
      if (file.name.toLowerCase().endsWith('.pdf')) {
        content = `[Binary PDF Artifact: ${file.name}] (${(file.size / 1024).toFixed(1)} KB)`;
      } else {
        content = new TextDecoder('utf-8', { fatal: false }).decode(buffer);
      }

      setSelectedFile({
        name: file.name,
        size: `${(file.size / 1024).toFixed(1)} KB`,
        sha256: hash,
        content,
        fileObj: file,
      });
    } catch (err) {
      console.error('Failed to read file:', err);
      setAnalysisError('Could not read the selected file. Please verify it is a valid .eml, .msg, or .pdf file.');
    }
  };

  // 1-Click Load Scenario
  const handleLoadScenario = async (scenario: SampleEmailScenario) => {
    setAnalysisError(null);
    try {
      const hash = await computeSha256(scenario.rawEmlContent);
      setSelectedFile({
        name: scenario.fileName,
        size: `${(scenario.rawEmlContent.length / 1024).toFixed(1)} KB`,
        sha256: hash,
        content: scenario.rawEmlContent,
      });
      setRawText(scenario.rawEmlContent);
    } catch (err) {
      console.error('Failed to load scenario:', err);
    }
  };

  const handleStartAnalysis = async () => {
    setAnalysisError(null);
    setAnalyzedTargetId(null);

    const content = selectedFile?.content || rawText;
    const fileName = selectedFile?.name || 'pasted-headers.eml';

    if (!content.trim()) return;

    setIsAnalyzing(true);

    try {
      let result;
      if (activeTab === 'upload' && selectedFile?.fileObj) {
        result = await emailService.uploadEmailFile(selectedFile.fileObj);
      } else {
        result = await emailService.parseEmailRaw(content, fileName);
      }

      setAnalyzedTargetId(result.id);
    } catch (err: any) {
      console.error('[AnalyzeEmailPage] Analysis error:', err);
      setIsAnalyzing(false);
      setAnalysisError(err.message || 'Analysis failed. Please try again.');
    }
  };

  const handleAnalysisComplete = () => {
    if (analyzedTargetId) {
      navigate(`/analyze/${analyzedTargetId}`);
    }
  };

  return (
    <div className="space-y-6 max-w-5xl mx-auto">
      {/* Header */}
      <div className="border-b border-[#263244] pb-4">
        <h1 className="text-xl font-bold text-gray-100 font-mono tracking-tight">
          Analyze Suspicious Email
        </h1>
        <p className="text-xs text-gray-400 mt-1">
          Upload an RFC 822 <code className="font-mono text-blue-400">.eml</code> container or paste raw header telemetry for AI threat extraction, relay origin tracing, and forensic preservation.
        </p>
      </div>

      {/* Error Alert UI if analysis failed */}
      {analysisError && (
        <div className="p-4 rounded-lg bg-red-950/40 border border-red-500/50 flex items-start justify-between font-mono animate-in fade-in">
          <div className="flex items-start gap-3">
            <AlertCircle className="w-5 h-5 text-red-400 mt-0.5 flex-shrink-0" />
            <div>
              <h4 className="text-xs font-bold text-red-200">Analysis Failed</h4>
              <p className="text-xs text-red-300/80 mt-1">{analysisError}</p>
            </div>
          </div>
          <button
            onClick={() => setAnalysisError(null)}
            className="p-1 text-red-400 hover:text-red-200 rounded transition"
            title="Dismiss error"
          >
            <RefreshCw className="w-4 h-4" />
          </button>
        </div>
      )}

      {/* Progress View if in progress */}
      {isAnalyzing ? (
        <AnalysisProgress
          fileName={selectedFile?.name || 'Raw Ingest Stream'}
          isReady={!!analyzedTargetId}
          onComplete={handleAnalysisComplete}
        />
      ) : (
        <>
          {/* Quick Demo Forensic Scenarios */}
          <div className="p-4 rounded-lg bg-[#151E2E] border border-[#263244] space-y-3 font-mono">
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold text-gray-200 uppercase tracking-wider flex items-center gap-2">
                <Sparkles className="w-4 h-4 text-blue-400" />
                One-Click Forensic Demonstration Scenarios
              </span>
              <span className="text-2xs text-gray-400">Instant judge / evaluation loader</span>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
              {sampleEmailScenarios.map((sc) => (
                <button
                  key={sc.id}
                  onClick={() => handleLoadScenario(sc)}
                  className={`p-3 rounded-lg border text-left transition flex flex-col justify-between group ${
                    selectedFile?.name === sc.fileName
                      ? 'border-blue-500 bg-blue-950/30'
                      : 'border-[#263244] bg-[#111827] hover:border-blue-500/50 hover:bg-[#1B263B]'
                  }`}
                >
                  <div className="space-y-1">
                    <span className="text-[10px] font-bold px-1.5 py-0.2 rounded bg-blue-500/20 text-blue-400 border border-blue-500/30">
                      {sc.badgeLabel}
                    </span>
                    <h4 className="text-xs font-bold text-gray-200 font-sans mt-1.5 group-hover:text-blue-300">
                      {sc.name.split(':')[1] || sc.name}
                    </h4>
                    <p className="text-2xs text-gray-400 font-sans line-clamp-2">{sc.description}</p>
                  </div>
                  <div className="pt-2 text-2xs text-blue-400 font-mono font-semibold flex items-center gap-1">
                    <span>Load Scenario</span>
                    <ArrowRight className="w-3 h-3" />
                  </div>
                </button>
              ))}
            </div>
          </div>

          {/* Mode Switcher Tabs */}
          <div className="flex items-center gap-2 border-b border-[#263244] font-mono text-xs">
            <button
              onClick={() => {
                setActiveTab('upload');
                setAnalysisError(null);
              }}
              className={`px-4 py-2 font-semibold border-b-2 transition flex items-center gap-2 ${
                activeTab === 'upload'
                  ? 'border-blue-500 text-blue-400 bg-blue-950/20'
                  : 'border-transparent text-gray-400 hover:text-gray-200'
              }`}
            >
              <UploadCloud className="w-4 h-4" />
              <span>Upload .EML / .PDF File</span>
            </button>
            <button
              onClick={() => {
                setActiveTab('paste');
                setAnalysisError(null);
              }}
              className={`px-4 py-2 font-semibold border-b-2 transition flex items-center gap-2 ${
                activeTab === 'paste'
                  ? 'border-blue-500 text-blue-400 bg-blue-950/20'
                  : 'border-transparent text-gray-400 hover:text-gray-200'
              }`}
            >
              <FileCode className="w-4 h-4" />
              <span>Paste Raw MIME Headers</span>
            </button>
          </div>

          {/* Tab 1: Upload Drag and Drop Area */}
          {activeTab === 'upload' && (
            <div className="space-y-4">
              <label
                htmlFor="eml-upload-input"
                className="flex flex-col items-center justify-center p-10 rounded-lg border-2 border-dashed border-[#263244] hover:border-blue-500/50 bg-[#151E2E]/60 transition cursor-pointer group"
              >
                <div className="p-3 rounded-full bg-[#1E293B] border border-[#263244] text-gray-400 group-hover:text-blue-400 mb-3 transition">
                  <UploadCloud className="w-8 h-8" />
                </div>
                <h3 className="text-sm font-semibold text-gray-200 font-mono">
                  Drag & drop RFC 822 <span className="text-blue-400">.EML</span> or exported <span className="text-purple-400">.PDF</span> file here
                </h3>
                <p className="text-xs text-gray-400 mt-1">or browse local workstation</p>
                <span className="text-[10px] text-gray-500 font-mono mt-3">
                  Maximum file size: 25 MB • MIME / Base64 & PDF text auto-extracted
                </span>
                <input
                  id="eml-upload-input"
                  type="file"
                  accept=".eml,.msg,.txt,.pdf,application/pdf"
                  onChange={handleFileSelect}
                  className="hidden"
                />
              </label>

              {/* Selected File Details Box */}
              {selectedFile && (
                <div className="p-4 rounded-lg bg-[#111827] border border-blue-500/30 flex items-center justify-between font-mono animate-in fade-in">
                  <div className="flex items-center gap-3">
                    <div className="p-2 rounded bg-blue-500/10 text-blue-400 border border-blue-500/20">
                      <FileText className="w-5 h-5" />
                    </div>
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-bold text-gray-100">{selectedFile.name}</span>
                        <span className="px-1.5 py-0.2 rounded bg-emerald-500/20 text-emerald-400 text-[10px] font-bold">
                          READY FOR ANALYSIS
                        </span>
                      </div>
                      <div className="flex items-center gap-3 text-2xs text-gray-400 mt-0.5">
                        <span>Size: {selectedFile.size}</span>
                        <span>•</span>
                        <span className="truncate max-w-xs" title={`SHA-256: ${selectedFile.sha256}`}>
                          SHA-256: {selectedFile.sha256.slice(0, 16)}...
                        </span>
                      </div>
                    </div>
                  </div>

                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => setSelectedFile(null)}
                      className="p-1.5 text-gray-400 hover:text-red-400 rounded hover:bg-red-500/10 transition"
                      title="Clear Selection"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                    <button
                      onClick={handleStartAnalysis}
                      className="flex items-center gap-1.5 px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded text-xs font-semibold shadow transition"
                    >
                      <Play className="w-3.5 h-3.5" />
                      <span>Start Forensic Pipeline</span>
                    </button>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Tab 2: Paste Raw Content */}
          {activeTab === 'paste' && (
            <div className="space-y-4">
              <textarea
                rows={12}
                placeholder="From: alice@example.com&#10;Subject: Security Verification&#10;Date: Mon, 31 Aug 2026 10:00:00 +0000&#10;&#10;Hi team, please review..."
                value={rawText}
                onChange={(e) => setRawText(e.target.value)}
                className="w-full bg-[#111827] border border-[#263244] rounded-lg p-4 font-mono text-xs text-gray-200 placeholder-gray-600 focus:outline-none focus:border-blue-500 leading-relaxed"
              />

              <div className="flex items-center justify-between font-mono">
                <span className="text-2xs text-gray-400">
                  {rawText.length} characters • RFC 822 Parser Ready
                </span>

                <div className="flex items-center gap-2">
                  <button
                    onClick={() => setRawText('')}
                    disabled={!rawText}
                    className="px-3 py-1.5 bg-[#151E2E] text-gray-400 hover:text-gray-200 border border-[#263244] rounded text-xs transition disabled:opacity-50"
                  >
                    Clear Raw Text
                  </button>
                  <button
                    onClick={handleStartAnalysis}
                    disabled={!rawText.trim()}
                    className="flex items-center gap-1.5 px-4 py-2 bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white rounded text-xs font-semibold shadow transition"
                  >
                    <Play className="w-3.5 h-3.5" />
                    <span>Start Analysis</span>
                  </button>
                </div>
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
};
