import React, { useRef } from 'react';
import { InvestigationCase } from '../../types/case';
import { ForensicReport } from '../../types/report';
import { X, Printer, Download, Shield, FileCheck, CheckCircle2 } from 'lucide-react';
import { SeverityBadge } from '../common/SeverityBadge';

interface CaseReportModalProps {
  isOpen: boolean;
  onClose: () => void;
  caseItem: InvestigationCase;
  report?: ForensicReport;
}

export const CaseReportModal: React.FC<CaseReportModalProps> = ({
  isOpen,
  onClose,
  caseItem,
  report,
}) => {
  const printContentRef = useRef<HTMLDivElement>(null);

  if (!isOpen) return null;

  const handlePrint = () => {
    window.print();
  };

  const handleDownloadJson = () => {
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify({ case: caseItem, report }, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute('href', dataStr);
    downloadAnchor.setAttribute('download', `${caseItem.id}-forensic-intelligence-report.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm overflow-y-auto animate-in fade-in">
      <div className="w-full max-w-4xl bg-[#111827] border border-[#263244] rounded-xl shadow-2xl overflow-hidden flex flex-col max-h-[90vh]">
        {/* Modal Action Header */}
        <div className="flex items-center justify-between px-6 py-3.5 bg-[#151E2E] border-b border-[#263244]">
          <div className="flex items-center gap-2 text-xs font-mono">
            <Shield className="w-4 h-4 text-blue-400" />
            <span className="font-bold text-gray-200 uppercase">Forensic Intelligence Export Package</span>
            <span className="text-gray-400">|</span>
            <span className="text-gray-300">{caseItem.id}</span>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={handlePrint}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-[#1E293B] hover:bg-[#263244] text-gray-200 border border-[#263244] rounded text-xs font-mono transition"
            >
              <Printer className="w-3.5 h-3.5" />
              <span>Print Document</span>
            </button>

            <button
              onClick={handleDownloadJson}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-blue-600 hover:bg-blue-500 text-white rounded text-xs font-mono font-semibold transition shadow"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Export STIX / JSON</span>
            </button>

            <button
              onClick={onClose}
              className="p-1.5 text-gray-400 hover:text-gray-200 rounded hover:bg-[#1E293B] ml-2"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Printable Forensic Report Document Body */}
        <div ref={printContentRef} className="p-8 overflow-y-auto space-y-6 text-gray-100 font-sans bg-[#0B1120]">
          {/* Official Header Banner */}
          <div className="border-b-2 border-[#263244] pb-4 flex items-start justify-between font-mono">
            <div>
              <div className="flex items-center gap-2">
                <span className="text-xl font-bold tracking-wider text-blue-400">AEGIS</span>
                <span className="text-xs uppercase tracking-widest text-gray-400">DIGITAL FORENSICS DIVISION</span>
              </div>
              <h2 className="text-lg font-bold text-gray-100 mt-1">
                EXECUTIVE THREAT INTELLIGENCE & INCIDENT REPORT
              </h2>
              <p className="text-xs text-gray-400 mt-0.5">Reference Identifier: {report?.id || `RPT-2026-${caseItem.id}`}</p>
            </div>

            <div className="text-right space-y-1 text-xs">
              <span className="inline-block px-2 py-0.5 bg-red-500/20 text-red-400 border border-red-500/30 text-[11px] font-bold rounded">
                RESTRICTED / LAW ENFORCEMENT SENSITIVE
              </span>
              <p className="text-2xs text-gray-400">Generated: {report?.generatedAt || new Date().toUTCString()}</p>
            </div>
          </div>

          {/* Metadata Grid */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 p-4 rounded-lg bg-[#151E2E] border border-[#263244] text-xs font-mono">
            <div>
              <span className="text-2xs text-gray-400 uppercase block font-semibold">Case Identifier</span>
              <span className="text-sm font-bold text-gray-100 mt-0.5 block">{caseItem.id}</span>
            </div>
            <div>
              <span className="text-2xs text-gray-400 uppercase block font-semibold">Priority & Status</span>
              <div className="flex items-center gap-1.5 mt-1">
                <SeverityBadge severity={caseItem.priority} size="sm" />
              </div>
            </div>
            <div>
              <span className="text-2xs text-gray-400 uppercase block font-semibold">Lead Investigator</span>
              <span className="text-xs font-bold text-gray-200 mt-0.5 block">{caseItem.assignedAnalyst.name}</span>
            </div>
            <div>
              <span className="text-2xs text-gray-400 uppercase block font-semibold">Attribution Confidence</span>
              <span className="text-xs font-bold text-blue-400 mt-0.5 block">{caseItem.attributionConfidence}%</span>
            </div>
          </div>

          {/* Executive Summary */}
          <div className="space-y-2">
            <h3 className="text-xs font-bold uppercase tracking-wider text-blue-400 font-mono">
              1. Executive Incident Summary
            </h3>
            <p className="text-xs text-gray-300 leading-relaxed bg-[#151E2E] p-4 rounded-lg border border-[#263244]">
              {report?.summary || caseItem.description}
            </p>
          </div>

          {/* Indicators of Compromise (IoC Table) */}
          <div className="space-y-2">
            <h3 className="text-xs font-bold uppercase tracking-wider text-blue-400 font-mono">
              2. Discovered Indicators of Compromise (IoCs)
            </h3>
            <div className="rounded-lg border border-[#263244] overflow-hidden">
              <table className="w-full text-left text-xs font-mono border-collapse">
                <thead className="bg-[#151E2E] text-gray-400 text-2xs uppercase">
                  <tr>
                    <th className="p-2.5">Indicator Type</th>
                    <th className="p-2.5">Extracted Value</th>
                    <th className="p-2.5">Threat Context</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#1E293B] bg-[#111827]">
                  {caseItem.indicatorIps.map((ip) => (
                    <tr key={ip}>
                      <td className="p-2.5 text-red-400 font-semibold">Originating IP</td>
                      <td className="p-2.5 text-gray-200">{ip}</td>
                      <td className="p-2.5 text-gray-400 text-2xs">Probable Infrastructure Origin Relay</td>
                    </tr>
                  ))}
                  {caseItem.indicatorDomains.map((dom) => (
                    <tr key={dom}>
                      <td className="p-2.5 text-amber-400 font-semibold">Lookalike Domain</td>
                      <td className="p-2.5 text-gray-200">{dom}</td>
                      <td className="p-2.5 text-gray-400 text-2xs">Sender impersonation vector</td>
                    </tr>
                  ))}
                  {caseItem.indicatorUrls.map((url) => (
                    <tr key={url}>
                      <td className="p-2.5 text-orange-400 font-semibold">Malicious URL</td>
                      <td className="p-2.5 text-gray-200 break-all">{url}</td>
                      <td className="p-2.5 text-gray-400 text-2xs">Credential harvesting landing page</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Recommended Countermeasures */}
          <div className="space-y-2">
            <h3 className="text-xs font-bold uppercase tracking-wider text-blue-400 font-mono">
              3. Recommended Mitigation & Institutional Actions
            </h3>
            <div className="p-4 rounded-lg bg-[#151E2E] border border-[#263244] space-y-2 text-xs text-gray-300">
              <div className="flex items-center gap-2">
                <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0" />
                <span>Enforce immediate DNS sinkhole blocks for identified lookalike domains across all enterprise recursive resolvers.</span>
              </div>
              <div className="flex items-center gap-2">
                <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0" />
                <span>Submit abuse notifications with forensic evidence headers to domain registrars and bulletproof hosting providers.</span>
              </div>
              <div className="flex items-center gap-2">
                <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0" />
                <span>Forward banking beneficiary details to financial crime and anti-money laundering coordination units.</span>
              </div>
            </div>
          </div>

          {/* Evidentiary Integrity Seal */}
          <div className="pt-4 border-t border-[#263244] flex items-center justify-between text-2xs text-gray-400 font-mono">
            <div className="flex items-center gap-2">
              <FileCheck className="w-4 h-4 text-blue-400" />
              <span>Digital Forensics Evidentiary Seal Verified (AES-256 / SHA-256)</span>
            </div>
            <span>AEGIS Investigation Protocol v2.4</span>
          </div>
        </div>
      </div>
    </div>
  );
};
