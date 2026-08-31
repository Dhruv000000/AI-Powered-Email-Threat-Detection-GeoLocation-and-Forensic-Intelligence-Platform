import React, { useState } from 'react';
import { EvidenceRecord } from '../../types/email';
import { FileCheck, ShieldCheck, Download, Copy, Check, Lock, History } from 'lucide-react';

interface EvidenceLockerProps {
  evidence: EvidenceRecord;
  caseId?: string;
}

export const EvidenceLocker: React.FC<EvidenceLockerProps> = ({ evidence, caseId }) => {
  const [copiedHash, setCopiedHash] = useState(false);

  const handleCopyHash = () => {
    navigator.clipboard.writeText(evidence.sha256);
    setCopiedHash(true);
    setTimeout(() => setCopiedHash(false), 2000);
  };

  const handleDownloadStub = () => {
    const element = document.createElement('a');
    const file = new Blob([`Evidence Identifier: ${evidence.evidenceId}\nSHA-256: ${evidence.sha256}\nOriginal File: ${evidence.originalFileName}\nPreserved at: ${evidence.uploadedAt}`], {
      type: 'text/plain',
    });
    element.href = URL.createObjectURL(file);
    element.download = `${evidence.evidenceId}-metadata.txt`;
    document.body.appendChild(element);
    element.click();
    document.body.removeChild(element);
  };

  return (
    <div className="space-y-6">
      {/* Evidence Integrity Card */}
      <div className="p-5 rounded-lg bg-[#111827] border border-[#263244] space-y-4">
        <div className="flex items-center justify-between border-b border-[#263244] pb-3">
          <div className="flex items-center gap-2">
            <Lock className="w-5 h-5 text-blue-400" />
            <div>
              <h4 className="text-xs font-bold uppercase tracking-wider text-gray-200 font-mono">
                Cryptographic Evidence Locker & Chain-of-Custody
              </h4>
              <p className="text-2xs text-gray-400">Forensic digital asset preserved with immutability seal</p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <span className="px-2.5 py-1 rounded bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 text-xs font-bold font-mono flex items-center gap-1.5">
              <ShieldCheck className="w-3.5 h-3.5" />
              INTEGRITY: {evidence.integrityStatus.toUpperCase()}
            </span>
          </div>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-4 text-xs font-mono">
          <div className="p-3 bg-[#0B1120] rounded border border-[#263244]">
            <span className="text-2xs text-gray-400 uppercase font-semibold block">Evidence ID</span>
            <span className="text-sm font-bold text-gray-100 mt-1 block">{evidence.evidenceId}</span>
          </div>
          <div className="p-3 bg-[#0B1120] rounded border border-[#263244]">
            <span className="text-2xs text-gray-400 uppercase font-semibold block">Original Filename</span>
            <span className="text-xs text-gray-200 mt-1 block truncate" title={evidence.originalFileName}>
              {evidence.originalFileName}
            </span>
          </div>
          <div className="p-3 bg-[#0B1120] rounded border border-[#263244]">
            <span className="text-2xs text-gray-400 uppercase font-semibold block">File Size</span>
            <span className="text-xs text-gray-200 mt-1 block">{evidence.fileSizeFormatted}</span>
          </div>
          <div className="p-3 bg-[#0B1120] rounded border border-[#263244]">
            <span className="text-2xs text-gray-400 uppercase font-semibold block">Ingestion Timestamp</span>
            <span className="text-xs text-gray-200 mt-1 block">{evidence.uploadedAt}</span>
          </div>
        </div>

        {/* Hashes */}
        <div className="space-y-2 text-xs font-mono">
          <div>
            <div className="flex items-center justify-between mb-1">
              <span className="text-2xs uppercase text-gray-400 font-semibold">SHA-256 Cryptographic Seal:</span>
              <button
                onClick={handleCopyHash}
                className="flex items-center gap-1 text-[11px] text-blue-400 hover:text-blue-300 transition"
              >
                {copiedHash ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                <span>{copiedHash ? 'Copied Hash' : 'Copy Hash'}</span>
              </button>
            </div>
            <div className="p-2.5 rounded bg-[#0B1120] border border-[#263244] text-xs text-blue-300 break-all select-all font-mono">
              {evidence.sha256}
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-2">
            <div>
              <span className="text-2xs uppercase text-gray-400 font-semibold block mb-1">MD5 Hash:</span>
              <div className="p-2 rounded bg-[#0B1120] border border-[#263244] text-2xs text-gray-300 break-all">
                {evidence.md5}
              </div>
            </div>
            <div>
              <span className="text-2xs uppercase text-gray-400 font-semibold block mb-1">SHA-1 Hash:</span>
              <div className="p-2 rounded bg-[#0B1120] border border-[#263244] text-2xs text-gray-300 break-all">
                {evidence.sha1}
              </div>
            </div>
          </div>
        </div>

        {/* Action Controls */}
        <div className="pt-2 flex items-center justify-between border-t border-[#1E293B]">
          <span className="text-2xs text-gray-400 font-mono">Linked Case: {caseId || 'Standalone Evidence Item'}</span>
          <button
            onClick={handleDownloadStub}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-[#1E293B] hover:bg-[#263244] text-gray-200 border border-[#263244] rounded text-xs font-mono transition"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Export Forensic Metadata Package</span>
          </button>
        </div>
      </div>

      {/* Chain of Custody Log */}
      <div className="p-5 rounded-lg bg-[#111827] border border-[#263244] space-y-4">
        <h4 className="text-xs font-bold uppercase tracking-wider text-gray-200 font-mono flex items-center gap-2">
          <History className="w-4 h-4 text-blue-400" />
          Immutable Chain-of-Custody Audit Trail ({evidence.chainOfCustody.length} Records)
        </h4>

        {evidence.chainOfCustody.length === 0 ? (
          <p className="text-xs text-gray-400 font-mono">No subsequent custody transfers recorded.</p>
        ) : (
          <div className="space-y-3 relative before:absolute before:inset-0 before:left-3 before:w-0.5 before:bg-[#263244] before:z-0">
            {evidence.chainOfCustody.map((event, idx) => (
              <div
                key={idx}
                className="relative z-10 p-3 rounded-lg border border-[#263244] bg-[#151E2E] space-y-1 text-xs font-mono"
              >
                <div className="flex items-center justify-between">
                  <span className="font-bold text-gray-200">{event.action}</span>
                  <span className="text-2xs text-gray-400">{event.timestamp}</span>
                </div>
                <div className="flex items-center justify-between text-2xs text-gray-400 pt-1">
                  <span>Authorized Actor: <strong className="text-gray-300">{event.actor}</strong></span>
                  <span className="text-emerald-400 font-bold">{event.hashVerification}</span>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};
