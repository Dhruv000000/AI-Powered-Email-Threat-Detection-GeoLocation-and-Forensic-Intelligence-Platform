import React, { useState, useEffect } from 'react';
import { reportService } from '../services/reportService';
import { caseService } from '../services/caseService';
import { ForensicReport } from '../types/report';
import { InvestigationCase } from '../types/case';
import { FileText, Download, Eye } from 'lucide-react';
import { CaseReportModal } from '../components/cases/CaseReportModal';
import { LoadingState } from '../components/common/LoadingState';

export const ReportsPage: React.FC = () => {
  const [reports, setReports] = useState<ForensicReport[]>([]);
  const [cases, setCases] = useState<InvestigationCase[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedReport, setSelectedReport] = useState<ForensicReport | null>(null);
  const [selectedCase, setSelectedCase] = useState<InvestigationCase | null>(null);
  const [isModalOpen, setIsModalOpen] = useState(false);

  useEffect(() => {
    async function fetchReports() {
      setLoading(true);
      const [r, c] = await Promise.all([reportService.getReports(), caseService.getCases()]);
      setReports(r);
      setCases(c);
      setLoading(false);
    }
    fetchReports();
  }, []);

  const handleOpenReport = (rpt: ForensicReport) => {
    const targetCase = cases.find((c) => c.id === rpt.caseId) || cases[0];
    setSelectedReport(rpt);
    setSelectedCase(targetCase);
    setIsModalOpen(true);
  };

  const handleDownloadStub = (rpt: ForensicReport) => {
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(rpt, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute('href', dataStr);
    downloadAnchor.setAttribute('download', `${rpt.id}-forensic-report.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  return (
    <div className="space-y-6">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-[#263244] pb-4">
        <div>
          <h1 className="text-xl font-bold text-gray-100 font-mono tracking-tight flex items-center gap-2">
            <FileText className="w-5 h-5 text-blue-400" />
            Forensic Intelligence Reports Repository
          </h1>
          <p className="text-xs text-gray-400 font-mono mt-1">
            Official exportable intelligence packages formatted for institutional governance, law enforcement coordination, and cyber incident response.
          </p>
        </div>
      </div>

      {/* Reports Table */}
      {loading ? (
        <LoadingState message="Loading forensic reports..." />
      ) : reports.length === 0 ? (
        <div className="p-12 text-center bg-[#111827] rounded-lg border border-[#263244] text-xs font-mono text-gray-400 space-y-3">
          <FileText className="w-8 h-8 text-blue-400/50 mx-auto" />
          <p className="text-gray-300 font-semibold">No forensic reports generated yet.</p>
          <p className="text-3xs text-gray-500">Ingest and analyze an email or PDF artifact to compile a forensic intelligence dossier.</p>
        </div>
      ) : (
        <div className="overflow-x-auto rounded-lg border border-[#263244] bg-[#111827]">
          <table className="w-full text-left text-xs border-collapse font-mono">
            <thead>
              <tr className="bg-[#151E2E] border-b border-[#263244] text-2xs uppercase tracking-wider text-gray-400 font-semibold">
                <th className="py-3 px-4">Report Identifier</th>
                <th className="py-3 px-4">Case Association</th>
                <th className="py-3 px-4">Classification</th>
                <th className="py-3 px-4">Generated Date</th>
                <th className="py-3 px-4">Investigator</th>
                <th className="py-3 px-4">Format</th>
                <th className="py-3 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1E293B]">
              {reports.map((rpt) => (
                <tr key={rpt.id} className="hover:bg-[#151E2E]/80 transition">
                  <td className="py-3 px-4">
                    <span className="font-bold text-blue-400">{rpt.id}</span>
                  </td>
                  <td className="py-3 px-4 max-w-xs font-sans">
                    <span className="font-semibold text-gray-100 block">{rpt.caseTitle}</span>
                    <span className="text-2xs text-gray-400 font-mono">{rpt.caseId}</span>
                  </td>
                  <td className="py-3 px-4">
                    <span className="px-2 py-0.5 rounded bg-red-500/10 text-red-400 border border-red-500/20 text-2xs font-bold">
                      {rpt.classification.split('/')[0]}
                    </span>
                  </td>
                  <td className="py-3 px-4 text-gray-300 text-2xs">
                    {rpt.generatedAt}
                  </td>
                  <td className="py-3 px-4 text-gray-300">
                    {rpt.generatedBy.name}
                  </td>
                  <td className="py-3 px-4">
                    <span className="px-1.5 py-0.2 rounded bg-[#1E293B] text-gray-300 border border-[#263244] text-[10px]">
                      {rpt.fileFormat}
                    </span>
                  </td>
                  <td className="py-3 px-4 text-right">
                    <div className="flex items-center justify-end gap-2">
                      <button
                        onClick={() => handleOpenReport(rpt)}
                        className="flex items-center gap-1 px-2.5 py-1 bg-blue-600/20 hover:bg-blue-600 text-blue-400 hover:text-white rounded border border-blue-500/30 transition text-2xs"
                      >
                        <Eye className="w-3 h-3" />
                        <span>View</span>
                      </button>
                      <button
                        onClick={() => handleDownloadStub(rpt)}
                        className="p-1 bg-[#1E293B] hover:bg-[#263244] text-gray-300 rounded border border-[#263244] transition"
                        title="Download JSON/STIX"
                      >
                        <Download className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Modal */}
      {selectedReport && selectedCase && (
        <CaseReportModal
          isOpen={isModalOpen}
          onClose={() => setIsModalOpen(false)}
          caseItem={selectedCase}
          report={selectedReport}
        />
      )}
    </div>
  );
};
