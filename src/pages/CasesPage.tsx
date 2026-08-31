import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Briefcase,
  Search,
  Filter,
  Plus,
  ArrowRight,
  Shield,
  Clock,
  User,
  Layers,
  FileCheck,
} from 'lucide-react';
import { caseService } from '../services/caseService';
import { InvestigationCase, CasePriority, CaseStatus } from '../types/case';
import { SeverityBadge } from '../components/common/SeverityBadge';
import { StatusBadge } from '../components/common/StatusBadge';
import { CreateCaseModal } from '../components/cases/CreateCaseModal';
import { LoadingState } from '../components/common/LoadingState';
import { EmptyState } from '../components/common/EmptyState';

export const CasesPage: React.FC = () => {
  const navigate = useNavigate();
  const [cases, setCases] = useState<InvestigationCase[]>([]);
  const [loading, setLoading] = useState(true);
  const [isCreateModalOpen, setIsCreateModalOpen] = useState(false);

  // Filters State
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedStatus, setSelectedStatus] = useState<CaseStatus | 'all'>('all');
  const [selectedPriority, setSelectedPriority] = useState<CasePriority | 'all'>('all');

  const fetchCases = async () => {
    setLoading(true);
    const data = await caseService.getCases({
      searchTerm,
      status: selectedStatus,
      priority: selectedPriority,
    });
    setCases(data);
    setLoading(false);
  };

  useEffect(() => {
    fetchCases();
  }, [searchTerm, selectedStatus, selectedPriority]);

  const handleCreateCase = async (newCaseData: { title: string; description: string; priority: CasePriority }) => {
    const created = await caseService.createCase(newCaseData);
    fetchCases();
    navigate(`/cases/${created.id}`);
  };

  return (
    <div className="space-y-6">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-[#263244] pb-4">
        <div>
          <h1 className="text-xl font-bold text-gray-100 font-mono tracking-tight flex items-center gap-2">
            <Briefcase className="w-5 h-5 text-blue-400" />
            Forensic Investigation Cases
          </h1>
          <p className="text-xs text-gray-400 font-mono mt-1">
            Collaborative incident workspaces grouping correlated email threats, IoCs, and chain-of-custody evidence.
          </p>
        </div>

        <button
          onClick={() => setIsCreateModalOpen(true)}
          className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded text-xs font-semibold font-mono tracking-wide shadow transition"
        >
          <Plus className="w-4 h-4" />
          <span>New Investigation Case</span>
        </button>
      </div>

      {/* Filter Bar */}
      <div className="p-4 rounded-lg bg-[#151E2E] border border-[#263244] space-y-3 font-mono">
        <div className="flex flex-wrap items-center gap-3">
          {/* Search Input */}
          <div className="relative flex-1 min-w-[240px]">
            <Search className="w-4 h-4 text-gray-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Search by Case ID, title, description, or analyst name..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full bg-[#0B1120] border border-[#263244] rounded pl-9 pr-3 py-1.5 text-xs text-gray-100 placeholder-gray-500 focus:outline-none focus:border-blue-500 font-sans"
            />
          </div>

          {/* Status Filter */}
          <select
            value={selectedStatus}
            onChange={(e) => setSelectedStatus(e.target.value as any)}
            className="bg-[#0B1120] border border-[#263244] text-gray-200 text-xs rounded px-3 py-1.5 focus:outline-none"
          >
            <option value="all">All Investigation States</option>
            <option value="under_investigation">Under Investigation</option>
            <option value="open">Open / Triage</option>
            <option value="escalated">Escalated</option>
            <option value="mitigated">Mitigated</option>
          </select>

          {/* Priority Filter */}
          <select
            value={selectedPriority}
            onChange={(e) => setSelectedPriority(e.target.value as any)}
            className="bg-[#0B1120] border border-[#263244] text-gray-200 text-xs rounded px-3 py-1.5 focus:outline-none"
          >
            <option value="all">All Priorities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
          </select>

          {(searchTerm || selectedStatus !== 'all' || selectedPriority !== 'all') && (
            <button
              onClick={() => {
                setSearchTerm('');
                setSelectedStatus('all');
                setSelectedPriority('all');
              }}
              className="text-xs text-blue-400 hover:underline px-2 py-1"
            >
              Reset Filters
            </button>
          )}
        </div>
      </div>

      {/* Case Cards Grid */}
      {loading ? (
        <LoadingState message="Loading case repositories..." />
      ) : cases.length === 0 ? (
        <EmptyState
          icon={Briefcase}
          title="No Investigation Cases Found"
          description="Try modifying search criteria or create a new case."
          actionLabel="Create New Case"
          onAction={() => setIsCreateModalOpen(true)}
        />
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {cases.map((c) => (
            <div
              key={c.id}
              onClick={() => navigate(`/cases/${c.id}`)}
              className="p-5 rounded-lg bg-[#151E2E] border border-[#263244] hover:border-blue-500/50 hover:bg-[#182337] transition cursor-pointer flex flex-col justify-between space-y-4 group"
            >
              {/* Card Header */}
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-blue-400 font-mono">{c.id}</span>
                  <div className="flex items-center gap-2">
                    <SeverityBadge severity={c.priority} size="sm" />
                    <StatusBadge status={c.status} />
                  </div>
                </div>

                <h3 className="text-sm font-bold text-gray-100 font-sans group-hover:text-blue-300 transition">
                  {c.title}
                </h3>
                <p className="text-xs text-gray-400 font-sans line-clamp-2 leading-relaxed">
                  {c.description}
                </p>
              </div>

              {/* IoC Metrics Pill Array */}
              <div className="grid grid-cols-4 gap-2 pt-2 border-t border-[#1E293B] text-center font-mono">
                <div className="p-1.5 rounded bg-[#0B1120] border border-[#263244]">
                  <span className="text-[10px] text-gray-400 block uppercase">Emails</span>
                  <span className="text-xs font-bold text-gray-200">{c.counts.emails}</span>
                </div>
                <div className="p-1.5 rounded bg-[#0B1120] border border-[#263244]">
                  <span className="text-[10px] text-gray-400 block uppercase">Domains</span>
                  <span className="text-xs font-bold text-amber-400">{c.counts.domains}</span>
                </div>
                <div className="p-1.5 rounded bg-[#0B1120] border border-[#263244]">
                  <span className="text-[10px] text-gray-400 block uppercase">IP Nodes</span>
                  <span className="text-xs font-bold text-red-400">{c.counts.ips}</span>
                </div>
                <div className="p-1.5 rounded bg-[#0B1120] border border-[#263244]">
                  <span className="text-[10px] text-gray-400 block uppercase">Evidence</span>
                  <span className="text-xs font-bold text-emerald-400">{c.counts.evidence}</span>
                </div>
              </div>

              {/* Card Footer: Analyst and Update Date */}
              <div className="pt-2 border-t border-[#1E293B] flex items-center justify-between text-2xs text-gray-400 font-mono">
                <div className="flex items-center gap-1.5">
                  <div className="w-5 h-5 rounded bg-blue-900/60 border border-blue-500/40 text-blue-300 flex items-center justify-center font-bold text-[10px]">
                    {c.assignedAnalyst.avatarInitials}
                  </div>
                  <span className="text-gray-300">{c.assignedAnalyst.name}</span>
                </div>
                <span className="flex items-center gap-1 text-blue-400 group-hover:underline">
                  <span>Open Workspace</span>
                  <ArrowRight className="w-3 h-3" />
                </span>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Modal */}
      <CreateCaseModal
        isOpen={isCreateModalOpen}
        onClose={() => setIsCreateModalOpen(false)}
        onCreate={handleCreateCase}
      />
    </div>
  );
};
