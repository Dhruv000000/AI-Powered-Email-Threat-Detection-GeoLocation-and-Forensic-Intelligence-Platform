import React, { useEffect, useState } from 'react';
import {
  X,
  Shield,
  Lock,
  Network,
  Share2,
  ExternalLink,
  CheckCircle2,
  AlertTriangle,
  ArrowRight,
  Info,
} from 'lucide-react';
import { EntityDetail, CytoscapeNode } from '../../types/investigation';
import { investigationService } from '../../services/investigationService';
import { SeverityBadge } from '../common/SeverityBadge';

interface EntityDetailsDrawerProps {
  investigationId: string;
  selectedNode: CytoscapeNode['data'] | null;
  onClose: () => void;
  onSelectEntityId: (entityId: string) => void;
}

export const EntityDetailsDrawer: React.FC<EntityDetailsDrawerProps> = ({
  investigationId,
  selectedNode,
  onClose,
  onSelectEntityId,
}) => {
  const [detail, setDetail] = useState<EntityDetail | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!selectedNode) {
      setDetail(null);
      return;
    }

    async function loadEntity() {
      if (!selectedNode) return;
      setLoading(true);
      const data = await investigationService.getEntityDetail(
        investigationId,
        selectedNode.id
      );
      setDetail(data);
      setLoading(false);
    }

    loadEntity();
  }, [investigationId, selectedNode]);

  if (!selectedNode) return null;

  return (
    <div className="fixed inset-y-0 right-0 z-50 w-full sm:w-96 bg-[#111827] border-l border-[#263244] shadow-2xl flex flex-col transition-transform duration-300 ease-in-out">
      {/* Header */}
      <div className="bg-[#151E2E] border-b border-[#263244] p-4 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <span className="w-2.5 h-2.5 rounded-full bg-purple-400" />
          <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-gray-100">
            Entity Intelligence Profile
          </h3>
        </div>
        <button
          onClick={onClose}
          className="p-1 rounded text-gray-400 hover:text-gray-200 hover:bg-[#1E293B] transition"
        >
          <X className="w-4 h-4" />
        </button>
      </div>

      {/* Content Body */}
      <div className="flex-1 overflow-y-auto p-4 space-y-4 font-mono text-xs">
        {/* Entity Primary Card */}
        <div className="bg-[#0D1117] border border-[#263244] rounded-lg p-3 space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-2xs uppercase px-2 py-0.5 rounded bg-[#151E2E] text-purple-300 font-bold border border-purple-900/50">
              {selectedNode.type}
            </span>
            {selectedNode.severity && <SeverityBadge severity={selectedNode.severity} className="text-3xs" />}
          </div>

          <div>
            <span className="block text-3xs text-gray-400 uppercase">Normalized Identifier</span>
            <p className="text-xs font-bold text-gray-100 break-all select-all font-mono mt-0.5">
              {selectedNode.id}
            </p>
          </div>

          <div>
            <span className="block text-3xs text-gray-400 uppercase">Display Value</span>
            <p className="text-xs text-gray-200 break-all font-mono mt-0.5">
              {selectedNode.label}
            </p>
          </div>
        </div>

        {/* Risk Assessment */}
        {selectedNode.risk_score !== undefined && (
          <div className="bg-[#151E2E] border border-[#263244] rounded-lg p-3 flex items-center justify-between">
            <span className="text-2xs text-gray-400 uppercase">Threat Risk Score</span>
            <span className="text-sm font-bold text-gray-100">
              {selectedNode.risk_score}
              <span className="text-2xs text-gray-400">/100</span>
            </span>
          </div>
        )}

        {/* Evidence Traceability */}
        <div className="bg-[#0D1117] border border-[#263244] rounded-lg p-3 space-y-2">
          <div className="flex items-center gap-1.5 text-2xs uppercase font-bold text-gray-300">
            <Lock className="w-3 h-3 text-emerald-400" />
            <span>Task 01 Evidence Source</span>
          </div>
          <p className="text-2xs text-gray-300 font-mono break-all">
            {selectedNode.evidence_reference || detail?.evidence_reference || 'email_analyses:structured_record'}
          </p>
        </div>

        {/* Properties Key-Value */}
        {selectedNode.properties && Object.keys(selectedNode.properties).length > 0 && (
          <div className="space-y-1.5">
            <span className="text-3xs uppercase tracking-wider text-gray-400 font-bold">
              Entity Properties
            </span>
            <div className="bg-[#0D1117] border border-[#263244] rounded-lg p-2.5 space-y-1.5 text-2xs">
              {Object.entries(selectedNode.properties).map(([k, v]) => {
                if (v === null || v === undefined || v === '') return null;
                return (
                  <div key={k} className="flex items-start justify-between gap-2 border-b border-[#1E293B] pb-1 last:border-0 last:pb-0">
                    <span className="text-gray-400 text-3xs">{k}:</span>
                    <span className="text-gray-200 text-right break-all max-w-[180px]">
                      {typeof v === 'boolean' ? (v ? 'true' : 'false') : String(v)}
                    </span>
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {/* Connected Relationships */}
        {detail && detail.related_entities && detail.related_entities.length > 0 && (
          <div className="space-y-1.5">
            <span className="text-3xs uppercase tracking-wider text-gray-400 font-bold">
              Connected Graph Nodes ({detail.related_entities.length})
            </span>
            <div className="space-y-1.5">
              {detail.related_entities.map((rel, idx) => (
                <button
                  key={idx}
                  onClick={() => onSelectEntityId(rel.entity_id)}
                  className="w-full text-left p-2 rounded bg-[#151E2E] hover:bg-[#1E293B] border border-[#263244] transition flex items-center justify-between gap-2"
                >
                  <div className="overflow-hidden">
                    <span className="text-3xs text-purple-400 uppercase font-semibold">
                      {rel.relationship_type}
                    </span>
                    <p className="text-2xs text-gray-200 truncate font-mono mt-0.5">
                      {rel.display_label}
                    </p>
                  </div>
                  <ArrowRight className="w-3 h-3 text-gray-400 shrink-0" />
                </button>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
