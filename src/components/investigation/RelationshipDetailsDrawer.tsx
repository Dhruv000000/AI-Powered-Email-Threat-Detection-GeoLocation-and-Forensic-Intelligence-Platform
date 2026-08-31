import React from 'react';
import {
  X,
  Share2,
  Lock,
  ArrowRight,
  ShieldCheck,
  CheckCircle2,
} from 'lucide-react';
import { CytoscapeEdge } from '../../types/investigation';

interface RelationshipDetailsDrawerProps {
  selectedEdge: CytoscapeEdge['data'] | null;
  onClose: () => void;
  onSelectEntityId: (entityId: string) => void;
}

export const RelationshipDetailsDrawer: React.FC<RelationshipDetailsDrawerProps> = ({
  selectedEdge,
  onClose,
  onSelectEntityId,
}) => {
  if (!selectedEdge) return null;

  return (
    <div className="fixed inset-y-0 right-0 z-50 w-full sm:w-96 bg-[#111827] border-l border-[#263244] shadow-2xl flex flex-col transition-transform duration-300 ease-in-out font-mono">
      {/* Header */}
      <div className="bg-[#151E2E] border-b border-[#263244] p-4 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Share2 className="w-4 h-4 text-purple-400" />
          <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-gray-100">
            Relationship Provenance
          </h3>
        </div>
        <button
          onClick={onClose}
          className="p-1 rounded text-gray-400 hover:text-gray-200 hover:bg-[#1E293B] transition"
        >
          <X className="w-4 h-4" />
        </button>
      </div>

      {/* Content */}
      <div className="flex-1 overflow-y-auto p-4 space-y-4 text-xs">
        {/* Relationship Type Badge */}
        <div className="bg-[#0D1117] border border-[#263244] rounded-lg p-3 space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold uppercase px-2 py-0.5 rounded bg-purple-950/80 text-purple-300 border border-purple-800/60">
              {selectedEdge.label}
            </span>
            <span className="text-2xs text-gray-400">
              Confidence:{' '}
              <strong className="text-emerald-400">
                {Math.round((selectedEdge.confidence || 1.0) * 100)}%
              </strong>
            </span>
          </div>

          <div className="pt-2 border-t border-[#1E293B]">
            <span className="block text-3xs text-gray-400 uppercase">Edge Identifier</span>
            <p className="text-2xs text-gray-200 break-all select-all font-mono mt-0.5">
              {selectedEdge.id}
            </p>
          </div>
        </div>

        {/* Source & Target Nodes */}
        <div className="space-y-2">
          <span className="text-3xs uppercase tracking-wider text-gray-400 font-bold">
            Connected Graph Nodes
          </span>

          <div className="bg-[#151E2E] border border-[#263244] rounded-lg p-3 space-y-2.5">
            <div>
              <span className="block text-3xs text-gray-400 uppercase">Source Entity</span>
              <button
                onClick={() => onSelectEntityId(selectedEdge.source)}
                className="text-2xs font-bold text-blue-400 hover:underline break-all text-left block mt-0.5"
              >
                {selectedEdge.source}
              </button>
            </div>

            <div className="flex justify-center text-purple-400">
              <ArrowRight className="w-4 h-4" />
            </div>

            <div>
              <span className="block text-3xs text-gray-400 uppercase">Target Entity</span>
              <button
                onClick={() => onSelectEntityId(selectedEdge.target)}
                className="text-2xs font-bold text-emerald-400 hover:underline break-all text-left block mt-0.5"
              >
                {selectedEdge.target}
              </button>
            </div>
          </div>
        </div>

        {/* Provenance Details */}
        <div className="bg-[#0D1117] border border-[#263244] rounded-lg p-3 space-y-2">
          <div className="flex items-center gap-1.5 text-2xs uppercase font-bold text-gray-300">
            <Lock className="w-3 h-3 text-emerald-400" />
            <span>Evidentiary Provenance</span>
          </div>

          <div className="space-y-1.5 text-2xs">
            <div className="flex items-center justify-between border-b border-[#1E293B] pb-1">
              <span className="text-gray-400 text-3xs">Extraction Layer:</span>
              <span className="text-gray-200 font-semibold">{selectedEdge.provenance || 'forensic_rule'}</span>
            </div>
            <div className="flex items-start justify-between gap-2 border-b border-[#1E293B] pb-1">
              <span className="text-gray-400 text-3xs">Evidence Reference:</span>
              <span className="text-gray-200 text-right break-all max-w-[180px]">
                {selectedEdge.source_reference || 'Task 01 forensic structure'}
              </span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
