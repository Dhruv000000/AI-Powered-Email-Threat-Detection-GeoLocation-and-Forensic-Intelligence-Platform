import React, { useState } from 'react';
import { Search, X, Globe, Link, Server, User, HardDrive, FileCode, ArrowRight } from 'lucide-react';
import { CytoscapeNode } from '../../types/investigation';

interface EntitySearchModalProps {
  nodes: CytoscapeNode[];
  isOpen: boolean;
  onClose: () => void;
  onSelectEntity: (node: CytoscapeNode['data']) => void;
}

export const EntitySearchModal: React.FC<EntitySearchModalProps> = ({
  nodes,
  isOpen,
  onClose,
  onSelectEntity,
}) => {
  const [query, setQuery] = useState('');

  if (!isOpen) return null;

  const filtered = nodes.filter((n) => {
    if (!query.trim()) return true;
    const q = query.toLowerCase();
    return (
      n.data.label.toLowerCase().includes(q) ||
      n.data.id.toLowerCase().includes(q) ||
      n.data.type.toLowerCase().includes(q)
    );
  });

  const getEntityIcon = (type: string) => {
    switch (type) {
      case 'Domain':
        return <Globe className="w-3.5 h-3.5 text-emerald-400" />;
      case 'URL':
        return <Link className="w-3.5 h-3.5 text-amber-400" />;
      case 'IP':
        return <Server className="w-3.5 h-3.5 text-rose-400" />;
      case 'EmailAddress':
      case 'Person':
        return <User className="w-3.5 h-3.5 text-blue-400" />;
      case 'Attachment':
      case 'FileHash':
        return <HardDrive className="w-3.5 h-3.5 text-pink-400" />;
      default:
        return <FileCode className="w-3.5 h-3.5 text-purple-400" />;
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-xs font-mono">
      <div className="bg-[#111827] border border-[#263244] rounded-xl w-full max-w-xl shadow-2xl overflow-hidden flex flex-col max-h-[80vh]">
        {/* Search Header */}
        <div className="p-3.5 border-b border-[#263244] flex items-center gap-3 bg-[#151E2E]">
          <Search className="w-4 h-4 text-purple-400 shrink-0" />
          <input
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search email, domain, URL, IP, hash, or attachment..."
            autoFocus
            className="flex-1 bg-transparent border-0 text-gray-100 text-xs focus:outline-none placeholder-gray-500"
          />
          {query && (
            <button onClick={() => setQuery('')} className="text-gray-400 hover:text-gray-200">
              <X className="w-3.5 h-3.5" />
            </button>
          )}
          <button onClick={onClose} className="text-gray-400 hover:text-gray-200 text-xs">
            Esc
          </button>
        </div>

        {/* Results List */}
        <div className="flex-1 overflow-y-auto p-2 space-y-1">
          {filtered.length === 0 ? (
            <div className="p-6 text-center text-xs text-gray-400">
              No matching entities found for &quot;{query}&quot;.
            </div>
          ) : (
            filtered.map((node) => (
              <button
                key={node.data.id}
                onClick={() => {
                  onSelectEntity(node.data);
                  onClose();
                }}
                className="w-full text-left p-2.5 rounded-lg hover:bg-[#1E293B] border border-transparent hover:border-[#263244] transition flex items-center justify-between gap-3 group"
              >
                <div className="flex items-center gap-2.5 overflow-hidden">
                  <div className="p-1.5 rounded bg-[#0D1117] border border-[#263244] shrink-0">
                    {getEntityIcon(node.data.type)}
                  </div>
                  <div className="overflow-hidden">
                    <div className="flex items-center gap-2">
                      <span className="text-3xs uppercase font-bold text-purple-400">
                        {node.data.type}
                      </span>
                      {node.data.is_suspicious && (
                        <span className="text-3xs text-rose-400 bg-rose-950/60 px-1 py-0.2 rounded border border-rose-800/40">
                          Suspicious
                        </span>
                      )}
                    </div>
                    <p className="text-xs text-gray-200 truncate font-mono mt-0.5">
                      {node.data.label}
                    </p>
                  </div>
                </div>

                <ArrowRight className="w-3.5 h-3.5 text-gray-500 group-hover:text-purple-400 transition shrink-0" />
              </button>
            ))
          )}
        </div>

        {/* Footer info */}
        <div className="p-2.5 bg-[#0D1117] border-t border-[#263244] text-3xs text-gray-400 flex items-center justify-between">
          <span>{filtered.length} entities in investigation</span>
          <span>Click to center & inspect in graph</span>
        </div>
      </div>
    </div>
  );
};
