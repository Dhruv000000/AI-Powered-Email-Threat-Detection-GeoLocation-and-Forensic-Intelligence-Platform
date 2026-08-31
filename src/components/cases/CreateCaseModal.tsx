import React, { useState } from 'react';
import { X, Briefcase, Plus } from 'lucide-react';
import { CasePriority } from '../../types/case';

interface CreateCaseModalProps {
  isOpen: boolean;
  onClose: () => void;
  onCreate: (data: { title: string; description: string; priority: CasePriority }) => void;
}

export const CreateCaseModal: React.FC<CreateCaseModalProps> = ({
  isOpen,
  onClose,
  onCreate,
}) => {
  const [title, setTitle] = useState('');
  const [description, setDescription] = useState('');
  const [priority, setPriority] = useState<CasePriority>('high');

  if (!isOpen) return null;

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!title.trim()) return;
    onCreate({ title: title.trim(), description: description.trim(), priority });
    setTitle('');
    setDescription('');
    onClose();
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-in fade-in">
      <div className="w-full max-w-lg bg-[#151E2E] border border-[#263244] rounded-xl shadow-2xl overflow-hidden flex flex-col font-mono">
        <div className="flex items-center justify-between px-6 py-4 bg-[#111827] border-b border-[#263244]">
          <div className="flex items-center gap-2">
            <Briefcase className="w-4 h-4 text-blue-400" />
            <h3 className="text-sm font-bold text-gray-100">Initiate Investigation Case</h3>
          </div>
          <button onClick={onClose} className="text-gray-400 hover:text-gray-200">
            <X className="w-4 h-4" />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="p-6 space-y-4 text-xs">
          <div>
            <label className="block text-2xs uppercase text-gray-400 font-semibold mb-1">
              Case Title / Operation Name
            </label>
            <input
              type="text"
              required
              placeholder="e.g., Executive BEC Wire Fraud Campaign"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              className="w-full bg-[#0B1120] border border-[#263244] rounded p-2.5 text-gray-100 placeholder-gray-500 focus:outline-none focus:border-blue-500 font-sans text-xs"
            />
          </div>

          <div>
            <label className="block text-2xs uppercase text-gray-400 font-semibold mb-1">
              Initial Priority Level
            </label>
            <select
              value={priority}
              onChange={(e) => setPriority(e.target.value as CasePriority)}
              className="w-full bg-[#0B1120] border border-[#263244] rounded p-2.5 text-gray-100 focus:outline-none focus:border-blue-500 text-xs"
            >
              <option value="critical">Critical (Immediate Financial/Perimeter Risk)</option>
              <option value="high">High (Credential Theft / Malicious Script)</option>
              <option value="medium">Medium (Targeted Phishing Attempt)</option>
              <option value="low">Low (Routine Telemetry / Bulk Suspicious)</option>
            </select>
          </div>

          <div>
            <label className="block text-2xs uppercase text-gray-400 font-semibold mb-1">
              Investigation Scope & Background Notes
            </label>
            <textarea
              rows={3}
              placeholder="Enter initial investigation scope, affected departments, and primary suspected vectors..."
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              className="w-full bg-[#0B1120] border border-[#263244] rounded p-2.5 text-gray-100 placeholder-gray-500 focus:outline-none focus:border-blue-500 font-sans text-xs"
            />
          </div>

          <div className="pt-3 border-t border-[#263244] flex items-center justify-end gap-3">
            <button
              type="button"
              onClick={onClose}
              className="px-3 py-1.5 rounded bg-[#0B1120] text-gray-400 hover:text-gray-200 border border-[#263244] transition"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={!title.trim()}
              className="px-4 py-1.5 rounded bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white font-semibold transition flex items-center gap-1.5"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>Create Case</span>
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
