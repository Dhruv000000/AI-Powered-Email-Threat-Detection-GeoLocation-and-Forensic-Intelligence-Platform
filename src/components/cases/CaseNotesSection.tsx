import React, { useState } from 'react';
import { CaseNote } from '../../types/case';
import { MessageSquare, Plus, Pin, Send, User } from 'lucide-react';

interface CaseNotesSectionProps {
  notes: CaseNote[];
  onAddNote: (content: string) => void;
}

export const CaseNotesSection: React.FC<CaseNotesSectionProps> = ({ notes, onAddNote }) => {
  const [newNoteText, setNewNoteText] = useState('');

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newNoteText.trim()) return;
    onAddNote(newNoteText.trim());
    setNewNoteText('');
  };

  return (
    <div className="space-y-6">
      {/* Add Note Form */}
      <form onSubmit={handleSubmit} className="p-4 rounded-lg bg-[#111827] border border-[#263244] space-y-3">
        <div className="flex items-center justify-between">
          <h4 className="text-xs font-bold uppercase tracking-wider text-gray-300 font-mono flex items-center gap-2">
            <MessageSquare className="w-4 h-4 text-blue-400" />
            Add Investigation Field Note
          </h4>
          <span className="text-2xs text-gray-400 font-mono">Logged with analyst timestamp</span>
        </div>

        <textarea
          rows={3}
          placeholder="Record investigative observations, law enforcement coordination details, or triage notes..."
          value={newNoteText}
          onChange={(e) => setNewNoteText(e.target.value)}
          className="w-full bg-[#0B1120] border border-[#263244] rounded p-3 text-xs text-gray-200 placeholder-gray-500 focus:outline-none focus:border-blue-500 font-sans"
        />

        <div className="flex justify-end">
          <button
            type="submit"
            disabled={!newNoteText.trim()}
            className="flex items-center gap-1.5 px-4 py-1.5 bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white rounded text-xs font-mono font-semibold transition shadow"
          >
            <Send className="w-3.5 h-3.5" />
            <span>Post Note</span>
          </button>
        </div>
      </form>

      {/* Notes List */}
      <div className="space-y-3">
        <h4 className="text-xs font-bold uppercase tracking-wider text-gray-400 font-mono">
          Analyst Discussion & Field Logs ({notes.length})
        </h4>

        {notes.length === 0 ? (
          <div className="p-6 text-center bg-[#111827] rounded-lg border border-[#263244] text-xs text-gray-400 font-mono">
            No investigation notes added yet.
          </div>
        ) : (
          notes.map((note) => (
            <div
              key={note.id}
              className={`p-4 rounded-lg border bg-[#151E2E] space-y-2 transition ${
                note.isPinned ? 'border-amber-500/40 bg-amber-950/10' : 'border-[#263244]'
              }`}
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <div className="w-6 h-6 rounded bg-blue-900/60 border border-blue-500/40 text-blue-300 flex items-center justify-center font-bold text-2xs font-mono">
                    {note.author.split(' ').map((n) => n[0]).join('')}
                  </div>
                  <div>
                    <span className="text-xs font-bold text-gray-200 font-mono">{note.author}</span>
                    <span className="text-2xs text-gray-400 ml-2 font-mono">({note.authorRole})</span>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  {note.isPinned && (
                    <span className="px-1.5 py-0.2 rounded bg-amber-500/20 text-amber-400 border border-amber-500/30 text-[10px] font-mono font-bold flex items-center gap-1">
                      <Pin className="w-3 h-3" /> PINNED
                    </span>
                  )}
                  <span className="text-2xs text-gray-400 font-mono">{note.createdAt}</span>
                </div>
              </div>

              <p className="text-xs text-gray-200 leading-relaxed font-sans pl-8">{note.content}</p>
            </div>
          ))
        )}
      </div>
    </div>
  );
};
