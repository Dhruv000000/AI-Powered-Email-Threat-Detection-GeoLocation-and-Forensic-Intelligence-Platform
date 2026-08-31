import React, { useState, useEffect, useRef } from 'react';
import { Search, X, Mail, Briefcase, Globe, Server, Link, FileCheck, ArrowRight } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { SearchResultItem } from '../../types/user';
import { SeverityBadge } from '../common/SeverityBadge';

interface GlobalSearchModalProps {
  isOpen: boolean;
  onClose: () => void;
}

const mockSearchIndex: SearchResultItem[] = [
  // Cases
  {
    id: 'CASE-001245',
    title: 'CASE-001245: Wire Fraud & Banking Credential Campaign',
    subtitle: 'High-profile BEC investigation | 4 emails, 3 domains, 3 IPs',
    category: 'Case',
    severity: 'critical',
    linkTo: '/cases/CASE-001245',
  },
  {
    id: 'CASE-001246',
    title: 'CASE-001246: Executive HR Payroll Diversion Cluster',
    subtitle: 'VP HR payroll redirection attempt | 2 emails',
    category: 'Case',
    severity: 'critical',
    linkTo: '/cases/CASE-001246',
  },
  {
    id: 'CASE-001247',
    title: 'CASE-001247: Enterprise Credential Harvesting Wave',
    subtitle: 'DocuSign & IRS SSO phishing attacks',
    category: 'Case',
    severity: 'high',
    linkTo: '/cases/CASE-001247',
  },
  // Emails
  {
    id: 'EML-2026-001',
    title: 'URGENT: Confidential Acquisition Escrow Wire Transfer (#ACQ-9921)',
    subtitle: 'From: ceo@corp-bankofamerica.xyz (Risk: 96/100)',
    category: 'Email',
    severity: 'critical',
    linkTo: '/analyze/EML-2026-001',
  },
  {
    id: 'EML-2026-002',
    title: 'ACTION REQUIRED: Multifactor Authentication (MFA) Session Expiring',
    subtitle: 'From: security-alerts@micros0ft-security-verify.com (Risk: 92/100)',
    category: 'Email',
    severity: 'critical',
    linkTo: '/analyze/EML-2026-002',
  },
  {
    id: 'EML-2026-003',
    title: 'OVERDUE INVOICE NOTICE: #INV-2026-8819 Final Settlement',
    subtitle: 'From: billing@supplier-invoices-pay.net (Risk: 88/100)',
    category: 'Email',
    severity: 'high',
    linkTo: '/analyze/EML-2026-003',
  },
  // IPs
  {
    id: '185.220.101.54',
    title: '185.220.101.54 — FlokiNET Tor Exit Relay',
    subtitle: 'Frankfurt, Germany | AS200651 | Probable Infrastructure Origin',
    category: 'IP',
    severity: 'critical',
    linkTo: '/map',
  },
  {
    id: '91.240.118.172',
    title: '91.240.118.172 — Serverius Hosting Proxy',
    subtitle: 'Amsterdam, Netherlands | AS49453 | 4 related threats',
    category: 'IP',
    severity: 'high',
    linkTo: '/map',
  },
  {
    id: '194.165.16.89',
    title: '194.165.16.89 — PIN SPB Datacenter',
    subtitle: 'Saint Petersburg, Russia | AS44050 | 8 related threats',
    category: 'IP',
    severity: 'critical',
    linkTo: '/map',
  },
  // Domains
  {
    id: 'corp-bankofamerica.xyz',
    title: 'corp-bankofamerica.xyz',
    subtitle: 'Lookalike domain registered 9 days ago (NameCheap)',
    category: 'Domain',
    severity: 'critical',
    linkTo: '/graph',
  },
  {
    id: 'micros0ft-security-verify.com',
    title: 'micros0ft-security-verify.com',
    subtitle: 'Typosquatted domain mimicking Microsoft 365',
    category: 'Domain',
    severity: 'critical',
    linkTo: '/graph',
  },
  // Evidence
  {
    id: 'EVD-2026-00045',
    title: 'Evidence EVD-2026-00045: urgent-escrow-wire-transfer.eml',
    subtitle: 'SHA-256: a8f92c0e891b7d559e13b8602b9e283cf2093481239840293847291823901a88',
    category: 'Evidence',
    severity: 'critical',
    linkTo: '/analyze/EML-2026-001',
  },
];

export const GlobalSearchModal: React.FC<GlobalSearchModalProps> = ({ isOpen, onClose }) => {
  const navigate = useNavigate();
  const [query, setQuery] = useState('');
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (isOpen) {
      setTimeout(() => inputRef.current?.focus(), 50);
    } else {
      setQuery('');
    }
  }, [isOpen]);

  // Global shortcut Ctrl+K listener
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
        e.preventDefault();
        if (isOpen) onClose();
        else onClose(); // parent handles toggle
      }
      if (e.key === 'Escape' && isOpen) {
        onClose();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  const filtered = query.trim()
    ? mockSearchIndex.filter(
        (item) =>
          item.title.toLowerCase().includes(query.toLowerCase()) ||
          item.subtitle.toLowerCase().includes(query.toLowerCase()) ||
          item.id.toLowerCase().includes(query.toLowerCase()) ||
          item.category.toLowerCase().includes(query.toLowerCase())
      )
    : mockSearchIndex.slice(0, 6);

  const getCategoryIcon = (cat: string) => {
    switch (cat) {
      case 'Case':
        return Briefcase;
      case 'Email':
        return Mail;
      case 'IP':
        return Server;
      case 'Domain':
        return Globe;
      case 'URL':
        return Link;
      case 'Evidence':
        return FileCheck;
      default:
        return Search;
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center pt-20 px-4 bg-black/70 backdrop-blur-sm animate-in fade-in-50">
      <div
        className="w-full max-w-2xl bg-[#151E2E] border border-[#263244] rounded-xl shadow-2xl overflow-hidden flex flex-col"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Search Header Bar */}
        <div className="flex items-center px-4 py-3 border-b border-[#263244] gap-3">
          <Search className="w-4 h-4 text-blue-400 flex-shrink-0" />
          <input
            ref={inputRef}
            type="text"
            placeholder="Search by Case ID, IP, Domain, Email subject, Evidence SHA-256..."
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            className="flex-1 bg-transparent text-sm text-gray-100 placeholder-gray-400 focus:outline-none font-mono"
          />
          {query && (
            <button
              onClick={() => setQuery('')}
              className="text-gray-400 hover:text-gray-200 p-1"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          )}
          <button
            onClick={onClose}
            className="px-1.5 py-0.5 rounded text-[10px] font-mono text-gray-400 bg-[#0B1120] border border-[#263244]"
          >
            ESC
          </button>
        </div>

        {/* Search Results List */}
        <div className="max-h-96 overflow-y-auto p-2 space-y-1 divide-y divide-[#1E293B]">
          {filtered.length === 0 ? (
            <div className="py-8 text-center text-xs text-gray-400">
              No matching intelligence entities found for "{query}"
            </div>
          ) : (
            filtered.map((item) => {
              const Icon = getCategoryIcon(item.category);
              return (
                <div
                  key={item.id}
                  onClick={() => {
                    navigate(item.linkTo);
                    onClose();
                  }}
                  className="flex items-center justify-between p-2.5 rounded-lg hover:bg-[#1B263B] transition cursor-pointer group"
                >
                  <div className="flex items-start gap-3 overflow-hidden">
                    <div className="p-2 rounded bg-[#0B1120] border border-[#263244] text-gray-400 group-hover:text-blue-400 flex-shrink-0">
                      <Icon className="w-4 h-4" />
                    </div>
                    <div className="flex flex-col overflow-hidden text-left">
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-semibold text-gray-200 truncate group-hover:text-blue-300">
                          {item.title}
                        </span>
                        <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-[#1E293B] text-gray-400">
                          {item.category}
                        </span>
                      </div>
                      <span className="text-2xs text-gray-400 truncate mt-0.5 font-mono">
                        {item.subtitle}
                      </span>
                    </div>
                  </div>

                  <div className="flex items-center gap-2 pl-3 flex-shrink-0">
                    {item.severity && <SeverityBadge severity={item.severity} size="sm" />}
                    <ArrowRight className="w-3.5 h-3.5 text-gray-400 group-hover:text-gray-200 transition-transform group-hover:translate-x-0.5" />
                  </div>
                </div>
              );
            })
          )}
        </div>

        {/* Footer shortcuts */}
        <div className="px-4 py-2 bg-[#0B1120] border-t border-[#263244] flex items-center justify-between text-[11px] text-gray-400 font-mono">
          <div className="flex items-center gap-3">
            <span>
              <kbd className="px-1 py-0.2 bg-[#151E2E] border border-[#263244] rounded text-[10px]">↑</kbd>{' '}
              <kbd className="px-1 py-0.2 bg-[#151E2E] border border-[#263244] rounded text-[10px]">↓</kbd> Navigate
            </span>
            <span>
              <kbd className="px-1 py-0.2 bg-[#151E2E] border border-[#263244] rounded text-[10px]">↵</kbd> Select
            </span>
          </div>
          <span>AEGIS Intelligence Index</span>
        </div>
      </div>
    </div>
  );
};
