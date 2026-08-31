import React, { useState } from 'react';
import { Search, Bell, Shield, ShieldAlert, CheckCircle2, ChevronRight } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { SystemNotification } from '../../types/user';

interface TopHeaderProps {
  title?: string;
  breadcrumbs?: { label: string; href?: string }[];
  onOpenSearch: () => void;
}

export const TopHeader: React.FC<TopHeaderProps> = ({
  title = 'Dashboard',
  breadcrumbs,
  onOpenSearch,
}) => {
  const navigate = useNavigate();
  const [notificationsOpen, setNotificationsOpen] = useState(false);
  const [notifications, setNotifications] = useState<SystemNotification[]>([
    {
      id: 'n-1',
      title: 'Critical Phishing Threat Intercepted',
      description: 'Executive wire fraud attempt detected on corp-bankofamerica.xyz',
      timeAgo: '5 min ago',
      timestamp: '2026-08-29 18:20:14',
      type: 'critical_threat',
      read: false,
      linkTo: '/analyze/EML-2026-001',
    },
    {
      id: 'n-2',
      title: 'Investigation Case Assigned',
      description: 'You have been assigned to lead CASE-001245',
      timeAgo: '22 min ago',
      timestamp: '2026-08-29 18:00:00',
      type: 'case_assigned',
      read: false,
      linkTo: '/cases/CASE-001245',
    },
    {
      id: 'n-3',
      title: 'AI Correlation Pipeline Finished',
      description: 'Discovered 3 new connected infrastructure nodes in Frankfurt cluster',
      timeAgo: '1 hour ago',
      timestamp: '2026-08-29 17:15:00',
      type: 'analysis_complete',
      read: true,
      linkTo: '/graph',
    },
  ]);

  const unreadCount = notifications.filter((n) => !n.read).length;

  const markAllRead = () => {
    setNotifications((prev) => prev.map((n) => ({ ...n, read: true })));
  };

  return (
    <header className="h-14 bg-[#111827]/80 backdrop-blur border-b border-[#263244] px-6 flex items-center justify-between sticky top-0 z-20">
      {/* Left: Breadcrumbs / Title */}
      <div className="flex items-center gap-2 text-xs">
        <span className="text-gray-400 font-medium">AEGIS</span>
        <ChevronRight className="w-3.5 h-3.5 text-gray-400" />
        {breadcrumbs ? (
          breadcrumbs.map((bc, idx) => (
            <React.Fragment key={idx}>
              {idx > 0 && <ChevronRight className="w-3.5 h-3.5 text-gray-400" />}
              {bc.href ? (
                <button
                  onClick={() => navigate(bc.href!)}
                  className="text-gray-400 hover:text-gray-200 transition font-medium"
                >
                  {bc.label}
                </button>
              ) : (
                <span className="text-gray-100 font-semibold">{bc.label}</span>
              )}
            </React.Fragment>
          ))
        ) : (
          <span className="text-gray-100 font-semibold">{title}</span>
        )}
      </div>

      {/* Right Controls: Global Search Trigger, Notifications, User */}
      <div className="flex items-center gap-3">
        {/* Global Search Button */}
        <button
          onClick={onOpenSearch}
          className="flex items-center gap-3 px-3 py-1.5 rounded-md bg-[#151E2E] hover:bg-[#1B263B] border border-[#263244] text-gray-400 hover:text-gray-200 transition text-xs group"
          title="Search anything across emails, cases, IPs, domains (Ctrl+K)"
        >
          <Search className="w-3.5 h-3.5 text-gray-400 group-hover:text-blue-400" />
          <span className="hidden sm:inline text-gray-400 text-xs">Search IoCs, Cases, IPs...</span>
          <kbd className="hidden sm:inline-flex items-center px-1.5 py-0.2 bg-[#0B1120] border border-[#263244] rounded text-[10px] font-mono text-gray-400">
            Ctrl+K
          </kbd>
        </button>

        {/* Notifications Popover */}
        <div className="relative">
          <button
            onClick={() => setNotificationsOpen(!notificationsOpen)}
            className="p-2 rounded-md bg-[#151E2E] hover:bg-[#1B263B] border border-[#263244] text-gray-300 hover:text-gray-100 transition relative"
            aria-label="Notifications"
          >
            <Bell className="w-4 h-4" />
            {unreadCount > 0 && (
              <span className="absolute -top-1 -right-1 w-4 h-4 rounded-full bg-red-500 text-white font-mono text-[9px] font-bold flex items-center justify-center border border-[#111827]">
                {unreadCount}
              </span>
            )}
          </button>

          {notificationsOpen && (
            <div className="absolute right-0 mt-2 w-80 bg-[#151E2E] border border-[#263244] rounded-lg shadow-xl py-2 z-50 animate-in fade-in-50">
              <div className="flex items-center justify-between px-4 py-2 border-b border-[#263244]">
                <div className="flex items-center gap-1.5">
                  <span className="text-xs font-bold text-gray-200">Alerts & Notifications</span>
                  {unreadCount > 0 && (
                    <span className="px-1.5 py-0.2 bg-red-500/20 text-red-400 text-[10px] font-mono rounded font-bold">
                      {unreadCount} new
                    </span>
                  )}
                </div>
                {unreadCount > 0 && (
                  <button
                    onClick={markAllRead}
                    className="text-[11px] text-blue-400 hover:underline"
                  >
                    Mark read
                  </button>
                )}
              </div>

              <div className="max-h-72 overflow-y-auto divide-y divide-[#1E293B]">
                {notifications.map((item) => (
                  <div
                    key={item.id}
                    onClick={() => {
                      if (item.linkTo) {
                        navigate(item.linkTo);
                        setNotificationsOpen(false);
                      }
                    }}
                    className={`p-3 text-left transition cursor-pointer hover:bg-[#1B263B] ${
                      !item.read ? 'bg-blue-950/20' : ''
                    }`}
                  >
                    <div className="flex items-start gap-2.5">
                      {item.type === 'critical_threat' ? (
                        <ShieldAlert className="w-4 h-4 text-red-400 flex-shrink-0 mt-0.5" />
                      ) : item.type === 'case_assigned' ? (
                        <Shield className="w-4 h-4 text-amber-400 flex-shrink-0 mt-0.5" />
                      ) : (
                        <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0 mt-0.5" />
                      )}
                      <div className="flex-1 overflow-hidden">
                        <p className="text-xs font-semibold text-gray-200">{item.title}</p>
                        <p className="text-2xs text-gray-400 mt-0.5 leading-relaxed">{item.description}</p>
                        <span className="text-[10px] text-gray-400 font-mono mt-1 inline-block">
                          {item.timeAgo}
                        </span>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* User Pill */}
        <div className="hidden md:flex items-center gap-2 pl-2 border-l border-[#263244]">
          <div className="w-7 h-7 rounded bg-blue-900/50 border border-blue-500/40 text-blue-300 flex items-center justify-center font-mono font-bold text-xs">
            DS
          </div>
          <div className="flex flex-col text-left">
            <span className="text-xs font-semibold text-gray-200 leading-tight">Dhruv Sharma</span>
            <span className="text-[10px] text-gray-400 leading-tight">Senior Forensics Lead</span>
          </div>
        </div>
      </div>
    </header>
  );
};
