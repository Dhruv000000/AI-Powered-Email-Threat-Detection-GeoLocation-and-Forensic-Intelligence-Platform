import React from 'react';
import { NavLink } from 'react-router-dom';
import {
  Shield,
  LayoutDashboard,
  SearchCode,
  ShieldAlert,
  MapPin,
  GitFork,
  Briefcase,
  FileText,
  Settings,
  LogOut,
} from 'lucide-react';
import { cn } from '../../lib/utils';

interface SidebarProps {
  threatsCount?: number;
  activeCasesCount?: number;
  onLogout?: () => void;
}

export const Sidebar: React.FC<SidebarProps> = ({
  threatsCount = 8,
  activeCasesCount = 4,
  onLogout,
}) => {
  const navItems = [
    {
      to: '/dashboard',
      label: 'Dashboard',
      icon: LayoutDashboard,
    },
    {
      to: '/analyze',
      label: 'Analyze Email',
      icon: SearchCode,
      highlight: true,
    },
    {
      to: '/threats',
      label: 'Threats',
      icon: ShieldAlert,
      badge: threatsCount,
      badgeColor: 'bg-red-500/20 text-red-400 border border-red-500/30',
    },
    {
      to: '/map',
      label: 'Threat Map',
      icon: MapPin,
    },
    {
      to: '/graph',
      label: 'Intelligence Graph',
      icon: GitFork,
    },
    {
      to: '/cases',
      label: 'Cases',
      icon: Briefcase,
      badge: activeCasesCount,
      badgeColor: 'bg-amber-500/20 text-amber-400 border border-amber-500/30',
    },
    {
      to: '/reports',
      label: 'Reports',
      icon: FileText,
    },
  ];

  return (
    <aside className="w-64 bg-[#111827] border-r border-[#263244] flex flex-col justify-between flex-shrink-0 select-none z-30 h-screen sticky top-0">
      {/* Brand Header */}
      <div>
        <div className="h-16 flex items-center px-4 border-b border-[#263244] gap-3">
          <div className="w-8 h-8 rounded bg-blue-600/20 border border-blue-500/40 flex items-center justify-center text-blue-400 flex-shrink-0 shadow-sm">
            <Shield className="w-4 h-4" />
          </div>
          <div className="flex flex-col overflow-hidden">
            <div className="flex items-center gap-1.5">
              <span className="font-bold text-sm tracking-wider text-gray-100 font-mono">AEGIS</span>
              <span className="px-1.5 py-0.2 text-[9px] font-bold bg-blue-600 text-white rounded font-mono">v2.4</span>
            </div>
            <span className="text-[11px] text-gray-400 truncate tracking-tight">Email Threat Intelligence</span>
          </div>
        </div>

        {/* Navigation Menu */}
        <div className="p-3 space-y-1">
          <div className="px-3 py-1.5 text-[10px] font-semibold tracking-wider text-gray-400 uppercase font-mono">
            Forensic Workstation
          </div>
          {navItems.map((item) => {
            const Icon = item.icon;
            return (
              <NavLink
                key={item.to}
                to={item.to}
                className={({ isActive }) =>
                  cn(
                    'flex items-center justify-between px-3 py-2 rounded text-xs font-medium transition-all group',
                    isActive
                      ? 'bg-blue-600/15 text-blue-400 border border-blue-500/30 font-semibold'
                      : 'text-gray-300 hover:text-gray-100 hover:bg-[#151E2E] border border-transparent',
                    item.highlight && !location.pathname.includes(item.to) && 'text-blue-300'
                  )
                }
              >
                <div className="flex items-center gap-2.5">
                  <Icon className="w-4 h-4 flex-shrink-0 transition-transform group-hover:scale-105" />
                  <span>{item.label}</span>
                </div>
                {item.badge !== undefined && item.badge > 0 && (
                  <span
                    className={cn(
                      'px-1.5 py-0.2 rounded text-[10px] font-mono font-bold leading-tight',
                      item.badgeColor || 'bg-[#1E293B] text-gray-300'
                    )}
                  >
                    {item.badge}
                  </span>
                )}
              </NavLink>
            );
          })}
        </div>
      </div>

      {/* Footer Navigation & User Profile */}
      <div className="p-3 border-t border-[#263244] space-y-2">
        <NavLink
          to="/settings"
          className={({ isActive }) =>
            cn(
              'flex items-center gap-2.5 px-3 py-2 rounded text-xs font-medium transition',
              isActive
                ? 'bg-blue-600/15 text-blue-400 border border-blue-500/30'
                : 'text-gray-400 hover:text-gray-200 hover:bg-[#151E2E]'
            )
          }
        >
          <Settings className="w-4 h-4" />
          <span>System Settings</span>
        </NavLink>

        <button
          onClick={onLogout}
          className="w-full flex items-center gap-2.5 px-3 py-2 rounded text-xs font-medium text-gray-400 hover:text-red-400 hover:bg-red-500/10 transition text-left"
        >
          <LogOut className="w-4 h-4" />
          <span>Sign Out</span>
        </button>

        {/* User Card */}
        <div className="mt-2 pt-2 border-t border-[#1E293B] flex items-center gap-2.5 px-2">
          <div className="w-7 h-7 rounded bg-blue-900/60 border border-blue-500/40 text-blue-300 flex items-center justify-center font-bold text-xs font-mono">
            DS
          </div>
          <div className="flex flex-col overflow-hidden text-left">
            <span className="text-xs font-medium text-gray-200 truncate">Dhruv Sharma</span>
            <span className="text-[10px] text-gray-400 truncate">Lead Forensics Analyst</span>
          </div>
        </div>
      </div>
    </aside>
  );
};
