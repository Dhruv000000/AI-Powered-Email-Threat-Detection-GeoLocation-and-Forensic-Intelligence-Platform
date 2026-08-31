import React, { useState } from 'react';
import { Outlet, useLocation, useNavigate } from 'react-router-dom';
import { Sidebar } from './Sidebar';
import { TopHeader } from './TopHeader';
import { GlobalSearchModal } from './GlobalSearchModal';

interface AppShellProps {
  onLogout?: () => void;
}

export const AppShell: React.FC<AppShellProps> = ({ onLogout }) => {
  const [searchOpen, setSearchOpen] = useState(false);
  const location = useLocation();
  const navigate = useNavigate();

  // Helper to determine title/breadcrumb from location
  const getPageContext = () => {
    const path = location.pathname;
    if (path.startsWith('/dashboard')) return { title: 'Dashboard', breadcrumbs: [{ label: 'Dashboard' }] };
    if (path.startsWith('/analyze/')) {
      const emailId = path.split('/')[2];
      return {
        title: 'Forensic Email Investigation',
        breadcrumbs: [{ label: 'Analyze', href: '/analyze' }, { label: emailId || 'Investigation' }],
      };
    }
    if (path.startsWith('/analyze')) return { title: 'Analyze Suspicious Email', breadcrumbs: [{ label: 'Analyze Email' }] };
    if (path.startsWith('/threats')) return { title: 'Threat Intelligence Feed', breadcrumbs: [{ label: 'Threats' }] };
    if (path.startsWith('/map')) return { title: 'Geographic Infrastructure Map', breadcrumbs: [{ label: 'Threat Map' }] };
    if (path.startsWith('/graph')) return { title: 'Intelligence Correlation Graph', breadcrumbs: [{ label: 'Intel Graph' }] };
    if (path.startsWith('/cases/')) {
      const caseId = path.split('/')[2];
      return {
        title: 'Case Investigation Workspace',
        breadcrumbs: [{ label: 'Cases', href: '/cases' }, { label: caseId || 'Workspace' }],
      };
    }
    if (path.startsWith('/cases')) return { title: 'Investigation Cases', breadcrumbs: [{ label: 'Cases' }] };
    if (path.startsWith('/reports')) return { title: 'Forensic Intelligence Reports', breadcrumbs: [{ label: 'Reports' }] };
    if (path.startsWith('/settings')) return { title: 'System Settings', breadcrumbs: [{ label: 'Settings' }] };
    return { title: 'AEGIS Forensics', breadcrumbs: [{ label: 'Console' }] };
  };

  const { title, breadcrumbs } = getPageContext();

  const handleLogout = () => {
    if (onLogout) onLogout();
    navigate('/login');
  };

  return (
    <div className="flex h-screen w-full bg-[#0B1120] text-gray-100 overflow-hidden font-sans">
      {/* Persistent Left Sidebar */}
      <Sidebar onLogout={handleLogout} />

      {/* Main Content Viewport */}
      <div className="flex-1 flex flex-col min-w-0 h-full overflow-hidden">
        {/* Top Header */}
        <TopHeader
          title={title}
          breadcrumbs={breadcrumbs}
          onOpenSearch={() => setSearchOpen(true)}
        />

        {/* Dynamic Page Container */}
        <main className="flex-1 overflow-y-auto p-6 bg-[#0B1120]">
          <div className="max-w-7xl mx-auto space-y-6">
            <Outlet />
          </div>
        </main>
      </div>

      {/* Global Command Palette Modal */}
      <GlobalSearchModal isOpen={searchOpen} onClose={() => setSearchOpen(false)} />
    </div>
  );
};
