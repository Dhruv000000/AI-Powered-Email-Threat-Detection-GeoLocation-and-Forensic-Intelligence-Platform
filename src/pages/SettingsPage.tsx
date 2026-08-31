import React, { useState } from 'react';
import { Settings as SettingsIcon, User, Sliders, ShieldCheck, Key, Save, Check } from 'lucide-react';

export const SettingsPage: React.FC = () => {
  const [name, setName] = useState('Dhruv Sharma');
  const [email, setEmail] = useState('dhruv.sharma@cyberdefense.gov.in');
  const [role, setRole] = useState('Senior Digital Forensics Lead');
  const [organization, setOrganization] = useState('Cyber Defense & Threat Intel Division');
  const [twoFactor, setTwoFactor] = useState(true);
  const [density, setDensity] = useState<'compact' | 'comfortable'>('compact');
  const [saved, setSaved] = useState(false);

  const handleSave = (e: React.FormEvent) => {
    e.preventDefault();
    setSaved(true);
    setTimeout(() => setSaved(false), 2500);
  };

  return (
    <div className="space-y-6 max-w-4xl">
      {/* Header */}
      <div className="border-b border-[#263244] pb-4">
        <h1 className="text-xl font-bold text-gray-100 font-mono tracking-tight flex items-center gap-2">
          <SettingsIcon className="w-5 h-5 text-blue-400" />
          System & Analyst Station Settings
        </h1>
        <p className="text-xs text-gray-400 font-mono mt-1">
          Configure investigator profile parameters, telemetry density, and hardware token authentication.
        </p>
      </div>

      <form onSubmit={handleSave} className="space-y-6">
        {/* Profile Settings */}
        <div className="p-5 rounded-lg bg-[#151E2E] border border-[#263244] space-y-4 font-mono text-xs">
          <div className="flex items-center gap-2 border-b border-[#263244] pb-3">
            <User className="w-4 h-4 text-blue-400" />
            <h3 className="text-xs font-bold uppercase tracking-wider text-gray-200">
              Investigator Identity Profile
            </h3>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div className="space-y-1">
              <label className="text-2xs uppercase text-gray-400 font-semibold block">Full Name</label>
              <input
                type="text"
                value={name}
                onChange={(e) => setName(e.target.value)}
                className="w-full bg-[#0B1120] border border-[#263244] rounded p-2 text-gray-200 focus:outline-none focus:border-blue-500 font-sans"
              />
            </div>
            <div className="space-y-1">
              <label className="text-2xs uppercase text-gray-400 font-semibold block">Official Email</label>
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="w-full bg-[#0B1120] border border-[#263244] rounded p-2 text-gray-200 focus:outline-none focus:border-blue-500 font-sans"
              />
            </div>
            <div className="space-y-1">
              <label className="text-2xs uppercase text-gray-400 font-semibold block">Role / Title</label>
              <input
                type="text"
                value={role}
                onChange={(e) => setRole(e.target.value)}
                className="w-full bg-[#0B1120] border border-[#263244] rounded p-2 text-gray-200 focus:outline-none focus:border-blue-500 font-sans"
              />
            </div>
            <div className="space-y-1">
              <label className="text-2xs uppercase text-gray-400 font-semibold block">Agency / Unit</label>
              <input
                type="text"
                value={organization}
                onChange={(e) => setOrganization(e.target.value)}
                className="w-full bg-[#0B1120] border border-[#263244] rounded p-2 text-gray-200 focus:outline-none focus:border-blue-500 font-sans"
              />
            </div>
          </div>
        </div>

        {/* Workstation Preferences */}
        <div className="p-5 rounded-lg bg-[#151E2E] border border-[#263244] space-y-4 font-mono text-xs">
          <div className="flex items-center gap-2 border-b border-[#263244] pb-3">
            <Sliders className="w-4 h-4 text-blue-400" />
            <h3 className="text-xs font-bold uppercase tracking-wider text-gray-200">
              Workstation Density & Theme
            </h3>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div className="space-y-1">
              <label className="text-2xs uppercase text-gray-400 font-semibold block">Theme Palette</label>
              <input
                type="text"
                disabled
                value="Dark Navy / Charcoal (#0B1120) [Enforced]"
                className="w-full bg-[#0B1120] border border-[#263244] rounded p-2 text-gray-400 cursor-not-allowed text-2xs"
              />
            </div>
            <div className="space-y-1">
              <label className="text-2xs uppercase text-gray-400 font-semibold block">Data Table Density</label>
              <select
                value={density}
                onChange={(e) => setDensity(e.target.value as any)}
                className="w-full bg-[#0B1120] border border-[#263244] rounded p-2 text-gray-200 focus:outline-none"
              >
                <option value="compact">Compact Analyst Density (Default)</option>
                <option value="comfortable">Comfortable Grid</option>
              </select>
            </div>
          </div>
        </div>

        {/* Security & Authentication */}
        <div className="p-5 rounded-lg bg-[#151E2E] border border-[#263244] space-y-4 font-mono text-xs">
          <div className="flex items-center gap-2 border-b border-[#263244] pb-3">
            <ShieldCheck className="w-4 h-4 text-blue-400" />
            <h3 className="text-xs font-bold uppercase tracking-wider text-gray-200">
              Security & Tokens
            </h3>
          </div>

          <div className="flex items-center justify-between p-3 bg-[#0B1120] rounded border border-[#263244]">
            <div>
              <span className="font-bold text-gray-200 block">Two-Factor Authentication (Hardware Token / FIDO2)</span>
              <span className="text-2xs text-gray-400">Enforce biometric or security key challenge on case escalation</span>
            </div>
            <button
              type="button"
              onClick={() => setTwoFactor(!twoFactor)}
              className={`px-3 py-1 rounded text-2xs font-bold transition border ${
                twoFactor
                  ? 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30'
                  : 'bg-red-500/20 text-red-400 border-red-500/30'
              }`}
            >
              {twoFactor ? 'ENABLED' : 'DISABLED'}
            </button>
          </div>
        </div>

        {/* Save Bar */}
        <div className="flex items-center justify-between pt-2">
          {saved ? (
            <span className="text-xs text-emerald-400 font-mono flex items-center gap-1.5 animate-in fade-in">
              <Check className="w-4 h-4" />
              <span>Station preferences saved successfully.</span>
            </span>
          ) : (
            <span />
          )}

          <button
            type="submit"
            className="flex items-center gap-2 px-5 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded text-xs font-mono font-semibold shadow transition"
          >
            <Save className="w-3.5 h-3.5" />
            <span>Save Settings</span>
          </button>
        </div>
      </form>
    </div>
  );
};
