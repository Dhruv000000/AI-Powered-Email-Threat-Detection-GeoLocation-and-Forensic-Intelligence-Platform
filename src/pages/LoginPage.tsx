import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Shield, Lock, Mail, Eye, EyeOff, ArrowRight } from 'lucide-react';

interface LoginPageProps {
  onLogin: () => void;
}

export const LoginPage: React.FC<LoginPageProps> = ({ onLogin }) => {
  const navigate = useNavigate();
  const [email, setEmail] = useState('dhruv.sharma@cyberdefense.gov.in');
  const [password, setPassword] = useState('••••••••••••');
  const [showPassword, setShowPassword] = useState(false);
  const [rememberMe, setRememberMe] = useState(true);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    onLogin();
    navigate('/dashboard');
  };

  return (
    <div className="min-h-screen w-full bg-[#0B1120] text-gray-100 flex flex-col justify-center items-center p-4 font-sans selection:bg-blue-600/30 selection:text-blue-200">
      {/* Platform Brand Header */}
      <div className="text-center mb-6 space-y-1">
        <div className="inline-flex items-center justify-center w-12 h-12 rounded-lg bg-blue-600/10 border border-blue-500/30 text-blue-400 mb-2 shadow-sm">
          <Shield className="w-6 h-6" />
        </div>
        <h1 className="text-2xl font-bold font-mono tracking-wider text-gray-100">AEGIS</h1>
        <p className="text-xs text-gray-400 font-sans tracking-wide">
          AI-Powered Email Threat Intelligence & Forensic Investigation Platform
        </p>
      </div>

      {/* Login Card */}
      <div className="w-full max-w-md bg-[#151E2E] border border-[#263244] rounded-xl shadow-2xl p-6 md:p-8 space-y-6">
        <div className="border-b border-[#263244] pb-4">
          <h2 className="text-base font-bold text-gray-200 font-mono">Analyst Authentication</h2>
          <p className="text-xs text-gray-400 mt-1">Sign in with authorized agency credentials</p>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4 font-mono text-xs">
          {/* Email Field */}
          <div className="space-y-1">
            <label className="block text-2xs uppercase text-gray-400 font-semibold">
              Security Analyst Email
            </label>
            <div className="relative">
              <Mail className="w-4 h-4 text-gray-400 absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="analyst@agency.gov.in"
                className="w-full bg-[#0B1120] border border-[#263244] rounded-md pl-9 pr-3 py-2 text-xs text-gray-200 placeholder-gray-500 focus:outline-none focus:border-blue-500"
              />
            </div>
          </div>

          {/* Password Field */}
          <div className="space-y-1">
            <div className="flex items-center justify-between">
              <label className="block text-2xs uppercase text-gray-400 font-semibold">
                Passphrase / Token
              </label>
              <button
                type="button"
                className="text-[11px] text-blue-400 hover:underline font-sans"
              >
                Reset Access
              </button>
            </div>
            <div className="relative">
              <Lock className="w-4 h-4 text-gray-400 absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                type={showPassword ? 'text' : 'password'}
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••••••"
                className="w-full bg-[#0B1120] border border-[#263244] rounded-md pl-9 pr-9 py-2 text-xs text-gray-200 placeholder-gray-500 focus:outline-none focus:border-blue-500"
              />
              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                className="text-gray-400 hover:text-gray-200 absolute right-3 top-1/2 -translate-y-1/2 p-0.5"
              >
                {showPassword ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
              </button>
            </div>
          </div>

          {/* Remember Me & Role Badge */}
          <div className="flex items-center justify-between pt-1">
            <label className="flex items-center gap-2 cursor-pointer font-sans text-xs text-gray-300 select-none">
              <input
                type="checkbox"
                checked={rememberMe}
                onChange={(e) => setRememberMe(e.target.checked)}
                className="rounded bg-[#0B1120] border-[#263244] text-blue-600 focus:ring-0 focus:ring-offset-0"
              />
              <span>Remember station session</span>
            </label>

            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-blue-600/15 text-blue-400 border border-blue-500/30">
              ROLE: SOC LEAD
            </span>
          </div>

          {/* Sign In Button */}
          <button
            type="submit"
            className="w-full flex items-center justify-center gap-2 py-2.5 bg-blue-600 hover:bg-blue-500 text-white rounded-md text-xs font-semibold uppercase tracking-wider transition shadow-lg mt-2"
          >
            <span>Access Forensic Workstation</span>
            <ArrowRight className="w-4 h-4" />
          </button>
        </form>

        <div className="border-t border-[#263244] pt-4 text-center text-2xs text-gray-400 space-y-1">
          <p>Government of India — Smart India Hackathon (SIH-2026)</p>
          <p className="text-[10px]">Restricted to authorized digital forensics & cyber intelligence personnel.</p>
        </div>
      </div>
    </div>
  );
};
