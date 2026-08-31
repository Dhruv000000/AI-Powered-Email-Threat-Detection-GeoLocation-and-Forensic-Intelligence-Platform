import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Mail,
  ShieldAlert,
  AlertOctagon,
  Briefcase,
  SearchCode,
  ArrowRight,
  RefreshCw,
  Clock,
  TrendingUp,
  Activity,
  Layers,
} from 'lucide-react';
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  BarChart,
  Bar,
  Legend,
} from 'recharts';
import { StatCard } from '../components/common/StatCard';
import { SeverityBadge } from '../components/common/SeverityBadge';
import { threatService } from '../services/threatService';
import { ThreatRecord } from '../types/threat';
import { LoadingState } from '../components/common/LoadingState';

export const DashboardPage: React.FC = () => {
  const navigate = useNavigate();
  const [stats, setStats] = useState<any>(null);
  const [recentThreats, setRecentThreats] = useState<ThreatRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [timeRange, setTimeRange] = useState<'24h' | '7d'>('24h');

  useEffect(() => {
    async function loadData() {
      setLoading(true);
      const [s, t] = await Promise.all([
        threatService.getThreatStats(),
        threatService.getThreats({ severity: 'all' }),
      ]);
      setStats(s);
      setRecentThreats(t.slice(0, 5));
      setLoading(false);
    }
    loadData();
  }, []);

  if (loading || !stats) {
    return <LoadingState message="Connecting to AEGIS Threat Intelligence Engine..." />;
  }

  return (
    <div className="space-y-6">
      {/* Top Action Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-[#263244] pb-4">
        <div>
          <h1 className="text-xl font-bold text-gray-100 font-mono tracking-tight">Security Overview</h1>
          <div className="flex items-center gap-2 text-2xs text-gray-400 font-mono mt-1">
            <span className="inline-block w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
            <span>AI Telemetry Active</span>
            <span>•</span>
            <Clock className="w-3 h-3 text-gray-400" />
            <span>Last synchronized: Just now</span>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => navigate('/analyze')}
            className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded text-xs font-semibold font-mono tracking-wide shadow transition"
          >
            <SearchCode className="w-4 h-4" />
            <span>Analyze New Email</span>
          </button>
        </div>
      </div>

      {/* 4 Summary Stat Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="Emails Analyzed"
          value={stats.emailsAnalyzed}
          icon={Mail}
          change={{ value: '+8.4%', isIncrease: true, period: 'vs last 7 days', isGood: true }}
          onClick={() => navigate('/threats')}
        />
        <StatCard
          title="Threats Detected"
          value={stats.threatsDetected}
          icon={ShieldAlert}
          variant="warning"
          change={{ value: '+14.2%', isIncrease: true, period: 'vs yesterday', isGood: false }}
          onClick={() => navigate('/threats')}
        />
        <StatCard
          title="Critical Threats"
          value={stats.criticalThreats}
          icon={AlertOctagon}
          variant="critical"
          change={{ value: '+2 new', isIncrease: true, period: 'requires triage', isGood: false }}
          onClick={() => navigate('/threats')}
        />
        <StatCard
          title="Active Cases"
          value={stats.activeCases}
          icon={Briefcase}
          variant="default"
          change={{ value: '4 assigned', isIncrease: false, period: 'to your desk' }}
          onClick={() => navigate('/cases')}
        />
      </div>

      {/* Visual Analytics Charts Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Threat Activity Over Time (2 cols) */}
        <div className="lg:col-span-2 p-5 rounded-lg bg-[#151E2E] border border-[#263244] space-y-4">
          <div className="flex items-center justify-between border-b border-[#263244] pb-3">
            <div className="flex items-center gap-2">
              <Activity className="w-4 h-4 text-blue-400" />
              <h2 className="text-xs font-bold uppercase tracking-wider text-gray-200 font-mono">
                Threat Activity Over Time
              </h2>
            </div>
            <div className="flex items-center gap-1 bg-[#0B1120] p-0.5 rounded border border-[#263244] font-mono text-2xs">
              <button
                onClick={() => setTimeRange('24h')}
                className={`px-2.5 py-1 rounded transition ${
                  timeRange === '24h' ? 'bg-blue-600 text-white font-bold' : 'text-gray-400 hover:text-gray-200'
                }`}
              >
                24 Hours
              </button>
              <button
                onClick={() => setTimeRange('7d')}
                className={`px-2.5 py-1 rounded transition ${
                  timeRange === '7d' ? 'bg-blue-600 text-white font-bold' : 'text-gray-400 hover:text-gray-200'
                }`}
              >
                7 Days
              </button>
            </div>
          </div>

          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={stats.timeSeriesActivity} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="colorPhish" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#EF4444" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#EF4444" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="colorBec" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#F59E0B" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#F59E0B" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="colorSpoof" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#3B82F6" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#3B82F6" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#263244" vertical={false} />
                <XAxis dataKey="time" stroke="#64748B" fontSize={11} tickLine={false} />
                <YAxis stroke="#64748B" fontSize={11} tickLine={false} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#151E2E',
                    borderColor: '#263244',
                    borderRadius: '8px',
                    fontSize: '11px',
                    fontFamily: 'JetBrains Mono',
                  }}
                  itemStyle={{ padding: 0 }}
                />
                <Area type="monotone" dataKey="phishing" name="Phishing" stroke="#EF4444" strokeWidth={2} fillOpacity={1} fill="url(#colorPhish)" />
                <Area type="monotone" dataKey="bec" name="BEC" stroke="#F59E0B" strokeWidth={2} fillOpacity={1} fill="url(#colorBec)" />
                <Area type="monotone" dataKey="spoofing" name="Spoofing" stroke="#3B82F6" strokeWidth={2} fillOpacity={1} fill="url(#colorSpoof)" />
              </AreaChart>
            </ResponsiveContainer>
          </div>

          <div className="flex items-center justify-center gap-6 pt-2 text-2xs font-mono text-gray-400">
            <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded bg-[#EF4444]" /> Phishing Vectors</span>
            <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded bg-[#F59E0B]" /> Business Email Compromise</span>
            <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded bg-[#3B82F6]" /> Domain Spoofing</span>
          </div>
        </div>

        {/* Threat Distribution Breakdown (1 col) */}
        <div className="p-5 rounded-lg bg-[#151E2E] border border-[#263244] space-y-4 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between border-b border-[#263244] pb-3 mb-3">
              <div className="flex items-center gap-2">
                <Layers className="w-4 h-4 text-blue-400" />
                <h2 className="text-xs font-bold uppercase tracking-wider text-gray-200 font-mono">
                  Threat Classification
                </h2>
              </div>
              <span className="text-2xs text-gray-400 font-mono">Total: 87</span>
            </div>

            <div className="space-y-3 font-mono">
              {stats.typeDistribution.map((item: any) => (
                <div key={item.name} className="space-y-1">
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-gray-300 font-medium">{item.name}</span>
                    <span className="text-gray-400 text-2xs">{item.count} ({item.percentage}%)</span>
                  </div>
                  <div className="h-1.5 w-full bg-[#0B1120] rounded-full overflow-hidden border border-[#263244]">
                    <div
                      className="h-full bg-blue-500 rounded-full"
                      style={{ width: `${item.percentage}%` }}
                    />
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Severity Quick Tally */}
          <div className="pt-3 border-t border-[#263244] grid grid-cols-4 gap-2 text-center font-mono">
            <div className="p-1.5 rounded bg-red-500/10 border border-red-500/20">
              <span className="text-[10px] text-red-400 font-bold block">CRIT</span>
              <span className="text-xs font-bold text-red-400">{stats.severityBreakdown.critical}</span>
            </div>
            <div className="p-1.5 rounded bg-orange-500/10 border border-orange-500/20">
              <span className="text-[10px] text-orange-400 font-bold block">HIGH</span>
              <span className="text-xs font-bold text-orange-400">{stats.severityBreakdown.high}</span>
            </div>
            <div className="p-1.5 rounded bg-amber-500/10 border border-amber-500/20">
              <span className="text-[10px] text-amber-400 font-bold block">MED</span>
              <span className="text-xs font-bold text-amber-400">{stats.severityBreakdown.medium}</span>
            </div>
            <div className="p-1.5 rounded bg-emerald-500/10 border border-emerald-500/20">
              <span className="text-[10px] text-emerald-400 font-bold block">LOW</span>
              <span className="text-xs font-bold text-emerald-400">{stats.severityBreakdown.low}</span>
            </div>
          </div>
        </div>
      </div>

      {/* Recent High-Risk Emails Table */}
      <div className="p-5 rounded-lg bg-[#151E2E] border border-[#263244] space-y-4">
        <div className="flex items-center justify-between border-b border-[#263244] pb-3">
          <div>
            <h2 className="text-xs font-bold uppercase tracking-wider text-gray-200 font-mono flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-red-400" />
              Recent High-Risk Email Interceptions
            </h2>
            <p className="text-2xs text-gray-400 mt-0.5">Click any row to open full technical forensic breakdown</p>
          </div>

          <button
            onClick={() => navigate('/threats')}
            className="flex items-center gap-1.5 text-xs text-blue-400 hover:text-blue-300 font-mono font-medium transition"
          >
            <span>View All Global Threats</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>

        <div className="overflow-x-auto rounded border border-[#263244] bg-[#111827]">
          <table className="w-full text-left text-xs border-collapse font-mono">
            <thead>
              <tr className="bg-[#151E2E] border-b border-[#263244] text-2xs uppercase tracking-wider text-gray-400">
                <th className="py-2.5 px-3">Severity</th>
                <th className="py-2.5 px-3">Email Subject</th>
                <th className="py-2.5 px-3">Sender Identity</th>
                <th className="py-2.5 px-3">Threat Vector</th>
                <th className="py-2.5 px-3">Risk Score</th>
                <th className="py-2.5 px-3">Detected</th>
                <th className="py-2.5 px-3 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1E293B]">
              {recentThreats.map((item) => (
                <tr
                  key={item.id}
                  onClick={() => navigate(`/analyze/${item.emailId}`)}
                  className="hover:bg-[#151E2E]/80 transition cursor-pointer group"
                >
                  <td className="py-2.5 px-3">
                    <SeverityBadge severity={item.severity} size="sm" />
                  </td>
                  <td className="py-2.5 px-3">
                    <span className="font-semibold text-gray-100 group-hover:text-blue-400 transition truncate max-w-xs block font-sans">
                      {item.subject}
                    </span>
                  </td>
                  <td className="py-2.5 px-3 text-gray-300 truncate max-w-[200px]">
                    {item.sender}
                  </td>
                  <td className="py-2.5 px-3">
                    <span className="px-2 py-0.5 rounded bg-[#1E293B] text-gray-300 border border-[#263244] text-2xs font-semibold">
                      {item.threatType}
                    </span>
                  </td>
                  <td className="py-2.5 px-3">
                    <span className="font-bold text-red-400">{item.riskScore}/100</span>
                  </td>
                  <td className="py-2.5 px-3 text-gray-400 text-2xs whitespace-nowrap">
                    {item.detectedAt}
                  </td>
                  <td className="py-2.5 px-3 text-right">
                    <button className="px-2.5 py-1 bg-[#1E293B] hover:bg-blue-600 hover:text-white rounded text-2xs text-gray-300 border border-[#263244] transition">
                      Investigate
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
