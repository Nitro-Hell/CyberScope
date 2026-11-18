'use client';

import React, { useState, useEffect, useCallback } from 'react';
import Image from 'next/image';
import {
  Shield,
  LayoutDashboard,
  Globe,
  Terminal,
  Search,
  Lock,
  Flag,
  Code2,
  FileSearch,
  Bot,
  BarChart3,
  Settings,
  Info,
  Menu,
  X,
  LogOut,
  ArrowUpRight,
  Printer,
} from 'lucide-react';
import LandingAndAuthView, { NavPageId, ActiveAnalyst } from '@/components/LandingAndAuthView';
import ModulesNetworkAndScanner from '@/components/ModulesNetworkAndScanner';
import ModulesTerminalAndThreats from '@/components/ModulesTerminalAndThreats';
import ModulesCtfWebForensics from '@/components/ModulesCtfWebForensics';
import ModulesTutorReportsSettingsAbout from '@/components/ModulesTutorReportsSettingsAbout';
import {
  ScanHistoryRecord,
  NetworkDeviceRecord,
  SecurityReportRecord,
  LearningProgressRecord,
} from '@/lib/server-db';

interface DashboardState {
  metrics: {
    securityPostureScore: number;
    authorizedDevicesCount: number;
    reviewRequiredDevices: number;
    totalScansCompleted: number;
    ctfSolvedCount: number;
    ctfTotalCount: number;
    ctfScorePoints: number;
    reportsGenerated: number;
  };
  scanHistory: ScanHistoryRecord[];
  networkDevices: NetworkDeviceRecord[];
  reports: SecurityReportRecord[];
  learningProgress: LearningProgressRecord[];
  scoreTrend: Array<{ label: string; score: number }>;
}

const SIDEBAR_ITEMS: Array<{
  id: NavPageId;
  label: string;
  section: 'CORE' | 'LABS' | 'INTEL';
  icon: React.ComponentType<{ className?: string }>;
}> = [
  { id: 'dashboard', label: 'Main Dashboard', section: 'CORE', icon: LayoutDashboard },
  { id: 'network', label: '01. Network Intelligence', section: 'CORE', icon: Globe },
  { id: 'scanner', label: '02. Security Scanner', section: 'CORE', icon: Shield },
  { id: 'terminal', label: '03. Cyber Terminal', section: 'LABS', icon: Terminal },
  { id: 'threats', label: '04. Threat Intelligence', section: 'INTEL', icon: Search },
  { id: 'crypto', label: '05. Cryptography Lab', section: 'LABS', icon: Lock },
  { id: 'ctf', label: '06. CTF Arena', section: 'LABS', icon: Flag },
  { id: 'weblab', label: '07. Web Security Lab', section: 'LABS', icon: Code2 },
  { id: 'forensics', label: '08. Digital Forensics', section: 'LABS', icon: FileSearch },
  { id: 'tutor', label: '09. AI Cyber Tutor', section: 'INTEL', icon: Bot },
  { id: 'reports', label: '10. Reports & Analytics', section: 'INTEL', icon: BarChart3 },
  { id: 'settings', label: 'User Settings', section: 'INTEL', icon: Settings },
  { id: 'about', label: 'About & Flask Blueprint', section: 'INTEL', icon: Info },
];

export default function CyberScopePage() {
  const [currentPage, setCurrentPage] = useState<NavPageId>('dashboard');
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [globalFilter, setGlobalFilter] = useState('');
  const [avatarError, setAvatarError] = useState(false);
  const [pdfOverviewOpen, setPdfOverviewOpen] = useState(false);
  const [analyst, setAnalyst] = useState<ActiveAnalyst>({
    id: 'usr-soc-01',
    username: 'elena.vance',
    email: 'elena.vance@cyberscope.sec',
    role: 'Lead Defensive Security Architect',
    clearance: 'SOC Tier-3 // Blue Team Lead',
  });

  const [dashData, setDashData] = useState<DashboardState>({
    metrics: {
      securityPostureScore: 84,
      authorizedDevicesCount: 5,
      reviewRequiredDevices: 1,
      totalScansCompleted: 3,
      ctfSolvedCount: 1,
      ctfTotalCount: 6,
      ctfScorePoints: 100,
      reportsGenerated: 3,
    },
    scanHistory: [],
    networkDevices: [],
    reports: [],
    learningProgress: [],
    scoreTrend: [
      { label: 'W-5', score: 68 },
      { label: 'W-4', score: 72 },
      { label: 'W-3', score: 76 },
      { label: 'W-2', score: 80 },
      { label: 'W-1', score: 84 },
      { label: 'Current', score: 84 },
    ],
  });

  const refreshDashboard = useCallback(async () => {
    try {
      const res = await fetch('/api/dashboard');
      const d = await res.json();
      if (d.status === 'ok') {
        setDashData({
          metrics: d.metrics,
          scanHistory: d.scanHistory || [],
          networkDevices: d.networkDevices || [],
          reports: d.reports || [],
          learningProgress: d.learningProgress || [],
          scoreTrend: d.scoreTrend || [],
        });
      }
    } catch {
      // Keep initial state if offline
    }
  }, []);

  useEffect(() => {
    fetch('/api/dashboard')
      .then((r) => r.json())
      .then((d) => {
        if (d.status === 'ok') {
          setDashData({
            metrics: d.metrics,
            scanHistory: d.scanHistory || [],
            networkDevices: d.networkDevices || [],
            reports: d.reports || [],
            learningProgress: d.learningProgress || [],
            scoreTrend: d.scoreTrend || [],
          });
        }
      })
      .catch(() => {});
  }, []);

  if (
    currentPage === 'landing' ||
    currentPage === 'login' ||
    currentPage === 'register'
  ) {
    return (
      <LandingAndAuthView
        currentPage={currentPage}
        onNavigate={(page) => setCurrentPage(page)}
        onAuthenticated={(user) => {
          setAnalyst(user);
          setCurrentPage('dashboard');
          refreshDashboard();
        }}
      />
    );
  }

  const activeNavMeta =
    SIDEBAR_ITEMS.find((i) => i.id === currentPage) || SIDEBAR_ITEMS[0];

  const filteredModules = SIDEBAR_ITEMS.filter(
    (item) =>
      item.id !== 'dashboard' &&
      item.label.toLowerCase().includes(globalFilter.toLowerCase())
  );

  const handleExportPdfOverview = () => {
    setCurrentPage('dashboard');
    setPdfOverviewOpen(true);
    setTimeout(() => {
      if (typeof window !== 'undefined' && typeof window.print === 'function') {
        window.print();
      }
    }, 100);
  };

  return (
    <div className="min-h-screen bg-[#080D1A] text-slate-100 flex">
      {/* Desktop Sidebar Navigation (260px) */}
      <aside className="hidden lg:flex lg:flex-col w-64 shrink-0 bg-[#0B1120] border-r border-slate-800/80 justify-between h-screen sticky top-0 print:hidden">
        <div className="p-4 overflow-y-auto">
          <div className="flex items-center justify-between pb-3 mb-3 border-b border-slate-800">
            <button
              type="button"
              onClick={() => setCurrentPage('landing')}
              className="text-lg font-bold tracking-tight text-white whitespace-nowrap cursor-pointer"
            >
              CyberScope
            </button>
            <span className="text-[11px] font-mono text-cyan-400">SOC v1.0</span>
          </div>

          <nav aria-label="CyberScope Primary Modules" className="space-y-0.5">
            {SIDEBAR_ITEMS.map((item) => {
              const Icon = item.icon;
              const isActive = currentPage === item.id;
              return (
                <button
                  key={item.id}
                  type="button"
                  onClick={() => setCurrentPage(item.id)}
                  className={`w-full flex items-center gap-3 px-3 py-1.5 text-xs font-medium rounded-lg transition-colors cursor-pointer whitespace-nowrap ${
                    isActive
                      ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/30'
                      : 'text-slate-400 hover:text-white hover:bg-slate-900/60'
                  }`}
                >
                  <Icon className="w-4 h-4 shrink-0" />
                  <span className="truncate">{item.label}</span>
                </button>
              );
            })}
          </nav>
        </div>

        {/* Analyst Profile Card at Bottom of Sidebar */}
        <div className="p-4 border-t border-slate-800 bg-[#080D1A]/60 shrink-0">
          <div className="flex items-center gap-3 mb-2.5">
            <div className="w-9 h-9 rounded-full overflow-hidden bg-slate-800 border border-slate-700 shrink-0 relative flex items-center justify-center">
              {!avatarError ? (
                <Image
                  src="/assets/images/avatar_soc_analyst_1794995981710.jpg"
                  alt="SOC Analyst Avatar"
                  fill
                  sizes="36px"
                  referrerPolicy="no-referrer"
                  className="object-cover"
                  onError={() => setAvatarError(true)}
                />
              ) : (
                <span className="text-xs font-mono font-bold text-cyan-400">EV</span>
              )}
            </div>
            <div className="min-w-0">
              <p className="text-xs font-semibold text-white truncate">{analyst.username}</p>
              <p className="text-[11px] text-slate-400 truncate">{analyst.role}</p>
            </div>
          </div>

          <div className="flex items-center justify-between gap-2 pt-2 border-t border-slate-800/80">
            <button
              type="button"
              onClick={() => setCurrentPage('landing')}
              className="text-xs text-slate-400 hover:text-white transition-colors cursor-pointer"
            >
              Landing Page
            </button>
            <button
              type="button"
              onClick={() => setCurrentPage('login')}
              className="text-xs text-cyan-400 hover:underline flex items-center gap-1 cursor-pointer"
            >
              <LogOut className="w-3 h-3" />
              <span>Switch User</span>
            </button>
          </div>
        </div>
      </aside>

      {/* Mobile Navigation Drawer */}
      {mobileMenuOpen && (
        <div className="fixed inset-0 z-50 lg:hidden flex">
          <div
            className="fixed inset-0 bg-black/70"
            onClick={() => setMobileMenuOpen(false)}
          />
          <div className="relative w-72 max-w-full bg-[#0B1120] border-r border-slate-800 h-full p-5 overflow-y-auto z-10">
            <div className="flex items-center justify-between pb-4 mb-4 border-b border-slate-800">
              <span className="text-lg font-bold text-white">CyberScope SOC</span>
              <button
                type="button"
                aria-label="Close navigation menu"
                onClick={() => setMobileMenuOpen(false)}
                className="p-1.5 text-slate-400 hover:text-white"
              >
                <X className="w-5 h-5" />
              </button>
            </div>
            <div className="space-y-1">
              {SIDEBAR_ITEMS.map((item) => {
                const Icon = item.icon;
                return (
                  <button
                    key={item.id}
                    type="button"
                    onClick={() => {
                      setCurrentPage(item.id);
                      setMobileMenuOpen(false);
                    }}
                    className={`w-full flex items-center gap-3 px-3 py-2.5 text-xs font-medium rounded-lg ${
                      currentPage === item.id
                        ? 'bg-cyan-500/15 text-cyan-300'
                        : 'text-slate-300 hover:bg-slate-900'
                    }`}
                  >
                    <Icon className="w-4 h-4 shrink-0" />
                    <span>{item.label}</span>
                  </button>
                );
              })}
              <div className="pt-4 mt-4 border-t border-slate-800 flex flex-col gap-2">
                <button
                  type="button"
                  onClick={() => {
                    setCurrentPage('landing');
                    setMobileMenuOpen(false);
                  }}
                  className="text-left px-3 py-2 text-xs text-slate-400 hover:text-white"
                >
                  Public Landing Page
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setCurrentPage('login');
                    setMobileMenuOpen(false);
                  }}
                  className="text-left px-3 py-2 text-xs text-cyan-400"
                >
                  Sign In / Register
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col min-w-0">
        {/* Strict SaaS Top Bar Contract: Breadcrumb on Left, 1-2 Primary Actions on Right */}
        <header className="flex items-center justify-between gap-4 px-6 py-4 bg-[#0B1120] border-b border-slate-800/80 print:hidden">
          <div className="flex items-center gap-3 min-w-0">
            <button
              type="button"
              aria-label="Open navigation menu"
              onClick={() => setMobileMenuOpen(true)}
              className="lg:hidden p-2 rounded-lg bg-slate-900 border border-slate-800 text-slate-200"
            >
              <Menu className="w-4 h-4" />
            </button>
            <div className="text-sm font-medium text-slate-300 truncate">
              <button
                type="button"
                onClick={() => setCurrentPage('dashboard')}
                className="text-slate-400 hover:text-white transition-colors cursor-pointer"
              >
                CyberScope SOC
              </button>
              <span className="mx-2 text-slate-600">/</span>
              <span className="text-white font-semibold">{activeNavMeta.label}</span>
            </div>
          </div>

          <div className="flex items-center gap-3 shrink-0">
            <button
              type="button"
              onClick={handleExportPdfOverview}
              className="px-3.5 py-2 text-xs font-medium text-slate-100 bg-slate-900 hover:bg-slate-800 border border-slate-700 rounded-lg transition-colors flex items-center gap-2 whitespace-nowrap shrink-0 cursor-pointer"
            >
              <Printer className="w-3.5 h-3.5 text-cyan-400" />
              <span>Export PDF Overview</span>
            </button>
            <button
              type="button"
              onClick={() => setCurrentPage('scanner')}
              className="px-3.5 py-2 text-xs font-semibold text-slate-950 bg-cyan-400 hover:bg-cyan-300 rounded-lg transition-colors whitespace-nowrap shrink-0 cursor-pointer"
            >
              New Security Scan
            </button>
          </div>
        </header>

        {/* Main Viewport */}
        <main className="flex-1 p-6 max-w-7xl w-full mx-auto">
          {currentPage === 'dashboard' && (
            <div className="space-y-6">
              {/* Printable PDF Executive Metric Overview Sheet (Triggered by Export PDF Overview) */}
              {pdfOverviewOpen && (
                <section
                  aria-label="Printable PDF Metric Overview"
                  className="bg-[#0F172A] print:bg-white print:text-slate-900 border border-cyan-500/40 print:border-slate-300 rounded-xl p-6 space-y-4"
                >
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-slate-800 print:border-slate-300">
                    <div>
                      <p className="text-xs font-mono text-cyan-400 print:text-slate-700">
                        CYBERSCOPE SOC · PRINTABLE PDF METRIC OVERVIEW
                      </p>
                      <h2 className="text-lg font-bold text-white print:text-slate-900 mt-0.5">
                        Executive Security Posture & Telemetry Summary
                      </h2>
                      <p className="text-xs text-slate-400 print:text-slate-600 mt-0.5">
                        Operator: {analyst.username} ({analyst.role}) · Clearance: {analyst.clearance}
                      </p>
                    </div>
                    <div className="flex items-center gap-2 print:hidden">
                      <button
                        type="button"
                        onClick={() => window.print()}
                        className="px-3.5 py-1.5 text-xs font-semibold text-slate-950 bg-cyan-400 hover:bg-cyan-300 rounded-lg flex items-center gap-1.5 whitespace-nowrap cursor-pointer"
                      >
                        <Printer className="w-3.5 h-3.5" />
                        <span>Print / Save PDF</span>
                      </button>
                      <button
                        type="button"
                        onClick={() => setPdfOverviewOpen(false)}
                        className="px-3 py-1.5 text-xs font-medium text-slate-300 hover:text-white bg-slate-900 border border-slate-700 rounded-lg whitespace-nowrap cursor-pointer"
                      >
                        Dismiss Preview
                      </button>
                    </div>
                  </div>

                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs font-mono tabular-nums">
                    <div className="p-3 rounded-lg bg-[#080D1A] print:bg-slate-100 border border-slate-800 print:border-slate-300">
                      <span className="text-slate-400 print:text-slate-600 block">
                        Security Posture Score
                      </span>
                      <span className="text-base font-bold text-cyan-400 print:text-slate-900">
                        {dashData.metrics.securityPostureScore}/100
                      </span>
                    </div>
                    <div className="p-3 rounded-lg bg-[#080D1A] print:bg-slate-100 border border-slate-800 print:border-slate-300">
                      <span className="text-slate-400 print:text-slate-600 block">
                        Authorized Network Assets
                      </span>
                      <span className="text-base font-bold text-white print:text-slate-900">
                        {dashData.metrics.authorizedDevicesCount} Nodes
                      </span>
                    </div>
                    <div className="p-3 rounded-lg bg-[#080D1A] print:bg-slate-100 border border-slate-800 print:border-slate-300">
                      <span className="text-slate-400 print:text-slate-600 block">
                        CTF Arena Progress
                      </span>
                      <span className="text-base font-bold text-emerald-400 print:text-slate-900">
                        {dashData.metrics.ctfSolvedCount}/{dashData.metrics.ctfTotalCount} (
                        {dashData.metrics.ctfScorePoints} pts)
                      </span>
                    </div>
                    <div className="p-3 rounded-lg bg-[#080D1A] print:bg-slate-100 border border-slate-800 print:border-slate-300">
                      <span className="text-slate-400 print:text-slate-600 block">
                        Published Audit Reports
                      </span>
                      <span className="text-base font-bold text-white print:text-slate-900">
                        {dashData.metrics.reportsGenerated} Reports
                      </span>
                    </div>
                  </div>
                </section>
              )}

              {/* Top 4 Executive Metrics */}
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                <div
                  data-testid="security-posture-score-card"
                  className="relative overflow-hidden bg-[#0F172A] border border-cyan-500/40 rounded-xl p-5 shadow-[0_0_24px_-6px_rgba(34,211,238,0.22)]"
                >
                  <div
                    aria-hidden="true"
                    className="pointer-events-none absolute inset-0 rounded-xl border border-cyan-400/50 bg-cyan-400/[0.03] animate-pulse"
                  />
                  <div className="relative flex items-center justify-between">
                    <p className="text-xs text-slate-300 font-medium">Security Posture Score</p>
                    <span className="text-[11px] font-mono text-cyan-400 animate-pulse">
                      LIVE
                    </span>
                  </div>
                  <p className="relative text-2xl font-bold text-cyan-400 font-mono tabular-nums mt-1">
                    {dashData.metrics.securityPostureScore}/100
                  </p>
                  <p className="relative text-xs text-slate-400 mt-1">
                    Aggregated across {dashData.metrics.totalScansCompleted} domain scans
                  </p>
                </div>

                <div className="bg-[#0F172A] border border-slate-800 rounded-xl p-5">
                  <p className="text-xs text-slate-400">Authorized Network Assets</p>
                  <p className="text-2xl font-bold text-white font-mono tabular-nums mt-1">
                    {dashData.metrics.authorizedDevicesCount} Nodes
                  </p>
                  <p className="text-xs text-amber-400 mt-1">
                    {dashData.metrics.reviewRequiredDevices} endpoint flagged (Port 4444)
                  </p>
                </div>

                <div className="bg-[#0F172A] border border-slate-800 rounded-xl p-5">
                  <p className="text-xs text-slate-400">CTF Arena Progress</p>
                  <p className="text-2xl font-bold text-emerald-400 font-mono tabular-nums mt-1">
                    {dashData.metrics.ctfSolvedCount}/{dashData.metrics.ctfTotalCount} Flags (
                    {dashData.metrics.ctfScorePoints} pts)
                  </p>
                  <p className="text-xs text-slate-400 mt-1">
                    Isolated cryptography & log labs
                  </p>
                </div>

                <div className="bg-[#0F172A] border border-slate-800 rounded-xl p-5">
                  <p className="text-xs text-slate-400">Published Audit Reports</p>
                  <p className="text-2xl font-bold text-white font-mono tabular-nums mt-1">
                    {dashData.metrics.reportsGenerated} Reports
                  </p>
                  <p className="text-xs text-slate-400 mt-1">
                    JSON & printable PDF ready
                  </p>
                </div>
              </div>

              {/* Score Trend SVG Chart & Recent Scans Table */}
              <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
                <div className="lg:col-span-5 bg-[#0F172A] border border-slate-800 rounded-xl p-6 flex flex-col justify-between">
                  <div>
                    <h2 className="text-base font-semibold text-white mb-1">
                      Security Posture Score Trend
                    </h2>
                    <p className="text-xs text-slate-400 mb-4">
                      6-week defensive hardening trajectory across perimeter services.
                    </p>
                    <div className="bg-[#080D1A] border border-slate-800 rounded-lg p-4">
                      <svg
                        viewBox="0 0 360 150"
                        className="w-full h-36"
                        role="img"
                        aria-label="Security Posture Score Trend Chart"
                      >
                        <line x1="30" y1="25" x2="340" y2="25" stroke="#1e293b" strokeWidth="1" />
                        <line x1="30" y1="65" x2="340" y2="65" stroke="#1e293b" strokeWidth="1" />
                        <line x1="30" y1="105" x2="340" y2="105" stroke="#1e293b" strokeWidth="1" />
                        <polyline
                          fill="none"
                          stroke="#22d3ee"
                          strokeWidth="2.5"
                          points={dashData.scoreTrend
                            .map((pt, idx) => `${40 + idx * 56},${125 - pt.score}`)
                            .join(' ')}
                        />
                        {dashData.scoreTrend.map((pt, idx) => {
                          const x = 40 + idx * 56;
                          const y = 125 - pt.score;
                          return (
                            <g key={pt.label}>
                              <circle cx={x} cy={y} r="4" fill="#10b981" />
                              <text
                                x={x}
                                y="142"
                                textAnchor="middle"
                                fill="#94a3b8"
                                fontSize="9"
                                fontFamily="monospace"
                              >
                                {pt.label}
                              </text>
                              <text
                                x={x}
                                y={y - 8}
                                textAnchor="middle"
                                fill="#f8fafc"
                                fontSize="9"
                                fontFamily="monospace"
                              >
                                {pt.score}
                              </text>
                            </g>
                          );
                        })}
                      </svg>
                    </div>
                  </div>
                  <div className="mt-4 flex items-center justify-between text-xs text-slate-400">
                    <span>Baseline: NIST SP 800-53 / OWASP ASVS</span>
                    <button
                      type="button"
                      onClick={() => setCurrentPage('reports')}
                      className="text-cyan-400 hover:underline font-mono cursor-pointer"
                    >
                      Open Analytics →
                    </button>
                  </div>
                </div>

                {/* Recent Security Scans Table */}
                <div className="lg:col-span-7 bg-[#0F172A] border border-slate-800 rounded-xl p-6">
                  <div className="flex items-center justify-between mb-4">
                    <div>
                      <h2 className="text-base font-semibold text-white">
                        Recent Security Assessments & Telemetry
                      </h2>
                      <p className="text-xs text-slate-400">
                        Live ledger of HTTP header, SSL/TLS, and DNS inspections.
                      </p>
                    </div>
                    <button
                      type="button"
                      onClick={() => setCurrentPage('scanner')}
                      className="text-xs text-cyan-400 hover:underline font-mono cursor-pointer whitespace-nowrap"
                    >
                      Launch Scanner →
                    </button>
                  </div>

                  <div className="overflow-x-auto">
                    <table className="w-full text-left border-collapse text-xs">
                      <thead>
                        <tr className="border-b border-slate-800 text-slate-400">
                          <th className="py-2 px-2">Target</th>
                          <th className="py-2 px-2">Type</th>
                          <th className="py-2 px-2">Summary</th>
                          <th className="py-2 px-2 text-right whitespace-nowrap">Grade</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800/70">
                        {dashData.scanHistory.slice(0, 5).map((scan) => (
                          <tr key={scan.id} className="hover:bg-slate-900/50">
                            <td className="py-2.5 px-2 font-mono text-white font-medium whitespace-nowrap">
                              {scan.target}
                            </td>
                            <td className="py-2.5 px-2 text-cyan-300 font-mono whitespace-nowrap">
                              {scan.scanType}
                            </td>
                            <td className="py-2.5 px-2 text-slate-300 max-w-[180px] truncate">
                              {scan.findingsSummary}
                            </td>
                            <td className="py-2.5 px-2 text-right font-mono tabular-nums font-bold text-emerald-400 whitespace-nowrap">
                              {scan.grade} ({scan.score})
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              </div>

              {/* Interactive 10-Module Quick Launcher with Search Filter */}
              <div className="bg-[#0F172A] border border-slate-800 rounded-xl p-6">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-5">
                  <div>
                    <h2 className="text-base font-semibold text-white">
                      CyberScope Workstation Directory
                    </h2>
                    <p className="text-xs text-slate-400">
                      Filter or select any module below to switch active SOC workstations.
                    </p>
                  </div>
                  <div className="w-full sm:w-64">
                    <label htmlFor="dashboard-module-filter" className="sr-only">
                      Filter Workstations
                    </label>
                    <input
                      id="dashboard-module-filter"
                      type="text"
                      value={globalFilter}
                      onChange={(e) => setGlobalFilter(e.target.value)}
                      placeholder="Filter modules (e.g. crypto, ctf)..."
                      className="w-full px-3.5 py-1.5 text-xs bg-[#080D1A] border border-slate-700 rounded-lg text-white focus:outline-none focus:border-cyan-400"
                    />
                  </div>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3.5">
                  {filteredModules.map((mod) => {
                    const Icon = mod.icon;
                    return (
                      <button
                        key={mod.id}
                        type="button"
                        aria-label={`Launch ${mod.label} Workstation`}
                        onClick={() => setCurrentPage(mod.id)}
                        className="text-left p-4 rounded-xl bg-[#080D1A] hover:bg-[#131D35] border border-slate-800 hover:border-cyan-500/50 transition-all flex items-center justify-between group cursor-pointer"
                      >
                        <div className="flex items-center gap-3 min-w-0">
                          <Icon className="w-4 h-4 text-cyan-400 shrink-0" />
                          <span className="text-xs font-semibold text-white group-hover:text-cyan-300 truncate">
                            {mod.label}
                          </span>
                        </div>
                        <ArrowUpRight className="w-3.5 h-3.5 text-slate-500 group-hover:text-cyan-400 shrink-0" />
                      </button>
                    );
                  })}
                </div>
              </div>
            </div>
          )}

          {(currentPage === 'network' || currentPage === 'scanner') && (
            <ModulesNetworkAndScanner
              mode={currentPage}
              initialDevices={dashData.networkDevices}
              onScanComplete={refreshDashboard}
            />
          )}

          {(currentPage === 'terminal' ||
            currentPage === 'threats' ||
            currentPage === 'crypto') && (
            <ModulesTerminalAndThreats
              mode={currentPage}
              onCryptoLogged={refreshDashboard}
            />
          )}

          {(currentPage === 'ctf' ||
            currentPage === 'weblab' ||
            currentPage === 'forensics') && (
            <ModulesCtfWebForensics
              mode={currentPage}
              onProgressUpdate={refreshDashboard}
            />
          )}

          {(currentPage === 'tutor' ||
            currentPage === 'reports' ||
            currentPage === 'settings' ||
            currentPage === 'about') && (
            <ModulesTutorReportsSettingsAbout
              mode={currentPage}
              analyst={analyst}
              reports={dashData.reports}
              scanHistory={dashData.scanHistory}
              learningProgress={dashData.learningProgress}
              onReportCreated={refreshDashboard}
            />
          )}
        </main>
      </div>
    </div>
  );
}
