'use client';

import React, { useState } from 'react';
import {
  Shield,
  Terminal,
  Globe,
  Lock,
  Search,
  Flag,
  Code2,
  FileSearch,
  Bot,
  BarChart3,
  ArrowRight,
  CheckCircle2,
  AlertTriangle,
  KeyRound,
  Server,
} from 'lucide-react';
import { evaluatePasswordStrength } from '@/lib/cyber-engine';

export type NavPageId =
  | 'landing'
  | 'login'
  | 'register'
  | 'dashboard'
  | 'network'
  | 'scanner'
  | 'terminal'
  | 'threats'
  | 'crypto'
  | 'ctf'
  | 'weblab'
  | 'forensics'
  | 'tutor'
  | 'reports'
  | 'settings'
  | 'about';

export interface ActiveAnalyst {
  id: string;
  username: string;
  email: string;
  role: string;
  clearance: string;
}

interface LandingAndAuthProps {
  currentPage: 'landing' | 'login' | 'register';
  onNavigate: (page: NavPageId) => void;
  onAuthenticated: (user: ActiveAnalyst) => void;
}

const TEN_MODULES_OVERVIEW: Array<{
  id: NavPageId;
  index: string;
  title: string;
  domain: string;
  summary: string;
  icon: React.ComponentType<{ className?: string }>;
}> = [
  {
    id: 'network',
    index: '01.',
    title: 'Network Intelligence',
    domain: 'DNS · Topology · PCAP',
    summary:
      'Inspect public IP telemetry, resolve live DNS records, map authorized device inventory, and dissect offline PCAP metadata.',
    icon: Globe,
  },
  {
    id: 'scanner',
    index: '02.',
    title: 'Security Scanner',
    domain: 'TLS · HTTP Headers · Entropy',
    summary:
      'Audit SSL/TLS certificates, evaluate defensive HTTP response headers with SSRF protection, and estimate password crack resistance.',
    icon: Shield,
  },
  {
    id: 'terminal',
    index: '03.',
    title: 'Cyber Terminal',
    domain: 'Linux Sandbox · Python Lab',
    summary:
      'Practice defensive reconnaissance, socket inspection, and security scripting inside a restricted Linux and Python simulator.',
    icon: Terminal,
  },
  {
    id: 'threats',
    index: '04.',
    title: 'Threat Intelligence',
    domain: 'CVE · CVSS v3.1 · Phishing',
    summary:
      'Query vulnerability advisories, inspect CVSS severity vectors, evaluate domain reputation heuristics, and review malware profiles.',
    icon: Search,
  },
  {
    id: 'crypto',
    index: '05.',
    title: 'Cryptography Lab',
    domain: 'SHA-2/512 · AES-GCM · RSA',
    summary:
      'Compute cryptographic digests, test classical Caesar and Vigenère ciphers, and verify authenticated AES-256-GCM and RSA signatures.',
    icon: Lock,
  },
  {
    id: 'ctf',
    index: '06.',
    title: 'CTF Arena',
    domain: 'Challenges · Hints · Scoring',
    summary:
      'Solve isolated Capture-The-Flag scenarios spanning cryptography, SSH log forensics, packet inspection, and SQL parameterization.',
    icon: Flag,
  },
  {
    id: 'weblab',
    index: '07.',
    title: 'Web Security Lab',
    domain: 'SQLi · XSS · CORS · Cookies',
    summary:
      'Compare vulnerable string concatenation against parameterized queries, test output encoding, and inspect Same-Origin policies.',
    icon: Code2,
  },
  {
    id: 'forensics',
    index: '08.',
    title: 'Digital Forensics',
    domain: 'Magic Bytes · SHA-256 · Timelines',
    summary:
      'Identify disguised binary headers, verify evidence hashes, and reconstruct chronological intrusion timelines from server logs.',
    icon: FileSearch,
  },
  {
    id: 'tutor',
    index: '09.',
    title: 'AI Cyber Tutor',
    domain: 'Server-Side Gemini · Remediation',
    summary:
      'Request structured explanations of CVEs, terminal commands, and defensive code remediation via server-side Gemini intelligence.',
    icon: Bot,
  },
  {
    id: 'reports',
    index: '10.',
    title: 'Reports & Analytics',
    domain: 'Posture Trends · Exports',
    summary:
      'Track organizational security scores, review historical scan ledgers, monitor lab completion, and export structured audit reports.',
    icon: BarChart3,
  },
];

export default function LandingAndAuthView({
  currentPage,
  onNavigate,
  onAuthenticated,
}: LandingAndAuthProps) {
  const [email, setEmail] = useState('elena.vance@cyberscope.sec');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('CyberScope#2026!');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const passwordMetrics = evaluatePasswordStrength(password);

  const handleAuthSubmit = async (e: React.FormEvent, action: 'login' | 'register') => {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      const res = await fetch('/api/auth', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          action,
          email,
          username: action === 'register' ? username : email,
          password,
        }),
      });
      const data = await res.json();
      if (!res.ok || data.status === 'error') {
        setError(data.error || 'Authentication failed.');
      } else {
        onAuthenticated(data.user);
      }
    } catch {
      setError('Unable to reach authentication endpoint.');
    } finally {
      setLoading(false);
    }
  };

  const handleQuickDemoLogin = () => {
    onAuthenticated({
      id: 'usr-soc-01',
      username: 'elena.vance',
      email: 'elena.vance@cyberscope.sec',
      role: 'Lead Defensive Security Architect',
      clearance: 'SOC Tier-3 // Blue Team Lead',
    });
  };

  if (currentPage === 'login' || currentPage === 'register') {
    const isRegister = currentPage === 'register';
    return (
      <div className="min-h-screen bg-[#080D1A] text-slate-100 flex flex-col">
        <header className="flex items-center justify-between gap-8 px-6 py-4 border-b border-slate-800/80 bg-[#0B1120]">
          <button
            type="button"
            onClick={() => onNavigate('landing')}
            className="text-lg font-bold tracking-tight text-white whitespace-nowrap shrink-0 cursor-pointer"
          >
            CyberScope
          </button>
          <nav className="hidden md:flex items-center gap-6 text-sm font-medium text-slate-400">
            <button
              type="button"
              onClick={() => onNavigate('landing')}
              className="hover:text-white transition-colors whitespace-nowrap shrink-0"
            >
              Overview
            </button>
            <button
              type="button"
              onClick={() => onNavigate('dashboard')}
              className="hover:text-white transition-colors whitespace-nowrap shrink-0"
            >
              SOC Console
            </button>
            <button
              type="button"
              onClick={() => onNavigate('about')}
              className="hover:text-white transition-colors whitespace-nowrap shrink-0"
            >
              Flask Architecture
            </button>
          </nav>
          <div className="flex items-center gap-3 shrink-0">
            <button
              type="button"
              onClick={handleQuickDemoLogin}
              className="px-4 py-2 text-xs font-semibold text-slate-950 bg-cyan-400 rounded-lg hover:bg-cyan-300 transition-colors whitespace-nowrap shrink-0"
            >
              Enter Demo SOC
            </button>
          </div>
        </header>

        <main className="flex-1 flex items-center justify-center p-6">
          <div className="w-full max-w-md bg-[#0F172A] border border-slate-800 rounded-xl p-8">
            <div className="mb-6">
              <p className="text-xs font-mono text-cyan-400 mb-1">
                PBKDF2-SHA512 · 100,000 ITERATIONS · HTTPS SESSION
              </p>
              <h1 className="text-2xl font-bold text-white">
                {isRegister ? 'Create Analyst Account' : 'Sign In to CyberScope SOC'}
              </h1>
              <p className="text-sm text-slate-400 mt-1">
                {isRegister
                  ? 'Register a defensive operator profile to persist scans, CTF flags, and reports.'
                  : 'Authenticate with your analyst credentials or launch the pre-seeded SOC session.'}
              </p>
            </div>

            {error && (
              <div
                role="alert"
                className="mb-5 p-3.5 rounded-lg bg-red-950/50 border border-red-800/70 text-xs text-red-200 flex items-start gap-2.5"
              >
                <AlertTriangle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
                <span>{error}</span>
              </div>
            )}

            <form
              onSubmit={(e) => handleAuthSubmit(e, isRegister ? 'register' : 'login')}
              className="space-y-4"
            >
              {isRegister && (
                <div>
                  <label
                    htmlFor="auth-username"
                    className="block text-xs font-medium text-slate-300 mb-1.5"
                  >
                    Analyst Handle
                  </label>
                  <input
                    id="auth-username"
                    type="text"
                    required
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    placeholder="e.g. marcus.chen"
                    className="w-full px-3.5 py-2.5 text-sm bg-[#080D1A] border border-slate-700 rounded-lg text-white focus:outline-none focus:border-cyan-400"
                  />
                </div>
              )}

              <div>
                <label
                  htmlFor="auth-email"
                  className="block text-xs font-medium text-slate-300 mb-1.5"
                >
                  {isRegister ? 'Work Email Address' : 'Email or Analyst Handle'}
                </label>
                <input
                  id="auth-email"
                  type="text"
                  required
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="elena.vance@cyberscope.sec"
                  className="w-full px-3.5 py-2.5 text-sm bg-[#080D1A] border border-slate-700 rounded-lg text-white focus:outline-none focus:border-cyan-400"
                />
              </div>

              <div>
                <div className="flex items-center justify-between mb-1.5">
                  <label
                    htmlFor="auth-password"
                    className="block text-xs font-medium text-slate-300"
                  >
                    Passphrase
                  </label>
                  <span className="text-xs font-mono tabular-nums text-slate-400">
                    Entropy: {passwordMetrics.entropyBits} bits ({passwordMetrics.rating})
                  </span>
                </div>
                <input
                  id="auth-password"
                  type="password"
                  required
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="w-full px-3.5 py-2.5 text-sm bg-[#080D1A] border border-slate-700 rounded-lg text-white font-mono focus:outline-none focus:border-cyan-400"
                />
              </div>

              <button
                type="submit"
                disabled={loading}
                className="w-full py-2.5 px-4 text-sm font-semibold text-slate-950 bg-cyan-400 hover:bg-cyan-300 rounded-lg transition-colors cursor-pointer disabled:opacity-50"
              >
                {loading
                  ? 'Verifying Credentials...'
                  : isRegister
                  ? 'Register & Open SOC Console'
                  : 'Sign In to SOC Console'}
              </button>
            </form>

            <div className="mt-5 pt-5 border-t border-slate-800 space-y-3">
              <button
                type="button"
                onClick={handleQuickDemoLogin}
                className="w-full py-2 px-4 text-xs font-medium text-cyan-300 bg-slate-900 hover:bg-slate-800 border border-slate-700 rounded-lg transition-colors flex items-center justify-center gap-2 cursor-pointer"
              >
                <KeyRound className="w-3.5 h-3.5" />
                <span>Quick Sign In as Demo Lead (Elena Vance)</span>
              </button>

              <div className="text-center text-xs text-slate-400">
                {isRegister ? (
                  <>
                    Already registered?{' '}
                    <button
                      type="button"
                      onClick={() => onNavigate('login')}
                      className="text-cyan-400 hover:underline font-medium"
                    >
                      Sign In
                    </button>
                  </>
                ) : (
                  <>
                    Need a new operator account?{' '}
                    <button
                      type="button"
                      onClick={() => onNavigate('register')}
                      className="text-cyan-400 hover:underline font-medium"
                    >
                      Create Account
                    </button>
                  </>
                )}
              </div>
            </div>
          </div>
        </main>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-[#080D1A] text-slate-100 flex flex-col">
      {/* Strict 3-Zone Top Bar Contract */}
      <header className="flex items-center justify-between gap-8 px-6 lg:px-12 py-4 border-b border-slate-800/80 bg-[#0B1120]/90 sticky top-0 z-30 backdrop-blur-md">
        <a
          href="#top"
          onClick={(e) => {
            e.preventDefault();
            onNavigate('landing');
          }}
          className="text-lg font-bold tracking-tight text-white whitespace-nowrap shrink-0"
        >
          CyberScope
        </a>

        <nav className="hidden md:flex items-center gap-6 text-sm font-medium text-slate-300">
          <a
            href="#modules"
            className="hover:text-white transition-colors whitespace-nowrap shrink-0"
          >
            Core Modules
          </a>
          <button
            type="button"
            onClick={() => onNavigate('scanner')}
            className="hover:text-white transition-colors whitespace-nowrap shrink-0 cursor-pointer"
          >
            Security Scanner
          </button>
          <button
            type="button"
            onClick={() => onNavigate('ctf')}
            className="hover:text-white transition-colors whitespace-nowrap shrink-0 cursor-pointer"
          >
            CTF Arena
          </button>
          <button
            type="button"
            onClick={() => onNavigate('about')}
            className="hover:text-white transition-colors whitespace-nowrap shrink-0 cursor-pointer"
          >
            Flask Blueprint
          </button>
          <button
            type="button"
            onClick={() => onNavigate('login')}
            className="hover:text-white transition-colors whitespace-nowrap shrink-0 cursor-pointer"
          >
            Sign In
          </button>
        </nav>

        <div className="flex items-center gap-3 shrink-0">
          <button
            type="button"
            onClick={() => onNavigate('dashboard')}
            className="px-4 py-2 text-xs font-semibold text-slate-950 bg-cyan-400 rounded-lg hover:bg-cyan-300 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
          >
            Launch SOC Console
          </button>
        </div>
      </header>

      {/* Hero Section */}
      <section className="px-6 lg:px-12 py-16 lg:py-20 max-w-7xl mx-auto w-full">
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-12 items-stretch">
          <div className="lg:col-span-7 flex flex-col justify-center">
            <p className="text-xs font-mono text-cyan-400 tracking-wide mb-4">
              LEARN · ANALYZE · DETECT · DEFEND
            </p>
            <h1
              className="text-4xl sm:text-5xl font-bold text-white tracking-tight leading-[1.12] mb-6"
              style={{ textWrap: 'balance' }}
            >
              Browser-Native Security Operations & Defensive Engineering Platform
            </h1>
            <p className="text-base text-slate-300 leading-relaxed max-w-2xl mb-8">
              CyberScope unifies 10 defensive cybersecurity workstations in a single HTTPS web
              interface: live DNS and TLS inspection, SSRF-hardened HTTP header auditing,
              cryptography primitives, digital forensics, isolated CTF challenges, and a
              server-side Gemini AI Cyber Tutor.
            </p>

            <div className="flex flex-wrap items-center gap-4">
              <button
                type="button"
                onClick={() => onNavigate('dashboard')}
                className="px-6 py-3 text-sm font-semibold text-slate-950 bg-cyan-400 hover:bg-cyan-300 rounded-lg transition-colors flex items-center gap-2 whitespace-nowrap shrink-0 cursor-pointer"
              >
                <span>Open Main SOC Dashboard</span>
                <ArrowRight className="w-4 h-4" />
              </button>
              <button
                type="button"
                onClick={() => onNavigate('login')}
                className="px-5 py-3 text-sm font-medium text-slate-200 bg-[#0F172A] hover:bg-slate-800 border border-slate-700 rounded-lg transition-colors whitespace-nowrap shrink-0 cursor-pointer"
              >
                Analyst Login / Register
              </button>
              <button
                type="button"
                onClick={() => onNavigate('about')}
                className="px-5 py-3 text-sm font-medium text-slate-300 hover:text-white transition-colors whitespace-nowrap shrink-0 cursor-pointer"
              >
                View Python Flask & Pydroid 3 Guide
              </button>
            </div>
          </div>

          {/* Right Column: Live Interactive Posture Preview Terminal */}
          <div className="lg:col-span-5 bg-[#0F172A] border border-slate-800 rounded-xl p-6 flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between pb-4 mb-4 border-b border-slate-800">
                <span className="text-xs font-mono text-slate-300">
                  cyberscope-soc-01 · perimeter-audit
                </span>
                <span className="text-xs font-mono text-emerald-400 tabular-nums">
                  TLSv1.3 · SSRF Guard Active
                </span>
              </div>
              <pre className="text-xs font-mono text-slate-300 leading-relaxed overflow-x-auto whitespace-pre-wrap">
{`$ cyberscope scan --headers https://cloudflare.com
[PASS] Strict-Transport-Security: max-age=31536000
[PASS] Content-Security-Policy: frame-ancestors 'none'
[PASS] X-Content-Type-Options: nosniff
[PASS] X-Frame-Options: DENY

$ cyberscope verify --ssrf http://127.0.0.1:8080
[BLOCKED] RFC1918 & Loopback targets rejected

$ cyberscope forensics --magic invoice_q4.pdf
[ALERT] Header 7F 45 4C 46 matches ELF Executable`}
              </pre>
            </div>

            <div className="mt-6 pt-4 border-t border-slate-800 flex items-center justify-between text-xs text-slate-400">
              <span>Zero APK or browser extension required</span>
              <button
                type="button"
                onClick={() => onNavigate('terminal')}
                className="text-cyan-400 hover:underline font-mono cursor-pointer"
              >
                Launch Interactive Terminal →
              </button>
            </div>
          </div>
        </div>

        {/* Full-Width 4-Column Quantitative Proof Strip */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mt-12 pt-10 border-t border-slate-800/80">
          <div className="bg-[#0F172A] border border-slate-800/90 rounded-xl p-5">
            <p className="text-xs text-slate-400 mb-1">Integrated Workstations</p>
            <p className="text-2xl font-bold text-white font-mono tabular-nums">
              10 Core Modules
            </p>
            <p className="text-xs text-slate-400 mt-1">
              Network · Scanner · Crypto · CTF · Forensics · AI
            </p>
          </div>
          <div className="bg-[#0F172A] border border-slate-800/90 rounded-xl p-5">
            <p className="text-xs text-slate-400 mb-1">Defensive API Controls</p>
            <p className="text-2xl font-bold text-cyan-400 font-mono tabular-nums">
              SSRF & Rate Guard
            </p>
            <p className="text-xs text-slate-400 mt-1">
              Blocks RFC1918, loopback & cloud metadata IPs
            </p>
          </div>
          <div className="bg-[#0F172A] border border-slate-800/90 rounded-xl p-5">
            <p className="text-xs text-slate-400 mb-1">Cryptographic Primitives</p>
            <p className="text-2xl font-bold text-emerald-400 font-mono tabular-nums">
              SHA-512 · AES-GCM
            </p>
            <p className="text-xs text-slate-400 mt-1">
              Plus 2048-bit RSA signatures & PBKDF2 auth
            </p>
          </div>
          <div className="bg-[#0F172A] border border-slate-800/90 rounded-xl p-5">
            <p className="text-xs text-slate-400 mb-1">Dual Deployment Stack</p>
            <p className="text-2xl font-bold text-white font-mono tabular-nums">
              Web + Flask SQL
            </p>
            <p className="text-xs text-slate-400 mt-1">
              Live HTTPS Web App + Python/Pydroid 3 Blueprint
            </p>
          </div>
        </div>
      </section>

      {/* Ten Core Modules Directory */}
      <section id="modules" className="px-6 lg:px-12 py-14 bg-[#0B1120] border-t border-slate-800/80">
        <div className="max-w-7xl mx-auto">
          <div className="flex flex-col md:flex-row md:items-end justify-between mb-10 gap-4">
            <div>
              <p className="text-xs font-mono text-cyan-400 mb-2">
                UNIFIED SECURITY OPERATIONS ARCHITECTURE
              </p>
              <h2 className="text-2xl sm:text-3xl font-bold text-white">
                Ten Specialized Cybersecurity Workstations
              </h2>
            </div>
            <p className="text-sm text-slate-400 max-w-md">
              Select any module card below to open that workstation directly inside the
              CyberScope console.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
            {TEN_MODULES_OVERVIEW.map((mod) => {
              const Icon = mod.icon;
              return (
                <button
                  key={mod.id}
                  type="button"
                  onClick={() => onNavigate(mod.id)}
                  className="text-left bg-[#0F172A] hover:bg-[#131D35] border border-slate-800 hover:border-cyan-500/50 rounded-xl p-6 transition-all flex flex-col justify-between group cursor-pointer"
                >
                  <div>
                    <div className="flex items-center justify-between mb-4">
                      <span className="text-xs font-mono text-cyan-400">
                        {mod.index} · {mod.domain}
                      </span>
                      <Icon className="w-4 h-4 text-slate-400 group-hover:text-cyan-400 transition-colors" />
                    </div>
                    <h3 className="text-lg font-semibold text-white mb-2 group-hover:text-cyan-300 transition-colors">
                      {mod.title}
                    </h3>
                    <p className="text-sm text-slate-400 leading-relaxed">{mod.summary}</p>
                  </div>
                  <div className="mt-5 pt-4 border-t border-slate-800/80 flex items-center justify-between text-xs font-medium text-cyan-400">
                    <span>Open Workstation</span>
                    <ArrowRight className="w-3.5 h-3.5" />
                  </div>
                </button>
              );
            })}
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="px-6 lg:px-12 py-8 border-t border-slate-800/80 bg-[#080D1A] text-xs text-slate-400">
        <div className="max-w-7xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <span className="font-semibold text-slate-200">CyberScope v1.0</span>
            <span aria-hidden="true">·</span>
            <span>Learn. Analyze. Detect. Defend.</span>
            <span aria-hidden="true">·</span>
            <span>Authorized Defensive Assessment Platform</span>
          </div>
          <div className="flex items-center gap-5">
            <button
              type="button"
              onClick={() => onNavigate('dashboard')}
              className="hover:text-white transition-colors cursor-pointer"
            >
              Dashboard
            </button>
            <button
              type="button"
              onClick={() => onNavigate('about')}
              className="hover:text-white transition-colors cursor-pointer"
            >
              Python Flask & Deployment Guide
            </button>
            <button
              type="button"
              onClick={() => onNavigate('settings')}
              className="hover:text-white transition-colors cursor-pointer"
            >
              Security Settings
            </button>
          </div>
        </div>
      </footer>
    </div>
  );
}
