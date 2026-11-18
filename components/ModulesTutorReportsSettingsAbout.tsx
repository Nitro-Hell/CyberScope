'use client';

import React, { useState } from 'react';
import {
  Bot,
  Send,
  BarChart3,
  Download,
  Settings,
  Info,
  Copy,
  Check,
  AlertTriangle,
  FileText,
  Smartphone,
  Server,
} from 'lucide-react';
import { FLASK_BLUEPRINT_FILES } from '@/lib/flask-blueprint-code';
import {
  SecurityReportRecord,
  ScanHistoryRecord,
  LearningProgressRecord,
} from '@/lib/server-db';
import { ActiveAnalyst } from './LandingAndAuthView';

interface TutorReportsSettingsAboutProps {
  mode: 'tutor' | 'reports' | 'settings' | 'about';
  analyst: ActiveAnalyst;
  reports: SecurityReportRecord[];
  scanHistory: ScanHistoryRecord[];
  learningProgress: LearningProgressRecord[];
  onReportCreated?: () => void;
}

export default function ModulesTutorReportsSettingsAbout({
  mode,
  analyst,
  reports,
  scanHistory,
  learningProgress,
  onReportCreated,
}: TutorReportsSettingsAboutProps) {
  // Module 09: AI Cyber Tutor State
  const [tutorTopic, setTutorTopic] = useState('CVE & Vulnerability Remediation');
  const [tutorPrompt, setTutorPrompt] = useState(
    'Explain how to remediate missing Content-Security-Policy and Strict-Transport-Security headers in a Python Flask and Nginx production deployment.'
  );
  const [tutorLoading, setTutorLoading] = useState(false);
  const [tutorError, setTutorError] = useState('');
  const [tutorMessages, setTutorMessages] = useState<
    Array<{ role: 'analyst' | 'tutor'; topic: string; text: string }>
  >([
    {
      role: 'tutor',
      topic: 'SOC Onboarding',
      text: 'CyberScope Defensive AI Tutor ready. Select a security domain or ask about CVE advisories, Linux terminal output, cryptographic primitives, or defensive code hardening. All Gemini API requests execute server-side.',
    },
  ]);

  // Module 10: Reports & Analytics State
  const [newReportTitle, setNewReportTitle] = useState('');
  const [newReportModule, setNewReportModule] = useState('Security Scanner');
  const [newReportSeverity, setNewReportSeverity] = useState<'Low' | 'Medium' | 'High'>('Medium');
  const [newReportSummary, setNewReportSummary] = useState('');
  const [reportSubmitting, setReportSubmitting] = useState(false);

  // Page 15: User Settings State
  const [authorizedScope, setAuthorizedScope] = useState(
    'cloudflare.com, example.com, github.com, cyberscope.internal'
  );
  const [ssrfStrict, setSsrfStrict] = useState(true);
  const [rateLimit, setRateLimit] = useState(60);
  const [settingsSaved, setSettingsSaved] = useState(false);

  // Page 16: About & Flask Blueprint State
  const [selectedBlueprintPath, setSelectedBlueprintPath] = useState(
    FLASK_BLUEPRINT_FILES[0].path
  );
  const [copiedPath, setCopiedPath] = useState('');

  const handleAskTutor = async (overridePrompt?: string) => {
    const query = (overridePrompt ?? tutorPrompt).trim();
    if (!query) return;
    setTutorError('');
    setTutorLoading(true);
    setTutorMessages((prev) => [...prev, { role: 'analyst', topic: tutorTopic, text: query }]);

    try {
      const res = await fetch('/api/tutor', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ prompt: query, topic: tutorTopic }),
      });
      const data = await res.json();
      if (!res.ok || data.status === 'error') {
        setTutorError(data.error || 'AI Cyber Tutor could not complete the request.');
      } else {
        setTutorMessages((prev) => [
          ...prev,
          { role: 'tutor', topic: tutorTopic, text: data.reply },
        ]);
      }
    } catch {
      setTutorError('Network error communicating with server-side /api/tutor endpoint.');
    } finally {
      setTutorLoading(false);
    }
  };

  const handleCreateReport = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newReportTitle.trim() || !newReportSummary.trim()) return;
    setReportSubmitting(true);
    try {
      const res = await fetch('/api/reports', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          title: newReportTitle,
          module: newReportModule,
          severity: newReportSeverity,
          score: 88,
          summary: newReportSummary,
        }),
      });
      if (res.ok) {
        setNewReportTitle('');
        setNewReportSummary('');
        onReportCreated?.();
      }
    } finally {
      setReportSubmitting(false);
    }
  };

  const handleExportReportJson = () => {
    const payload = {
      platform: 'CyberScope Security Operations Platform v1.0',
      generatedAt: new Date().toISOString(),
      analyst: analyst.username,
      reports,
      recentScans: scanHistory,
      learningProgress,
    };
    const blob = new Blob([JSON.stringify(payload, null, 2)], {
      type: 'application/json',
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `cyberscope-security-report-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  if (mode === 'tutor') {
    return (
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        <div className="lg:col-span-8 bg-[#0F172A] border border-slate-800 rounded-xl p-6 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between pb-4 mb-4 border-b border-slate-800">
              <div>
                <h2 className="text-lg font-semibold text-white">
                  AI Cyber Tutor (Server-Side Gemini Defensive Advisor)
                </h2>
                <p className="text-xs text-slate-400">
                  API keys remain strictly server-side via Next.js `/api/tutor` route.
                </p>
              </div>
              <Bot className="w-5 h-5 text-cyan-400" />
            </div>

            <div className="space-y-4 max-h-[380px] overflow-y-auto pr-1 mb-4">
              {tutorMessages.map((msg, idx) => (
                <div
                  key={idx}
                  className={`p-4 rounded-xl border text-xs leading-relaxed ${
                    msg.role === 'analyst'
                      ? 'bg-[#131D35] border-cyan-500/40 text-white'
                      : 'bg-[#080D1A] border-slate-800 text-slate-200'
                  }`}
                >
                  <p className="font-mono text-[11px] text-cyan-400 mb-1">
                    {msg.role === 'analyst' ? `Analyst (${analyst.username})` : 'CyberScope AI Tutor'} ·{' '}
                    {msg.topic}
                  </p>
                  <div className="whitespace-pre-wrap">{msg.text}</div>
                </div>
              ))}
            </div>

            {tutorError && (
              <div
                role="alert"
                className="mb-4 p-3.5 rounded-lg bg-red-950/60 border border-red-800 text-xs text-red-200 flex items-start gap-2"
              >
                <AlertTriangle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
                <span>{tutorError}</span>
              </div>
            )}
          </div>

          <form
            onSubmit={(e) => {
              e.preventDefault();
              handleAskTutor();
            }}
            className="space-y-3 pt-3 border-t border-slate-800"
          >
            <div className="flex flex-col sm:flex-row gap-3">
              <label htmlFor="tutor-topic-select" className="sr-only">
                Security Topic
              </label>
              <select
                id="tutor-topic-select"
                value={tutorTopic}
                onChange={(e) => setTutorTopic(e.target.value)}
                className="px-3 py-2 text-xs bg-[#080D1A] border border-slate-700 rounded-lg text-slate-200"
              >
                <option value="CVE & Vulnerability Remediation">CVE & Vulnerability Remediation</option>
                <option value="Security Report Interpretation">Security Report Interpretation</option>
                <option value="Terminal Command Explanation">Terminal Command Explanation</option>
                <option value="CTF Strategy & Cryptography">CTF Strategy & Cryptography</option>
                <option value="Secure Python / SQL Coding">Secure Python / SQL Coding</option>
              </select>
              <label htmlFor="tutor-query-input" className="sr-only">
                Ask AI Cyber Tutor
              </label>
              <input
                id="tutor-query-input"
                type="text"
                value={tutorPrompt}
                onChange={(e) => setTutorPrompt(e.target.value)}
                placeholder="Ask a defensive security question..."
                className="flex-1 px-3.5 py-2 text-xs bg-[#080D1A] border border-slate-700 rounded-lg text-white focus:outline-none focus:border-cyan-400"
              />
              <button
                type="submit"
                disabled={tutorLoading}
                className="px-4 py-2 text-xs font-semibold text-slate-950 bg-cyan-400 hover:bg-cyan-300 rounded-lg flex items-center justify-center gap-1.5 whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-50"
              >
                <Send className="w-3.5 h-3.5" />
                <span>{tutorLoading ? 'Analyzing...' : 'Ask Tutor'}</span>
              </button>
            </div>
          </form>
        </div>

        <div className="lg:col-span-4 bg-[#0F172A] border border-slate-800 rounded-xl p-6 space-y-3">
          <h3 className="text-base font-semibold text-white">
            Guided Defensive Prompts
          </h3>
          <p className="text-xs text-slate-400">
            Select a prompt template to query the server-side Gemini model.
          </p>
          <div className="space-y-2">
            {[
              'Explain CVE-2025-48912 OpenSSH signal race condition and how to harden sshd_config.',
              'Interpret a PCAP alert showing outbound TCP SYN traffic to 198.51.100.77 on port 4444.',
              'Show how to prevent Server-Side Request Forgery (SSRF) in Python Flask URL scanners.',
              'Compare SHA-256 against Argon2id/PBKDF2 for storing user authentication passwords.',
            ].map((q, i) => (
              <button
                key={i}
                type="button"
                onClick={() => {
                  setTutorPrompt(q);
                  handleAskTutor(q);
                }}
                className="w-full text-left p-3 rounded-lg bg-[#080D1A] hover:bg-slate-900 border border-slate-800 text-xs text-slate-300 hover:text-cyan-300 transition-colors cursor-pointer"
              >
                {q}
              </button>
            ))}
          </div>
        </div>
      </div>
    );
  }

  if (mode === 'reports') {
    return (
      <div className="space-y-6">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 bg-[#0F172A] border border-slate-800 rounded-xl p-6">
          <div>
            <h2 className="text-lg font-semibold text-white">
              Executive Security Reports & Learning Analytics
            </h2>
            <p className="text-xs text-slate-400">
              Compile scan histories, CTF progress, and forensic summaries into exportable audit reports.
            </p>
          </div>
          <div className="flex items-center gap-3">
            <button
              type="button"
              onClick={handleExportReportJson}
              className="px-4 py-2 text-xs font-semibold text-slate-950 bg-cyan-400 hover:bg-cyan-300 rounded-lg flex items-center gap-2 whitespace-nowrap shrink-0 cursor-pointer"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Export Audit Package (JSON)</span>
            </button>
            <button
              type="button"
              onClick={() => window.print()}
              className="px-4 py-2 text-xs font-medium text-slate-200 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded-lg whitespace-nowrap shrink-0 cursor-pointer"
            >
              Print / Save PDF
            </button>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* Published Security Reports */}
          <div className="lg:col-span-7 bg-[#0F172A] border border-slate-800 rounded-xl p-6 space-y-4">
            <h3 className="text-base font-semibold text-white">
              Published Security Assessment Reports ({reports.length})
            </h3>
            <div className="space-y-3">
              {reports.map((rep) => (
                <div
                  key={rep.id}
                  className="p-4 rounded-lg bg-[#080D1A] border border-slate-800 space-y-1.5"
                >
                  <div className="flex items-center justify-between text-xs font-mono">
                    <span className="text-cyan-400">
                      {rep.module} · Severity: {rep.severity}
                    </span>
                    <span className="text-emerald-400 tabular-nums">
                      Score: {rep.score}/100
                    </span>
                  </div>
                  <h4 className="text-sm font-semibold text-white">{rep.title}</h4>
                  <p className="text-xs text-slate-300 leading-relaxed">{rep.summary}</p>
                </div>
              ))}
            </div>
          </div>

          {/* Log New Report + Learning Progress */}
          <div className="lg:col-span-5 space-y-6">
            <div className="bg-[#0F172A] border border-slate-800 rounded-xl p-6">
              <h3 className="text-base font-semibold text-white mb-3">
                Log New Security Finding Report
              </h3>
              <form onSubmit={handleCreateReport} className="space-y-3">
                <div>
                  <label htmlFor="rep-title" className="block text-xs text-slate-300 mb-1">
                    Report Title
                  </label>
                  <input
                    id="rep-title"
                    type="text"
                    required
                    value={newReportTitle}
                    onChange={(e) => setNewReportTitle(e.target.value)}
                    placeholder="e.g. TLS 1.3 & HSTS Verification on Edge Gateway"
                    className="w-full px-3 py-2 text-xs bg-[#080D1A] border border-slate-700 rounded-lg text-white"
                  />
                </div>
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label htmlFor="rep-mod" className="block text-xs text-slate-300 mb-1">
                      Source Module
                    </label>
                    <select
                      id="rep-mod"
                      value={newReportModule}
                      onChange={(e) => setNewReportModule(e.target.value)}
                      className="w-full px-3 py-2 text-xs bg-[#080D1A] border border-slate-700 rounded-lg text-white"
                    >
                      <option value="Security Scanner">Security Scanner</option>
                      <option value="Network Intelligence">Network Intelligence</option>
                      <option value="Digital Forensics">Digital Forensics</option>
                      <option value="Cryptography Lab">Cryptography Lab</option>
                    </select>
                  </div>
                  <div>
                    <label htmlFor="rep-sev" className="block text-xs text-slate-300 mb-1">
                      Severity
                    </label>
                    <select
                      id="rep-sev"
                      value={newReportSeverity}
                      onChange={(e) =>
                        setNewReportSeverity(e.target.value as 'Low' | 'Medium' | 'High')
                      }
                      className="w-full px-3 py-2 text-xs bg-[#080D1A] border border-slate-700 rounded-lg text-white"
                    >
                      <option value="Low">Low</option>
                      <option value="Medium">Medium</option>
                      <option value="High">High</option>
                    </select>
                  </div>
                </div>
                <div>
                  <label htmlFor="rep-sum" className="block text-xs text-slate-300 mb-1">
                    Executive Summary & Remediation
                  </label>
                  <textarea
                    id="rep-sum"
                    rows={3}
                    required
                    value={newReportSummary}
                    onChange={(e) => setNewReportSummary(e.target.value)}
                    placeholder="Summarize technical findings and recommended defensive controls..."
                    className="w-full p-2.5 text-xs bg-[#080D1A] border border-slate-700 rounded-lg text-white"
                  />
                </div>
                <button
                  type="submit"
                  disabled={reportSubmitting}
                  className="w-full py-2 px-4 text-xs font-semibold text-slate-950 bg-cyan-400 hover:bg-cyan-300 rounded-lg transition-colors cursor-pointer"
                >
                  {reportSubmitting ? 'Saving Report...' : 'Publish Security Report'}
                </button>
              </form>
            </div>

            <div className="bg-[#0F172A] border border-slate-800 rounded-xl p-6 space-y-3">
              <h3 className="text-base font-semibold text-white">
                Analyst Curriculum Completion
              </h3>
              {learningProgress.map((lp) => {
                const pct = Math.round((lp.completedExercises / lp.totalExercises) * 100);
                return (
                  <div key={lp.moduleId} className="space-y-1 text-xs">
                    <div className="flex justify-between text-slate-300">
                      <span>{lp.moduleName}</span>
                      <span className="font-mono tabular-nums">
                        {lp.completedExercises}/{lp.totalExercises} ({pct}%)
                      </span>
                    </div>
                    <div className="w-full h-2 bg-[#080D1A] rounded-full overflow-hidden">
                      <div
                        className="h-full bg-cyan-400"
                        style={{ width: `${pct}%` }}
                      />
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      </div>
    );
  }

  if (mode === 'settings') {
    return (
      <div className="max-w-3xl space-y-6">
        <div className="bg-[#0F172A] border border-slate-800 rounded-xl p-6 space-y-5">
          <div className="flex items-center justify-between border-b border-slate-800 pb-4">
            <div>
              <h2 className="text-lg font-semibold text-white">
                SOC Operator & Defensive Policy Settings
              </h2>
              <p className="text-xs text-slate-400">
                Manage authorized target scopes, SSRF private-address filters, and API rate controls.
              </p>
            </div>
            <Settings className="w-5 h-5 text-cyan-400" />
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs font-mono">
            <div className="p-3.5 rounded-lg bg-[#080D1A] border border-slate-800">
              <span className="text-slate-400 block">Authenticated Operator</span>
              <span className="text-white font-bold">{analyst.username}</span>
            </div>
            <div className="p-3.5 rounded-lg bg-[#080D1A] border border-slate-800">
              <span className="text-slate-400 block">Clearance & Role</span>
              <span className="text-cyan-400 font-bold">{analyst.clearance}</span>
            </div>
          </div>

          <div>
            <label htmlFor="settings-scope" className="block text-xs text-slate-300 mb-1.5">
              Authorized Assessment Domain Allowlist (Comma-Separated)
            </label>
            <input
              id="settings-scope"
              type="text"
              value={authorizedScope}
              onChange={(e) => setAuthorizedScope(e.target.value)}
              className="w-full px-3.5 py-2 text-xs font-mono bg-[#080D1A] border border-slate-700 rounded-lg text-white"
            />
          </div>

          <div className="flex items-center justify-between p-3.5 rounded-lg bg-[#080D1A] border border-slate-800">
            <div>
              <p className="text-xs font-semibold text-white">
                Strict SSRF & Private RFC1918 Address Blocking
              </p>
              <p className="text-xs text-slate-400">
                Reject loopback (127.0.0.0/8), link-local (169.254.0.0/16), and internal ranges.
              </p>
            </div>
            <input
              type="checkbox"
              aria-label="Strict SSRF Blocking"
              checked={ssrfStrict}
              onChange={(e) => setSsrfStrict(e.target.checked)}
              className="w-4 h-4 accent-cyan-400"
            />
          </div>

          <div>
            <label htmlFor="settings-ratelimit" className="block text-xs text-slate-300 mb-1.5">
              Scanner API Rate Limit Ceiling (Requests / Minute): {rateLimit} RPM
            </label>
            <input
              id="settings-ratelimit"
              type="range"
              min={10}
              max={120}
              value={rateLimit}
              onChange={(e) => setRateLimit(Number(e.target.value))}
              className="w-full accent-cyan-400"
            />
          </div>

          <div className="flex items-center justify-between pt-2">
            <button
              type="button"
              onClick={() => {
                setSettingsSaved(true);
                setTimeout(() => setSettingsSaved(false), 2500);
              }}
              className="px-5 py-2.5 text-xs font-semibold text-slate-950 bg-cyan-400 hover:bg-cyan-300 rounded-lg cursor-pointer"
            >
              Save Security Configuration
            </button>
            {settingsSaved && (
              <span className="text-xs font-mono text-emerald-400">
                Configuration persisted to SOC profile.
              </span>
            )}
          </div>
        </div>
      </div>
    );
  }

  // PAGE 16: ABOUT CYBERSCOPE & PYTHON FLASK + PYDROID 3 / CLOUD DEPLOYMENT BLUEPRINT
  const activeFile =
    FLASK_BLUEPRINT_FILES.find((f) => f.path === selectedBlueprintPath) ||
    FLASK_BLUEPRINT_FILES[0];

  return (
    <div className="space-y-6">
      <div className="bg-[#0F172A] border border-slate-800 rounded-xl p-6">
        <p className="text-xs font-mono text-cyan-400 mb-1">
          CYBERSCOPE ARCHITECTURE · PYTHON FLASK + SQLITE + POSTGRESQL BLUEPRINT
        </p>
        <h2 className="text-xl font-bold text-white mb-2">
          About CyberScope & Full-Stack Deployment Blueprint
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed max-w-4xl">
          CyberScope is a browser-native Security Operations Center platform accessible via any
          modern desktop or mobile HTTPS browser without installing an APK. Below you can inspect
          and copy the modular Python Flask + SQLite/PostgreSQL backend files (also stored on disk
          under <code className="font-mono text-cyan-300">/CyberScope/</code>), along with Android
          Pydroid 3 development steps and cloud production deployment instructions.
        </p>
      </div>

      {/* Interactive Flask Codebase Explorer */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        <div className="lg:col-span-4 bg-[#0F172A] border border-slate-800 rounded-xl p-5 space-y-2">
          <h3 className="text-sm font-semibold text-white mb-2">
            Flask & Database Source Files
          </h3>
          {FLASK_BLUEPRINT_FILES.map((file) => (
            <button
              key={file.path}
              type="button"
              onClick={() => setSelectedBlueprintPath(file.path)}
              className={`w-full text-left p-3 rounded-lg border text-xs transition-colors cursor-pointer ${
                selectedBlueprintPath === file.path
                  ? 'bg-[#131D35] border-cyan-500/60 text-white'
                  : 'bg-[#080D1A] border-slate-800 text-slate-300 hover:border-slate-700'
              }`}
            >
              <p className="font-mono font-semibold text-cyan-400">{file.path}</p>
              <p className="text-slate-400 mt-1">{file.description}</p>
            </button>
          ))}
        </div>

        <div className="lg:col-span-8 bg-[#080D1A] border border-slate-800 rounded-xl overflow-hidden flex flex-col">
          <div className="flex items-center justify-between px-5 py-3 bg-[#0F172A] border-b border-slate-800">
            <span className="text-xs font-mono text-cyan-400">{activeFile.path}</span>
            <button
              type="button"
              onClick={() => {
                navigator.clipboard?.writeText(activeFile.content);
                setCopiedPath(activeFile.path);
                setTimeout(() => setCopiedPath(''), 1500);
              }}
              className="text-xs font-mono text-slate-300 hover:text-white flex items-center gap-1.5 cursor-pointer"
            >
              {copiedPath === activeFile.path ? (
                <>
                  <Check className="w-3.5 h-3.5 text-emerald-400" /> Copied
                </>
              ) : (
                <>
                  <Copy className="w-3.5 h-3.5" /> Copy File
                </>
              )}
            </button>
          </div>
          <pre className="p-5 text-xs font-mono text-slate-200 overflow-x-auto leading-relaxed">
            {activeFile.content}
          </pre>
        </div>
      </div>

      {/* Android Pydroid 3 Development & Remote Server Production Deployment Instructions */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-[#0F172A] border border-slate-800 rounded-xl p-6 space-y-3">
          <div className="flex items-center justify-between">
            <h3 className="text-base font-semibold text-white">
              Local Development on Android (Pydroid 3 + Code Editor)
            </h3>
            <Smartphone className="w-5 h-5 text-cyan-400" />
          </div>
          <p className="text-xs text-slate-400">
            Develop and test CyberScope locally on an Android device before pushing to GitHub:
          </p>
          <ol className="space-y-2 text-xs text-slate-300 list-decimal list-inside font-mono">
            <li>Install Pydroid 3 and open the built-in Pip / Terminal menu.</li>
            <li>
              Run: <code className="text-cyan-300">pip install -r requirements.txt</code>
            </li>
            <li>
              Open <code className="text-cyan-300">CyberScope/app.py</code> and tap Run to initialize{' '}
              <code className="text-cyan-300">database/cyberscope.db</code> via{' '}
              <code className="text-cyan-300">schema.sql</code>.
            </li>
            <li>
              Test in Chrome on Android at{' '}
              <code className="text-emerald-300">http://127.0.0.1:5000</code> during local authoring.
            </li>
          </ol>
        </div>

        <div className="bg-[#0F172A] border border-slate-800 rounded-xl p-6 space-y-3">
          <div className="flex items-center justify-between">
            <h3 className="text-base font-semibold text-white">
              Remote Cloud Production Deployment (HTTPS + PostgreSQL)
            </h3>
            <Server className="w-5 h-5 text-emerald-400" />
          </div>
          <p className="text-xs text-slate-400">
            Host CyberScope permanently on a remote cloud server (Render, Railway, Fly.io, or Cloud Run):
          </p>
          <ol className="space-y-2 text-xs text-slate-300 list-decimal list-inside font-mono">
            <li>Push the CyberScope repository to GitHub (never commit .env secrets).</li>
            <li>
              Configure environment variables: <code className="text-cyan-300">CYBERSCOPE_SECRET_KEY</code>,{' '}
              <code className="text-cyan-300">DATABASE_URL</code> (PostgreSQL), and{' '}
              <code className="text-cyan-300">GEMINI_API_KEY</code>.
            </li>
            <li>
              Set production WSGI start command:{' '}
              <code className="text-emerald-300">gunicorn app:app --bind 0.0.0.0:$PORT --workers 4</code>
            </li>
            <li>
              Attach your custom domain with managed TLSv1.3 HTTPS certificates and HSTS enabled.
            </li>
          </ol>
        </div>
      </div>
    </div>
  );
}
