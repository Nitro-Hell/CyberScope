'use client';

import React, { useState, useEffect } from 'react';
import {
  Flag,
  Trophy,
  HelpCircle,
  CheckCircle2,
  Code2,
  FileSearch,
  AlertTriangle,
  ShieldCheck,
} from 'lucide-react';
import { FileSignatureMatch, LogAnalysisSummary } from '@/lib/cyber-engine';

interface CtfWebForensicsProps {
  mode: 'ctf' | 'weblab' | 'forensics';
  onProgressUpdate?: () => void;
}

interface SanitizedChallenge {
  id: string;
  title: string;
  category: string;
  difficulty: string;
  points: number;
  description: string;
  artifact: string;
  hint: string;
  solved: boolean;
}

export default function ModulesCtfWebForensics({
  mode,
  onProgressUpdate,
}: CtfWebForensicsProps) {
  // Module 06: CTF Arena State
  const [challenges, setChallenges] = useState<SanitizedChallenge[]>([]);
  const [userPoints, setUserPoints] = useState(100);
  const [leaderboard, setLeaderboard] = useState<
    Array<{ rank: number; handle: string; role: string; solved: number; points: number }>
  >([]);
  const [activeChallengeId, setActiveChallengeId] = useState('ctf-crypto-01');
  const [flagInput, setFlagInput] = useState('');
  const [ctfFeedback, setCtfFeedback] = useState<{
    correct?: boolean;
    message: string;
  } | null>(null);
  const [showHint, setShowHint] = useState(false);

  // Module 07: Web Security Lab State
  const [sqliUsernameInput, setSqliUsernameInput] = useState("admin' OR '1'='1");
  const [xssInput, setXssInput] = useState('<img src=x onerror="alert(document.cookie)">');
  const [corsOriginInput, setCorsOriginInput] = useState('https://evil-attacker.example');

  // Module 08: Digital Forensics State
  const [forensicFileName, setForensicFileName] = useState('invoice_q4.pdf');
  const [forensicHexHeader, setForensicHexHeader] = useState('7F 45 4C 46 02 01 01 00 00 00 00 00');
  const [forensicLogContent, setForensicLogContent] = useState(
    'Nov 18 02:14:01 soc-gw01 sshd[4192]: Failed password for root from 185.220.101.44 port 51822 ssh2\nNov 18 02:14:03 soc-gw01 sshd[4192]: Failed password for invalid user admin from 185.220.101.44 port 51828 ssh2\nNov 18 02:14:06 soc-gw01 sudo: analyst : TTY=pts/0 ; USER=root ; COMMAND=/usr/bin/tcpdump -i eth0\nNov 18 02:14:09 soc-gw01 sshd[4201]: Accepted publickey for analyst from 10.20.1.15 port 44110 ssh2'
  );
  const [forensicNotes, setForensicNotes] = useState(
    'Case #2026-1118: Suspected ELF binary masquerading as PDF attachment alongside SSH brute-force activity from 185.220.101.44.'
  );
  const [forensicResult, setForensicResult] = useState<{
    fileName: string;
    sizeBytes: number;
    sha256: string;
    sha512: string;
    signatureMatch: FileSignatureMatch;
    logAnalysis: LogAnalysisSummary | null;
  } | null>(null);

  const runForensicAnalysis = async (
    overrideFile?: string,
    overrideHex?: string
  ) => {
    try {
      const res = await fetch('/api/forensics/hash', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          fileName: overrideFile ?? forensicFileName,
          hexHeader: overrideHex ?? forensicHexHeader,
          content: forensicLogContent,
        }),
      });
      const data = await res.json();
      if (data.status === 'ok') {
        setForensicResult(data);
      }
    } catch {
      // ignore
    }
  };

  useEffect(() => {
    if (mode === 'ctf') {
      fetch('/api/ctf/challenges')
        .then((r) => r.json())
        .then((d) => {
          if (d.challenges) {
            setChallenges(d.challenges);
            setUserPoints(d.userPoints || 0);
            setLeaderboard(d.leaderboard || []);
          }
        })
        .catch(() => {});
    } else if (mode === 'forensics') {
      fetch('/api/forensics/hash', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          fileName: 'invoice_q4.pdf',
          hexHeader: '7F 45 4C 46 02 01 01 00 00 00 00 00',
          content:
            'Nov 18 02:14:01 soc-gw01 sshd[4192]: Failed password for root from 185.220.101.44 port 51822 ssh2\nNov 18 02:14:03 soc-gw01 sshd[4192]: Failed password for invalid user admin from 185.220.101.44 port 51828 ssh2\nNov 18 02:14:06 soc-gw01 sudo: analyst : TTY=pts/0 ; USER=root ; COMMAND=/usr/bin/tcpdump -i eth0\nNov 18 02:14:09 soc-gw01 sshd[4201]: Accepted publickey for analyst from 10.20.1.15 port 44110 ssh2',
        }),
      })
        .then((r) => r.json())
        .then((d) => {
          if (d.status === 'ok') setForensicResult(d);
        })
        .catch(() => {});
    }
  }, [mode]);

  const handleFlagSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!flagInput.trim()) return;
    setCtfFeedback(null);
    try {
      const res = await fetch('/api/ctf/submit', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          challengeId: activeChallengeId,
          flag: flagInput,
        }),
      });
      const data = await res.json();
      setCtfFeedback({
        correct: data.correct,
        message: data.message || 'Submission evaluated.',
      });
      if (data.correct) {
        setFlagInput('');
        const refresh = await fetch('/api/ctf/challenges').then((r) => r.json());
        if (refresh.challenges) {
          setChallenges(refresh.challenges);
          setUserPoints(refresh.userPoints);
          setLeaderboard(refresh.leaderboard);
        }
        onProgressUpdate?.();
      }
    } catch {
      setCtfFeedback({ correct: false, message: 'Failed to submit flag.' });
    }
  };

  if (mode === 'ctf') {
    const activeChallenge =
      challenges.find((c) => c.id === activeChallengeId) || challenges[0];

    return (
      <div className="space-y-6">
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* Challenge List */}
          <div className="lg:col-span-5 bg-[#0F172A] border border-slate-800 rounded-xl p-5 space-y-3">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <div>
                <h2 className="text-base font-semibold text-white">
                  Isolated CTF Challenge Matrix
                </h2>
                <p className="text-xs text-slate-400">
                  Select a challenge to inspect its forensic artifact and submit a flag.
                </p>
              </div>
              <span className="text-sm font-mono font-bold text-cyan-400 tabular-nums">
                {userPoints} pts
              </span>
            </div>

            <div className="space-y-2">
              {challenges.map((c) => (
                <button
                  key={c.id}
                  type="button"
                  onClick={() => {
                    setActiveChallengeId(c.id);
                    setCtfFeedback(null);
                    setShowHint(false);
                  }}
                  className={`w-full text-left p-3.5 rounded-lg border transition-colors cursor-pointer ${
                    activeChallenge?.id === c.id
                      ? 'bg-[#131D35] border-cyan-500/60'
                      : 'bg-[#080D1A] border-slate-800 hover:border-slate-700'
                  }`}
                >
                  <div className="flex items-center justify-between text-xs font-mono mb-1">
                    <span className="text-cyan-400">
                      {c.category} · {c.difficulty}
                    </span>
                    <span
                      className={
                        c.solved ? 'text-emerald-400 font-bold' : 'text-slate-300 tabular-nums'
                      }
                    >
                      {c.solved ? `SOLVED (+${c.points})` : `${c.points} pts`}
                    </span>
                  </div>
                  <p className="text-sm font-semibold text-white">{c.title}</p>
                </button>
              ))}
            </div>
          </div>

          {/* Active Challenge Workbench & Scoreboard */}
          <div className="lg:col-span-7 space-y-6">
            {activeChallenge && (
              <div className="bg-[#0F172A] border border-slate-800 rounded-xl p-6 space-y-4">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-xs font-mono text-cyan-400">
                      {activeChallenge.category} · {activeChallenge.difficulty} ·{' '}
                      {activeChallenge.points} Points
                    </p>
                    <h3 className="text-xl font-bold text-white mt-0.5">
                      {activeChallenge.title}
                    </h3>
                  </div>
                  {activeChallenge.solved && (
                    <span className="text-xs font-mono text-emerald-400 flex items-center gap-1">
                      <CheckCircle2 className="w-4 h-4" /> Flag Verified
                    </span>
                  )}
                </div>

                <p className="text-sm text-slate-300 leading-relaxed">
                  {activeChallenge.description}
                </p>

                <div className="p-4 rounded-lg bg-[#080D1A] border border-slate-800">
                  <p className="text-xs font-mono text-slate-400 mb-1.5">
                    Captured Forensic Artifact:
                  </p>
                  <pre className="text-xs font-mono text-cyan-300 whitespace-pre-wrap break-all">
                    {activeChallenge.artifact}
                  </pre>
                </div>

                <form onSubmit={handleFlagSubmit} className="flex flex-col sm:flex-row gap-3">
                  <label htmlFor="ctf-flag-input" className="sr-only">
                    Candidate Flag Token
                  </label>
                  <input
                    id="ctf-flag-input"
                    type="text"
                    value={flagInput}
                    onChange={(e) => setFlagInput(e.target.value)}
                    placeholder="Enter flag (e.g. CS{...})"
                    className="flex-1 px-3.5 py-2 text-sm font-mono bg-[#080D1A] border border-slate-700 rounded-lg text-white focus:outline-none focus:border-cyan-400"
                  />
                  <button
                    type="submit"
                    className="px-5 py-2 text-xs font-semibold text-slate-950 bg-cyan-400 hover:bg-cyan-300 rounded-lg transition-colors whitespace-nowrap shrink-0 cursor-pointer"
                  >
                    Submit Flag
                  </button>
                </form>

                <div className="flex items-center justify-between pt-1">
                  <button
                    type="button"
                    onClick={() => setShowHint(!showHint)}
                    className="text-xs text-slate-400 hover:text-cyan-300 flex items-center gap-1.5 cursor-pointer"
                  >
                    <HelpCircle className="w-3.5 h-3.5" />
                    <span>{showHint ? 'Hide Tactical Hint' : 'Reveal Tactical Hint'}</span>
                  </button>
                </div>

                {showHint && (
                  <div className="p-3 rounded-lg bg-slate-900 border border-slate-700 text-xs text-cyan-200 font-mono">
                    Hint: {activeChallenge.hint}
                  </div>
                )}

                {ctfFeedback && (
                  <div
                    role="status"
                    className={`p-3.5 rounded-lg border text-xs font-mono ${
                      ctfFeedback.correct
                        ? 'bg-emerald-950/50 border-emerald-700 text-emerald-200'
                        : 'bg-red-950/50 border-red-800 text-red-200'
                    }`}
                  >
                    {ctfFeedback.message}
                  </div>
                )}
              </div>
            )}

            {/* CTF Leaderboard */}
            <div className="bg-[#0F172A] border border-slate-800 rounded-xl p-6">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-base font-semibold text-white">
                  SOC CTF Arena Leaderboard
                </h3>
                <Trophy className="w-4 h-4 text-amber-400" />
              </div>
              <table className="w-full text-left border-collapse text-xs">
                <thead>
                  <tr className="border-b border-slate-800 text-slate-400">
                    <th className="py-2 px-3">Rank</th>
                    <th className="py-2 px-3">Operator Handle</th>
                    <th className="py-2 px-3">Role</th>
                    <th className="py-2 px-3 text-right">Flags</th>
                    <th className="py-2 px-3 text-right">Score</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/70 font-mono">
                  {leaderboard.map((row) => (
                    <tr key={row.handle}>
                      <td className="py-2.5 px-3 text-cyan-400 tabular-nums">#{row.rank}</td>
                      <td className="py-2.5 px-3 text-white font-semibold">{row.handle}</td>
                      <td className="py-2.5 px-3 text-slate-400">{row.role}</td>
                      <td className="py-2.5 px-3 text-right text-slate-300 tabular-nums">
                        {row.solved}/6
                      </td>
                      <td className="py-2.5 px-3 text-right text-emerald-400 font-bold tabular-nums">
                        {row.points} pts
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </div>
    );
  }

  if (mode === 'weblab') {
    const isSqliAttempt = /('|--|OR\s+1=1|UNION\s+SELECT|;)/i.test(sqliUsernameInput);
    const escapedXss = xssInput
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
    const allowedOrigins = ['https://cyberscope.sec', 'https://app.cyberscope.sec'];
    const isOriginAllowed = allowedOrigins.includes(corsOriginInput.trim());

    return (
      <div className="space-y-6">
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* SQL Injection Simulator vs Parameterized Defense */}
          <div className="lg:col-span-6 bg-[#0F172A] border border-slate-800 rounded-xl p-6 space-y-4">
            <div className="flex items-center justify-between">
              <h2 className="text-lg font-semibold text-white">
                SQL Injection vs. Parameterized Query Simulator
              </h2>
              <Code2 className="w-5 h-5 text-cyan-400" />
            </div>
            <p className="text-xs text-slate-400">
              Observe how string concatenation alters SQL AST structure while parameterized
              placeholders (`?`) bind user input strictly as a literal value.
            </p>

            <div>
              <label htmlFor="sqli-input" className="block text-xs text-slate-300 mb-1.5">
                Simulated Login Username Input:
              </label>
              <input
                id="sqli-input"
                type="text"
                value={sqliUsernameInput}
                onChange={(e) => setSqliUsernameInput(e.target.value)}
                className="w-full px-3.5 py-2 text-xs font-mono bg-[#080D1A] border border-slate-700 rounded-lg text-white"
              />
            </div>

            <div className="p-3.5 rounded-lg bg-red-950/30 border border-red-900/60 space-y-1.5">
              <p className="text-xs font-mono text-red-300 font-semibold">
                VULNERABLE (String Formatting):
              </p>
              <pre className="text-xs font-mono text-slate-200 whitespace-pre-wrap break-all">
                {`SELECT id, role FROM users WHERE username = '${sqliUsernameInput}';`}
              </pre>
              <p className="text-xs text-red-300">
                {isSqliAttempt
                  ? 'Outcome: Tautology / AST injection triggered! Query returns all rows (Authentication Bypass).'
                  : 'Outcome: Normal literal lookup, but vulnerable to quote injection.'}
              </p>
            </div>

            <div className="p-3.5 rounded-lg bg-emerald-950/30 border border-emerald-900/60 space-y-1.5">
              <p className="text-xs font-mono text-emerald-300 font-semibold">
                DEFENDED (Python SQLite3 Parameterized Query):
              </p>
              <pre className="text-xs font-mono text-slate-200 whitespace-pre-wrap break-all">
                {`cursor.execute("SELECT id, role FROM users WHERE username = ?", (${JSON.stringify(
                  sqliUsernameInput
                )},))`}
              </pre>
              <p className="text-xs text-emerald-300">
                Outcome: Input treated strictly as bound parameter literal `$1`. Injection neutralized.
              </p>
            </div>
          </div>

          {/* XSS Output Encoding & CORS / Cookie Security Lab */}
          <div className="lg:col-span-6 space-y-6">
            <div className="bg-[#0F172A] border border-slate-800 rounded-xl p-6 space-y-4">
              <h2 className="text-lg font-semibold text-white">
                Cross-Site Scripting (XSS) & Context-Aware Encoding
              </h2>
              <div>
                <label htmlFor="xss-input" className="block text-xs text-slate-300 mb-1.5">
                  Untrusted User Comment Payload:
                </label>
                <input
                  id="xss-input"
                  type="text"
                  value={xssInput}
                  onChange={(e) => setXssInput(e.target.value)}
                  className="w-full px-3.5 py-2 text-xs font-mono bg-[#080D1A] border border-slate-700 rounded-lg text-white"
                />
              </div>
              <div className="p-3.5 rounded-lg bg-[#080D1A] border border-slate-800 text-xs font-mono space-y-1.5">
                <p className="text-cyan-400">HTML-Escaped Safe Output (Jinja2 / React Default):</p>
                <p className="text-emerald-300 break-all">{escapedXss}</p>
              </div>
            </div>

            <div className="bg-[#0F172A] border border-slate-800 rounded-xl p-6 space-y-4">
              <h2 className="text-lg font-semibold text-white">
                Same-Origin Policy (SOP), CORS & Cookie Flags Simulator
              </h2>
              <div>
                <label htmlFor="cors-origin-input" className="block text-xs text-slate-300 mb-1.5">
                  Simulated Request `Origin:` Header
                </label>
                <div className="flex gap-2">
                  <input
                    id="cors-origin-input"
                    type="text"
                    value={corsOriginInput}
                    onChange={(e) => setCorsOriginInput(e.target.value)}
                    className="flex-1 px-3 py-1.5 text-xs font-mono bg-[#080D1A] border border-slate-700 rounded-lg text-white"
                  />
                  <button
                    type="button"
                    onClick={() => setCorsOriginInput('https://app.cyberscope.sec')}
                    className="px-3 py-1.5 text-xs font-mono bg-slate-800 text-cyan-300 rounded-lg cursor-pointer"
                  >
                    Test Trusted Origin
                  </button>
                </div>
              </div>
              <div className="p-3.5 rounded-lg bg-[#080D1A] border border-slate-800 text-xs font-mono space-y-1">
                <p className={isOriginAllowed ? 'text-emerald-400' : 'text-amber-400'}>
                  {isOriginAllowed
                    ? `Access-Control-Allow-Origin: ${corsOriginInput.trim()}`
                    : 'CORS Policy: Origin rejected (Not in strict allowlist)'}
                </p>
                <p className="text-slate-300">
                  Set-Cookie: session=eyJ...; Secure; HttpOnly; SameSite=Lax; Path=/
                </p>
              </div>
            </div>
          </div>
        </div>
      </div>
    );
  }

  // MODULE 08: DIGITAL FORENSICS
  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Magic Bytes & SHA-256 Artifact Verifier */}
        <div className="lg:col-span-6 bg-[#0F172A] border border-slate-800 rounded-xl p-6 space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-lg font-semibold text-white">
                File Signature (Magic Bytes) & SHA-256 Verifier
              </h2>
              <p className="text-xs text-slate-400">
                Detect disguised executables and compute chain-of-custody cryptographic hashes.
              </p>
            </div>
            <FileSearch className="w-5 h-5 text-cyan-400" />
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div>
              <label htmlFor="forensic-filename" className="block text-xs text-slate-300 mb-1">
                Claimed File Name
              </label>
              <input
                id="forensic-filename"
                type="text"
                value={forensicFileName}
                onChange={(e) => setForensicFileName(e.target.value)}
                className="w-full px-3 py-2 text-xs font-mono bg-[#080D1A] border border-slate-700 rounded-lg text-white"
              />
            </div>
            <div>
              <label htmlFor="forensic-hex" className="block text-xs text-slate-300 mb-1">
                First 12 Bytes (Hex Header)
              </label>
              <input
                id="forensic-hex"
                type="text"
                value={forensicHexHeader}
                onChange={(e) => setForensicHexHeader(e.target.value)}
                className="w-full px-3 py-2 text-xs font-mono bg-[#080D1A] border border-slate-700 rounded-lg text-white"
              />
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2 text-xs">
            <span className="text-slate-400">Artifact Presets:</span>
            {[
              { name: 'invoice_q4.pdf (Disguised ELF)', file: 'invoice_q4.pdf', hex: '7F 45 4C 46 02 01 01 00' },
              { name: 'capture.pcap (Libpcap)', file: 'capture.pcap', hex: 'D4 C3 B2 A1 02 00 04 00' },
              { name: 'updater.jpg (Disguised PE EXE)', file: 'updater.jpg', hex: '4D 5A 90 00 03 00 00 00' },
            ].map((p) => (
              <button
                key={p.name}
                type="button"
                onClick={() => {
                  setForensicFileName(p.file);
                  setForensicHexHeader(p.hex);
                  runForensicAnalysis(p.file, p.hex);
                }}
                className="px-2.5 py-1 rounded bg-slate-900 hover:bg-slate-800 text-cyan-300 border border-slate-700 font-mono cursor-pointer"
              >
                {p.name}
              </button>
            ))}
          </div>

          <button
            type="button"
            onClick={() => runForensicAnalysis()}
            className="w-full py-2.5 px-4 text-xs font-semibold text-slate-950 bg-cyan-400 hover:bg-cyan-300 rounded-lg transition-colors cursor-pointer"
          >
            Inspect File Signature & Reconstruct Log Timeline
          </button>

          {forensicResult && (
            <div className="p-4 rounded-lg bg-[#080D1A] border border-slate-800 space-y-2 text-xs font-mono">
              <div className="flex items-center justify-between">
                <span className="text-slate-400">Detected Binary Format:</span>
                <span className="text-white font-bold">
                  {forensicResult.signatureMatch.detectedType}
                </span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-slate-400">Extension Match:</span>
                <span
                  className={
                    forensicResult.signatureMatch.extensionMatch
                      ? 'text-emerald-400 font-bold'
                      : 'text-red-400 font-bold'
                  }
                >
                  {forensicResult.signatureMatch.extensionMatch
                    ? 'CONSISTENT'
                    : 'MASQUERADING ALERT'}
                </span>
              </div>
              <p className="text-amber-300 pt-1">{forensicResult.signatureMatch.riskNote}</p>
              <div className="pt-2 border-t border-slate-800">
                <p className="text-slate-400">Evidence SHA-256 Chain-of-Custody Digest:</p>
                <p className="text-cyan-300 break-all">{forensicResult.sha256}</p>
              </div>
            </div>
          )}
        </div>

        {/* Log Intrusion Timeline & Evidence Notes */}
        <div className="lg:col-span-6 bg-[#0F172A] border border-slate-800 rounded-xl p-6 space-y-4">
          <h2 className="text-lg font-semibold text-white">
            Intrusion Log Analyzer & Chronological Timeline
          </h2>
          <div>
            <label htmlFor="forensic-logs-textarea" className="block text-xs text-slate-300 mb-1">
              Raw Authentication / Server Log Stream:
            </label>
            <textarea
              id="forensic-logs-textarea"
              rows={4}
              value={forensicLogContent}
              onChange={(e) => setForensicLogContent(e.target.value)}
              className="w-full p-3 text-xs font-mono bg-[#080D1A] border border-slate-700 rounded-lg text-white"
            />
          </div>

          {forensicResult?.logAnalysis && (
            <div className="space-y-3">
              <div className="flex items-center justify-between text-xs font-mono text-slate-300">
                <span>
                  Failed Auth Events: {forensicResult.logAnalysis.failedAuthCount}
                </span>
                <span>
                  Top Threat IP:{' '}
                  {forensicResult.logAnalysis.suspiciousIps[0]?.ip || 'None'}
                </span>
              </div>

              <div className="space-y-2 max-h-48 overflow-y-auto">
                {forensicResult.logAnalysis.timeline.map((ev, i) => (
                  <div
                    key={i}
                    className="p-2.5 rounded bg-[#080D1A] border border-slate-800 text-xs font-mono"
                  >
                    <div className="flex items-center justify-between text-cyan-400 mb-0.5">
                      <span>
                        {ev.timestamp} · {ev.eventType}
                      </span>
                      <span
                        className={
                          ev.severity === 'Critical'
                            ? 'text-red-400 font-bold'
                            : 'text-amber-400'
                        }
                      >
                        {ev.severity} ({ev.sourceIp})
                      </span>
                    </div>
                    <p className="text-slate-300 truncate">{ev.detail}</p>
                  </div>
                ))}
              </div>
            </div>
          )}

          <div>
            <label htmlFor="forensic-notes-input" className="block text-xs text-slate-300 mb-1">
              Investigator Chain-of-Custody Evidence Notes:
            </label>
            <textarea
              id="forensic-notes-input"
              rows={2}
              value={forensicNotes}
              onChange={(e) => setForensicNotes(e.target.value)}
              className="w-full p-2.5 text-xs bg-[#080D1A] border border-slate-700 rounded-lg text-slate-200"
            />
          </div>
        </div>
      </div>
    </div>
  );
}
