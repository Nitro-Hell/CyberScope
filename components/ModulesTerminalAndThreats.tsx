'use client';

import React, { useState } from 'react';
import {
  Terminal,
  Search,
  Lock,
  Play,
  Copy,
  Check,
  AlertTriangle,
  ShieldAlert,
  Key,
} from 'lucide-react';
import { executeSandboxCommand } from '@/lib/cyber-engine';

interface TerminalThreatsCryptoProps {
  mode: 'terminal' | 'threats' | 'crypto';
  onCryptoLogged?: () => void;
}

interface CveEntry {
  id: string;
  title: string;
  cvssScore: number;
  severity: 'Critical' | 'High' | 'Medium';
  vector: string;
  affected: string;
  summary: string;
  mitigation: string;
}

const CURATED_CVE_FEED: CveEntry[] = [
  {
    id: 'CVE-2026-21408',
    title: 'Edge Gateway HTTP/2 Rapid Reset & Header Desync',
    cvssScore: 9.8,
    severity: 'Critical',
    vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    affected: 'Reverse Proxy Gateways < 2.14.2',
    summary:
      'Improper validation of HTTP/2 RST_STREAM frames combined with oversized CONTINUATION headers permits unauthenticated denial-of-service and request smuggling.',
    mitigation:
      'Upgrade proxy binary to >= 2.14.2; enforce http2_max_concurrent_streams 128 and strict header frame timeouts.',
  },
  {
    id: 'CVE-2025-48912',
    title: 'OpenSSH Pre-Auth Signal Race Condition (regreSSHion Variant)',
    cvssScore: 8.1,
    severity: 'High',
    vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H',
    affected: 'OpenSSH Server (sshd) 8.5p1 – 9.7p1',
    summary:
      'Async-signal-unsafe logging within SIGALRM LoginGraceTime handler allows remote heap corruption prior to user authentication.',
    mitigation:
      'Set LoginGraceTime 0 in /etc/ssh/sshd_config as immediate workaround or upgrade to OpenSSH >= 9.8p1.',
  },
  {
    id: 'CVE-2025-31094',
    title: 'Python Web Framework Unsafe Deserialization in Session Cookie',
    cvssScore: 9.1,
    severity: 'Critical',
    vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N',
    affected: 'Legacy Pickle-based Session Serializers',
    summary:
      'Applications using pickle-based session serialization with predictable SECRET_KEY values allow arbitrary code execution via forged session cookies.',
    mitigation:
      'Use JSON-only HMAC-SHA256 signed session serializers (ItsDangerous URLSafeTimedSerializer) and 256-bit CSPRNG secret keys.',
  },
  {
    id: 'CVE-2025-19440',
    title: 'PostgreSQL JDBC & ORM Unparameterized Literal Injection',
    cvssScore: 7.5,
    severity: 'High',
    vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
    affected: 'Custom SQL Query Builders without Bound Parameters',
    summary:
      'Improper escaping of nested JSONB filter keys allows boolean-based blind SQL data extraction.',
    mitigation:
      'Enforce strict parameterized queries ($1, $2 or ?) and allowlist permitted sort/filter column identifiers.',
  },
];

export default function ModulesTerminalAndThreats({
  mode,
  onCryptoLogged,
}: TerminalThreatsCryptoProps) {
  // Module 03: Cyber Terminal State
  const [termTheme, setTermTheme] = useState<'cyan' | 'emerald' | 'amber'>('cyan');
  const [cmdInput, setCmdInput] = useState('');
  const [history, setHistory] = useState<Array<{ cmd: string; output: string; status: string }>>([
    {
      cmd: 'help',
      output: executeSandboxCommand('help').output,
      status: 'ok',
    },
  ]);

  // Module 04: Threat Intelligence State
  const [cveSearch, setCveSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [domainCheckInput, setDomainCheckInput] = useState('secure-login-paypa1-update.xyz');

  // Module 05: Cryptography Lab State
  const [cryptoInput, setCryptoInput] = useState('CS{b4se64_b34c0n1_decod3d}');
  const [hmacKey, setHmacKey] = useState('cyberscope-soc-secret-2026');
  const [hashResult, setHashResult] = useState<{
    sha256: string;
    sha512: string;
    hmacSha256: string;
  } | null>(null);
  const [cipherMode, setCipherMode] = useState('base64-encode');
  const [cipherShift, setCipherShift] = useState(7);
  const [cipherKey, setCipherKey] = useState('CYBERSCOPE');
  const [cipherOutput, setCipherOutput] = useState('');
  const [cipherDetails, setCipherDetails] = useState<Record<string, string>>({});
  const [copiedField, setCopiedField] = useState('');

  const handleRunTerminalCmd = (raw?: string) => {
    const commandToRun = (raw ?? cmdInput).trim();
    if (!commandToRun) return;
    if (commandToRun.toLowerCase() === 'clear') {
      setHistory([]);
      setCmdInput('');
      return;
    }
    const res = executeSandboxCommand(commandToRun);
    setHistory((prev) => [...prev, { cmd: commandToRun, output: res.output, status: res.status }]);
    setCmdInput('');
  };

  const handleComputeHashes = async () => {
    if (!cryptoInput.trim()) return;
    try {
      const res = await fetch('/api/crypto/hash', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text: cryptoInput, algorithm: 'sha256', hmacKey }),
      });
      const data = await res.json();
      if (data.status === 'ok') {
        setHashResult(data.digests);
        onCryptoLogged?.();
      }
    } catch {
      // ignore
    }
  };

  const handleRunCipher = async (overrideMode?: string, overrideText?: string) => {
    const activeMode = overrideMode ?? cipherMode;
    const activeText = overrideText ?? cryptoInput;
    if (!activeText.trim()) return;
    try {
      const res = await fetch('/api/crypto/encode', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          text: activeText,
          mode: activeMode,
          shift: cipherShift,
          key: cipherKey,
        }),
      });
      const data = await res.json();
      if (data.status === 'ok') {
        setCipherOutput(data.output);
        setCipherDetails(data.details || {});
        onCryptoLogged?.();
      }
    } catch {
      // ignore
    }
  };

  const copyText = (val: string, label: string) => {
    navigator.clipboard?.writeText(val);
    setCopiedField(label);
    setTimeout(() => setCopiedField(''), 1500);
  };

  if (mode === 'terminal') {
    const themeColor =
      termTheme === 'emerald'
        ? 'text-emerald-300'
        : termTheme === 'amber'
        ? 'text-amber-300'
        : 'text-cyan-300';

    return (
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Main Terminal Console */}
        <div className="lg:col-span-8 bg-[#080D1A] border border-slate-800 rounded-xl flex flex-col overflow-hidden">
          <div className="flex flex-wrap items-center justify-between gap-3 px-5 py-3.5 bg-[#0F172A] border-b border-slate-800">
            <div className="flex items-center gap-2 text-xs font-mono text-slate-300">
              <Terminal className="w-4 h-4 text-cyan-400" />
              <span>analyst@cyberscope-soc-01:/home/analyst/cyberscope-lab</span>
            </div>
            <div className="flex items-center gap-1.5 text-xs">
              <span className="text-slate-400 mr-1">Theme:</span>
              {(['cyan', 'emerald', 'amber'] as const).map((t) => (
                <button
                  key={t}
                  type="button"
                  onClick={() => setTermTheme(t)}
                  className={`px-2.5 py-1 rounded capitalize font-mono cursor-pointer ${
                    termTheme === t
                      ? 'bg-slate-800 text-white border border-slate-600'
                      : 'text-slate-400 hover:text-white'
                  }`}
                >
                  {t}
                </button>
              ))}
            </div>
          </div>

          <div className="p-5 font-mono text-xs space-y-4 min-h-[380px] max-h-[480px] overflow-y-auto">
            {history.map((item, idx) => (
              <div key={idx} className="space-y-1.5">
                <div className="text-slate-400">
                  <span className="text-emerald-400">analyst@cyberscope-soc</span>:
                  <span className="text-cyan-400">~/lab</span>$ {item.cmd}
                </div>
                <pre
                  className={`whitespace-pre-wrap leading-relaxed ${
                    item.status === 'blocked' ? 'text-red-400' : themeColor
                  }`}
                >
                  {item.output}
                </pre>
              </div>
            ))}
          </div>

          <form
            onSubmit={(e) => {
              e.preventDefault();
              handleRunTerminalCmd();
            }}
            className="flex items-center gap-2 px-5 py-3.5 bg-[#0F172A] border-t border-slate-800"
          >
            <span className="text-xs font-mono text-emerald-400 shrink-0">$</span>
            <label htmlFor="cyber-terminal-input" className="sr-only">
              Terminal Command Input
            </label>
            <input
              id="cyber-terminal-input"
              type="text"
              value={cmdInput}
              onChange={(e) => setCmdInput(e.target.value)}
              placeholder="Type a command (e.g. help, whoami, ifconfig, nmap -sV 10.20.1.10, cat /var/log/auth.log)..."
              className="flex-1 bg-transparent text-xs font-mono text-white focus:outline-none"
            />
            <button
              type="submit"
              className="px-3.5 py-1.5 text-xs font-semibold text-slate-950 bg-cyan-400 hover:bg-cyan-300 rounded-md cursor-pointer"
            >
              Execute
            </button>
          </form>
        </div>

        {/* Guided Exercises & Command Reference */}
        <div className="lg:col-span-4 space-y-5">
          <div className="bg-[#0F172A] border border-slate-800 rounded-xl p-5">
            <h3 className="text-base font-semibold text-white mb-1">
              Guided Security Exercises
            </h3>
            <p className="text-xs text-slate-400 mb-4">
              Click any exercise below to execute it inside the restricted Linux simulator.
            </p>
            <div className="space-y-2">
              {[
                { label: '01. Inspect Network Interfaces', cmd: 'ifconfig' },
                { label: '02. Audit Active Listening Sockets', cmd: 'netstat -tulnp' },
                { label: '03. Scan Authorized Lab Node', cmd: 'nmap -sV 10.20.1.10' },
                { label: '04. Analyze SSH Brute-Force Logs', cmd: 'cat /var/log/auth.log' },
                { label: '05. Verify PCAP File SHA-256 Digest', cmd: 'sha256sum capture_perimeter.pcap' },
                { label: '06. Run Python SHA-256 Sandbox', cmd: 'python3 -c "import hashlib"' },
                { label: '07. Test Sandbox Destruction Guard', cmd: 'rm -rf /' },
              ].map((ex) => (
                <button
                  key={ex.cmd}
                  type="button"
                  onClick={() => handleRunTerminalCmd(ex.cmd)}
                  className="w-full text-left p-2.5 rounded-lg bg-[#080D1A] hover:bg-slate-900 border border-slate-800 hover:border-cyan-500/40 transition-colors flex items-center justify-between group cursor-pointer"
                >
                  <div>
                    <p className="text-xs font-medium text-slate-200 group-hover:text-cyan-300">
                      {ex.label}
                    </p>
                    <p className="text-[11px] font-mono text-slate-400">{ex.cmd}</p>
                  </div>
                  <Play className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                </button>
              ))}
            </div>
          </div>
        </div>
      </div>
    );
  }

  if (mode === 'threats') {
    const filteredCves = CURATED_CVE_FEED.filter((cve) => {
      const matchesQuery =
        cve.id.toLowerCase().includes(cveSearch.toLowerCase()) ||
        cve.title.toLowerCase().includes(cveSearch.toLowerCase()) ||
        cve.summary.toLowerCase().includes(cveSearch.toLowerCase());
      const matchesSev = severityFilter === 'ALL' || cve.severity === severityFilter;
      return matchesQuery && matchesSev;
    });

    // Domain Phishing Heuristic Check
    const cleanDom = domainCheckInput.trim().toLowerCase();
    const suspiciousSignals: string[] = [];
    if (/[0-9]/.test(cleanDom.split('.')[0])) {
      suspiciousSignals.push('Homograph / numeric substitution detected in brand token (e.g. paypa1 / micr0soft).');
    }
    if ((cleanDom.match(/-/g) || []).length >= 2) {
      suspiciousSignals.push('Multiple hyphens in primary hostname typical of credential harvesting kits.');
    }
    if (/\.(xyz|top|click|zip|work|gq)$/i.test(cleanDom)) {
      suspiciousSignals.push('High-risk TLD frequently abused in automated phishing campaigns.');
    }
    if (/(login|verify|update|secure|account|wallet)/i.test(cleanDom)) {
      suspiciousSignals.push('Urgency/authentication lure keyword embedded in domain label.');
    }

    return (
      <div className="space-y-6">
        {/* CVE Vulnerability Database */}
        <div className="bg-[#0F172A] border border-slate-800 rounded-xl p-6">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-5">
            <div>
              <h2 className="text-lg font-semibold text-white">
                CVE Advisory & CVSS v3.1 Threat Intelligence Feed
              </h2>
              <p className="text-xs text-slate-400">
                Search high-priority vulnerabilities, inspect CVSS vectors, and review defensive patches.
              </p>
            </div>
            <div className="flex flex-wrap items-center gap-3">
              <label htmlFor="cve-search-input" className="sr-only">
                Search CVE Advisories
              </label>
              <input
                id="cve-search-input"
                type="text"
                value={cveSearch}
                onChange={(e) => setCveSearch(e.target.value)}
                placeholder="Search CVE ID or keyword..."
                className="px-3.5 py-1.5 text-xs bg-[#080D1A] border border-slate-700 rounded-lg text-white focus:outline-none focus:border-cyan-400"
              />
              <select
                aria-label="Filter CVEs by Severity"
                value={severityFilter}
                onChange={(e) => setSeverityFilter(e.target.value)}
                className="px-3 py-1.5 text-xs bg-[#080D1A] border border-slate-700 rounded-lg text-slate-200"
              >
                <option value="ALL">All Severities</option>
                <option value="Critical">Critical (9.0+)</option>
                <option value="High">High (7.0–8.9)</option>
              </select>
            </div>
          </div>

          <div className="space-y-4">
            {filteredCves.map((cve) => (
              <div
                key={cve.id}
                className="p-4 rounded-xl bg-[#080D1A] border border-slate-800 space-y-2"
              >
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-2 text-xs font-mono">
                    <span className="text-cyan-400 font-bold">{cve.id}</span>
                    <span aria-hidden="true">·</span>
                    <span className="text-slate-300">{cve.affected}</span>
                  </div>
                  <div className="text-xs font-mono tabular-nums">
                    <span
                      className={
                        cve.severity === 'Critical' ? 'text-red-400 font-bold' : 'text-amber-400 font-bold'
                      }
                    >
                      CVSS {cve.cvssScore.toFixed(1)} ({cve.severity})
                    </span>
                  </div>
                </div>
                <h3 className="text-sm font-semibold text-white">{cve.title}</h3>
                <p className="text-xs text-slate-300 leading-relaxed">{cve.summary}</p>
                <div className="pt-2 border-t border-slate-800/80 flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs">
                  <span className="font-mono text-slate-400">{cve.vector}</span>
                  <span className="text-emerald-400 font-medium">
                    Mitigation: {cve.mitigation}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Phishing Domain Reputation & Malware Taxonomy */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          <div className="lg:col-span-6 bg-[#0F172A] border border-slate-800 rounded-xl p-6">
            <h3 className="text-base font-semibold text-white mb-1">
              Phishing & Suspicious Domain Heuristic Analyzer
            </h3>
            <p className="text-xs text-slate-400 mb-4">
              Evaluate suspicious hostnames for homograph attacks, credential lures, and high-risk TLDs.
            </p>
            <label htmlFor="phish-domain-input" className="sr-only">
              Suspicious Domain to Inspect
            </label>
            <input
              id="phish-domain-input"
              type="text"
              value={domainCheckInput}
              onChange={(e) => setDomainCheckInput(e.target.value)}
              className="w-full px-3.5 py-2 text-xs font-mono bg-[#080D1A] border border-slate-700 rounded-lg text-white mb-4 focus:outline-none focus:border-cyan-400"
            />
            <div className="p-4 rounded-lg bg-[#080D1A] border border-slate-800 space-y-2">
              <div className="flex items-center justify-between text-xs font-mono">
                <span className="text-slate-400">Reputation Verdict</span>
                <span
                  className={
                    suspiciousSignals.length >= 2
                      ? 'text-red-400 font-bold'
                      : suspiciousSignals.length === 1
                      ? 'text-amber-400 font-bold'
                      : 'text-emerald-400 font-bold'
                  }
                >
                  {suspiciousSignals.length >= 2
                    ? 'HIGH PHISHING RISK'
                    : suspiciousSignals.length === 1
                    ? 'MODERATE SUSPICION'
                    : 'CLEAN HEURISTICS'}
                </span>
              </div>
              {suspiciousSignals.length > 0 ? (
                <ul className="space-y-1.5 text-xs text-slate-300 pt-2">
                  {suspiciousSignals.map((sig, i) => (
                    <li key={i} className="flex items-start gap-2">
                      <AlertTriangle className="w-3.5 h-3.5 text-amber-400 shrink-0 mt-0.5" />
                      <span>{sig}</span>
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="text-xs text-slate-400 pt-1">
                  No lexical phishing lures or homograph substitutions detected.
                </p>
              )}
            </div>
          </div>

          <div className="lg:col-span-6 bg-[#0F172A] border border-slate-800 rounded-xl p-6">
            <h3 className="text-base font-semibold text-white mb-1">
              Defensive Malware Classification Reference
            </h3>
            <p className="text-xs text-slate-400 mb-4">
              Behavioral indicators and containment playbooks for SOC incident responders.
            </p>
            <div className="space-y-3 text-xs">
              <div className="p-3 rounded-lg bg-[#080D1A] border border-slate-800">
                <p className="font-semibold text-white">
                  Ransomware / Crypto-Extortion · MITRE T1486
                </p>
                <p className="text-slate-400 mt-1">
                  Indicators: Rapid volume shadow copy deletion (`vssadmin delete shadows`), high-entropy file renames. Defense: Immutable offline backups & SMBv1 disablement.
                </p>
              </div>
              <div className="p-3 rounded-lg bg-[#080D1A] border border-slate-800">
                <p className="font-semibold text-white">
                  InfoStealers & Session Token Harvesters · MITRE T1539
                </p>
                <p className="text-slate-400 mt-1">
                  Indicators: Unauthorized reads of browser SQLite cookie stores and DPAPI keys. Defense: Hardware-bound FIDO2 WebAuthn & short-lived HttpOnly tokens.
                </p>
              </div>
              <div className="p-3 rounded-lg bg-[#080D1A] border border-slate-800">
                <p className="font-semibold text-white">
                  Fileless Memory Injection / LOLBins · MITRE T1055
                </p>
                <p className="text-slate-400 mt-1">
                  Indicators: Encoded PowerShell or anomalous child processes spawned by web workers. Defense: Application allowlisting and strict egress firewalling.
                </p>
              </div>
            </div>
          </div>
        </div>
      </div>
    );
  }

  // MODULE 05: CRYPTOGRAPHY LAB
  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left: Input & Cryptographic Hash Generator */}
        <div className="lg:col-span-6 bg-[#0F172A] border border-slate-800 rounded-xl p-6 space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-lg font-semibold text-white">
                SHA-256 / SHA-512 & HMAC Digest Workbench
              </h2>
              <p className="text-xs text-slate-400">
                Compute collision-resistant cryptographic hashes and keyed HMAC authenticators.
              </p>
            </div>
            <Lock className="w-5 h-5 text-cyan-400" />
          </div>

          <div>
            <label htmlFor="crypto-payload-input" className="block text-xs text-slate-300 mb-1.5">
              Input Payload (Plaintext or Base64 / Ciphertext Artifact)
            </label>
            <textarea
              id="crypto-payload-input"
              rows={3}
              value={cryptoInput}
              onChange={(e) => setCryptoInput(e.target.value)}
              className="w-full p-3 text-xs font-mono bg-[#080D1A] border border-slate-700 rounded-lg text-white focus:outline-none focus:border-cyan-400"
            />
          </div>

          <div>
            <label htmlFor="crypto-hmac-key" className="block text-xs text-slate-300 mb-1.5">
              HMAC Secret Key
            </label>
            <input
              id="crypto-hmac-key"
              type="text"
              value={hmacKey}
              onChange={(e) => setHmacKey(e.target.value)}
              className="w-full px-3 py-2 text-xs font-mono bg-[#080D1A] border border-slate-700 rounded-lg text-white focus:outline-none focus:border-cyan-400"
            />
          </div>

          <button
            type="button"
            onClick={handleComputeHashes}
            className="w-full py-2.5 px-4 text-xs font-semibold text-slate-950 bg-cyan-400 hover:bg-cyan-300 rounded-lg transition-colors cursor-pointer"
          >
            Generate Cryptographic Digests (SHA-256 / SHA-512 / HMAC)
          </button>

          {hashResult && (
            <div className="space-y-3 pt-2 text-xs font-mono">
              {[
                { label: 'SHA-256 (256-bit)', val: hashResult.sha256 },
                { label: 'SHA-512 (512-bit)', val: hashResult.sha512 },
                { label: 'HMAC-SHA256', val: hashResult.hmacSha256 },
              ].map((item) => (
                <div
                  key={item.label}
                  className="p-3 rounded-lg bg-[#080D1A] border border-slate-800"
                >
                  <div className="flex items-center justify-between text-slate-400 mb-1">
                    <span>{item.label}</span>
                    <button
                      type="button"
                      onClick={() => copyText(item.val, item.label)}
                      className="text-cyan-400 hover:underline flex items-center gap-1 cursor-pointer"
                    >
                      {copiedField === item.label ? (
                        <>
                          <Check className="w-3 h-3" /> Copied
                        </>
                      ) : (
                        <>
                          <Copy className="w-3 h-3" /> Copy
                        </>
                      )}
                    </button>
                  </div>
                  <p className="text-emerald-300 break-all">{item.val}</p>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Right: Encoding, Classical Ciphers, AES-256-GCM & RSA Digital Signatures */}
        <div className="lg:col-span-6 bg-[#0F172A] border border-slate-800 rounded-xl p-6 space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-lg font-semibold text-white">
                Ciphers, Base64, AES-256-GCM & RSA Signatures
              </h2>
              <p className="text-xs text-slate-400">
                Decode CTF artifacts or demonstrate authenticated encryption and digital signatures.
              </p>
            </div>
            <Key className="w-5 h-5 text-emerald-400" />
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div>
              <label htmlFor="cipher-mode-select" className="block text-xs text-slate-300 mb-1.5">
                Operation / Algorithm
              </label>
              <select
                id="cipher-mode-select"
                value={cipherMode}
                onChange={(e) => setCipherMode(e.target.value)}
                className="w-full px-3 py-2 text-xs bg-[#080D1A] border border-slate-700 rounded-lg text-white font-mono"
              >
                <option value="base64-encode">Base64 Encode</option>
                <option value="base64-decode">Base64 Decode</option>
                <option value="caesar-encrypt">Caesar Cipher (Encrypt)</option>
                <option value="caesar-decrypt">Caesar Cipher (Decrypt)</option>
                <option value="vigenere-encrypt">Vigenère Cipher (Encrypt)</option>
                <option value="vigenere-decrypt">Vigenère Cipher (Decrypt)</option>
                <option value="aes-gcm-demo">AES-256-GCM Authenticated Encrypt</option>
                <option value="rsa-sign-demo">RSA-2048 Digital Signature & Verify</option>
              </select>
            </div>

            {cipherMode.startsWith('caesar') ? (
              <div>
                <label htmlFor="caesar-shift-input" className="block text-xs text-slate-300 mb-1.5">
                  Shift Key (1–25)
                </label>
                <input
                  id="caesar-shift-input"
                  type="number"
                  min={1}
                  max={25}
                  value={cipherShift}
                  onChange={(e) => setCipherShift(Number(e.target.value))}
                  className="w-full px-3 py-2 text-xs font-mono bg-[#080D1A] border border-slate-700 rounded-lg text-white"
                />
              </div>
            ) : (
              <div>
                <label htmlFor="cipher-key-input" className="block text-xs text-slate-300 mb-1.5">
                  Cipher Passphrase / Key
                </label>
                <input
                  id="cipher-key-input"
                  type="text"
                  value={cipherKey}
                  onChange={(e) => setCipherKey(e.target.value)}
                  className="w-full px-3 py-2 text-xs font-mono bg-[#080D1A] border border-slate-700 rounded-lg text-white"
                />
              </div>
            )}
          </div>

          <div className="flex flex-wrap items-center gap-2 text-xs">
            <span className="text-slate-400">CTF Quick Load:</span>
            <button
              type="button"
              onClick={() => {
                const artifact = 'Q1N7YjRzZTY0X2IzNGMwbjFfZGVjb2QzZH0=';
                setCryptoInput(artifact);
                setCipherMode('base64-decode');
                handleRunCipher('base64-decode', artifact);
              }}
              className="px-2.5 py-1 rounded bg-slate-900 hover:bg-slate-800 text-cyan-300 border border-slate-700 font-mono cursor-pointer"
            >
              Decode CTF-01 Base64
            </button>
            <button
              type="button"
              onClick={() => {
                const artifact = 'JZ{jh3zhy_zo1ma_jyfwa0}';
                setCryptoInput(artifact);
                setCipherMode('caesar-decrypt');
                setCipherShift(7);
                handleRunCipher('caesar-decrypt', artifact);
              }}
              className="px-2.5 py-1 rounded bg-slate-900 hover:bg-slate-800 text-cyan-300 border border-slate-700 font-mono cursor-pointer"
            >
              Decrypt CTF-02 Caesar (-7)
            </button>
          </div>

          <button
            type="button"
            onClick={() => handleRunCipher()}
            className="w-full py-2.5 px-4 text-xs font-semibold text-white bg-slate-800 hover:bg-slate-700 border border-slate-600 rounded-lg transition-colors cursor-pointer"
          >
            Execute Transformation ({cipherMode})
          </button>

          {cipherOutput && (
            <div className="p-4 rounded-lg bg-[#080D1A] border border-slate-800 font-mono text-xs space-y-2">
              <div className="flex items-center justify-between text-slate-400">
                <span>Result Output</span>
                <button
                  type="button"
                  onClick={() => copyText(cipherOutput, 'cipherOut')}
                  className="text-cyan-400 hover:underline cursor-pointer"
                >
                  {copiedField === 'cipherOut' ? 'Copied' : 'Copy Output'}
                </button>
              </div>
              <p className="text-cyan-300 break-all text-sm font-semibold">{cipherOutput}</p>
              {Object.keys(cipherDetails).length > 0 && (
                <div className="pt-2 border-t border-slate-800 space-y-1 text-slate-300">
                  {Object.entries(cipherDetails).map(([k, v]) => (
                    <p key={k} className="break-all">
                      <span className="text-slate-400">{k}:</span> {v}
                    </p>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
