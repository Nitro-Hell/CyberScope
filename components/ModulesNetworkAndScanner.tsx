'use client';

import React, { useState, useEffect } from 'react';
import {
  Globe,
  Shield,
  Search,
  RefreshCw,
  Lock,
  AlertTriangle,
  CheckCircle2,
  Network,
  KeyRound,
} from 'lucide-react';
import { evaluatePasswordStrength, HeaderCheckItem } from '@/lib/cyber-engine';
import { NetworkDeviceRecord } from '@/lib/server-db';

interface NetworkAndScannerProps {
  mode: 'network' | 'scanner';
  initialDevices: NetworkDeviceRecord[];
  onScanComplete?: () => void;
}

interface DnsResult {
  hostname: string;
  queryTimeMs: number;
  records: {
    A: string[];
    AAAA: string[];
    MX: Array<{ exchange: string; priority: number }>;
    NS: string[];
    TXT: string[];
    DMARC: string[];
  };
  dnsSecPosture: {
    spfPresent: boolean;
    dmarcPresent: boolean;
    redundancyNsCount: number;
  };
}

interface HeaderScanResponse {
  target: string;
  hostname: string;
  isHttps: boolean;
  statusCode: number;
  latencyMs: number;
  assessment: {
    score: number;
    grade: string;
    checks: HeaderCheckItem[];
    summary: string;
  };
}

interface SslScanResponse {
  hostname: string;
  score: number;
  grade: string;
  certificate: {
    subject: string;
    issuer: string;
    validFrom: string;
    validTo: string;
    daysRemaining: number;
    protocol: string;
    cipherSuite: string;
    serialNumber: string;
    fingerprint256: string;
  };
}

const SAMPLE_PCAP_PACKETS = [
  {
    frame: 1,
    ts: '02:14:00.104',
    src: '10.20.1.15:51422',
    dst: '1.1.1.1:53',
    proto: 'DNS',
    len: 74,
    info: 'Standard query 0x8a11 A cyberscope.internal',
  },
  {
    frame: 2,
    ts: '02:14:00.115',
    src: '1.1.1.1:53',
    dst: '10.20.1.15:51422',
    proto: 'DNS',
    len: 90,
    info: 'Standard query response 0x8a11 A 93.184.215.14',
  },
  {
    frame: 3,
    ts: '02:14:01.402',
    src: '185.220.101.44:51822',
    dst: '10.20.0.1:22',
    proto: 'SSHv2',
    len: 148,
    info: 'Client: Key Exchange Init (Repeated failed auth origin)',
  },
  {
    frame: 44,
    ts: '02:14:19.882',
    src: '10.20.4.19:59122',
    dst: '198.51.100.77:4444',
    proto: 'TCP',
    len: 60,
    info: '[SYN] Seq=0 Win=64240 Len=0 MSS=1460 (Anomalous C2 Port 4444)',
  },
];

export default function ModulesNetworkAndScanner({
  mode,
  initialDevices,
  onScanComplete,
}: NetworkAndScannerProps) {
  // Network Intelligence States
  const [dnsInput, setDnsInput] = useState('cloudflare.com');
  const [dnsLoading, setDnsLoading] = useState(false);
  const [dnsError, setDnsError] = useState('');
  const [dnsData, setDnsData] = useState<DnsResult | null>(null);
  const [deviceFilter, setDeviceFilter] = useState('');
  const [zoneFilter, setZoneFilter] = useState<string>('ALL');
  const [selectedPacket, setSelectedPacket] = useState(SAMPLE_PCAP_PACKETS[3]);
  const [publicTelemetry, setPublicTelemetry] = useState({
    observedPublicIp: '203.0.113.42',
    asnOrganization: 'AS15169 Google Cloud / Edge Gateway',
    tlsProtocol: 'TLSv1.3 (AEAD-AES256-GCM-SHA384)',
    gatewayHostname: 'cyberscope-soc-gw01',
  });

  // Security Scanner States
  const [scanUrl, setScanUrl] = useState('https://cloudflare.com');
  const [scanLoading, setScanLoading] = useState(false);
  const [scanError, setScanError] = useState('');
  const [headerResult, setHeaderResult] = useState<HeaderScanResponse | null>(null);
  const [sslResult, setSslResult] = useState<SslScanResponse | null>(null);
  const [authorizedConfirm, setAuthorizedConfirm] = useState(true);
  const [passwordTestInput, setPasswordTestInput] = useState('CyberScope#BlueTeam2026!');

  const runDnsLookup = async (domainToQuery?: string) => {
    const target = (domainToQuery ?? dnsInput).trim();
    setDnsError('');
    setDnsLoading(true);
    try {
      const res = await fetch(`/api/network/dns?domain=${encodeURIComponent(target)}`);
      const data = await res.json();
      if (!res.ok || data.status === 'error') {
        setDnsError(data.error || 'DNS lookup rejected.');
        setDnsData(null);
      } else {
        setDnsData(data);
        onScanComplete?.();
      }
    } catch {
      setDnsError('Network DNS lookup service error.');
    } finally {
      setDnsLoading(false);
    }
  };

  const runFullSecurityScan = async (overrideTarget?: string) => {
    const target = (overrideTarget ?? scanUrl).trim();
    if (!authorizedConfirm) {
      setScanError('You must confirm authorization to assess the target domain.');
      return;
    }
    setScanError('');
    setScanLoading(true);
    try {
      const [hRes, sRes] = await Promise.all([
        fetch(`/api/scanner/headers?url=${encodeURIComponent(target)}`),
        fetch(`/api/scanner/ssl?host=${encodeURIComponent(target)}`),
      ]);
      const hData = await hRes.json();
      const sData = await sRes.json();

      if (!hRes.ok || hData.status === 'error') {
        setScanError(hData.error || 'Target blocked by SSRF security policy.');
        setHeaderResult(null);
        setSslResult(null);
      } else {
        setHeaderResult(hData);
        if (sRes.ok && sData.status === 'ok') {
          setSslResult(sData);
        }
        onScanComplete?.();
      }
    } catch {
      setScanError('Failed to execute security assessment.');
    } finally {
      setScanLoading(false);
    }
  };

  useEffect(() => {
    if (mode === 'network') {
      fetch('/api/network/info')
        .then((r) => r.json())
        .then((d) => {
          if (d.clientTelemetry) setPublicTelemetry(d.clientTelemetry);
        })
        .catch(() => {});
      fetch('/api/network/dns?domain=cloudflare.com')
        .then((r) => r.json())
        .then((d) => {
          if (d.status === 'ok') setDnsData(d);
        })
        .catch(() => {});
    } else if (mode === 'scanner') {
      Promise.all([
        fetch('/api/scanner/headers?url=https%3A%2F%2Fcloudflare.com').then((r) => r.json()),
        fetch('/api/scanner/ssl?host=https%3A%2F%2Fcloudflare.com').then((r) => r.json()),
      ])
        .then(([hData, sData]) => {
          if (hData.status === 'ok') setHeaderResult(hData);
          if (sData.status === 'ok') setSslResult(sData);
        })
        .catch(() => {});
    }
  }, [mode]);

  const filteredDevices = initialDevices.filter((d) => {
    const matchesText =
      d.hostname.toLowerCase().includes(deviceFilter.toLowerCase()) ||
      d.ipAddress.includes(deviceFilter) ||
      d.os.toLowerCase().includes(deviceFilter.toLowerCase());
    const matchesZone = zoneFilter === 'ALL' || d.zone === zoneFilter;
    return matchesText && matchesZone;
  });

  const pwAssessment = evaluatePasswordStrength(passwordTestInput);

  if (mode === 'network') {
    return (
      <div className="space-y-6">
        {/* Top Telemetry Bar */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          <div className="bg-[#0F172A] border border-slate-800 rounded-xl p-4">
            <p className="text-xs text-slate-400">Observed Public Edge IP</p>
            <p className="text-lg font-bold text-white font-mono tabular-nums mt-1">
              {publicTelemetry.observedPublicIp}
            </p>
            <p className="text-xs text-slate-400 mt-1">{publicTelemetry.asnOrganization}</p>
          </div>
          <div className="bg-[#0F172A] border border-slate-800 rounded-xl p-4">
            <p className="text-xs text-slate-400">Transport Encryption</p>
            <p className="text-lg font-bold text-emerald-400 font-mono tabular-nums mt-1">
              TLSv1.3 AEAD
            </p>
            <p className="text-xs text-slate-400 mt-1">{publicTelemetry.tlsProtocol}</p>
          </div>
          <div className="bg-[#0F172A] border border-slate-800 rounded-xl p-4">
            <p className="text-xs text-slate-400">Authorized Inventory</p>
            <p className="text-lg font-bold text-cyan-400 font-mono tabular-nums mt-1">
              {initialDevices.length} Active Nodes
            </p>
            <p className="text-xs text-slate-400 mt-1">
              1 Endpoint flagged for port 4444 review
            </p>
          </div>
          <div className="bg-[#0F172A] border border-slate-800 rounded-xl p-4">
            <p className="text-xs text-slate-400">DNS Resolver Latency</p>
            <p className="text-lg font-bold text-white font-mono tabular-nums mt-1">
              {dnsData ? `${dnsData.queryTimeMs} ms` : '11 ms'}
            </p>
            <p className="text-xs text-slate-400 mt-1">
              Gateway: {publicTelemetry.gatewayHostname}
            </p>
          </div>
        </div>

        {/* DNS Lookup & Topology Split */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          <div className="lg:col-span-7 bg-[#0F172A] border border-slate-800 rounded-xl p-6">
            <div className="flex items-center justify-between mb-4">
              <div>
                <h2 className="text-lg font-semibold text-white">
                  Live DNS Resolution & Email Authentication Inspector
                </h2>
                <p className="text-xs text-slate-400">
                  Query A, AAAA, MX, NS, SPF, and DMARC records with SSRF private-IP filtering.
                </p>
              </div>
              <Globe className="w-5 h-5 text-cyan-400" />
            </div>

            <form
              onSubmit={(e) => {
                e.preventDefault();
                runDnsLookup();
              }}
              className="flex flex-col sm:flex-row gap-3 mb-4"
            >
              <label htmlFor="dns-domain-input" className="sr-only">
                Domain to Resolve
              </label>
              <input
                id="dns-domain-input"
                type="text"
                value={dnsInput}
                onChange={(e) => setDnsInput(e.target.value)}
                placeholder="Enter public domain (e.g. cloudflare.com, google.com)"
                className="flex-1 px-3.5 py-2 text-sm bg-[#080D1A] border border-slate-700 rounded-lg text-white font-mono focus:outline-none focus:border-cyan-400"
              />
              <button
                type="submit"
                disabled={dnsLoading}
                className="px-4 py-2 text-xs font-semibold text-slate-950 bg-cyan-400 hover:bg-cyan-300 rounded-lg transition-colors whitespace-nowrap shrink-0 cursor-pointer"
              >
                {dnsLoading ? 'Resolving...' : 'Resolve DNS Records'}
              </button>
            </form>

            <div className="flex flex-wrap items-center gap-2 mb-4 text-xs">
              <span className="text-slate-400">Presets:</span>
              {['cloudflare.com', 'google.com', 'example.com', '127.0.0.1'].map((preset) => (
                <button
                  key={preset}
                  type="button"
                  onClick={() => {
                    setDnsInput(preset);
                    runDnsLookup(preset);
                  }}
                  className="px-2.5 py-1 rounded bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-700/80 font-mono cursor-pointer"
                >
                  {preset}
                </button>
              ))}
            </div>

            {dnsError && (
              <div
                role="alert"
                className="p-3.5 rounded-lg bg-red-950/50 border border-red-800 text-xs text-red-200 flex items-center gap-2"
              >
                <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
                <span>{dnsError}</span>
              </div>
            )}

            {dnsData && (
              <div className="space-y-3 mt-4">
                <div className="flex flex-wrap items-center justify-between text-xs text-slate-300 pb-3 border-b border-slate-800">
                  <span className="font-mono">
                    Host: <strong className="text-white">{dnsData.hostname}</strong> · Latency:{' '}
                    {dnsData.queryTimeMs} ms
                  </span>
                  <span className="font-mono">
                    SPF: {dnsData.dnsSecPosture.spfPresent ? 'Enforced' : 'Not Detected'} · DMARC:{' '}
                    {dnsData.dnsSecPosture.dmarcPresent ? 'Enforced' : 'Not Detected'}
                  </span>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs font-mono">
                  <div className="p-3 rounded-lg bg-[#080D1A] border border-slate-800">
                    <p className="text-cyan-400 mb-1">IPv4 (A) Records</p>
                    <p className="text-slate-200">
                      {dnsData.records.A.length > 0
                        ? dnsData.records.A.join(', ')
                        : 'No A records returned'}
                    </p>
                  </div>
                  <div className="p-3 rounded-lg bg-[#080D1A] border border-slate-800">
                    <p className="text-cyan-400 mb-1">Nameservers (NS)</p>
                    <p className="text-slate-200">
                      {dnsData.records.NS.length > 0
                        ? dnsData.records.NS.slice(0, 3).join(', ')
                        : 'Default authoritative NS'}
                    </p>
                  </div>
                  <div className="p-3 rounded-lg bg-[#080D1A] border border-slate-800 sm:col-span-2">
                    <p className="text-cyan-400 mb-1">TXT / SPF Policy Records</p>
                    <p className="text-slate-300 break-all">
                      {dnsData.records.TXT.length > 0
                        ? dnsData.records.TXT.slice(0, 2).join(' | ')
                        : 'No TXT records published'}
                    </p>
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* Network Topology SVG Visualization */}
          <div className="lg:col-span-5 bg-[#0F172A] border border-slate-800 rounded-xl p-6 flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between mb-3">
                <h2 className="text-lg font-semibold text-white">
                  SOC Network Segment Topology
                </h2>
                <Network className="w-5 h-5 text-cyan-400" />
              </div>
              <p className="text-xs text-slate-400 mb-4">
                Real-time logical segmentation across DMZ, Core SOC, Production, and Endpoint VLANs.
              </p>

              <div className="bg-[#080D1A] border border-slate-800 rounded-lg p-3">
                <svg
                  viewBox="0 0 480 220"
                  className="w-full h-48"
                  role="img"
                  aria-label="CyberScope Network Topology Diagram"
                >
                  {/* Links */}
                  <line x1="240" y1="38" x2="82" y2="110" stroke="#06b6d4" strokeWidth="1.5" />
                  <line x1="240" y1="38" x2="240" y2="110" stroke="#06b6d4" strokeWidth="1.5" />
                  <line x1="240" y1="38" x2="398" y2="110" stroke="#f59e0b" strokeWidth="1.5" strokeDasharray="4 3" />
                  <line x1="240" y1="110" x2="240" y2="185" stroke="#10b981" strokeWidth="1.5" />

                  {/* Edge Firewall Node */}
                  <rect x="160" y="14" width="160" height="32" rx="6" fill="#0F172A" stroke="#22d3ee" strokeWidth="1.5" />
                  <text x="240" y="34" textAnchor="middle" fill="#f8fafc" fontSize="9.5" fontFamily="monospace">
                    soc-edge-fw01 (10.20.0.1)
                  </text>

                  {/* Core SOC Node */}
                  <rect x="10" y="96" width="145" height="34" rx="6" fill="#0F172A" stroke="#10b981" strokeWidth="1.5" />
                  <text x="82" y="116" textAnchor="middle" fill="#f8fafc" fontSize="9.5" fontFamily="monospace">
                    siem-01 (10.20.1.15)
                  </text>

                  {/* Prod API Gateway */}
                  <rect x="168" y="96" width="145" height="34" rx="6" fill="#0F172A" stroke="#38bdf8" strokeWidth="1.5" />
                  <text x="240" y="116" textAnchor="middle" fill="#f8fafc" fontSize="9.5" fontFamily="monospace">
                    api-gw02 (10.20.2.40)
                  </text>

                  {/* Flagged Workstation */}
                  <rect x="325" y="96" width="145" height="34" rx="6" fill="#0F172A" stroke="#f59e0b" strokeWidth="1.5" />
                  <text x="397" y="116" textAnchor="middle" fill="#fde68a" fontSize="9.5" fontFamily="monospace">
                    wkst-19 (Port 4444!)
                  </text>

                  {/* PostgreSQL Replica */}
                  <rect x="160" y="170" width="160" height="32" rx="6" fill="#0F172A" stroke="#10b981" strokeWidth="1.5" />
                  <text x="240" y="190" textAnchor="middle" fill="#f8fafc" fontSize="9.5" fontFamily="monospace">
                    pg-replica (10.20.2.88)
                  </text>
                </svg>
              </div>
            </div>

            <div className="mt-4 flex items-center justify-between text-xs text-slate-400">
              <span>Segment Isolation: RFC1918 VLANs</span>
              <span className="text-amber-300 font-mono">1 Anomaly: 10.20.4.19:4444</span>
            </div>
          </div>
        </div>

        {/* Authorized Network Device Inventory */}
        <div className="bg-[#0F172A] border border-slate-800 rounded-xl p-6">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-5">
            <div>
              <h2 className="text-lg font-semibold text-white">
                Authorized Network Device Inventory
              </h2>
              <p className="text-xs text-slate-400">
                Live asset registry across monitored VLANs with open port and latency telemetry.
              </p>
            </div>
            <div className="flex flex-wrap items-center gap-3">
              <label htmlFor="device-search" className="sr-only">
                Filter network devices
              </label>
              <input
                id="device-search"
                type="text"
                value={deviceFilter}
                onChange={(e) => setDeviceFilter(e.target.value)}
                placeholder="Filter hostname or IP..."
                className="px-3 py-1.5 text-xs bg-[#080D1A] border border-slate-700 rounded-lg text-white focus:outline-none focus:border-cyan-400"
              />
              <select
                aria-label="Filter by Network Zone"
                value={zoneFilter}
                onChange={(e) => setZoneFilter(e.target.value)}
                className="px-3 py-1.5 text-xs bg-[#080D1A] border border-slate-700 rounded-lg text-slate-200"
              >
                <option value="ALL">All Zones</option>
                <option value="DMZ Perimeter">DMZ Perimeter</option>
                <option value="Core SOC">Core SOC</option>
                <option value="Production App">Production App</option>
                <option value="Endpoint VLAN">Endpoint VLAN</option>
              </select>
            </div>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-slate-800 text-xs text-slate-400">
                  <th className="py-2.5 px-3 font-medium">Hostname</th>
                  <th className="py-2.5 px-3 font-medium">IPv4 / MAC</th>
                  <th className="py-2.5 px-3 font-medium">Security Zone</th>
                  <th className="py-2.5 px-3 font-medium">OS / Platform</th>
                  <th className="py-2.5 px-3 font-medium">Open Ports</th>
                  <th className="py-2.5 px-3 font-medium text-right">Latency</th>
                  <th className="py-2.5 px-3 font-medium text-right">Posture</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/70 text-xs">
                {filteredDevices.map((dev) => (
                  <tr key={dev.id} className="hover:bg-slate-900/60">
                    <td className="py-3 px-3 font-mono text-white font-medium">
                      {dev.hostname}
                    </td>
                    <td className="py-3 px-3 font-mono text-slate-300 tabular-nums">
                      {dev.ipAddress} · <span className="text-slate-400">{dev.macAddress}</span>
                    </td>
                    <td className="py-3 px-3 text-slate-300">{dev.zone}</td>
                    <td className="py-3 px-3 text-slate-300">{dev.os}</td>
                    <td className="py-3 px-3 font-mono text-cyan-300 tabular-nums">
                      {dev.openPorts.join(', ')}
                    </td>
                    <td className="py-3 px-3 font-mono text-right text-slate-300 tabular-nums">
                      {dev.latencyMs.toFixed(1)} ms
                    </td>
                    <td className="py-3 px-3 text-right font-medium">
                      <span
                        className={
                          dev.status === 'Authorized'
                            ? 'text-emerald-400'
                            : 'text-amber-400'
                        }
                      >
                        {dev.status}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Offline PCAP Metadata Dissector */}
        <div className="bg-[#0F172A] border border-slate-800 rounded-xl p-6">
          <div className="mb-4">
            <h2 className="text-lg font-semibold text-white">
              Offline PCAP Packet Metadata Analyzer (capture_perimeter.pcap)
            </h2>
            <p className="text-xs text-slate-400">
              Click any captured frame below to inspect L3/L4 header metadata and CTF beacon indicators.
            </p>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
            <div className="lg:col-span-8 overflow-x-auto">
              <table className="w-full text-left border-collapse text-xs font-mono">
                <thead>
                  <tr className="border-b border-slate-800 text-slate-400">
                    <th className="py-2 px-2.5">Frame</th>
                    <th className="py-2 px-2.5">Time</th>
                    <th className="py-2 px-2.5">Source</th>
                    <th className="py-2 px-2.5">Destination</th>
                    <th className="py-2 px-2.5">Proto</th>
                    <th className="py-2 px-2.5">Summary</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/70">
                  {SAMPLE_PCAP_PACKETS.map((pkt) => (
                    <tr
                      key={pkt.frame}
                      onClick={() => setSelectedPacket(pkt)}
                      className={`cursor-pointer transition-colors ${
                        selectedPacket.frame === pkt.frame
                          ? 'bg-cyan-950/40 text-cyan-200'
                          : 'hover:bg-slate-900/60 text-slate-300'
                      }`}
                    >
                      <td className="py-2.5 px-2.5 tabular-nums">#{pkt.frame}</td>
                      <td className="py-2.5 px-2.5 tabular-nums">{pkt.ts}</td>
                      <td className="py-2.5 px-2.5 tabular-nums">{pkt.src}</td>
                      <td className="py-2.5 px-2.5 tabular-nums">{pkt.dst}</td>
                      <td className="py-2.5 px-2.5 text-cyan-400">{pkt.proto}</td>
                      <td className="py-2.5 px-2.5">{pkt.info}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            <div className="lg:col-span-4 bg-[#080D1A] border border-slate-800 rounded-lg p-4 text-xs font-mono space-y-2">
              <p className="text-cyan-400 font-semibold">
                Frame #{selectedPacket.frame} Dissection
              </p>
              <p className="text-slate-300">Timestamp: {selectedPacket.ts} UTC</p>
              <p className="text-slate-300">Source Socket: {selectedPacket.src}</p>
              <p className="text-slate-300">Target Socket: {selectedPacket.dst}</p>
              <p className="text-slate-300">
                Protocol: {selectedPacket.proto} · Length: {selectedPacket.len} bytes
              </p>
              <p className="text-slate-400 pt-2 border-t border-slate-800">
                {selectedPacket.info}
              </p>
            </div>
          </div>
        </div>
      </div>
    );
  }

  // MODULE 02: SECURITY SCANNER
  return (
    <div className="space-y-6">
      <div className="bg-[#0F172A] border border-slate-800 rounded-xl p-6">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-5">
          <div>
            <h2 className="text-lg font-semibold text-white">
              Authorized Website Security & SSL/TLS Assessment
            </h2>
            <p className="text-xs text-slate-400">
              Inspect HTTP defensive headers, TLS cipher suites, and certificate validity. SSRF
              protection blocks private RFC1918 and loopback addresses.
            </p>
          </div>
          <div className="flex items-center gap-2 text-xs font-mono text-emerald-400">
            <Shield className="w-4 h-4" />
            <span>SSRF Private-IP Blocker Active</span>
          </div>
        </div>

        <form
          onSubmit={(e) => {
            e.preventDefault();
            runFullSecurityScan();
          }}
          className="space-y-3"
        >
          <div className="flex flex-col sm:flex-row gap-3">
            <label htmlFor="scanner-url-input" className="sr-only">
              Target HTTPS URL to Scan
            </label>
            <input
              id="scanner-url-input"
              type="text"
              value={scanUrl}
              onChange={(e) => setScanUrl(e.target.value)}
              placeholder="https://cloudflare.com"
              className="flex-1 px-3.5 py-2.5 text-sm bg-[#080D1A] border border-slate-700 rounded-lg text-white font-mono focus:outline-none focus:border-cyan-400"
            />
            <button
              type="submit"
              disabled={scanLoading}
              className="px-5 py-2.5 text-xs font-semibold text-slate-950 bg-cyan-400 hover:bg-cyan-300 rounded-lg transition-colors flex items-center justify-center gap-2 whitespace-nowrap shrink-0 cursor-pointer"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${scanLoading ? 'animate-spin' : ''}`} />
              <span>{scanLoading ? 'Scanning Target...' : 'Run Security Scan'}</span>
            </button>
          </div>

          <div className="flex flex-wrap items-center justify-between gap-4 pt-1">
            <label className="flex items-center gap-2 text-xs text-slate-300 cursor-pointer">
              <input
                type="checkbox"
                checked={authorizedConfirm}
                onChange={(e) => setAuthorizedConfirm(e.target.checked)}
                className="rounded border-slate-700 bg-slate-900 text-cyan-400"
              />
              <span>
                I confirm I own or am explicitly authorized to assess this domain.
              </span>
            </label>

            <div className="flex flex-wrap items-center gap-2 text-xs">
              <span className="text-slate-400">Quick Targets:</span>
              {[
                { label: 'cloudflare.com (Grade A)', url: 'https://cloudflare.com' },
                { label: 'example.com (Missing Headers)', url: 'https://example.com' },
                { label: 'Test SSRF Guard (127.0.0.1)', url: 'http://127.0.0.1:8080/admin' },
              ].map((t) => (
                <button
                  key={t.url}
                  type="button"
                  onClick={() => {
                    setScanUrl(t.url);
                    runFullSecurityScan(t.url);
                  }}
                  className="px-2.5 py-1 rounded bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-700/80 font-mono cursor-pointer"
                >
                  {t.label}
                </button>
              ))}
            </div>
          </div>
        </form>

        {scanError && (
          <div
            role="alert"
            className="mt-4 p-4 rounded-lg bg-red-950/60 border border-red-800 text-xs text-red-200 flex items-center gap-2.5"
          >
            <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
            <span className="font-mono">{scanError}</span>
          </div>
        )}
      </div>

      {/* Results Grid */}
      {headerResult && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* HTTP Security Headers Breakdown */}
          <div className="lg:col-span-7 bg-[#0F172A] border border-slate-800 rounded-xl p-6">
            <div className="flex items-center justify-between pb-4 mb-4 border-b border-slate-800">
              <div>
                <h3 className="text-base font-semibold text-white">
                  HTTP Defensive Headers Audit ({headerResult.hostname})
                </h3>
                <p className="text-xs text-slate-400 mt-0.5">
                  {headerResult.assessment.summary}
                </p>
              </div>
              <div className="text-right font-mono tabular-nums">
                <span className="text-2xl font-bold text-cyan-400">
                  {headerResult.assessment.score}/100
                </span>
                <span className="ml-2 text-sm text-white">
                  Grade {headerResult.assessment.grade}
                </span>
              </div>
            </div>

            <div className="space-y-3">
              {headerResult.assessment.checks.map((chk) => (
                <div
                  key={chk.header}
                  className="p-3.5 rounded-lg bg-[#080D1A] border border-slate-800 flex flex-col gap-1"
                >
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-mono font-semibold text-white">
                      {chk.header}
                    </span>
                    <span
                      className={`text-xs font-mono ${
                        chk.present ? 'text-emerald-400' : 'text-amber-400'
                      }`}
                    >
                      {chk.present ? `PASS (+${chk.weight} pts)` : `MISSING (0/${chk.weight} pts)`}
                    </span>
                  </div>
                  <p className="text-xs font-mono text-slate-400 truncate">
                    Observed: {chk.value}
                  </p>
                  {!chk.present && (
                    <p className="text-xs text-cyan-300 mt-1">
                      Remediation: <code className="font-mono">{chk.remediation}</code>
                    </p>
                  )}
                </div>
              ))}
            </div>
          </div>

          {/* SSL/TLS Inspector & Password Strength Estimator */}
          <div className="lg:col-span-5 space-y-6">
            {sslResult && (
              <div className="bg-[#0F172A] border border-slate-800 rounded-xl p-6">
                <div className="flex items-center justify-between mb-4">
                  <h3 className="text-base font-semibold text-white">
                    SSL/TLS Certificate & Cipher Suite
                  </h3>
                  <Lock className="w-4 h-4 text-emerald-400" />
                </div>
                <dl className="space-y-2.5 text-xs font-mono">
                  <div className="flex justify-between py-1.5 border-b border-slate-800/80">
                    <dt className="text-slate-400">Subject CN</dt>
                    <dd className="text-white">{sslResult.certificate.subject}</dd>
                  </div>
                  <div className="flex justify-between py-1.5 border-b border-slate-800/80">
                    <dt className="text-slate-400">Issuer CA</dt>
                    <dd className="text-slate-200 text-right">{sslResult.certificate.issuer}</dd>
                  </div>
                  <div className="flex justify-between py-1.5 border-b border-slate-800/80">
                    <dt className="text-slate-400">Protocol & Cipher</dt>
                    <dd className="text-emerald-400">{sslResult.certificate.cipherSuite}</dd>
                  </div>
                  <div className="flex justify-between py-1.5 border-b border-slate-800/80">
                    <dt className="text-slate-400">Validity Remaining</dt>
                    <dd className="text-cyan-300 tabular-nums">
                      {sslResult.certificate.daysRemaining} days ({sslResult.certificate.validTo})
                    </dd>
                  </div>
                  <div className="pt-1">
                    <dt className="text-slate-400 mb-1">SHA-256 Certificate Fingerprint</dt>
                    <dd className="text-slate-300 break-all text-[11px]">
                      {sslResult.certificate.fingerprint256}
                    </dd>
                  </div>
                </dl>
              </div>
            )}

            {/* Password Strength & Entropy Analyzer */}
            <div className="bg-[#0F172A] border border-slate-800 rounded-xl p-6">
              <div className="flex items-center justify-between mb-3">
                <h3 className="text-base font-semibold text-white">
                  Password Entropy & Crack-Time Estimator
                </h3>
                <KeyRound className="w-4 h-4 text-cyan-400" />
              </div>
              <label htmlFor="pw-strength-input" className="block text-xs text-slate-400 mb-2">
                Test candidate passphrase against offline GPU brute-force math (10B hashes/sec):
              </label>
              <input
                id="pw-strength-input"
                type="text"
                value={passwordTestInput}
                onChange={(e) => setPasswordTestInput(e.target.value)}
                className="w-full px-3.5 py-2 text-xs font-mono bg-[#080D1A] border border-slate-700 rounded-lg text-white mb-3 focus:outline-none focus:border-cyan-400"
              />
              <div className="grid grid-cols-3 gap-2 text-xs font-mono tabular-nums mb-3">
                <div className="p-2.5 rounded bg-[#080D1A] border border-slate-800">
                  <span className="text-slate-400 block">Entropy</span>
                  <span className="text-white font-bold">{pwAssessment.entropyBits} bits</span>
                </div>
                <div className="p-2.5 rounded bg-[#080D1A] border border-slate-800">
                  <span className="text-slate-400 block">Rating</span>
                  <span className="text-cyan-400 font-bold">{pwAssessment.rating}</span>
                </div>
                <div className="p-2.5 rounded bg-[#080D1A] border border-slate-800">
                  <span className="text-slate-400 block">Crack Time</span>
                  <span className="text-emerald-400 font-bold">{pwAssessment.crackTimeOffline}</span>
                </div>
              </div>
              <ul className="space-y-1 text-xs text-slate-300">
                {pwAssessment.recommendations.map((rec, i) => (
                  <li key={i} className="flex items-start gap-2">
                    <CheckCircle2 className="w-3.5 h-3.5 text-cyan-400 shrink-0 mt-0.5" />
                    <span>{rec}</span>
                  </li>
                ))}
              </ul>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
