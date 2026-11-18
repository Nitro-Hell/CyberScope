import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { CTF_CHALLENGES, CtfChallenge } from './cyber-engine';

export interface UserRecord {
  id: string;
  username: string;
  email: string;
  role: string;
  clearance: string;
  passwordHash: string;
  salt: string;
  createdAt: string;
}

export interface UserSettingsRecord {
  userId: string;
  authorizedDomains: string[];
  ssrfStrictMode: boolean;
  rateLimitRpm: number;
  terminalTheme: 'cyan-matrix' | 'emerald-soc' | 'amber-phosphor';
  exportFormat: 'PDF-Ready HTML' | 'JSON' | 'CSV';
}

export interface ScanHistoryRecord {
  id: string;
  target: string;
  scanType: 'HTTP Headers' | 'SSL/TLS Certificate' | 'DNS Resolution' | 'Full Assessment';
  score: number;
  grade: string;
  findingsSummary: string;
  timestamp: string;
}

export interface NetworkDeviceRecord {
  id: string;
  hostname: string;
  ipAddress: string;
  macAddress: string;
  zone: 'DMZ Perimeter' | 'Core SOC' | 'Production App' | 'Endpoint VLAN';
  os: string;
  openPorts: number[];
  latencyMs: number;
  status: 'Authorized' | 'Review Required' | 'Isolated';
  lastSeen: string;
}

export interface CryptoHistoryRecord {
  id: string;
  operation: string;
  algorithm: string;
  inputPreview: string;
  outputPreview: string;
  timestamp: string;
}

export interface SecurityReportRecord {
  id: string;
  title: string;
  module: string;
  severity: 'Low' | 'Medium' | 'High' | 'Informational';
  score: number;
  summary: string;
  createdAt: string;
}

export interface LearningProgressRecord {
  moduleId: string;
  moduleName: string;
  completedExercises: number;
  totalExercises: number;
  lastActivity: string;
}

export interface CyberScopeDatabase {
  users: UserRecord[];
  settings: UserSettingsRecord[];
  scan_history: ScanHistoryRecord[];
  network_devices: NetworkDeviceRecord[];
  ctf_challenges: CtfChallenge[];
  ctf_progress: string[]; // solved challenge IDs
  crypto_history: CryptoHistoryRecord[];
  reports: SecurityReportRecord[];
  learning_progress: LearningProgressRecord[];
}

const DB_FILE_PATH = path.join('/tmp', 'cyberscope_sqlite_mirror.json');

export function hashPasswordPbkdf2(password: string, salt?: string): { hash: string; salt: string } {
  const actualSalt = salt || crypto.randomBytes(16).toString('hex');
  const hash = crypto.pbkdf2Sync(password, actualSalt, 100000, 64, 'sha512').toString('hex');
  return { hash, salt: actualSalt };
}

function createInitialSeedDatabase(): CyberScopeDatabase {
  const demoAuth = hashPasswordPbkdf2('CyberScope#2026!');
  return {
    users: [
      {
        id: 'usr-soc-01',
        username: 'elena.vance',
        email: 'elena.vance@cyberscope.sec',
        role: 'Lead Defensive Security Architect',
        clearance: 'SOC Tier-3 // Blue Team Lead',
        passwordHash: demoAuth.hash,
        salt: demoAuth.salt,
        createdAt: '2026-10-01T08:00:00Z',
      },
    ],
    settings: [
      {
        userId: 'usr-soc-01',
        authorizedDomains: ['example.com', 'google.com', 'cloudflare.com', 'github.com', 'cyberscope.internal'],
        ssrfStrictMode: true,
        rateLimitRpm: 60,
        terminalTheme: 'cyan-matrix',
        exportFormat: 'PDF-Ready HTML',
      },
    ],
    scan_history: [
      {
        id: 'scan-101',
        target: 'https://cloudflare.com',
        scanType: 'HTTP Headers',
        score: 90,
        grade: 'A',
        findingsSummary: 'HSTS, X-Content-Type-Options, X-Frame-Options enforced; strict TLSv1.3 active.',
        timestamp: '2026-11-18T01:30:00Z',
      },
      {
        id: 'scan-102',
        target: 'https://example.com',
        scanType: 'Full Assessment',
        score: 55,
        grade: 'C',
        findingsSummary: 'Valid TLS certificate (DigiCert), but Content-Security-Policy and HSTS preload missing.',
        timestamp: '2026-11-18T01:42:00Z',
      },
      {
        id: 'scan-103',
        target: 'https://github.com',
        scanType: 'SSL/TLS Certificate',
        score: 95,
        grade: 'A+',
        findingsSummary: 'TLSv1.3 AEAD cipher suite verified; HSTS max-age=31536000; CSP enforced.',
        timestamp: '2026-11-18T01:50:00Z',
      },
    ],
    network_devices: [
      {
        id: 'dev-01',
        hostname: 'soc-edge-fw01.cyberscope.internal',
        ipAddress: '10.20.0.1',
        macAddress: '00:1B:63:84:45:E6',
        zone: 'DMZ Perimeter',
        os: 'pfSense Enterprise 24.03',
        openPorts: [443, 10443],
        latencyMs: 0.8,
        status: 'Authorized',
        lastSeen: '2026-11-18T01:55:00Z',
      },
      {
        id: 'dev-02',
        hostname: 'siem-collector-01.cyberscope.internal',
        ipAddress: '10.20.1.15',
        macAddress: '02:42:AC:11:00:0F',
        zone: 'Core SOC',
        os: 'Ubuntu 24.04 LTS (Hardened)',
        openPorts: [22, 443, 9200],
        latencyMs: 1.4,
        status: 'Authorized',
        lastSeen: '2026-11-18T01:56:00Z',
      },
      {
        id: 'dev-03',
        hostname: 'prod-api-gw02.cyberscope.internal',
        ipAddress: '10.20.2.40',
        macAddress: '02:42:AC:12:00:28',
        zone: 'Production App',
        os: 'Debian 12.7 Bookworm',
        openPorts: [80, 443],
        latencyMs: 2.1,
        status: 'Authorized',
        lastSeen: '2026-11-18T01:54:00Z',
      },
      {
        id: 'dev-04',
        hostname: 'wkst-eng-19.cyberscope.internal',
        ipAddress: '10.20.4.19',
        macAddress: '3C:22:FB:91:08:CC',
        zone: 'Endpoint VLAN',
        os: 'Linux 6.6 Workstation',
        openPorts: [22, 4444],
        latencyMs: 4.9,
        status: 'Review Required',
        lastSeen: '2026-11-18T01:52:00Z',
      },
      {
        id: 'dev-05',
        hostname: 'db-replica-pg01.cyberscope.internal',
        ipAddress: '10.20.2.88',
        macAddress: '02:42:AC:12:00:58',
        zone: 'Production App',
        os: 'PostgreSQL 16 / Alpine 3.20',
        openPorts: [5432],
        latencyMs: 1.7,
        status: 'Authorized',
        lastSeen: '2026-11-18T01:56:00Z',
      },
    ],
    ctf_challenges: CTF_CHALLENGES,
    ctf_progress: ['ctf-crypto-01'],
    crypto_history: [
      {
        id: 'cry-01',
        operation: 'SHA-256 Digest',
        algorithm: 'SHA-256',
        inputPreview: 'CYBERSCOPE-SOC-INITIAL-SEED',
        outputPreview: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
        timestamp: '2026-11-18T01:20:00Z',
      },
    ],
    reports: [
      {
        id: 'rep-01',
        title: 'Q4 Perimeter HTTP Header & TLS Posture Audit',
        module: 'Security Scanner',
        severity: 'Medium',
        score: 84,
        summary: '3 external domains inspected. HSTS and TLSv1.3 verified on primary gateways; CSP hardening advised on staging.',
        createdAt: '2026-11-18T01:45:00Z',
      },
      {
        id: 'rep-02',
        title: 'SSH Credential Stuffing Forensics (185.220.101.44)',
        module: 'Digital Forensics',
        severity: 'High',
        score: 92,
        summary: 'Identified 3 rapid failed root/admin SSH login attempts originating from Tor exit relay 185.220.101.44.',
        createdAt: '2026-11-18T01:48:00Z',
      },
      {
        id: 'rep-03',
        title: 'Endpoint VLAN 10.20.4.19 Port 4444 Anomaly',
        module: 'Network Intelligence',
        severity: 'High',
        score: 78,
        summary: 'PCAP metadata dissection flagged outbound SYN traffic from 10.20.4.19 to port 4444.',
        createdAt: '2026-11-18T01:51:00Z',
      },
    ],
    learning_progress: [
      {
        moduleId: 'mod-01',
        moduleName: 'Network Intelligence & PCAP Analysis',
        completedExercises: 4,
        totalExercises: 5,
        lastActivity: '2026-11-18T01:40:00Z',
      },
      {
        moduleId: 'mod-02',
        moduleName: 'HTTP Headers & TLS Hardening',
        completedExercises: 5,
        totalExercises: 5,
        lastActivity: '2026-11-18T01:45:00Z',
      },
      {
        moduleId: 'mod-05',
        moduleName: 'Applied Cryptography & Hashing',
        completedExercises: 4,
        totalExercises: 6,
        lastActivity: '2026-11-18T01:35:00Z',
      },
      {
        moduleId: 'mod-07',
        moduleName: 'Web Security (SQLi, XSS, CORS, CSRF)',
        completedExercises: 3,
        totalExercises: 5,
        lastActivity: '2026-11-18T01:50:00Z',
      },
    ],
  };
}

export function readDb(): CyberScopeDatabase {
  try {
    if (fs.existsSync(DB_FILE_PATH)) {
      const raw = fs.readFileSync(DB_FILE_PATH, 'utf-8');
      return JSON.parse(raw) as CyberScopeDatabase;
    }
  } catch {
    // Fallback to initial seed
  }
  const initial = createInitialSeedDatabase();
  writeDb(initial);
  return initial;
}

export function writeDb(data: CyberScopeDatabase): void {
  try {
    fs.writeFileSync(DB_FILE_PATH, JSON.stringify(data, null, 2), 'utf-8');
  } catch {
    // Ignore read-only filesystem edge cases
  }
}
