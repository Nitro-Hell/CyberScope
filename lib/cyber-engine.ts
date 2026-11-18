// Pure, deterministic cybersecurity logic for CyberScope modules.
// Decoupled from DOM/React for fast node:test unit verification and server/client reuse.

export interface SsrfValidationResult {
  valid: boolean;
  hostname: string;
  normalizedUrl: string;
  reason?: string;
}

const PRIVATE_IPV4_PATTERNS = [
  /^127\./,
  /^10\./,
  /^192\.168\./,
  /^172\.(1[6-9]|2[0-9]|3[0-1])\./,
  /^169\.254\./,
  /^0\./,
  /^100\.(6[4-9]|[7-9][0-9]|1[0-1][0-9]|12[0-7])\./, // CGNAT
];

const BLOCKED_HOSTNAMES = new Set([
  'localhost',
  'localhost.localdomain',
  '0.0.0.0',
  '[::1]',
  '::1',
  'metadata.google.internal',
  '169.254.169.254',
]);

export function validateTargetUrl(rawInput: string): SsrfValidationResult {
  const trimmed = (rawInput || '').trim();
  if (!trimmed) {
    return {
      valid: false,
      hostname: '',
      normalizedUrl: '',
      reason: 'Target URL or domain is required.',
    };
  }

  const withProtocol = /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
  let parsed: URL;
  try {
    parsed = new URL(withProtocol);
  } catch {
    return {
      valid: false,
      hostname: '',
      normalizedUrl: '',
      reason: 'Malformed URL syntax. Provide a valid domain or HTTPS URL.',
    };
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return {
      valid: false,
      hostname: parsed.hostname,
      normalizedUrl: '',
      reason: 'Only HTTP and HTTPS protocols are permitted.',
    };
  }

  const host = parsed.hostname.toLowerCase();
  if (
    BLOCKED_HOSTNAMES.has(host) ||
    host.endsWith('.local') ||
    host.endsWith('.internal') ||
    host.endsWith('.localhost') ||
    host.includes(':') // IPv6 literal
  ) {
    return {
      valid: false,
      hostname: host,
      normalizedUrl: '',
      reason: 'SSRF Protection: Loopback, internal, and link-local hosts are blocked.',
    };
  }

  for (const regex of PRIVATE_IPV4_PATTERNS) {
    if (regex.test(host)) {
      return {
        valid: false,
        hostname: host,
        normalizedUrl: '',
        reason: `SSRF Protection: Private RFC1918 / reserved address (${host}) is blocked.`,
      };
    }
  }

  if (!host.includes('.') || host.startsWith('.') || host.endsWith('.')) {
    return {
      valid: false,
      hostname: host,
      normalizedUrl: '',
      reason: 'Invalid public domain name format.',
    };
  }

  return {
    valid: true,
    hostname: host,
    normalizedUrl: parsed.toString(),
  };
}

export interface PasswordAssessment {
  entropyBits: number;
  poolSize: number;
  length: number;
  score: number;
  rating: 'Critical' | 'Weak' | 'Moderate' | 'Strong' | 'Cryptographic';
  crackTimeOffline: string;
  recommendations: string[];
}

export function evaluatePasswordStrength(password: string): PasswordAssessment {
  const length = password.length;
  if (length === 0) {
    return {
      entropyBits: 0,
      poolSize: 0,
      length: 0,
      score: 0,
      rating: 'Critical',
      crackTimeOffline: 'Instant (0 sec)',
      recommendations: ['Enter a passphrase of at least 14 characters.'],
    };
  }

  const hasLower = /[a-z]/.test(password);
  const hasUpper = /[A-Z]/.test(password);
  const hasDigit = /[0-9]/.test(password);
  const hasSymbol = /[^a-zA-Z0-9]/.test(password);

  let poolSize = 0;
  if (hasLower) poolSize += 26;
  if (hasUpper) poolSize += 26;
  if (hasDigit) poolSize += 10;
  if (hasSymbol) poolSize += 32;

  const rawEntropy = length * Math.log2(Math.max(poolSize, 1));
  const uniqueChars = new Set(password.split('')).size;
  const repetitionFactor = Math.max(0.4, uniqueChars / length);
  const commonPatternPenalty =
    /(1234|password|qwerty|admin|cyberscope|letmein|welcome)/i.test(password) ? 22 : 0;

  const entropyBits = Math.max(
    0,
    Math.round((rawEntropy * repetitionFactor - commonPatternPenalty) * 10) / 10
  );

  const score = Math.min(100, Math.max(0, Math.round((entropyBits / 95) * 100)));

  let rating: PasswordAssessment['rating'] = 'Critical';
  if (entropyBits >= 85) rating = 'Cryptographic';
  else if (entropyBits >= 65) rating = 'Strong';
  else if (entropyBits >= 48) rating = 'Moderate';
  else if (entropyBits >= 30) rating = 'Weak';

  // Estimate crack time assuming 10^10 hashes/sec (offline GPU rig)
  const combinations = Math.pow(2, entropyBits);
  const seconds = combinations / 2e10;
  let crackTimeOffline = 'Instant (< 1 ms)';
  if (seconds >= 31536000 * 1000) crackTimeOffline = '> 1,000 centuries';
  else if (seconds >= 31536000) crackTimeOffline = `${Math.round(seconds / 31536000)} years`;
  else if (seconds >= 86400) crackTimeOffline = `${Math.round(seconds / 86400)} days`;
  else if (seconds >= 3600) crackTimeOffline = `${Math.round(seconds / 3600)} hours`;
  else if (seconds >= 60) crackTimeOffline = `${Math.round(seconds / 60)} minutes`;
  else if (seconds >= 1) crackTimeOffline = `${Math.round(seconds)} seconds`;

  const recommendations: string[] = [];
  if (length < 14) recommendations.push('Increase length to at least 14 characters (NIST SP 800-63B).');
  if (!hasUpper || !hasLower) recommendations.push('Mix uppercase and lowercase characters.');
  if (!hasDigit) recommendations.push('Include numeric digits in unpredictable positions.');
  if (!hasSymbol) recommendations.push('Add special symbols or spaces to expand the character pool.');
  if (commonPatternPenalty > 0) {
    recommendations.push('Remove common dictionary words or sequential keyboard patterns.');
  }
  if (recommendations.length === 0) {
    recommendations.push('Passphrase meets high-assurance entropy thresholds. Store only with Argon2id or PBKDF2.');
  }

  return {
    entropyBits,
    poolSize,
    length,
    score,
    rating,
    crackTimeOffline,
    recommendations,
  };
}

export interface HeaderCheckItem {
  header: string;
  present: boolean;
  value: string;
  weight: number;
  status: 'Pass' | 'Warn' | 'Missing';
  remediation: string;
}

export interface HeaderAssessmentResult {
  score: number;
  grade: 'A+' | 'A' | 'B' | 'C' | 'D' | 'F';
  checks: HeaderCheckItem[];
  summary: string;
}

export function evaluateSecurityHeaders(
  rawHeaders: Record<string, string>,
  isHttps: boolean
): HeaderAssessmentResult {
  const normalized: Record<string, string> = {};
  for (const [k, v] of Object.entries(rawHeaders)) {
    normalized[k.toLowerCase()] = v;
  }

  const specs: Array<{
    header: string;
    key: string;
    weight: number;
    remediation: string;
  }> = [
    {
      header: 'Strict-Transport-Security',
      key: 'strict-transport-security',
      weight: 25,
      remediation: 'Add Strict-Transport-Security: max-age=63072000; includeSubDomains; preload',
    },
    {
      header: 'Content-Security-Policy',
      key: 'content-security-policy',
      weight: 25,
      remediation: "Define Content-Security-Policy: default-src 'self'; object-src 'none'; frame-ancestors 'none'",
    },
    {
      header: 'X-Content-Type-Options',
      key: 'x-content-type-options',
      weight: 15,
      remediation: 'Add X-Content-Type-Options: nosniff to prevent MIME-sniffing attacks.',
    },
    {
      header: 'X-Frame-Options',
      key: 'x-frame-options',
      weight: 15,
      remediation: 'Add X-Frame-Options: DENY or SAMEORIGIN to mitigate Clickjacking.',
    },
    {
      header: 'Referrer-Policy',
      key: 'referrer-policy',
      weight: 10,
      remediation: 'Add Referrer-Policy: strict-origin-when-cross-origin',
    },
    {
      header: 'Permissions-Policy',
      key: 'permissions-policy',
      weight: 10,
      remediation: 'Add Permissions-Policy: geolocation=(), microphone=(), camera=()',
    },
  ];

  let totalScore = isHttps ? 0 : -15;
  const checks: HeaderCheckItem[] = specs.map((spec) => {
    const val = normalized[spec.key] || '';
    const present = val.trim().length > 0;
    if (present) {
      totalScore += spec.weight;
    }
    return {
      header: spec.header,
      present,
      value: present ? val : 'Not Set',
      weight: spec.weight,
      status: present ? 'Pass' : 'Missing',
      remediation: spec.remediation,
    };
  });

  const clamped = Math.max(0, Math.min(100, totalScore));
  let grade: HeaderAssessmentResult['grade'] = 'F';
  if (clamped >= 95) grade = 'A+';
  else if (clamped >= 85) grade = 'A';
  else if (clamped >= 70) grade = 'B';
  else if (clamped >= 55) grade = 'C';
  else if (clamped >= 40) grade = 'D';

  const missingCount = checks.filter((c) => !c.present).length;
  const summary =
    missingCount === 0
      ? 'All primary HTTP defensive security headers are enforced.'
      : `${missingCount} of ${checks.length} recommended defensive HTTP headers are missing.`;

  return {
    score: clamped,
    grade,
    checks,
    summary,
  };
}

export function caesarCipher(text: string, shift: number, decrypt = false): string {
  const effectiveShift = ((((decrypt ? -shift : shift) % 26) + 26) % 26);
  return text.replace(/[a-zA-Z]/g, (char) => {
    const base = char <= 'Z' ? 65 : 97;
    return String.fromCharCode(((char.charCodeAt(0) - base + effectiveShift) % 26) + base);
  });
}

export function vigenereCipher(text: string, key: string, decrypt = false): string {
  const cleanKey = key.replace(/[^a-zA-Z]/g, '').toUpperCase();
  if (!cleanKey) return text;
  let keyIdx = 0;
  return text.replace(/[a-zA-Z]/g, (char) => {
    const base = char <= 'Z' ? 65 : 97;
    const shift = cleanKey.charCodeAt(keyIdx % cleanKey.length) - 65;
    keyIdx++;
    const effectiveShift = decrypt ? (26 - shift) % 26 : shift;
    return String.fromCharCode(((char.charCodeAt(0) - base + effectiveShift) % 26) + base);
  });
}

export interface FileSignatureMatch {
  detectedType: string;
  mimeType: string;
  magicBytes: string;
  extensionMatch: boolean;
  riskNote: string;
}

const MAGIC_SIGNATURES: Array<{
  prefix: string;
  detectedType: string;
  mimeType: string;
  extensions: string[];
  riskNote: string;
}> = [
  {
    prefix: '89504E470D0A1A0A',
    detectedType: 'PNG Image Container',
    mimeType: 'image/png',
    extensions: ['png'],
    riskNote: 'Inspect ancillary chunks (tEXt/zTXt) for steganographic payloads.',
  },
  {
    prefix: '25504446',
    detectedType: 'PDF Document',
    mimeType: 'application/pdf',
    extensions: ['pdf'],
    riskNote: 'Scan for embedded /JavaScript, /OpenAction, or /Launch streams.',
  },
  {
    prefix: '504B0304',
    detectedType: 'ZIP / OOXML / JAR Archive',
    mimeType: 'application/zip',
    extensions: ['zip', 'docx', 'xlsx', 'pptx', 'jar', 'apk'],
    riskNote: 'Verify archive entries against Zip-Slip path traversal (../) and macro streams.',
  },
  {
    prefix: '7F454C46',
    detectedType: 'ELF Linux Executable',
    mimeType: 'application/x-executable',
    extensions: ['elf', 'bin', 'so', 'out'],
    riskNote: 'Executable binary detected. Analyze in isolated sandbox before execution.',
  },
  {
    prefix: '4D5A',
    detectedType: 'Windows PE / DOS Executable (MZ)',
    mimeType: 'application/vnd.microsoft.portable-executable',
    extensions: ['exe', 'dll', 'sys', 'scr'],
    riskNote: 'High risk: Windows Portable Executable header identified.',
  },
  {
    prefix: 'D4C3B2A1',
    detectedType: 'Libpcap Network Capture (Little-Endian)',
    mimeType: 'application/vnd.tcpdump.pcap',
    extensions: ['pcap', 'cap'],
    riskNote: 'Offline packet capture file ready for protocol metadata dissection.',
  },
  {
    prefix: 'A1B2C3D4',
    detectedType: 'Libpcap Network Capture (Big-Endian)',
    mimeType: 'application/vnd.tcpdump.pcap',
    extensions: ['pcap', 'cap'],
    riskNote: 'Offline packet capture file ready for protocol metadata dissection.',
  },
  {
    prefix: 'FFD8FF',
    detectedType: 'JPEG Image Stream',
    mimeType: 'image/jpeg',
    extensions: ['jpg', 'jpeg'],
    riskNote: 'Check EXIF APP1 metadata markers for GPS coordinates or camera serials.',
  },
];

export function identifyFileSignature(
  hexHeader: string,
  claimedFileName = ''
): FileSignatureMatch {
  const cleanHex = hexHeader.replace(/[^0-9a-fA-F]/g, '').toUpperCase();
  const ext = claimedFileName.includes('.')
    ? claimedFileName.split('.').pop()!.toLowerCase()
    : '';

  for (const sig of MAGIC_SIGNATURES) {
    if (cleanHex.startsWith(sig.prefix)) {
      const extensionMatch = !ext || sig.extensions.includes(ext);
      return {
        detectedType: sig.detectedType,
        mimeType: sig.mimeType,
        magicBytes: sig.prefix.replace(/(..)/g, '$1 ').trim(),
        extensionMatch,
        riskNote: extensionMatch
          ? sig.riskNote
          : `ALERT: Extension masquerading detected (.${ext} claims to be different from ${sig.detectedType}). ${sig.riskNote}`,
      };
    }
  }

  return {
    detectedType: 'ASCII / UTF-8 Text or Unrecognized Binary Stream',
    mimeType: 'application/octet-stream',
    magicBytes: cleanHex.slice(0, 16).replace(/(..)/g, '$1 ').trim() || 'NONE',
    extensionMatch: true,
    riskNote: 'No known binary executable magic bytes matched in the first 8 bytes.',
  };
}

export interface ForensicTimelineEvent {
  timestamp: string;
  sourceIp: string;
  eventType: 'SSH_BRUTE_FORCE' | 'PRIVILEGE_ESCALATION' | 'SQLI_PROBE' | 'AUTH_SUCCESS' | 'INFO';
  severity: 'Critical' | 'High' | 'Medium' | 'Low';
  detail: string;
}

export interface LogAnalysisSummary {
  totalLines: number;
  failedAuthCount: number;
  suspiciousIps: Array<{ ip: string; count: number }>;
  timeline: ForensicTimelineEvent[];
}

export function analyzeAuthLog(logContent: string): LogAnalysisSummary {
  const lines = logContent
    .split('\n')
    .map((l) => l.trim())
    .filter(Boolean);

  const ipCounts: Record<string, number> = {};
  let failedAuthCount = 0;
  const timeline: ForensicTimelineEvent[] = [];

  for (const line of lines) {
    const tsMatch = line.match(/^([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z?)/);
    const timestamp = tsMatch ? tsMatch[1] : 'Unknown-TS';
    const ipMatch = line.match(/\b(\d{1,3}(?:\.\d{1,3}){3})\b/);
    const sourceIp = ipMatch ? ipMatch[1] : 'local';

    if (/Failed password|authentication failure|Invalid user/i.test(line)) {
      failedAuthCount++;
      if (sourceIp !== 'local') {
        ipCounts[sourceIp] = (ipCounts[sourceIp] || 0) + 1;
      }
      timeline.push({
        timestamp,
        sourceIp,
        eventType: 'SSH_BRUTE_FORCE',
        severity: 'High',
        detail: line,
      });
    } else if (/sudo:.*COMMAND=|session opened for user root/i.test(line)) {
      timeline.push({
        timestamp,
        sourceIp,
        eventType: 'PRIVILEGE_ESCALATION',
        severity: 'Critical',
        detail: line,
      });
    } else if (/UNION\s+SELECT|OR\s+1=1|<script>|\/etc\/passwd/i.test(line)) {
      if (sourceIp !== 'local') {
        ipCounts[sourceIp] = (ipCounts[sourceIp] || 0) + 1;
      }
      timeline.push({
        timestamp,
        sourceIp,
        eventType: 'SQLI_PROBE',
        severity: 'Critical',
        detail: line,
      });
    } else if (/Accepted publickey|Accepted password/i.test(line)) {
      timeline.push({
        timestamp,
        sourceIp,
        eventType: 'AUTH_SUCCESS',
        severity: 'Medium',
        detail: line,
      });
    }
  }

  const suspiciousIps = Object.entries(ipCounts)
    .map(([ip, count]) => ({ ip, count }))
    .sort((a, b) => b.count - a.count);

  return {
    totalLines: lines.length,
    failedAuthCount,
    suspiciousIps,
    timeline,
  };
}

export interface CtfChallenge {
  id: string;
  title: string;
  category: 'Cryptography' | 'Log Analysis' | 'Network Analysis' | 'Web Security' | 'Forensics';
  difficulty: 'Beginner' | 'Intermediate' | 'Advanced';
  points: number;
  description: string;
  artifact: string;
  hint: string;
  expectedFlag: string;
}

export const CTF_CHALLENGES: CtfChallenge[] = [
  {
    id: 'ctf-crypto-01',
    title: 'Intercepted Base64 Beacon',
    category: 'Cryptography',
    difficulty: 'Beginner',
    points: 100,
    description:
      'A perimeter sensor captured an encoded C2 heartbeat string. Decode the Base64 payload to recover the flag.',
    artifact: 'Q1N7YjRzZTY0X2IzNGMwbjFfZGVjb2QzZH0=',
    hint: 'Use the Cryptography Lab Base64 decoder on the artifact string.',
    expectedFlag: 'CS{b4se64_b34c0n1_decod3d}',
  },
  {
    id: 'ctf-crypto-02',
    title: 'Roman Shift in Transit',
    category: 'Cryptography',
    difficulty: 'Beginner',
    points: 150,
    description:
      'An legacy telemetry service obfuscated its configuration token using a Caesar shift of +7. Reverse the shift (-7) to extract the plaintext flag.',
    artifact: 'JZ{jh3zhy_zo1ma_jyfwa0}',
    hint: 'Run Caesar Cipher in Decrypt mode with Shift = 7.',
    expectedFlag: 'CS{ca3sar_sh1ft_crypt0}',
  },
  {
    id: 'ctf-logs-01',
    title: 'SSH Brute-Force Originator',
    category: 'Log Analysis',
    difficulty: 'Intermediate',
    points: 250,
    description:
      'Analyze the SSH daemon log snippet below. Identify the external IPv4 address conducting automated root credential stuffing and submit it formatted as CS{IP_ADDRESS}.',
    artifact:
      'Nov 18 02:14:01 soc-gw01 sshd[4192]: Failed password for root from 185.220.101.44 port 51822 ssh2\nNov 18 02:14:03 soc-gw01 sshd[4192]: Failed password for invalid user admin from 185.220.101.44 port 51828 ssh2\nNov 18 02:14:09 soc-gw01 sshd[4201]: Accepted publickey for analyst from 10.20.1.15 port 44110 ssh2',
    hint: 'Look for the external IP address repeated across Failed password entries.',
    expectedFlag: 'CS{185.220.101.44}',
  },
  {
    id: 'ctf-net-01',
    title: 'Suspicious Beaconing Port',
    category: 'Network Analysis',
    difficulty: 'Intermediate',
    points: 300,
    description:
      'During PCAP metadata inspection, workstation 10.20.4.19 initiated an outbound TCP SYN to 198.51.100.77 on a classic Metasploit default reverse shell port. Format the flag as CS{PORT_NUMBER}.',
    artifact:
      'Frame 44: 10.20.4.19:59122 -> 198.51.100.77:4444 [SYN] Seq=0 Win=64240 Len=0 MSS=1460',
    hint: 'Check the destination port after the colon on 198.51.100.77.',
    expectedFlag: 'CS{4444}',
  },
  {
    id: 'ctf-web-01',
    title: 'Parameterized Query Defense',
    category: 'Web Security',
    difficulty: 'Advanced',
    points: 400,
    description:
      'In Python SQLite3 (`cursor.execute`), what single-character placeholder symbol is used for safe parameterized queries to prevent SQL injection? Submit as CS{SYMBOL_NAME} (e.g. CS{question_mark}).',
    artifact: 'cursor.execute("SELECT id, role FROM users WHERE username = ?", (username,))',
    hint: 'The symbol `?` is called a question_mark.',
    expectedFlag: 'CS{question_mark}',
  },
  {
    id: 'ctf-forensics-01',
    title: 'Disguised ELF Binary Magic Bytes',
    category: 'Forensics',
    difficulty: 'Advanced',
    points: 450,
    description:
      'An attacker uploaded `invoice_q4.pdf`, but hex inspection revealed the header `7F 45 4C 46`. Identify the 3-letter executable format and submit as CS{FORMAT}.',
    artifact: '00000000: 7f45 4c46 0201 0100 0000 0000 0000 0000  .ELF............',
    hint: 'Linux binaries begin with 0x7F followed by ASCII ELF.',
    expectedFlag: 'CS{ELF}',
  },
];

export function verifyCtfFlag(challengeId: string, submittedFlag: string): {
  correct: boolean;
  pointsAwarded: number;
  message: string;
} {
  const challenge = CTF_CHALLENGES.find((c) => c.id === challengeId);
  if (!challenge) {
    return { correct: false, pointsAwarded: 0, message: 'Challenge ID not found.' };
  }
  const cleanSubmitted = submittedFlag.trim();
  if (cleanSubmitted.toLowerCase() === challenge.expectedFlag.toLowerCase()) {
    return {
      correct: true,
      pointsAwarded: challenge.points,
      message: `Flag verified for "${challenge.title}" (+${challenge.points} pts).`,
    };
  }
  return {
    correct: false,
    pointsAwarded: 0,
    message: 'Incorrect flag signature. Review the artifact and hint.',
  };
}

export function executeSandboxCommand(rawCmd: string): {
  output: string;
  status: 'ok' | 'blocked';
} {
  const cmd = rawCmd.trim();
  if (!cmd) return { output: '', status: 'ok' };

  if (/rm\s+-rf|mkfs|dd\s+if=|:\(\)\{|wget\s+http|curl\s+.*\|\s*sh/i.test(cmd)) {
    return {
      status: 'blocked',
      output:
        '[SANDBOX GUARD] Command blocked by CyberScope Restricted Terminal Policy. Destructive filesystem or remote pipe-to-shell operations are prohibited.',
    };
  }

  const lower = cmd.toLowerCase();
  if (lower === 'help') {
    return {
      status: 'ok',
      output: [
        'CyberScope Restricted Security Terminal v1.0 (Educational Sandbox)',
        'Available commands:',
        '  whoami / id              Display active SOC sandbox operator context',
        '  ifconfig / ip a          Inspect virtual network interfaces',
        '  netstat -tulnp / ss      List active listening sockets and PIDs',
        '  ping <host>              Simulate ICMP echo latency probe',
        '  dig <domain>             Query DNS A/AAAA/MX/TXT records',
        '  nmap -sV <target>        Run authorized lab service version scan',
        '  ls -la                   List workspace forensic & lab files',
        '  cat /var/log/auth.log    Inspect sample SSH authentication logs',
        '  cat flag.txt             Read local sandbox verification token',
        '  sha256sum <file>         Compute SHA-256 digest of sandbox file',
        '  python3 -c "<code>"      Execute safe educational Python expression',
        '  clear                    Clear terminal buffer',
      ].join('\n'),
    };
  }

  if (lower === 'whoami') {
    return { status: 'ok', output: 'analyst@cyberscope-soc' };
  }
  if (lower === 'id') {
    return {
      status: 'ok',
      output: 'uid=1001(analyst) gid=1001(soc-operators) groups=1001(soc-operators),110(pcap-read)',
    };
  }
  if (lower === 'pwd') {
    return { status: 'ok', output: '/home/analyst/cyberscope-lab' };
  }
  if (lower === 'uname -a' || lower === 'uname') {
    return {
      status: 'ok',
      output: 'Linux cyberscope-soc-01 6.6.32-secops-hardened #1 SMP PREEMPT_DYNAMIC x86_64 GNU/Linux',
    };
  }
  if (lower === 'ls' || lower === 'ls -la' || lower === 'ls -l') {
    return {
      status: 'ok',
      output: [
        'total 36',
        'drwxr-xr-x 4 analyst soc-operators 4096 Nov 18 01:40 .',
        'drwxr-xr-x 3 root    root          4096 Nov 01 00:00 ..',
        '-rw-r----- 1 analyst soc-operators  412 Nov 18 01:12 capture_perimeter.pcap',
        '-rw-r--r-- 1 analyst soc-operators   38 Nov 18 01:00 flag.txt',
        '-rwxr-xr-x 1 analyst soc-operators 1840 Nov 18 01:25 header_audit.py',
        '-rw-r----- 1 analyst soc-operators 2048 Nov 18 01:39 /var/log/auth.log',
      ].join('\n'),
    };
  }
  if (lower === 'cat flag.txt') {
    return {
      status: 'ok',
      output: 'CS{t3rm1n4l_s4ndb0x_m4st3r}\n# Submit or test tokens in the CTF Arena module.',
    };
  }
  if (lower === 'cat /var/log/auth.log') {
    return {
      status: 'ok',
      output: [
        'Nov 18 02:14:01 soc-gw01 sshd[4192]: Failed password for root from 185.220.101.44 port 51822 ssh2',
        'Nov 18 02:14:03 soc-gw01 sshd[4192]: Failed password for invalid user admin from 185.220.101.44 port 51828 ssh2',
        'Nov 18 02:14:05 soc-gw01 sshd[4195]: Failed password for root from 185.220.101.44 port 51839 ssh2',
        'Nov 18 02:14:09 soc-gw01 sshd[4201]: Accepted publickey for analyst from 10.20.1.15 port 44110 ssh2',
      ].join('\n'),
    };
  }
  if (lower === 'ifconfig' || lower === 'ip a' || lower === 'ip addr') {
    return {
      status: 'ok',
      output: [
        'eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500',
        '      inet 10.20.1.15  netmask 255.255.255.0  broadcast 10.20.1.255',
        '      inet6 fe80::42:acff:fe11:000f  prefixlen 64  scopeid 0x20<link>',
        '      ether 02:42:ac:11:00:0f  txqueuelen 1000  (Ethernet)',
        '      RX packets 148291  bytes 98412044 (93.8 MiB)',
        '      TX packets 92310   bytes 18492011 (17.6 MiB)',
      ].join('\n'),
    };
  }
  if (lower.startsWith('netstat') || lower.startsWith('ss')) {
    return {
      status: 'ok',
      output: [
        'Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name',
        'tcp        0      0 127.0.0.1:5432          0.0.0.0:*               LISTEN      812/postgres',
        'tcp        0      0 0.0.0.0:443             0.0.0.0:*               LISTEN      1044/nginx: master',
        'tcp        0      0 10.20.1.15:22           0.0.0.0:*               LISTEN      609/sshd',
        'tcp        0      0 10.20.1.15:443          198.51.100.12:52411     ESTABLISHED 1045/nginx: worker',
      ].join('\n'),
    };
  }
  if (lower.startsWith('ping ')) {
    const target = cmd.slice(5).trim() || '10.20.1.1';
    return {
      status: 'ok',
      output: [
        `PING ${target} (${target}) 56(84) bytes of data.`,
        `64 bytes from ${target}: icmp_seq=1 ttl=64 time=1.84 ms`,
        `64 bytes from ${target}: icmp_seq=2 ttl=64 time=1.62 ms`,
        `64 bytes from ${target}: icmp_seq=3 ttl=64 time=1.71 ms`,
        `--- ${target} ping statistics ---`,
        `3 packets transmitted, 3 received, 0% packet loss, time 2003ms`,
      ].join('\n'),
    };
  }
  if (lower.startsWith('nmap')) {
    const target = cmd.replace(/^nmap\s+(-[a-zA-Z0-9]+\s+)*/, '').trim() || '10.20.1.10';
    return {
      status: 'ok',
      output: [
        `Starting CyberScope Nmap 7.94SVN ( https://nmap.org ) at 2026-11-18 02:00 UTC`,
        `Nmap scan report for authorized-lab-node (${target})`,
        `Host is up (0.0021s latency).`,
        `PORT     STATE SERVICE  VERSION`,
        `22/tcp   open  ssh      OpenSSH 9.6p1 Ubuntu 3ubuntu13 (protocol 2.0)`,
        `80/tcp   open  http     nginx 1.26.1 (Strict-Transport-Security redirect active)`,
        `443/tcp  open  ssl/http nginx 1.26.1 (TLSv1.3 ECDHE-RSA-AES256-GCM-SHA384)`,
        `Service detection performed. 1 IP address (1 host up) scanned in 1.42 seconds.`,
      ].join('\n'),
    };
  }
  if (lower.startsWith('dig ') || lower.startsWith('nslookup ')) {
    const domain = cmd.split(/\s+/)[1] || 'cyberscope.internal';
    return {
      status: 'ok',
      output: [
        `; <<>> DiG 9.18.24 <<>> ${domain} ANY`,
        `;; ANSWER SECTION:`,
        `${domain}.        300     IN      A       93.184.215.14`,
        `${domain}.        3600    IN      TXT     "v=spf1 include:_spf.cyberscope.sec -all"`,
        `;; Query time: 11 msec`,
        `;; SERVER: 1.1.1.1#53(1.1.1.1) (UDP)`,
      ].join('\n'),
    };
  }
  if (lower.startsWith('sha256sum')) {
    return {
      status: 'ok',
      output:
        'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  capture_perimeter.pcap',
    };
  }
  if (lower.startsWith('python3')) {
    return {
      status: 'ok',
      output: [
        'Python 3.12.4 (CyberScope Restricted Educational Runtime)',
        '>>> import hashlib, secrets',
        '>>> hashlib.sha256(b"CYBERSCOPE").hexdigest()',
        '"8f3d28a940b19e7c5a37e582b8d55209c0a81d187b9e6e24c5192f0b174832c1"',
      ].join('\n'),
    };
  }

  return {
    status: 'ok',
    output: `cyberscope-sh: executed '${cmd}' in restricted sandbox. Type 'help' for supported defensive security commands.`,
  };
}
