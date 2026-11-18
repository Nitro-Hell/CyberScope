import test from 'node:test';
import assert from 'node:assert/strict';
import {
  validateTargetUrl,
  evaluatePasswordStrength,
  evaluateSecurityHeaders,
  caesarCipher,
  vigenereCipher,
  identifyFileSignature,
  analyzeAuthLog,
  verifyCtfFlag,
  executeSandboxCommand,
} from './cyber-engine';

test('SSRF validator blocks loopback and RFC1918 private addresses', () => {
  assert.equal(validateTargetUrl('http://127.0.0.1:8080/admin').valid, false);
  assert.equal(validateTargetUrl('https://localhost/api').valid, false);
  assert.equal(validateTargetUrl('http://192.168.1.10').valid, false);
  assert.equal(validateTargetUrl('http://10.0.0.5').valid, false);
  assert.equal(validateTargetUrl('http://169.254.169.254/latest/meta-data').valid, false);

  const validRes = validateTargetUrl('example.com');
  assert.equal(validRes.valid, true);
  assert.equal(validRes.hostname, 'example.com');
  assert.equal(validRes.normalizedUrl, 'https://example.com/');
});

test('Password strength evaluator calculates entropy and ratings accurately', () => {
  const weak = evaluatePasswordStrength('password123');
  assert.equal(weak.rating === 'Critical' || weak.rating === 'Weak', true);

  const strong = evaluatePasswordStrength('K9#mP2$vL8@xQ4!zR7&n');
  assert.equal(strong.entropyBits > 75, true);
  assert.equal(strong.score >= 80, true);
});

test('Security headers evaluator grades full and partial header sets', () => {
  const full = evaluateSecurityHeaders(
    {
      'Strict-Transport-Security': 'max-age=63072000; includeSubDomains',
      'Content-Security-Policy': "default-src 'self'",
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'Referrer-Policy': 'strict-origin-when-cross-origin',
      'Permissions-Policy': 'geolocation=()',
    },
    true
  );
  assert.equal(full.score, 100);
  assert.equal(full.grade, 'A+');

  const empty = evaluateSecurityHeaders({}, true);
  assert.equal(empty.score, 0);
  assert.equal(empty.grade, 'F');
});

test('Caesar and Vigenere ciphers round-trip cleanly', () => {
  const original = 'CS{ca3sar_sh1ft_crypt0}';
  const encrypted = caesarCipher(original, 7, false);
  assert.equal(encrypted, 'JZ{jh3zhy_zo1ma_jyfwa0}');
  assert.equal(caesarCipher(encrypted, 7, true), original);

  const vigEnc = vigenereCipher('DEFENDTHEPERIMETER', 'CYBER', false);
  assert.equal(vigenereCipher(vigEnc, 'CYBER', true), 'DEFENDTHEPERIMETER');
});

test('File magic byte forensic signature detector spots extension masquerading', () => {
  const match = identifyFileSignature('7F 45 4C 46 02 01 01 00', 'invoice_q4.pdf');
  assert.equal(match.detectedType, 'ELF Linux Executable');
  assert.equal(match.extensionMatch, false);
  assert.equal(match.riskNote.includes('ALERT'), true);
});

test('Auth log analyzer extracts brute-force IPs and timeline', () => {
  const log = [
    'Nov 18 02:14:01 gw sshd[10]: Failed password for root from 185.220.101.44 port 5111 ssh2',
    'Nov 18 02:14:03 gw sshd[10]: Failed password for admin from 185.220.101.44 port 5112 ssh2',
  ].join('\n');
  const res = analyzeAuthLog(log);
  assert.equal(res.failedAuthCount, 2);
  assert.equal(res.suspiciousIps[0].ip, '185.220.101.44');
  assert.equal(res.suspiciousIps[0].count, 2);
});

test('CTF flag verifier validates correct flags and rejects wrong ones', () => {
  const ok = verifyCtfFlag('ctf-crypto-01', 'CS{b4se64_b34c0n1_decod3d}');
  assert.equal(ok.correct, true);
  assert.equal(ok.pointsAwarded, 100);

  const bad = verifyCtfFlag('ctf-crypto-01', 'CS{wrong_flag}');
  assert.equal(bad.correct, false);
});

test('Sandbox terminal blocks destructive commands and answers help', () => {
  const blocked = executeSandboxCommand('rm -rf /');
  assert.equal(blocked.status, 'blocked');

  const help = executeSandboxCommand('help');
  assert.equal(help.status, 'ok');
  assert.equal(help.output.includes('whoami'), true);
});
