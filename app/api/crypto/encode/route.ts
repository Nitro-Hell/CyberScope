import { NextRequest, NextResponse } from 'next/server';
import crypto from 'node:crypto';
import { caesarCipher, vigenereCipher } from '@/lib/cyber-engine';
import { readDb, writeDb } from '@/lib/server-db';

export const dynamic = 'force-dynamic';

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const text = typeof body.text === 'string' ? body.text : '';
    const mode = body.mode || 'base64-encode';
    const shift = Number(body.shift ?? 7);
    const key = typeof body.key === 'string' && body.key ? body.key : 'CYBERSCOPE';

    if (!text) {
      return NextResponse.json(
        { status: 'error', error: 'Input payload is required.' },
        { status: 400 }
      );
    }

    let result = '';
    let details: Record<string, string> = {};

    if (mode === 'base64-encode') {
      result = Buffer.from(text, 'utf8').toString('base64');
    } else if (mode === 'base64-decode') {
      result = Buffer.from(text, 'base64').toString('utf8');
    } else if (mode === 'caesar-encrypt') {
      result = caesarCipher(text, shift, false);
    } else if (mode === 'caesar-decrypt') {
      result = caesarCipher(text, shift, true);
    } else if (mode === 'vigenere-encrypt') {
      result = vigenereCipher(text, key, false);
    } else if (mode === 'vigenere-decrypt') {
      result = vigenereCipher(text, key, true);
    } else if (mode === 'aes-gcm-demo') {
      const derivedKey = crypto.createHash('sha256').update(key).digest();
      const iv = crypto.randomBytes(12);
      const cipher = crypto.createCipheriv('aes-256-gcm', derivedKey, iv);
      const encrypted = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
      const authTag = cipher.getAuthTag();
      result = encrypted.toString('hex');
      details = {
        algorithm: 'AES-256-GCM (Authenticated Encryption)',
        ivHex: iv.toString('hex'),
        authTagHex: authTag.toString('hex'),
        keyFingerprint: derivedKey.toString('hex').slice(0, 16) + '...',
      };
    } else if (mode === 'rsa-sign-demo') {
      const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
      });
      const sign = crypto.createSign('SHA256');
      sign.update(text);
      sign.end();
      const signature = sign.sign(privateKey, 'base64');

      const verify = crypto.createVerify('SHA256');
      verify.update(text);
      verify.end();
      const verified = verify.verify(publicKey, signature, 'base64');

      result = signature;
      details = {
        algorithm: 'RSA-PSS / RSASSA-PKCS1-v1_5 (2048-bit SHA-256)',
        signatureVerified: verified ? 'VALID SIGNATURE' : 'INVALID',
        publicKeySpkiPreview: publicKey
          .export({ type: 'spki', format: 'pem' })
          .toString()
          .split('\n')
          .slice(0, 3)
          .join('\n'),
      };
    } else {
      result = Buffer.from(text, 'utf8').toString('hex');
    }

    const db = readDb();
    db.crypto_history.unshift({
      id: `cry-${Date.now()}`,
      operation: mode,
      algorithm: mode.toUpperCase(),
      inputPreview: text.slice(0, 32),
      outputPreview: result.slice(0, 48),
      timestamp: new Date().toISOString(),
    });
    writeDb(db);

    return NextResponse.json({
      status: 'ok',
      mode,
      output: result,
      details,
    });
  } catch {
    return NextResponse.json(
      { status: 'error', error: 'Unable to process encoding/cipher transformation.' },
      { status: 400 }
    );
  }
}
