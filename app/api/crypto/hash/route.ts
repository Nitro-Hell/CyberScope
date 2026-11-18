import { NextRequest, NextResponse } from 'next/server';
import crypto from 'node:crypto';
import { readDb, writeDb } from '@/lib/server-db';

export const dynamic = 'force-dynamic';

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const text = typeof body.text === 'string' ? body.text : '';
    const algorithm = (body.algorithm || 'sha256').toLowerCase();
    const hmacKey = typeof body.hmacKey === 'string' ? body.hmacKey : '';

    if (!text) {
      return NextResponse.json(
        { status: 'error', error: 'Input plaintext is required for cryptographic hashing.' },
        { status: 400 }
      );
    }

    const sha256 = crypto.createHash('sha256').update(text, 'utf8').digest('hex');
    const sha512 = crypto.createHash('sha512').update(text, 'utf8').digest('hex');
    const hmacSha256 = hmacKey
      ? crypto.createHmac('sha256', hmacKey).update(text, 'utf8').digest('hex')
      : crypto.createHmac('sha256', 'cyberscope-default-key').update(text, 'utf8').digest('hex');

    const primaryOutput = algorithm === 'sha512' ? sha512 : sha256;

    const db = readDb();
    db.crypto_history.unshift({
      id: `cry-${Date.now()}`,
      operation: 'Cryptographic Hash',
      algorithm: algorithm.toUpperCase(),
      inputPreview: text.slice(0, 32),
      outputPreview: primaryOutput.slice(0, 48),
      timestamp: new Date().toISOString(),
    });
    writeDb(db);

    return NextResponse.json({
      status: 'ok',
      algorithm: algorithm.toUpperCase(),
      byteLength: Buffer.byteLength(text, 'utf8'),
      digests: {
        sha256,
        sha512,
        hmacSha256,
      },
    });
  } catch {
    return NextResponse.json(
      { status: 'error', error: 'Invalid JSON request payload.' },
      { status: 400 }
    );
  }
}
