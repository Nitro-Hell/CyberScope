import { NextRequest, NextResponse } from 'next/server';
import crypto from 'node:crypto';
import { identifyFileSignature, analyzeAuthLog } from '@/lib/cyber-engine';

export const dynamic = 'force-dynamic';

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const fileName = typeof body.fileName === 'string' ? body.fileName : 'evidence_artifact.bin';
    const content = typeof body.content === 'string' ? body.content : '';
    const hexHeader = typeof body.hexHeader === 'string' ? body.hexHeader : '';
    const expectedSha256 =
      typeof body.expectedSha256 === 'string' ? body.expectedSha256.trim().toLowerCase() : '';

    const buffer = Buffer.from(content || hexHeader || 'empty', 'utf8');
    const sha256 = crypto.createHash('sha256').update(buffer).digest('hex');
    const sha512 = crypto.createHash('sha512').update(buffer).digest('hex');

    const effectiveHex =
      hexHeader.trim() || buffer.subarray(0, 16).toString('hex').toUpperCase();
    const signatureMatch = identifyFileSignature(effectiveHex, fileName);
    const logAnalysis = content ? analyzeAuthLog(content) : null;

    const hashVerified = expectedSha256 ? expectedSha256 === sha256.toLowerCase() : null;

    return NextResponse.json({
      status: 'ok',
      fileName,
      sizeBytes: buffer.byteLength,
      sha256,
      sha512,
      hashVerified,
      signatureMatch,
      logAnalysis,
    });
  } catch {
    return NextResponse.json(
      { status: 'error', error: 'Forensic artifact inspection failed.' },
      { status: 400 }
    );
  }
}
