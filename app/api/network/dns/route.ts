import { NextRequest, NextResponse } from 'next/server';
import dns from 'node:dns/promises';
import { validateTargetUrl } from '@/lib/cyber-engine';
import { readDb, writeDb } from '@/lib/server-db';

export const dynamic = 'force-dynamic';

export async function GET(req: NextRequest) {
  const domainParam = req.nextUrl.searchParams.get('domain') || 'example.com';
  const validation = validateTargetUrl(domainParam);

  if (!validation.valid) {
    return NextResponse.json(
      { status: 'error', error: validation.reason },
      { status: 200 }
    );
  }

  const host = validation.hostname;
  const startTime = Date.now();

  const [aRecords, aaaaRecords, mxRecords, txtRecords, nsRecords] = await Promise.all([
    dns.resolve4(host).catch(() => [] as string[]),
    dns.resolve6(host).catch(() => [] as string[]),
    dns.resolveMx(host).catch(() => []),
    dns.resolveTxt(host).catch(() => [] as string[][]),
    dns.resolveNs(host).catch(() => [] as string[]),
  ]);

  const queryTimeMs = Math.max(1, Date.now() - startTime);
  const flatTxt = txtRecords.map((chunks) => chunks.join(''));
  const hasSpf = flatTxt.some((t) => t.toLowerCase().includes('v=spf1'));
  const dmarcTxt = await dns
    .resolveTxt(`_dmarc.${host}`)
    .then((r) => r.map((c) => c.join('')))
    .catch(() => [] as string[]);

  const db = readDb();
  db.scan_history.unshift({
    id: `scan-${Date.now()}`,
    target: host,
    scanType: 'DNS Resolution',
    score: hasSpf ? 88 : 70,
    grade: hasSpf ? 'A' : 'B',
    findingsSummary: `Resolved ${aRecords.length} IPv4, ${aaaaRecords.length} IPv6, ${mxRecords.length} MX records in ${queryTimeMs}ms.`,
    timestamp: new Date().toISOString(),
  });
  writeDb(db);

  return NextResponse.json({
    status: 'ok',
    hostname: host,
    queryTimeMs,
    records: {
      A: aRecords,
      AAAA: aaaaRecords,
      MX: mxRecords,
      NS: nsRecords,
      TXT: flatTxt,
      DMARC: dmarcTxt,
    },
    dnsSecPosture: {
      spfPresent: hasSpf,
      dmarcPresent: dmarcTxt.length > 0,
      redundancyNsCount: nsRecords.length,
    },
  });
}
