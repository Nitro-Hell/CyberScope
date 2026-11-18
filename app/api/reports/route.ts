import { NextRequest, NextResponse } from 'next/server';
import { readDb, writeDb } from '@/lib/server-db';

export const dynamic = 'force-dynamic';

export async function GET() {
  const db = readDb();
  return NextResponse.json({
    status: 'ok',
    reports: db.reports,
    scanHistory: db.scan_history,
    learningProgress: db.learning_progress,
    ctfSolvedCount: db.ctf_progress.length,
    ctfTotalCount: db.ctf_challenges.length,
  });
}

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const title = typeof body.title === 'string' ? body.title.trim() : '';
    const moduleName = typeof body.module === 'string' ? body.module : 'Security Scanner';
    const severity = body.severity || 'Medium';
    const score = Number(body.score ?? 85);
    const summary = typeof body.summary === 'string' ? body.summary.trim() : '';

    if (!title || !summary) {
      return NextResponse.json(
        { status: 'error', error: 'Report title and summary are required.' },
        { status: 400 }
      );
    }

    const db = readDb();
    const newReport = {
      id: `rep-${Date.now()}`,
      title,
      module: moduleName,
      severity,
      score,
      summary,
      createdAt: new Date().toISOString(),
    };
    db.reports.unshift(newReport);
    writeDb(db);

    return NextResponse.json({
      status: 'ok',
      report: newReport,
      reports: db.reports,
    });
  } catch {
    return NextResponse.json(
      { status: 'error', error: 'Unable to create report.' },
      { status: 400 }
    );
  }
}
