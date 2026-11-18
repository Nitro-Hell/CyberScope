import { NextResponse } from 'next/server';
import { readDb } from '@/lib/server-db';

export const dynamic = 'force-dynamic';

export async function GET() {
  const db = readDb();
  const avgScore =
    db.scan_history.length > 0
      ? Math.round(
          db.scan_history.reduce((acc, s) => acc + s.score, 0) / db.scan_history.length
        )
      : 82;

  const solvedPoints = db.ctf_challenges
    .filter((c) => db.ctf_progress.includes(c.id))
    .reduce((acc, c) => acc + c.points, 0);

  return NextResponse.json({
    status: 'ok',
    metrics: {
      securityPostureScore: avgScore,
      authorizedDevicesCount: db.network_devices.length,
      reviewRequiredDevices: db.network_devices.filter((d) => d.status !== 'Authorized').length,
      totalScansCompleted: db.scan_history.length,
      ctfSolvedCount: db.ctf_progress.length,
      ctfTotalCount: db.ctf_challenges.length,
      ctfScorePoints: solvedPoints,
      reportsGenerated: db.reports.length,
    },
    scanHistory: db.scan_history.slice(0, 8),
    networkDevices: db.network_devices,
    reports: db.reports,
    learningProgress: db.learning_progress,
    cryptoHistory: db.crypto_history.slice(0, 6),
    scoreTrend: [
      { label: 'W-5', score: 68 },
      { label: 'W-4', score: 72 },
      { label: 'W-3', score: 76 },
      { label: 'W-2', score: 80 },
      { label: 'W-1', score: 84 },
      { label: 'Current', score: avgScore },
    ],
  });
}
