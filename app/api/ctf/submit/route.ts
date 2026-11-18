import { NextRequest, NextResponse } from 'next/server';
import { verifyCtfFlag } from '@/lib/cyber-engine';
import { readDb, writeDb } from '@/lib/server-db';

export const dynamic = 'force-dynamic';

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const challengeId = typeof body.challengeId === 'string' ? body.challengeId : '';
    const flag = typeof body.flag === 'string' ? body.flag : '';

    if (!challengeId || !flag) {
      return NextResponse.json(
        { status: 'error', error: 'Both challengeId and flag are required.' },
        { status: 400 }
      );
    }

    const result = verifyCtfFlag(challengeId, flag);
    const db = readDb();

    if (result.correct && !db.ctf_progress.includes(challengeId)) {
      db.ctf_progress.push(challengeId);
      writeDb(db);
    }

    const totalPoints = db.ctf_challenges
      .filter((c) => db.ctf_progress.includes(c.id))
      .reduce((acc, c) => acc + c.points, 0);

    return NextResponse.json({
      status: 'ok',
      correct: result.correct,
      pointsAwarded: result.pointsAwarded,
      message: result.message,
      solvedIds: db.ctf_progress,
      totalPoints,
    });
  } catch {
    return NextResponse.json(
      { status: 'error', error: 'Invalid CTF flag submission payload.' },
      { status: 400 }
    );
  }
}
