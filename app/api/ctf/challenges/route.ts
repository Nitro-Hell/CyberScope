import { NextResponse } from 'next/server';
import { readDb } from '@/lib/server-db';

export const dynamic = 'force-dynamic';

export async function GET() {
  const db = readDb();
  const sanitizedChallenges = db.ctf_challenges.map((c) => ({
    id: c.id,
    title: c.title,
    category: c.category,
    difficulty: c.difficulty,
    points: c.points,
    description: c.description,
    artifact: c.artifact,
    hint: c.hint,
    solved: db.ctf_progress.includes(c.id),
  }));

  const userPoints = sanitizedChallenges
    .filter((c) => c.solved)
    .reduce((acc, c) => acc + c.points, 0);

  return NextResponse.json({
    status: 'ok',
    challenges: sanitizedChallenges,
    solvedIds: db.ctf_progress,
    userPoints,
    leaderboard: [
      { rank: 1, handle: 'kestrel_sec', role: 'Red/Blue Lead', solved: 6, points: 1650 },
      { rank: 2, handle: 'elena.vance (You)', role: 'SOC Architect', solved: db.ctf_progress.length, points: userPoints },
      { rank: 3, handle: 'cipher_hound', role: 'Threat Hunter', solved: 3, points: 650 },
      { rank: 4, handle: 'packet_wraith', role: 'Forensics Analyst', solved: 2, points: 400 },
    ].sort((a, b) => b.points - a.points).map((entry, idx) => ({ ...entry, rank: idx + 1 })),
  });
}
