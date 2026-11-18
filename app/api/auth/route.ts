import { NextRequest, NextResponse } from 'next/server';
import { readDb, writeDb, hashPasswordPbkdf2 } from '@/lib/server-db';
import { evaluatePasswordStrength } from '@/lib/cyber-engine';

export const dynamic = 'force-dynamic';

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const action = body.action || 'login';
    const email = (body.email || '').trim().toLowerCase();
    const username = (body.username || '').trim();
    const password = body.password || '';

    const db = readDb();

    if (action === 'register') {
      if (!username || !email || !password) {
        return NextResponse.json(
          { status: 'error', error: 'Username, email, and password are required.' },
          { status: 400 }
        );
      }
      const strength = evaluatePasswordStrength(password);
      if (password.length < 8) {
        return NextResponse.json(
          {
            status: 'error',
            error: 'Password must be at least 8 characters long for SOC console access.',
          },
          { status: 400 }
        );
      }

      const existing = db.users.find(
        (u) => u.email.toLowerCase() === email || u.username.toLowerCase() === username.toLowerCase()
      );
      if (existing) {
        return NextResponse.json(
          { status: 'error', error: 'An analyst account with this email or username already exists.' },
          { status: 409 }
        );
      }

      const { hash, salt } = hashPasswordPbkdf2(password);
      const newUser = {
        id: `usr-${Date.now()}`,
        username,
        email,
        role: 'Defensive Security Analyst',
        clearance: `SOC Tier-2 // Entropy ${strength.entropyBits} bits`,
        passwordHash: hash,
        salt,
        createdAt: new Date().toISOString(),
      };
      db.users.push(newUser);
      writeDb(db);

      return NextResponse.json({
        status: 'ok',
        user: {
          id: newUser.id,
          username: newUser.username,
          email: newUser.email,
          role: newUser.role,
          clearance: newUser.clearance,
        },
      });
    }

    // Login flow
    if (!email || !password) {
      return NextResponse.json(
        { status: 'error', error: 'Email/Username and password are required.' },
        { status: 400 }
      );
    }

    const user = db.users.find(
      (u) => u.email.toLowerCase() === email || u.username.toLowerCase() === email
    );

    if (!user) {
      return NextResponse.json(
        { status: 'error', error: 'Invalid credentials. Use Demo SOC Analyst button or register.' },
        { status: 401 }
      );
    }

    const { hash } = hashPasswordPbkdf2(password, user.salt);
    if (hash !== user.passwordHash) {
      return NextResponse.json(
        { status: 'error', error: 'Invalid password digest.' },
        { status: 401 }
      );
    }

    return NextResponse.json({
      status: 'ok',
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role,
        clearance: user.clearance,
      },
    });
  } catch {
    return NextResponse.json(
      { status: 'error', error: 'Authentication service error.' },
      { status: 500 }
    );
  }
}
