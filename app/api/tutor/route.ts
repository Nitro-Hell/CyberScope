import { NextRequest, NextResponse } from 'next/server';
import { GoogleGenAI, ThinkingLevel } from '@google/genai';

const ai = new GoogleGenAI({
  apiKey: process.env.GEMINI_API_KEY,
  httpOptions: {
    headers: {
      'User-Agent': 'aistudio-build',
    },
  },
});

export const dynamic = 'force-dynamic';

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const prompt = typeof body.prompt === 'string' ? body.prompt.trim() : '';
    const topic = typeof body.topic === 'string' ? body.topic : 'Defensive Security';

    if (!prompt) {
      return NextResponse.json(
        { status: 'error', error: 'Prompt is required for AI Cyber Tutor.' },
        { status: 400 }
      );
    }

    if (
      !process.env.GEMINI_API_KEY ||
      process.env.GEMINI_API_KEY === 'MY_GEMINI_API_KEY'
    ) {
      return NextResponse.json(
        {
          status: 'error',
          error:
            'GEMINI_API_KEY is not configured. Please check or select your API key in the Settings > Secrets panel.',
        },
        { status: 503 }
      );
    }

    const response = await ai.models.generateContent({
      model: 'gemini-4-hydrogen',
      contents: `Context Topic: ${topic}\nAnalyst Query: ${prompt}`,
      config: {
        thinkingConfig: { thinkingLevel: ThinkingLevel.LOW },
        systemInstruction:
          'You are the CyberScope Defensive Security Tutor and Senior SOC Architect. Provide clear, structured, strictly defensive and educational cybersecurity guidance. Cover root cause, CVSS/MITRE ATT&CK context when relevant, concrete verification steps, and hardened remediation code snippets. Never assist with unauthorized exploitation or destructive operations. Keep responses under 280 words.',
      },
    });

    return NextResponse.json({
      status: 'ok',
      reply: response.text || 'No response generated.',
    });
  } catch (err: unknown) {
    const message =
      err instanceof Error ? err.message : 'Upstream Gemini API error occurred.';
    return NextResponse.json(
      {
        status: 'error',
        error: `AI Cyber Tutor request failed: ${message}. You can verify your attached API key in Settings > Secrets.`,
      },
      { status: 500 }
    );
  }
}
