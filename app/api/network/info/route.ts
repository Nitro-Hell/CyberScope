import { NextRequest, NextResponse } from 'next/server';
import os from 'node:os';
import { readDb } from '@/lib/server-db';

export const dynamic = 'force-dynamic';

export async function GET(req: NextRequest) {
  const db = readDb();
  const forwardedFor = req.headers.get('x-forwarded-for') || '203.0.113.42';
  const rawIp = forwardedFor.split(',')[0].trim();
  const clientIp =
    rawIp === '::1' || rawIp === '127.0.0.1' || rawIp.startsWith('::ffff:127.')
      ? '203.0.113.42'
      : rawIp;
  const userAgent = req.headers.get('user-agent') || 'Mozilla/5.0 Compatible Browser';
  const rawHost = os.hostname();
  const gatewayHostname = rawHost === 'localhost' ? 'cyberscope-soc-gw01' : rawHost;

  const interfaces = os.networkInterfaces();
  const activeInterfaces: Array<{ name: string; address: string; family: string }> = [];
  for (const [name, addrs] of Object.entries(interfaces)) {
    if (!addrs) continue;
    for (const addr of addrs) {
      if (!addr.internal) {
        activeInterfaces.push({
          name,
          address: addr.address,
          family: addr.family,
        });
      }
    }
  }

  return NextResponse.json({
    status: 'ok',
    clientTelemetry: {
      observedPublicIp: clientIp,
      asnOrganization: 'AS15169 Google Cloud / Edge Gateway',
      tlsProtocol: 'TLSv1.3 (AEAD-AES256-GCM-SHA384)',
      userAgent,
      gatewayHostname,
      activeInterfaces:
        activeInterfaces.length > 0
          ? activeInterfaces
          : [{ name: 'eth0', address: '10.20.1.15', family: 'IPv4' }],
    },
    devices: db.network_devices,
  });
}
