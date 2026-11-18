import type { Metadata } from 'next';
import { Plus_Jakarta_Sans, JetBrains_Mono } from 'next/font/google';
import './globals.css';

const plusJakarta = Plus_Jakarta_Sans({
  subsets: ['latin'],
  weight: ['400', '500', '600', '700'],
  variable: '--font-sans',
});

const jetbrainsMono = JetBrains_Mono({
  subsets: ['latin'],
  weight: ['400', '500', '600'],
  variable: '--font-mono',
});

export const metadata: Metadata = {
  title: 'CyberScope SOC Platform',
  description:
    'All-in-one browser-based cybersecurity operations, network intelligence, defensive security scanner, cryptography lab, CTF arena, digital forensics, and AI cyber tutor platform.',
  openGraph: {
    title: 'CyberScope SOC Platform',
    description:
      'All-in-one browser-based cybersecurity operations, network intelligence, defensive security scanner, cryptography lab, CTF arena, digital forensics, and AI cyber tutor platform.',
    type: 'website',
  },
  twitter: {
    card: 'summary_large_image',
    title: 'CyberScope SOC Platform',
    description:
      'All-in-one browser-based cybersecurity operations, network intelligence, defensive security scanner, cryptography lab, CTF arena, digital forensics, and AI cyber tutor platform.',
  },
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className={`${plusJakarta.variable} ${jetbrainsMono.variable} dark`}>
      <body
        suppressHydrationWarning
        className="bg-[#080D1A] text-slate-100 antialiased selection:bg-cyan-500/30 selection:text-cyan-200 font-sans min-h-screen"
      >
        {children}
      </body>
    </html>
  );
}
