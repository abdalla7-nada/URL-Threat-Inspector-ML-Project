import type { Metadata } from 'next';
import { Geist, Geist_Mono } from 'next/font/google';
import './globals.css';

const geistSans = Geist({
  variable: '--font-geist-sans',
  subsets: ['latin'],
});

const geistMono = Geist_Mono({
  variable: '--font-geist-mono',
  subsets: ['latin'],
});

export const metadata: Metadata = {
  title: 'CYBERSEC URL INSPECTOR | Deterministic Threat Assessment',
  description:
    'Enterprise URL Security & Threat Inspector powered by a deterministic Lexical & Gradient Boost Engine.',
  keywords: [
    'cybersecurity',
    'url inspector',
    'phishing detection',
    'threat intelligence',
    'lexical forensics',
  ],
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html
      lang="en"
      suppressHydrationWarning
      className={`${geistSans.variable} ${geistMono.variable} dark antialiased`}
    >
      <body
        className="min-h-screen bg-zinc-950 text-zinc-100 font-sans selection:bg-zinc-800 selection:text-emerald-400"
        suppressHydrationWarning
      >
        {children}
      </body>
    </html>
  );
}
