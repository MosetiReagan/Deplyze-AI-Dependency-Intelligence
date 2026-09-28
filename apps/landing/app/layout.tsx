import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = {
  title: 'Deplyze — AI Dependency Intelligence & Security',
  description: 'Move beyond static CVE lookups. Deplyze uses deep behavioral AST analysis and AI threat models to catch zero-days, malicious releases, typosquats, and supply chain sabotage before installation.',
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body className="antialiased selection:bg-slate-800 selection:text-white">
        {children}
      </body>
    </html>
  );
}
