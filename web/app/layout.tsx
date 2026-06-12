import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "MCP Auditor — governed multi-agent security audit",
  description:
    "Paste an MCP endpoint and watch six SAFE-T security agents hunt vulnerabilities in real time, under a governance gate.",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body className="min-h-screen antialiased">
        <div className="relative z-10">{children}</div>
      </body>
    </html>
  );
}
