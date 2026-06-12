import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  reactStrictMode: true,
  // Emit a self-contained server bundle (.next/standalone) so the Render Docker
  // image ships only the traced runtime deps — not the full node_modules tree.
  output: "standalone",
};

export default nextConfig;
