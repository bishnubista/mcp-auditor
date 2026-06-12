"use client";

import { parseGithubRepo } from "@/lib/safe";

// Provenance only (PLAN-UI §6): parse owner/repo, show name + a SAFE https link.
// We never echo arbitrary user text as a link — only a github.com URL we rebuild.
export function GithubProvenance({ githubUrl }: { githubUrl: string }) {
  const repo = parseGithubRepo(githubUrl);
  if (!repo) return null;

  return (
    <div className="flex items-center gap-2 rounded border border-[var(--color-line)] bg-[var(--color-panel)] px-3 py-2 text-[11px]">
      <span className="text-[var(--color-ink-faint)]">repo</span>
      <a
        href={repo.href}
        target="_blank"
        rel="noopener noreferrer nofollow"
        className="font-mono text-[var(--color-cyan)] underline-offset-2 hover:underline"
      >
        {repo.owner}/{repo.repo}
      </a>
    </div>
  );
}
