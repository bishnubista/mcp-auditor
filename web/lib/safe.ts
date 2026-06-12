// Trust-boundary helpers (PLAN-UI §6). ALL target-derived evidence is untrusted
// DATA. We render it as plain text via React children (which escapes), never via
// dangerouslySetInnerHTML, and we never trust target/C1 URLs.

// Only same-document hash anchors are permitted as hrefs sourced from data.
// https:// links are allowed ONLY when WE construct them from a known-safe base
// (e.g. github.com provenance) — never from untrusted evidence text.
export function isSafeHttpsUrl(url: string): boolean {
  try {
    const u = new URL(url);
    return u.protocol === "https:";
  } catch {
    return false;
  }
}

// Parse a GitHub repo URL to owner/repo for provenance display. Returns null if
// it is not a recognizable github.com https URL — we never echo arbitrary text
// as a link.
export function parseGithubRepo(
  input: string,
): { owner: string; repo: string; href: string } | null {
  const trimmed = input.trim();
  if (trimmed === "") return null;
  let u: URL;
  try {
    u = new URL(trimmed);
  } catch {
    return null;
  }
  if (u.protocol !== "https:") return null;
  if (u.hostname !== "github.com" && u.hostname !== "www.github.com") {
    return null;
  }
  const parts = u.pathname.split("/").filter(Boolean);
  if (parts.length < 2) return null;
  const owner = parts[0];
  const repo = parts[1].replace(/\.git$/, "");
  if (!/^[\w.-]+$/.test(owner) || !/^[\w.-]+$/.test(repo)) return null;
  return {
    owner,
    repo,
    href: `https://github.com/${owner}/${repo}`,
  };
}

// Clamp untrusted evidence to a sane length for display (defense-in-depth; the
// backend already truncates). Returns plain text — caller renders as children.
export function clampEvidence(text: string, max = 600): string {
  if (text.length <= max) return text;
  return text.slice(0, max) + "…";
}
