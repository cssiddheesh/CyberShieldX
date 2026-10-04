export const TYPE_LABELS = {
  url: "URL", domain: "Domain", ipv4: "IPv4 address", ipv6: "IPv6 address", md5: "MD5 hash", sha1: "SHA-1 hash",
  sha256: "SHA-256 hash", cve: "CVE", file: "File", password: "Password", text: "Text", image: "Image", unknown: "Unknown",
};

export const RISK_LEVELS = ["Minimal", "Low", "Moderate", "High", "Critical"];

export const STATE_INFO = {
  AVAILABLE: { label: "Available", tone: "ok" },
  UNCHECKED: { label: "Not checked yet", tone: "muted" },
  NOT_CONFIGURED: { label: "Not configured", tone: "warn" },
  UNAVAILABLE: { label: "Unavailable", tone: "bad" },
  RATE_LIMITED: { label: "Rate limited", tone: "warn" },
  ERROR: { label: "Error", tone: "bad" },
  DISABLED: { label: "Disabled", tone: "muted" },
};

export const levelClass = (level) => `risk-${String(level || "minimal").toLowerCase()}`;

export function formatDateTime(iso) {
  if (!iso) return "";
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  return date.toLocaleString(undefined, { day: "numeric", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit" });
}

export function timeAgo(iso) {
  const seconds = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
  if (Number.isNaN(seconds)) return "";
  if (seconds < 60) return "just now";
  if (seconds < 3600) return `${Math.floor(seconds / 60)} min ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)} h ago`;
  return `${Math.floor(seconds / 86400)} d ago`;
}

export const confidenceLabel = (c) => (c < 0.4 ? "Low" : c < 0.7 ? "Moderate" : "High");
