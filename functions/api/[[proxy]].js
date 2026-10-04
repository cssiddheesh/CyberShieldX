// Cloudflare Pages Function: proxies /api/* to the Flask backend.
//
// Same-origin proxy, so the frontend works unchanged (it calls relative
// /api/... URLs) and no CORS changes are needed on the backend.
// Set the BACKEND_URL environment variable on the Pages project to the
// public address of the backend, e.g. https://cybershield.example.com
// (typically a Cloudflare Tunnel hostname pointing at the laptop).
// For an Access-protected Tunnel, also set BACKEND_ACCESS_CLIENT_ID and
// BACKEND_ACCESS_CLIENT_SECRET as Pages secrets.
export async function onRequest(context) {
  const backend = (context.env.BACKEND_URL || "").replace(/\/+$/, "");
  if (!backend) {
    return Response.json(
      { error: { code: "backend_not_configured", message: "BACKEND_URL is not set for this Pages project." } },
      { status: 503 }
    );
  }
  const accessClientId = context.env.BACKEND_ACCESS_CLIENT_ID || "";
  const accessClientSecret = context.env.BACKEND_ACCESS_CLIENT_SECRET || "";
  if (Boolean(accessClientId) !== Boolean(accessClientSecret)) {
    return Response.json(
      { error: { code: "backend_access_misconfigured", message: "Both Cloudflare Access service-token values must be configured." } },
      { status: 503 }
    );
  }
  const url = new URL(context.request.url);
  const target = backend + url.pathname + url.search;

  const headers = new Headers();
  context.request.headers.forEach((value, key) => {
    const lower = key.toLowerCase();
    if (lower === "host" || lower === "content-length" || lower === "cookie" || lower === "authorization" ||
        lower === "proxy-authorization" || lower.startsWith("cf-") || lower.startsWith("x-forwarded")) return;
    headers.set(key, value);
  });
  if (accessClientId) {
    headers.set("CF-Access-Client-Id", accessClientId);
    headers.set("CF-Access-Client-Secret", accessClientSecret);
  }

  const init = { method: context.request.method, headers, redirect: "manual" };
  if (context.request.method !== "GET" && context.request.method !== "HEAD") {
    init.body = context.request.body;
    init.duplex = "half";
  }

  let upstream;
  try {
    upstream = await fetch(target, init);
  } catch {
    return Response.json(
      { error: { code: "backend_unreachable", message: "Cannot reach the CyberShield X backend. It may be offline." } },
      { status: 502 }
    );
  }

  const out = new Headers();
  upstream.headers.forEach((value, key) => {
    const lower = key.toLowerCase();
    if (lower === "content-length" || lower === "content-encoding") return;
    out.set(key, value);
  });
  return new Response(upstream.body, { status: upstream.status, headers: out });
}
