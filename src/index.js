import { jwtVerify, createRemoteJWKSet } from 'jose';

// ═══════════════════════════════════════════════════════════
//  ALXMOVIES PROXY — Cloudflare Worker
//  v2.3 — auth + nonce por sessão (proteção contra mods)
// ═══════════════════════════════════════════════════════════

const SUPABASE_URL = "https://onqxflwfkexitipylixc.supabase.co";
const JWKS = createRemoteJWKSet(
  new URL(`${SUPABASE_URL}/auth/v1/.well-known/jwks.json`)
);

const ORIGINS = {
  "alx":  { target: "https://alx-api.onrender.com" },
  "jney": { target: "https://api-alex-jney.onrender.com" },

  "sb": {
    target: "https://onqxflwfkexitipylixc.supabase.co",
    headers: { "apikey": "env:SUPABASE_PUBLISHABLE_KEY" }
  },
  "sb-rest": {
    target: "https://onqxflwfkexitipylixc.supabase.co/rest/v1",
    headers: {
      "apikey": "env:SUPABASE_PUBLISHABLE_KEY",
      "Authorization": "env:SUPABASE_PUBLISHABLE_KEY"
    }
  },
  "sb-auth": { target: "https://onqxflwfkexitipylixc.supabase.co/auth/v1" },
  "sb-fn":   { target: "https://onqxflwfkexitipylixc.supabase.co/functions/v1" },
  "sb-storage": {
    target: "https://onqxflwfkexitipylixc.supabase.co/storage/v1",
    headers: { "apikey": "env:SUPABASE_PUBLISHABLE_KEY" }
  },

  "canais": { target: "https://alx-player.netlify.app/.netlify/functions/canais", exact: true },
  "epg":    { target: "https://alx-player.netlify.app/.netlify/functions/programacao", exact: true },

  "release":  { target: "https://api.github.com/repos/Alexander20007/alxmovies-tv/releases/latest", exact: true },
  "releases": { target: "https://api.github.com/repos/Alexander20007/alxmovies-tv/releases", exact: true },
  "repo":     { target: "https://api.github.com/repos/Alexander20007/alxmovies-tv", exact: true },

  "tmdb": { target: "https://image.tmdb.org/t/p" }
};

// Rotas que NÃO exigem JWT nem nonce
const PUBLIC_ROUTES = ["sb-auth", "tmdb"];

const NONCE_TTL_SECONDS = 300;
const NONCE_HEADER = "X-Nonce";

const BLOCKED_HOSTS = [
  /^localhost$/i, /^127\./, /^0\./, /^10\./, /^192\.168\./,
  /^172\.(1[6-9]|2[0-9]|3[01])\./, /^169\.254\./, /^::1$/, /^fc00:/i, /^fe80:/i
];

const rateBuckets = new Map();

function generateNonce() {
  const bytes = new Uint8Array(24);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, b => b.toString(16).padStart(2, "0")).join("");
}

async function verifySupabaseJWT(request) {
  const authHeader = request.headers.get("Authorization");
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return { ok: false, reason: "missing_token" };
  }
  const token = authHeader.substring(7);
  if (token.startsWith("sb_") || token.length < 30) {
    return { ok: false, reason: "not_a_jwt" };
  }
  try {
    const { payload } = await jwtVerify(token, JWKS, {
      issuer: `${SUPABASE_URL}/auth/v1`,
      audience: "authenticated"
    });
    return { ok: true, user: payload };
  } catch (err) {
    return { ok: false, reason: "invalid_token", detail: err.message };
  }
}

function accessDenied(env, request, status = 401) {
  return new Response("Acesso negado", {
    status,
    headers: {
      "content-type": "text/plain; charset=utf-8",
      ...corsHeaders(env, request)
    }
  });
}

export default {
  async fetch(request, env, ctx) {
    const start = Date.now();
    const id = crypto.randomUUID().slice(0, 8);
    const url = new URL(request.url);
    const parts = url.pathname.split("/").filter(Boolean);

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders(env, request) });
    }

    // ─── Endpoint /nonce (público) ───
    if (parts.length === 1 && parts[0] === "nonce" && request.method === "GET") {
      const nonce = generateNonce();
      const expiresAt = Date.now() + NONCE_TTL_SECONDS * 1000;
      try {
        await env.NONCE_STORE.put(`nonce:${nonce}`, JSON.stringify({
          created: Date.now(), expiresAt
        }), { expirationTtl: NONCE_TTL_SECONDS });
      } catch (err) {
        console.error("KV put failed:", err.message);
        return accessDenied(env, request, 500);
      }
      log(id, "NONCE_ISSUED", ip(request), 200, Date.now() - start);
      return json({ nonce, expiresIn: NONCE_TTL_SECONDS }, 200, env, request);
    }

    if (parts.length === 0) {
      return json({
        service: "ALXMOVIES Proxy",
        status: "online",
        version: "2.3.0",
        routes: Object.keys(ORIGINS),
        publicRoutes: PUBLIC_ROUTES,
        note: "Obtém um nonce em GET /nonce antes de fazer pedidos autenticados."
      }, 200, env, request);
    }

    const prefix = parts[0];
    const config = ORIGINS[prefix];

    if (!config) {
      log(id, "NOT_FOUND:" + prefix, ip(request), 404, Date.now() - start);
      return accessDenied(env, request, 404);
    }

    if (url.pathname.includes("..")) {
      return accessDenied(env, request, 400);
    }

    const isPublic = PUBLIC_ROUTES.includes(prefix);
    let userId = null;

    if (!isPublic) {
      // ─── Valida JWT ───
      const auth = await verifySupabaseJWT(request);
      if (!auth.ok) {
        log(id, "AUTH_DENY:" + auth.reason, ip(request), 401, Date.now() - start);
        return accessDenied(env, request, 401);
      }
      userId = auth.user.sub;

      // ─── Valida nonce ───
      const nonce = request.headers.get(NONCE_HEADER);
      if (!nonce) {
        log(id, "NONCE_MISSING", userId, 401, Date.now() - start);
        return accessDenied(env, request, 401);
      }

      const key = `nonce:${nonce}`;
      let stored;
      try {
        stored = await env.NONCE_STORE.get(key);
      } catch (err) {
        console.error("KV get failed:", err.message);
        return accessDenied(env, request, 500);
      }

      if (!stored) {
        log(id, "NONCE_INVALID:" + nonce.slice(0, 8), userId, 401, Date.now() - start);
        return accessDenied(env, request, 401);
      }

      // uso único — apaga
      try {
        await env.NONCE_STORE.delete(key);
      } catch (err) {
        console.error("KV delete failed:", err.message);
      }

      log(id, "NONCE_OK:" + nonce.slice(0, 8), userId, 200, Date.now() - start);
    }

    try {
      const clientIp = ip(request);
      const rlKey = userId || clientIp;
      const rl = checkRateLimit(rlKey, Number(env.RATE_LIMIT_PER_MIN) || 120);
      if (!rl.ok) {
        log(id, "RATE_LIMIT", rlKey, 429, Date.now() - start);
        return accessDenied(env, request, 429);
      }

      const allowed = config.methods || ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"];
      if (!allowed.includes(request.method)) {
        return accessDenied(env, request, 405);
      }

      const maxBody = Number(env.MAX_BODY_BYTES) || 1048576;
      if (Number(request.headers.get("content-length") || 0) > maxBody) {
        return accessDenied(env, request, 413);
      }

      let targetUrl;
      if (config.exact) {
        targetUrl = new URL(config.target + url.search);
      } else {
        const rest = parts.slice(1).join("/");
        const base = config.target.endsWith("/") ? config.target : config.target + "/";
        targetUrl = new URL(base + rest + url.search);
      }

      if (isBlockedHost(targetUrl.hostname)) {
        return accessDenied(env, request, 403);
      }

      const headers = new Headers(request.headers);
      ["host", "cf-connecting-ip", "cf-ray", "cf-worker", "cf-ipcountry",
       "x-forwarded-for", "x-forwarded-proto", "x-real-ip",
       NONCE_HEADER.toLowerCase()].forEach(h => headers.delete(h));
      headers.set("x-proxy-by", "alx-proxy/2.3");

      if (targetUrl.hostname === "api.github.com" && !headers.has("user-agent")) {
        headers.set("user-agent", "alx-proxy/2.3");
      }

      if (config.headers) {
        for (const [k, v] of Object.entries(config.headers)) {
          const resolved = (typeof v === "string" && v.startsWith("env:"))
            ? env[v.slice(4)] : v;
          if (resolved) headers.set(k, resolved);
        }
      }

      const timeoutMs = Number(env.UPSTREAM_TIMEOUT_MS) || 25000;
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

      const proxyReq = new Request(targetUrl.toString(), {
        method: request.method,
        headers,
        body: ["GET", "HEAD"].includes(request.method) ? undefined : request.body,
        redirect: "follow",
        signal: controller.signal
      });

      let response;
      try {
        response = await fetch(proxyReq);
      } finally {
        clearTimeout(timeoutId);
      }

      const newHeaders = new Headers(response.headers);
      for (const [k, v] of Object.entries(corsHeaders(env, request))) {
        newHeaders.set(k, v);
      }
      newHeaders.set("x-content-type-options", "nosniff");
      newHeaders.set("referrer-policy", "no-referrer");

      log(id, prefix, userId || clientIp, response.status, Date.now() - start);
      return new Response(response.body, {
        status: response.status,
        statusText: response.statusText,
        headers: newHeaders
      });

    } catch (err) {
      const isTimeout = err.name === "AbortError";
      log(id, isTimeout ? "TIMEOUT" : "ERROR", "?", isTimeout ? 504 : 502, Date.now() - start);
      return accessDenied(env, request, isTimeout ? 504 : 502);
    }
  }
};

function corsHeaders(env, request) {
  const allowed = (env.ALLOWED_ORIGINS || "").split(",").map(s => s.trim()).filter(Boolean);
  const origin = request?.headers.get("origin") || "";
  const allowOrigin = allowed.length === 0 ? "*" : (allowed.includes(origin) ? origin : allowed[0]);
  return {
    "Access-Control-Allow-Origin": allowOrigin,
    "Access-Control-Allow-Methods": "GET,POST,PUT,PATCH,DELETE,HEAD,OPTIONS",
    "Access-Control-Allow-Headers": "*",
    "Access-Control-Max-Age": "86400",
    "Vary": "Origin"
  };
}

function json(obj, status, env, request) {
  return new Response(JSON.stringify(obj, null, 2), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      ...corsHeaders(env, request)
    }
  });
}

function ip(request) {
  return request.headers.get("cf-connecting-ip") || "unknown";
}

function isBlockedHost(hostname) {
  return BLOCKED_HOSTS.some(re => re.test(hostname));
}

function checkRateLimit(key, maxPerMin) {
  const now = Date.now();
  const windowMs = 60000;
  let bucket = rateBuckets.get(key);
  if (!bucket || now - bucket.start > windowMs) {
    bucket = { start: now, count: 0 };
    rateBuckets.set(key, bucket);
  }
  bucket.count++;
  if (rateBuckets.size > 5000) {
    for (const [k, b] of rateBuckets) {
      if (now - b.start > windowMs) rateBuckets.delete(k);
    }
  }
  if (bucket.count > maxPerMin) {
    return { ok: false, retryAfter: Math.ceil((bucket.start + windowMs - now) / 1000) };
  }
  return { ok: true };
}

function log(id, route, key, status, ms) {
  const short = key === "unknown" ? key : key.split(".").slice(0, 2).join(".") + ".x.x";
  console.log(JSON.stringify({
    t: new Date().toISOString(),
    id, route, key: short, status, ms
  }));
}
