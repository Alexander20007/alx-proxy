import { jwtVerify, createRemoteJWKSet } from 'jose';

// ═══════════════════════════════════════════════════════════
//  ALXMOVIES PROXY — Cloudflare Worker
//  v2.5.0 — auth + nonce + WebSocket + rotas publicas condicionais
// ═══════════════════════════════════════════════════════════

const SUPABASE_URL = "https://onqxflwfkexitipylixc.supabase.co";
const SUPABASE_WS = "wss://onqxflwfkexitipylixc.supabase.co";
const JWKS = createRemoteJWKSet(
  new URL(`${SUPABASE_URL}/auth/v1/.well-known/jwks.json`)
);

// ─── Configuracao base ───
const ORIGINS = {
  "alx":   { target: "https://alx-api.onrender.com" },
  "alxm":  { target: "https://alx-api.onrender.com" },
  "jney":  { target: "https://api-alex-jney.onrender.com" },
  "jneym": { target: "https://api-alex-jney.onrender.com" },

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

  "release":  {
    target: "https://api.github.com/repos/Alexander20007/alxmovies-tv/releases/latest",
    exact: true,
    headers: { "Authorization": "Bearer env:GITHUB_TOKEN", "User-Agent": "alx-proxy/2.5.0" }
  },
  "releases": {
    target: "https://api.github.com/repos/Alexander20007/alxmovies-tv/releases",
    exact: true,
    headers: { "Authorization": "Bearer env:GITHUB_TOKEN", "User-Agent": "alx-proxy/2.5.0" }
  },
  "repo": {
    target: "https://api.github.com/repos/Alexander20007/alxmovies-tv",
    exact: true,
    headers: { "Authorization": "Bearer env:GITHUB_TOKEN", "User-Agent": "alx-proxy/2.5.0" }
  },

  "tmdb": { target: "https://image.tmdb.org/t/p" }
};

// ─── Rotas completamente publicas (sem JWT, sem nonce) ───
const PUBLIC_ROUTES = ["sb-auth", "tmdb", "release", "releases", "repo"];

// ─── Rotas com "allowPaths": publicas so em paths especificos ───
// O player HLS.js e o 1DM nao enviam headers, por isso estes paths
// precisam de ser publicos. O resto do prefixo continua protegido.
const ALLOW_PATHS = {
  // /alxm/api/proxy e /alxm/api/proxy/... sao publicos
  "alxm": ["api/proxy"],
  "alx":  ["api/proxy"],
  "jneym": ["proxy"],
  "jney":  ["proxy"]
};

// ─── Prefixos que tem um rate limit especifico ───
const RATE_LIMIT_OVERRIDES = {
  "sb-fn-guest-redeem": 10   // 10/min por IP
};

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

    // ─── WebSocket ───
    if (parts[0] === "ws" && parts[1] === "realtime") {
      return handleWebSocket(request, env, url);
    }

    // ─── /nonce ───
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

    // ─── Raiz ───
    if (parts.length === 0) {
      return json({
        service: "ALXMOVIES Proxy",
        status: "online",
        version: "2.5.0",
        routes: Object.keys(ORIGINS),
        publicRoutes: PUBLIC_ROUTES,
        allowPaths: ALLOW_PATHS,
        websocket: "/ws/realtime?token=<jwt>&apikey=<key>&vsn=1.0.0"
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

    // ─── Verificar se o pedido e "path publico" ───
    const rest = parts.slice(1).join("/");
    const isPathPublic = (ALLOW_PATHS[prefix] || []).some(p =>
      rest === p || rest.startsWith(p + "/") || rest.startsWith(p + "?")
    );

    // ─── Rotas "parcialmente publicas": /sb-storage e /sb-fn ───
    // Essas nao entram no ALLOW_PATHS porque dependem do path especifico.
    let isPublic = PUBLIC_ROUTES.includes(prefix) || isPathPublic;

    // /sb-storage/object/public/* e publico (GET/HEAD)
    if (prefix === "sb-storage" && rest.startsWith("object/public/") && ["GET", "HEAD"].includes(request.method)) {
      isPublic = true;
    }

    // POST /sb-fn/guest-redeem-code e publico (com rate limit 10/min por IP)
    const isGuestRedeem = (prefix === "sb-fn" && rest === "guest-redeem-code" && request.method === "POST");
    if (isGuestRedeem) {
      isPublic = true;
    }

    let userId = null;

    if (!isPublic) {
      const auth = await verifySupabaseJWT(request);
      if (!auth.ok) {
        log(id, "AUTH_DENY:" + auth.reason, ip(request), 401, Date.now() - start);
        return accessDenied(env, request, 401);
      }
      userId = auth.user.sub;

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

      try {
        await env.NONCE_STORE.delete(key);
      } catch (err) {
        console.error("KV delete failed:", err.message);
      }

      log(id, "NONCE_OK:" + nonce.slice(0, 8), userId, 200, Date.now() - start);
    }

    try {
      // ─── Rate limit (com override) ───
      const clientIp = ip(request);
      const rlKey = userId || clientIp;
      const defaultMax = Number(env.RATE_LIMIT_PER_MIN) || 300;
      const maxPerMin = isGuestRedeem ? RATE_LIMIT_OVERRIDES["sb-fn-guest-redeem"] : defaultMax;
      const rl = checkRateLimit(rlKey, maxPerMin);
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

      // ─── URL de destino ───
      let targetUrl;
      if (config.exact) {
        targetUrl = new URL(config.target + url.search);
      } else {
        const base = config.target.endsWith("/") ? config.target : config.target + "/";
        targetUrl = new URL(base + rest + url.search);
      }

      if (isBlockedHost(targetUrl.hostname)) {
        return accessDenied(env, request, 403);
      }

      // ─── Headers ───
      const headers = new Headers(request.headers);
      ["host", "cf-connecting-ip", "cf-ray", "cf-worker", "cf-ipcountry",
       "x-forwarded-for", "x-forwarded-proto", "x-real-ip",
       NONCE_HEADER.toLowerCase()].forEach(h => headers.delete(h));

      const isSupabase = targetUrl.hostname.includes("supabase.co");
      if (!isSupabase) {
        headers.delete("authorization");
      }

      headers.set("x-proxy-by", "alx-proxy/2.5.0");

      if (targetUrl.hostname === "api.github.com" && !headers.has("user-agent")) {
        headers.set("user-agent", "alx-proxy/2.5.0");
      }

      if (config.headers) {
        for (const [k, v] of Object.entries(config.headers)) {
          let resolved = v;
          if (typeof v === "string") {
            if (v.startsWith("env:")) {
              resolved = env[v.slice(4)];
            } else if (v.startsWith("Bearer env:")) {
              const key = v.slice(11);
              resolved = `Bearer ${env[key] || ""}`;
            }
          }
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

// ═══════════════════════════════════════════════════════════
// WebSocket handler (repassa token, apikey e vsn ao Supabase)
// ═══════════════════════════════════════════════════════════

async function handleWebSocket(request, env, url) {
  if (request.headers.get("Upgrade") !== "websocket") {
    return new Response("Esperado WebSocket", { status: 400 });
  }

  const token = url.searchParams.get("token");
  if (!token) {
    return new Response("Acesso negado", { status: 401 });
  }

  try {
    await jwtVerify(token, JWKS, {
      issuer: `${SUPABASE_URL}/auth/v1`,
      audience: "authenticated"
    });
  } catch (err) {
    return new Response("Acesso negado", { status: 401 });
  }

  // Repassa TODOS os query params para o Supabase (token, apikey, vsn, etc.)
  const supaPath = url.pathname.replace(/^\/ws\/realtime/, "/realtime/v1/websocket");
  const apiKey = env.SUPABASE_PUBLISHABLE_KEY || url.searchParams.get("apikey") || "";
  const vsn = url.searchParams.get("vsn") || "1.0.0";

  const supaUrl = new URL(`${SUPABASE_WS}${supaPath}`);
  supaUrl.searchParams.set("apikey", apiKey);
  supaUrl.searchParams.set("vsn", vsn);
  supaUrl.searchParams.set("access_token", token);

  const supabaseResponse = await fetch(supaUrl.toString(), {
    headers: { Upgrade: "websocket" }
  });

  if (supabaseResponse.status !== 101) {
    return new Response("Falha ao ligar ao Supabase Realtime", { status: 502 });
  }

  const [client, server] = Object.values(new WebSocketPair());
  server.accept();

  const supabaseWs = supabaseResponse.webSocket;
  supabaseWs.accept();

  server.addEventListener("message", (event) => {
    try { supabaseWs.send(event.data); } catch (e) {}
  });

  supabaseWs.addEventListener("message", (event) => {
    try { server.send(event.data); } catch (e) {}
  });

  server.addEventListener("close", () => {
    try { supabaseWs.close(); } catch (e) {}
  });

  supabaseWs.addEventListener("close", () => {
    try { server.close(); } catch (e) {}
  });

  return new Response(null, {
    status: 101,
    webSocket: client
  });
}

// ═══════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════

function corsHeaders(env, request) {
  const defaults = "https://alxmovies.netlify.app,https://alx-player.netlify.app,capacitor://localhost,http://localhost,file://";
  const allowed = ((env.ALLOWED_ORIGINS || defaults) + "," + defaults)
    .split(",").map(s => s.trim()).filter(Boolean);
  const origin = request?.headers.get("origin") || "";
  const allowOrigin = allowed.length === 0 ? "*" : (allowed.includes(origin) || origin === "" ? (origin || "*") : allowed[0]);
  return {
    "Access-Control-Allow-Origin": allowOrigin,
    "Access-Control-Allow-Methods": "GET,POST,PUT,PATCH,DELETE,HEAD,OPTIONS",
    "Access-Control-Allow-Headers": "*",
    "Access-Control-Allow-Credentials": "true",
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
