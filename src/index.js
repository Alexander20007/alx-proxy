import { jwtVerify, createRemoteJWKSet } from 'jose';

// ═══════════════════════════════════════════════════════════
//  ALXMOVIES PROXY — Cloudflare Worker (com Auth Supabase)
// ═══════════════════════════════════════════════════════════

// URL do teu projeto Supabase
const SUPABASE_URL = "https://onqxflwfkexitipylixc.supabase.co";
// JWKS endpoint (chaves públicas para validar JWTs)
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
  "sb-auth":    { target: "https://onqxflwfkexitipylixc.supabase.co/auth/v1" },
  "sb-fn":      { target: "https://onqxflwfkexitipylixc.supabase.co/functions/v1" },
  "sb-storage": {
    target: "https://onqxflwfkexitipylixc.supabase.co/storage/v1",
    headers: { "apikey": "env:SUPABASE_PUBLISHABLE_KEY" }
  },
  "canais": { target: "https://alx-player.netlify.app/.netlify/functions/canais", exact: true },
  "epg":    { target: "https://alx-player.netlify.app/.netlify/functions/programacao", exact: true },
  "release": {
    target: "https://api.github.com/repos/Alexander20007/alxmovies-tv/releases/latest",
    exact: true
  },
  "releases": {
    target: "https://api.github.com/repos/Alexander20007/alxmovies-tv/releases",
    exact: true
  },
  "repo": {
    target: "https://api.github.com/repos/Alexander20007/alxmovies-tv",
    exact: true
  },
  "tmdb": {
    target: "https://image.tmdb.org/t/p"
  }
};

// Rotas que NÃO precisam de autenticação (ex: imagens TMDB, health check)
const PUBLIC_PREFIXES = ["tmdb"];

const BLOCKED_HOSTS = [
  /^localhost$/i, /^127\./, /^0\./, /^10\./, /^192\.168\./,
  /^172\.(1[6-9]|2[0-9]|3[01])\./, /^169\.254\./, /^::1$/, /^fc00:/i, /^fe80:/i
];

const rateBuckets = new Map();

// ─── Verifica o JWT do Supabase ─────────────────────────────
async function verifySupabaseJWT(request) {
  const authHeader = request.headers.get("Authorization");
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return { ok: false, reason: "missing_token" };
  }

  const token = authHeader.substring(7);

  // A publishable key NÃO é um JWT — não a tentar validar como token
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
    console.error("JWT validation failed:", err.message);
    return { ok: false, reason: "invalid_token", detail: err.message };
  }
}

export default {
  async fetch(request, env, ctx) {
    const start = Date.now();
    const id = crypto.randomUUID().slice(0, 8);
    const url = new URL(request.url);
    const parts = url.pathname.split("/").filter(Boolean);

    // ─── CORS preflight ───
    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders(env, request) });
    }

    // ─── Rota raiz: índice (público) ───
    if (parts.length === 0) {
      return json({
        service: "ALXMOVIES Proxy",
        status: "online",
        version: "2.0.0-auth",
        routes: Object.keys(ORIGINS)
      }, 200, env, request);
    }

    const prefix = parts[0];

    // ─── Verificar se a rota é pública ───
    const isPublic = PUBLIC_PREFIXES.includes(prefix);

    if (!isPublic) {
      // ─── AUTH: só utilizadores com JWT válido do Supabase passam ───
      const auth = await verifySupabaseJWT(request);
      if (!auth.ok) {
        log(id, "AUTH_DENY:" + auth.reason, ip(request), 401, Date.now() - start);
        return json({
          error: "Unauthorized",
          reason: auth.reason,
          hint: "Envia um JWT válido do Supabase no header Authorization: Bearer <token>"
        }, 401, env, request);
      }
      // Guarda o ID do utilizador para logs e rate limit
      request.userId = auth.user.sub;
    }

    try {
      // ─── Rate limit ───
      const clientIp = ip(request);
      const rlKey = request.userId || clientIp; // Por utilizador, se autenticado
      const rl = checkRateLimit(rlKey, Number(env.RATE_LIMIT_PER_MIN) || 120);
      if (!rl.ok) {
        log(id, "RATE_LIMIT", rlKey, 429, Date.now() - start);
        return json({ error: "Too Many Requests", retryAfter: rl.retryAfter }, 429, env, request);
      }

      // ─── Path traversal ───
      if (url.pathname.includes("..")) {
        return json({ error: "Bad Request" }, 400, env, request);
      }

      // ─── Validacao de prefixo ───
      const config = ORIGINS[prefix];
      if (!config) {
        log(id, "NOT_FOUND:" + prefix, clientIp, 404, Date.now() - start);
        return json({ error: 'Prefixo "' + prefix + '" nao configurado' }, 404, env, request);
      }

      // ─── Métodos permitidos ───
      const allowed = config.methods || ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"];
      if (!allowed.includes(request.method)) {
        return json({ error: "Method Not Allowed" }, 405, env, request);
      }

      // ─── Tamanho máximo do body ───
      const maxBody = Number(env.MAX_BODY_BYTES) || 1048576;
      if (Number(request.headers.get("content-length") || 0) > maxBody) {
        return json({ error: "Payload Too Large" }, 413, env, request);
      }

      // ─── Constroi URL de destino ───
      let targetUrl;
      if (config.exact) {
        targetUrl = new URL(config.target + url.search);
      } else {
        const rest = "/" + parts.slice(1).join("/");
        targetUrl = new URL(rest + url.search, config.target);
      }

      // ─── Bloqueio SSRF ───
      if (isBlockedHost(targetUrl.hostname)) {
        return json({ error: "Forbidden" }, 403, env, request);
      }

      // ─── Headers ───
      const headers = new Headers(request.headers);
      ["host", "cf-connecting-ip", "cf-ray", "cf-worker", "cf-ipcountry",
       "x-forwarded-for", "x-forwarded-proto", "x-real-ip"].forEach(h => headers.delete(h));
      headers.set("x-proxy-by", "alx-proxy/2.0");

      // GitHub API exige User-Agent
      if (targetUrl.hostname === "api.github.com" && !headers.has("user-agent")) {
        headers.set("user-agent", "alx-proxy/2.0");
      }

      // Injeta headers fixos (env:...)
      if (config.headers) {
        for (const [k, v] of Object.entries(config.headers)) {
          const resolved = (typeof v === "string" && v.startsWith("env:"))
            ? env[v.slice(4)] : v;
          if (resolved) headers.set(k, resolved);
        }
      }

      // ─── Timeout de upstream ───
      const timeoutMs = Number(env.UPSTREAM_TIMEOUT_MS) || 25000;
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

      // ─── Pedido upstream ───
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

      // ─── Resposta ───
      const newHeaders = new Headers(response.headers);
      for (const [k, v] of Object.entries(corsHeaders(env, request))) {
        newHeaders.set(k, v);
      }
      newHeaders.set("x-content-type-options", "nosniff");
      newHeaders.set("referrer-policy", "no-referrer");

      log(id, prefix, request.userId || clientIp, response.status, Date.now() - start);
      return new Response(response.body, {
        status: response.status,
        statusText: response.statusText,
        headers: newHeaders
      });

    } catch (err) {
      const isTimeout = err.name === "AbortError";
      log(id, isTimeout ? "TIMEOUT" : "ERROR", "?", isTimeout ? 504 : 502, Date.now() - start);
      return json(
        { error: isTimeout ? "Gateway Timeout" : "Bad Gateway", detail: err.message },
        isTimeout ? 504 : 502,
        env, request
      );
    }
  }
};

// ═══════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════

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
    id, route,
    key: short,
    status, ms
  }));
}
