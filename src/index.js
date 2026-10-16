// ═══════════════════════════════════════════════════════════
//  ALXMOVIES PROXY — Cloudflare Worker
//  Gateway unico para todos os servicos do projeto.
// ═══════════════════════════════════════════════════════════

const ORIGINS = {
  "alx":  { target: "https://alx-api.onrender.com" },
  "jney": { target: "https://api-alex-jney.onrender.com" },

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
  }
};

const BLOCKED_HOSTS = [
  /^localhost$/i,
  /^127\./,
  /^0\./,
  /^10\./,
  /^192\.168\./,
  /^172\.(1[6-9]|2[0-9]|3[01])\./,
  /^169\.254\./,
  /^::1$/,
  /^fc00:/i,
  /^fe80:/i
];

const rateBuckets = new Map();

export default {
  async fetch(request, env, ctx) {
    const start = Date.now();
    const id = crypto.randomUUID().slice(0, 8);

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders(env, request) });
    }

    try {
      const ip = request.headers.get("cf-connecting-ip") || "unknown";
      const rl = checkRateLimit(ip, Number(env.RATE_LIMIT_PER_MIN) || 120);
      if (!rl.ok) {
        log(id, "RATE_LIMIT", ip, 429, Date.now() - start);
        return json({ error: "Too Many Requests", retryAfter: rl.retryAfter }, 429, env, request);
      }

      const url = new URL(request.url);
      const parts = url.pathname.split("/").filter(Boolean);

      if (url.pathname.includes("..")) {
        log(id, "TRAVERSAL", ip, 400, Date.now() - start);
        return json({ error: "Bad Request" }, 400, env, request);
      }

      if (parts.length === 0) {
        log(id, "INDEX", ip, 200, Date.now() - start);
        return json({
          service: "ALXMOVIES Proxy",
          status: "online",
          version: "1.0.0",
          routes: Object.keys(ORIGINS)
        }, 200, env, request);
      }

      const prefix = parts[0];
      const config = ORIGINS[prefix];
      if (!config) {
        log(id, "NOT_FOUND:" + prefix, ip, 404, Date.now() - start);
        return json({ error: 'Prefixo "' + prefix + '" nao configurado' }, 404, env, request);
      }

      const allowed = config.methods || ["GET", "POST", "PUT", "DELETE", "HEAD"];
      if (!allowed.includes(request.method)) {
        log(id, "METHOD:" + request.method, ip, 405, Date.now() - start);
        return json({ error: "Method Not Allowed" }, 405, env, request);
      }

      const maxBody = Number(env.MAX_BODY_BYTES) || 1048576;
      const contentLength = Number(request.headers.get("content-length") || 0);
      if (contentLength > maxBody) {
        log(id, "BODY_TOO_LARGE", ip, 413, Date.now() - start);
        return json({ error: "Payload Too Large" }, 413, env, request);
      }

      let targetUrl;
      if (config.exact) {
        targetUrl = new URL(config.target + url.search);
      } else {
        const rest = "/" + parts.slice(1).join("/");
        targetUrl = new URL(rest + url.search, config.target);
      }

      if (isBlockedHost(targetUrl.hostname)) {
        log(id, "SSRF_BLOCK", ip, 403, Date.now() - start);
        return json({ error: "Forbidden" }, 403, env, request);
      }

      const headers = new Headers(request.headers);
      ["host", "cf-connecting-ip", "cf-ray", "cf-worker", "cf-ipcountry",
       "x-forwarded-for", "x-forwarded-proto", "x-real-ip"].forEach(function (h) {
        headers.delete(h);
      });
      headers.set("x-proxy-by", "alx-proxy/1.0");

      if (config.headers) {
        for (const [k, v] of Object.entries(config.headers)) {
          const resolved = (typeof v === "string" && v.startsWith("env:"))
            ? env[v.slice(4)]
            : v;
          if (resolved) headers.set(k, resolved);
        }
      }

      const timeoutMs = Number(env.UPSTREAM_TIMEOUT_MS) || 25000;
      const controller = new AbortController();
      const timeoutId = setTimeout(function () { controller.abort(); }, timeoutMs);

      const proxyReq = new Request(targetUrl.toString(), {
        method: request.method,
        headers: headers,
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
      const ch = corsHeaders(env, request);
      for (const [k, v] of Object.entries(ch)) {
        newHeaders.set(k, v);
      }
      newHeaders.set("x-content-type-options", "nosniff");
      newHeaders.set("referrer-policy", "no-referrer");

      log(id, prefix, ip, response.status, Date.now() - start);
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
        env,
        request
      );
    }
  }
};

function corsHeaders(env, request) {
  const allowed = (env.ALLOWED_ORIGINS || "").split(",").map(function (s) { return s.trim(); }).filter(Boolean);
  const origin = request && request.headers ? (request.headers.get("origin") || "") : "";
  let allowOrigin;
  if (allowed.length === 0) {
    allowOrigin = "*";
  } else if (allowed.includes(origin)) {
    allowOrigin = origin;
  } else {
    allowOrigin = allowed[0];
  }
  return {
    "Access-Control-Allow-Origin": allowOrigin,
    "Access-Control-Allow-Methods": "GET,POST,PUT,DELETE,HEAD,OPTIONS",
    "Access-Control-Allow-Headers": "*",
    "Access-Control-Max-Age": "86400",
    "Vary": "Origin"
  };
}

function json(obj, status, env, request) {
  const base = { "content-type": "application/json; charset=utf-8" };
  const ch = corsHeaders(env, request);
  const merged = Object.assign(base, ch);
  return new Response(JSON.stringify(obj, null, 2), {
    status: status,
    headers: merged
  });
}

function isBlockedHost(hostname) {
  return BLOCKED_HOSTS.some(function (re) { return re.test(hostname); });
}

function checkRateLimit(ip, maxPerMin) {
  const now = Date.now();
  const windowMs = 60000;
  let bucket = rateBuckets.get(ip);

  if (!bucket || now - bucket.start > windowMs) {
    bucket = { start: now, count: 0 };
    rateBuckets.set(ip, bucket);
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

function log(id, route, ip, status, ms) {
  const shortIp = ip === "unknown" ? ip : ip.split(".").slice(0, 2).join(".") + ".x.x";
  console.log(JSON.stringify({
    t: new Date().toISOString(),
    id: id,
    route: route,
    ip: shortIp,
    status: status,
    ms: ms
  }));
}
