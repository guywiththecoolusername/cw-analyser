// cw-analyse share worker
// KV namespace: SHARE_DB (bind in Cloudflare dashboard)
// Auto-expires entries after 7 days via KV TTL

export default {
  async fetch(request, env) {
    const { SHARE_DB } = env;
    const method = request.method;
    const url    = new URL(request.url);

    const cors = {
      "Access-Control-Allow-Origin":  "*",
      "Access-Control-Allow-Methods": "GET, POST, PATCH, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
    };
    
    if (url.pathname === '/mal-token' && request.method === 'POST') {
      return handleMalToken(request);
    }

    if (url.pathname === '/mal-proxy') {
      return handleMalProxy(request);
    }

    if (method === "OPTIONS") return new Response(null, { headers: cors });

    // ── POST /share — store list, return short ID ─────────────────────
    if (method === "POST" && url.pathname === "/share") {
      let body;
      try { body = await request.text(); }
      catch { return json({ error: "Invalid body" }, 400, cors); }

      // Sanity check size — KV values max 25MB, we reject above 5MB
      if (body.length > 5 * 1024 * 1024) {
        return json({ error: "List too large (max 5MB)" }, 413, cors);
      }

      // Check KV is actually available
      if (!SHARE_DB) return json({ error: "Storage unavailable" }, 503, cors);

      // Generate a short random ID — 8 chars, url-safe
      const id = Array.from(crypto.getRandomValues(new Uint8Array(6)))
        .map(b => b.toString(36).padStart(2, '0')).join('').slice(0, 8);

      // Store with 7-day TTL (KV expirationTtl is in seconds)
      try {
        await SHARE_DB.put(`share:${id}`, body, { expirationTtl: 7 * 24 * 60 * 60 });
      } catch (e) {
        return json({ error: "Storage write failed: " + e.message }, 503, cors);
      }

      return json({ id }, 200, cors);
    }

    // ── GET /share/{id} — retrieve list ───────────────────────────────
    if (method === "GET" && url.pathname.startsWith("/share/")) {
      const id = url.pathname.slice(7); // strip "/share/"
      if (!id || id.length > 20) return json({ error: "Invalid ID" }, 400, cors);

      if (!SHARE_DB) return json({ error: "Storage unavailable" }, 503, cors);

      let data;
      try { data = await SHARE_DB.get(`share:${id}`); }
      catch (e) { return json({ error: "Storage read failed" }, 503, cors); }

      if (!data) return json({ error: "Not found or expired" }, 404, cors);

      return new Response(data, {
        headers: { ...cors, "Content-Type": "application/json" },
      });
    }

    return new Response("Not found", { status: 404, headers: cors });
  },
};

function json(obj, status, cors) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { ...cors, "Content-Type": "application/json" },
  });
}

async function handleMalToken(request) {
  const ALLOWED_ORIGINS = [
    'https://cw-analyser.vercel.app',       // <-- replace with your actual site origin(s)
    'http://localhost:8000',             // local dev
    'http://127.0.0.1:8000',
  ];

  const origin = request.headers.get('Origin') ?? '';
  const corsOrigin = ALLOWED_ORIGINS.includes(origin) ? origin : ALLOWED_ORIGINS[0];

  const corsHeaders = {
    'Access-Control-Allow-Origin': corsOrigin,
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Vary': 'Origin',
  };

  // Handle CORS preflight
  if (request.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: corsHeaders });
  }

  try {
    const { client_id, code, code_verifier, redirect_uri } = await request.json();
    if (!client_id || !code || !code_verifier || !redirect_uri) {
      return new Response(JSON.stringify({ error: 'Missing parameters' }), {
        status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    // Exchange code for token — this is what the browser can't do itself
    const body = new URLSearchParams({
      client_id,
      code,
      code_verifier,
      grant_type: 'authorization_code',
      redirect_uri,
    });

    const malRes = await fetch('https://myanimelist.net/v1/oauth2/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body,
    });

    const data = await malRes.json();

    if (!malRes.ok) {
      return new Response(JSON.stringify({ error: data.error ?? 'MAL token error', detail: data.message }), {
        status: malRes.status, headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    // Only forward what the browser needs — don't leak refresh token if you prefer
    return new Response(JSON.stringify({
      access_token: data.access_token,
      refresh_token: data.refresh_token,
      expires_in: data.expires_in,
    }), {
      status: 200,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });

  } catch (e) {
    return new Response(JSON.stringify({ error: 'Worker error', detail: e.message }), {
      status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  }
}


async function handleMalProxy(request) {
  const origin = request.headers.get('Origin') ?? '';

  const corsHeaders = {
    'Access-Control-Allow-Origin': origin,
    'Access-Control-Allow-Methods': 'GET, PATCH, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  };

  if (request.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: corsHeaders });
  }

  const token = request.headers.get('Authorization');
  const url = new URL(request.url);
  const target = url.searchParams.get('url');

  if (!token || !target) {
    return new Response(JSON.stringify({ error: 'Missing token or url' }), {
      status: 400,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }

  const fetchOptions = {
    method: request.method,
    headers: { Authorization: token },
  };

  // Forward body and Content-Type for PATCH/POST requests
  if (request.method === 'PATCH' || request.method === 'POST') {
    fetchOptions.headers['Content-Type'] = request.headers.get('Content-Type') ?? 'application/x-www-form-urlencoded';
    fetchOptions.body = await request.text();
  }

  const malRes = await fetch(target, fetchOptions);

  const data = await malRes.text();

  return new Response(data, {
    status: malRes.status,
    headers: {
      ...corsHeaders,
      'Content-Type': 'application/json'
    }
  });
}