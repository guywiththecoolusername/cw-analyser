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
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
    };

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