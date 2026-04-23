// Cloudflare Worker — ProxyLink Backend
//
// Required environment variables (set in Cloudflare dashboard):
//   YAML_GIST_URL  (Secret)  — GitHub Gist raw URL of your YAML subscription file
//   CONFIG_URL     (Plain)   — GitHub Pages URL of config.json, e.g.
//                              https://yourname.github.io/yourrepo/config.json
//
// Required KV namespace binding:
//   TOKENS  — stores single-use token state

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    const cors = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
    };

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: cors });
    }

    // POST /verify — validate password, issue single-use token
    if (url.pathname === "/verify" && request.method === "POST") {
      let password;
      try {
        ({ password } = await request.json());
      } catch {
        return Response.json({ error: "Bad request" }, { status: 400, headers: cors });
      }

      if (!password) {
        return Response.json({ error: "Missing password" }, { status: 400, headers: cors });
      }

      // Fetch password hash from GitHub Pages config.json (cached 60s)
      let config;
      try {
        const configResp = await fetch(env.CONFIG_URL, {
          cf: { cacheTtl: 60, cacheEverything: true },
        });
        if (!configResp.ok) throw new Error("config fetch failed");
        config = await configResp.json();
      } catch {
        return Response.json({ error: "Server config error" }, { status: 502, headers: cors });
      }

      // SHA-256 the submitted password and compare
      const encoded = new TextEncoder().encode(password);
      const hashBuf = await crypto.subtle.digest("SHA-256", encoded);
      const hashHex = Array.from(new Uint8Array(hashBuf))
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");

      if (hashHex !== config.passwordHash) {
        return Response.json({ error: "Wrong password" }, { status: 403, headers: cors });
      }

      // Generate single-use token (valid 5 minutes)
      const token = crypto.randomUUID();
      await env.TOKENS.put(token, "unused", { expirationTtl: 300 });

      const subUrl = `${url.origin}/sub/${token}`;
      return Response.json({ url: subUrl }, { headers: cors });
    }

    // GET /sub/<token> — serve YAML once, then invalidate token
    if (url.pathname.startsWith("/sub/")) {
      const token = url.pathname.slice(5);
      if (!token) return new Response("Missing token", { status: 400 });

      const status = await env.TOKENS.get(token);

      if (status === null) {
        return new Response("链接已失效或不存在", { status: 403 });
      }
      if (status === "used") {
        return new Response("链接已使用，请重新获取新链接", { status: 403 });
      }

      // Mark used before fetching (fail-safe: even if gist fetch fails, token is spent)
      await env.TOKENS.put(token, "used", { expirationTtl: 300 });

      let yaml;
      try {
        const gistResp = await fetch(env.YAML_GIST_URL);
        if (!gistResp.ok) throw new Error("gist fetch failed");
        yaml = await gistResp.text();
      } catch {
        return new Response("无法获取订阅文件，请联系管理员", { status: 502 });
      }

      return new Response(yaml, {
        headers: {
          "Content-Type": "text/plain; charset=utf-8",
        },
      });
    }

    return new Response("Not Found", { status: 404 });
  },
};
