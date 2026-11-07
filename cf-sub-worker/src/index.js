/**
 * Cloudflare Worker for Disaster Recovery Subscription Delivery & Fallback
 * Primary Origin: Configured via env.ORIGIN_URL or default origin
 * Fallback: Cloudflare KV Cached Profiles
 */

const DEFAULT_ORIGIN = "https://origin.your-domain.com";
const FETCH_TIMEOUT_MS = 5000;

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const originUrl = env.ORIGIN_URL || DEFAULT_ORIGIN;

    // Health / Status endpoint
    if (url.pathname === "/health" || url.pathname === "/status") {
      let vpsAlive = false;
      let vpsDetail = "unreachable";
      try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 3500);
        const res = await fetch(`${originUrl}/status`, {
          signal: controller.signal,
          headers: { "User-Agent": "CF-Worker-Health" }
        });
        clearTimeout(timeoutId);
        vpsAlive = res.ok;
        vpsDetail = `HTTP ${res.status}`;
      } catch (err) {
        vpsDetail = err.message;
      }

      return new Response(JSON.stringify({
        status: "ok",
        service: "Cloudflare Disaster Recovery Sub Server",
        timestamp: new Date().toISOString(),
        primary_vps: {
          url: originUrl,
          alive: vpsAlive,
          detail: vpsDetail
        }
      }, null, 2), {
        headers: {
          "Content-Type": "application/json; charset=utf-8",
          "Access-Control-Allow-Origin": "*"
        }
      });
    }

    // Subscription endpoint: /sub or /sub/
    if (url.pathname === "/sub" || url.pathname === "/sub/") {
      const token = url.searchParams.get("token") || "";
      if (!token) {
        return new Response("Missing token parameter. Example: /sub?token=...", {
          status: 400,
          headers: { "Content-Type": "text/plain; charset=utf-8" }
        });
      }

      // 1. Try to fetch from Primary VPS with strict timeout
      try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);

        const vpsUrl = `${originUrl}/sub?${url.searchParams.toString()}`;
        const vpsResponse = await fetch(vpsUrl, {
          method: "GET",
          headers: {
            "User-Agent": request.headers.get("User-Agent") || "CF-Worker-Sub",
            "Accept": "*/*"
          },
          signal: controller.signal
        });
        clearTimeout(timeoutId);

        if (vpsResponse.ok) {
          const bodyText = await vpsResponse.text();

          // Asynchronously save to KV cache for disaster recovery
          if (env.SUB_CACHE && bodyText.length > 50) {
            ctx.waitUntil((async () => {
              try {
                const subUserInfo = vpsResponse.headers.get("subscription-userinfo") || "";
                await env.SUB_CACHE.put(`cache_${token}`, JSON.stringify({
                  body: bodyText,
                  userInfo: subUserInfo,
                  updatedAt: new Date().toISOString()
                }), { expirationTtl: 86400 * 30 }); // 30 days
              } catch (e) {
                console.error("KV cache write failed:", e);
              }
            })());
          }

          // Return fresh response from VPS with clean headers
          const responseHeaders = new Headers();
          responseHeaders.set("Content-Type", "text/plain; charset=utf-8");
          responseHeaders.set("Content-Disposition", 'attachment; filename="subscription.txt"');
          responseHeaders.set("X-Sub-Source", "VPS-Primary-Live");
          responseHeaders.set("X-Failover-Available", "true");
          
          const userInfo = vpsResponse.headers.get("subscription-userinfo");
          if (userInfo) responseHeaders.set("Subscription-Userinfo", userInfo);
          const updateInterval = vpsResponse.headers.get("profile-update-interval");
          if (updateInterval) responseHeaders.set("Profile-Update-Interval", updateInterval);

          return new Response(bodyText, {
            status: 200,
            headers: responseHeaders
          });
        }
      } catch (vpsErr) {
        console.warn("Primary VPS sub fetch failed or timed out:", vpsErr);
      }

      // 2. Primary VPS failed or timed out -> Fallback to Cloudflare KV Cache
      if (env.SUB_CACHE) {
        try {
          const cachedJson = await env.SUB_CACHE.get(`cache_${token}`);
          if (cachedJson) {
            const cachedData = JSON.parse(cachedJson);
            const headers = new Headers();
            headers.set("Content-Type", "text/plain; charset=utf-8");
            headers.set("Content-Disposition", 'attachment; filename="subscription.txt"');
            headers.set("X-Sub-Source", "Cloudflare-KV-Disaster-Recovery");
            headers.set("X-Cached-At", cachedData.updatedAt || "");
            if (cachedData.userInfo) {
              headers.set("Subscription-Userinfo", cachedData.userInfo);
            }
            return new Response(cachedData.body, {
              status: 200,
              headers
            });
          }
        } catch (kvErr) {
          console.error("KV cache read failed:", kvErr);
        }
      }

      // 3. Fallback: Both VPS and KV missed
      return new Response("Error: Subscription service unavailable and no cached profiles found", {
        status: 503,
        headers: { "Content-Type": "text/plain; charset=utf-8" }
      });
    }

    // Default route
    return new Response("Cloudflare Subscription Disaster Recovery Node active. Query /sub?token=...", {
      status: 200,
      headers: { "Content-Type": "text/plain; charset=utf-8" }
    });
  }
};
