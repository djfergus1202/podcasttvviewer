const express = require("express");
const Parser = require("rss-parser");
const helmet = require("helmet");
const compression = require("compression");
const crypto = require("crypto");
const net = require("net");

/**
 * RSS → “TV Channel” HTML
 * - Works with (almost) any RSS feed that contains audio/video enclosures or media:content
 * - Supports runtime RSS selection via ?rss=ENCODED_URL (optional)
 * - Includes basic SSRF guardrails (blocks obvious localhost/private IP literals)
 * - Includes caching per RSS URL to reduce rate-limits / speed up
 */

const app = express();

app.disable("x-powered-by");
app.use(compression());
app.use(
  helmet({
    // Simple single-page HTML. If you add external scripts, configure CSP properly.
    contentSecurityPolicy: false,
  })
);

// RSS parser with common podcast extensions
const parser = new Parser({
  customFields: {
    item: [
      ["media:content", "mediaContent", { keepArray: true }],
      ["media:thumbnail", "mediaThumbnail", { keepArray: true }],
      ["itunes:image", "itunesImage"],
      ["itunes:duration", "duration"],
    ],
  },
});

// -------------------- Configuration --------------------
const DEFAULT_RSS_URL = process.env.RSS_URL || "https://anchor.fm/s/your-default-rss-id/podcast/rss";
const EP_LIMIT = Number(process.env.EP_LIMIT || 100);
const CACHE_TTL_MS = Number(process.env.CACHE_TTL_MS || 5 * 60 * 1000);
const PORT = process.env.PORT || 3000;

/**
 * If ALLOW_QUERY_RSS=1, user can override feed via ?rss=...
 * If 0/undefined, the app will only use RSS_URL env var.
 */
const ALLOW_QUERY_RSS = String(process.env.ALLOW_QUERY_RSS || "1") === "1";

/**
 * If you expose this publicly, consider restricting which domains can be requested
 * (e.g., to your own feeds). Provide a comma-separated allowlist:
 *   RSS_DOMAIN_ALLOWLIST=example.com,feeds.example.org
 * If set, ?rss= will be accepted only if hostname ends with one of these values.
 */
const RSS_DOMAIN_ALLOWLIST = (process.env.RSS_DOMAIN_ALLOWLIST || "")
  .split(",")
  .map((s) => s.trim().toLowerCase())
  .filter(Boolean);

// -------------------- Utilities --------------------
function escapeHtml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function stripHtml(str) {
  if (!str) return "";
  return String(str).replace(/<[^>]*>?/gm, "");
}

function safeTruncate(str, n = 320) {
  const s = stripHtml(str).replace(/\s+/g, " ").trim();
  if (!s) return "";
  return s.length > n ? s.slice(0, n).trim() + "…" : s;
}

function normalizeToHttps(url) {
  if (!url) return "";
  // Avoid mixed-content issues if your app is served over HTTPS.
  return url.startsWith("http://") ? url.replace("http://", "https://") : url;
}

function pickImageUrl(item) {
  const tn =
    item.mediaThumbnail &&
    item.mediaThumbnail[0] &&
    item.mediaThumbnail[0].$ &&
    item.mediaThumbnail[0].$.url;

  if (tn) return normalizeToHttps(tn);

  if (item.itunesImage) {
    if (typeof item.itunesImage === "string") return normalizeToHttps(item.itunesImage);
    if (item.itunesImage.href) return normalizeToHttps(item.itunesImage.href);
    if (item.itunesImage.url) return normalizeToHttps(item.itunesImage.url);
  }
  return "";
}

function pickMedia(item) {
  if (item.enclosure && item.enclosure.url) {
    return { url: item.enclosure.url, type: item.enclosure.type || "" };
  }
  const mc = item.mediaContent && item.mediaContent[0];
  if (mc && mc.$ && mc.$.url) {
    return { url: mc.$.url, type: mc.$.type || "" };
  }
  return { url: item.link || "", type: "" };
}

function inferKind(mediaUrl, mediaType) {
  const u = (mediaUrl || "").toLowerCase();
  const t = (mediaType || "").toLowerCase();

  if (t.startsWith("video/")) return "video";
  if (t.startsWith("audio/")) return "audio";

  if (u.includes(".m3u8")) return "video"; // HLS
  if (u.match(/\.(mp4|webm|mov)(\?|#|$)/)) return "video";
  if (u.match(/\.(mp3|m4a|aac|ogg|wav)(\?|#|$)/)) return "audio";

  // Podcast feeds are typically audio.
  return "audio";
}

function stableHash(input) {
  return crypto.createHash("sha256").update(String(input)).digest("hex").slice(0, 24);
}

function isPrivateIpLiteral(hostname) {
  // Only checks literal IPs. Does not resolve DNS -> IP (still helpful guardrails).
  if (!hostname) return false;
  const ipVersion = net.isIP(hostname);
  if (!ipVersion) return false;

  // IPv4 private ranges
  if (ipVersion === 4) {
    const parts = hostname.split(".").map((p) => parseInt(p, 10));
    const [a, b] = parts;

    // 10.0.0.0/8
    if (a === 10) return true;
    // 172.16.0.0/12
    if (a === 172 && b >= 16 && b <= 31) return true;
    // 192.168.0.0/16
    if (a === 192 && b === 168) return true;
    // 127.0.0.0/8 loopback
    if (a === 127) return true;
    // 169.254.0.0/16 link-local
    if (a === 169 && b === 254) return true;
    // 0.0.0.0/8 and 100.64.0.0/10 (CGNAT) – treat as non-public
    if (a === 0) return true;
    if (a === 100 && b >= 64 && b <= 127) return true;

    return false;
  }

  // IPv6: block loopback, link-local, unique-local (fc00::/7)
  const h = hostname.toLowerCase();
  if (h === "::1") return true;
  if (h.startsWith("fe80:")) return true; // link-local
  if (h.startsWith("fc") || h.startsWith("fd")) return true; // unique local

  return false;
}

function passesAllowlist(hostname) {
  if (!RSS_DOMAIN_ALLOWLIST.length) return true;
  const h = (hostname || "").toLowerCase();
  return RSS_DOMAIN_ALLOWLIST.some((allowed) => h === allowed || h.endsWith("." + allowed));
}

function validateRssUrl(inputUrl) {
  let url;
  try {
    url = new URL(inputUrl);
  } catch {
    return { ok: false, reason: "Invalid URL" };
  }

  if (!["http:", "https:"].includes(url.protocol)) {
    return { ok: false, reason: "Only http/https URLs are allowed" };
  }

  const hostname = url.hostname;

  // Block obvious localhost forms
  const h = hostname.toLowerCase();
  if (h === "localhost" || h.endsWith(".localhost") || h.endsWith(".local")) {
    return { ok: false, reason: "Localhost/local domains are not allowed" };
  }

  // Block literal private IPs
  if (isPrivateIpLiteral(hostname)) {
    return { ok: false, reason: "Private IP addresses are not allowed" };
  }

  // Optional allowlist
  if (!passesAllowlist(hostname)) {
    return { ok: false, reason: "Hostname not in allowlist" };
  }

  return { ok: true, url: url.toString() };
}

// -------------------- Caching --------------------
const cache = new Map(); // key -> { at, feed }

async function getFeed(rssUrl, force = false) {
  const key = stableHash(rssUrl);
  const now = Date.now();
  const existing = cache.get(key);

  if (!force && existing && existing.feed && now - existing.at < CACHE_TTL_MS) {
    return existing.feed;
  }

  const feed = await parser.parseURL(rssUrl);
  cache.set(key, { at: now, feed });
  return feed;
}

// -------------------- Routes --------------------
app.get("/health", (req, res) => res.status(200).send("ok"));

/**
 * Returns normalized episode metadata for any RSS feed.
 * Usage:
 *   /api/episodes.json
 *   /api/episodes.json?rss=https%3A%2F%2Fexample.com%2Ffeed.xml
 */
app.get("/api/episodes.json", async (req, res) => {
  try {
    let rssUrl = DEFAULT_RSS_URL;

    if (ALLOW_QUERY_RSS && req.query.rss) {
      const v = validateRssUrl(String(req.query.rss));
      if (!v.ok) return res.status(400).json({ error: v.reason });
      rssUrl = v.url;
    }

    const force = req.query.refresh === "1";
    const feed = await getFeed(rssUrl, force);

    const episodes = (feed.items || [])
      .slice(0, EP_LIMIT)
      .map((it, idx) => {
        const media = pickMedia(it);
        const mediaUrl = media.url || "";
        const kind = inferKind(mediaUrl, media.type);

        const dateStr = it.isoDate
          ? new Date(it.isoDate).toISOString()
          : it.pubDate || "";

        return {
          id: idx,
          title: it.title || "Untitled Episode",
          date: dateStr,
          description: safeTruncate(it.contentSnippet || it.content || "", 1000),
          mediaUrl,
          mediaType: media.type || "",
          kind, // audio|video
          imageUrl: pickImageUrl(it),
          duration: it.duration || "",
          link: it.link || "",
        };
      })
      .filter((e) => !!e.mediaUrl);

    res.setHeader("Cache-Control", "public, max-age=60");
    res.json({
      feed: {
        title: feed.title || "",
        link: feed.link || "",
        description: stripHtml(feed.description || ""),
        rssUrl,
      },
      episodes,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error fetching/parsing RSS feed." });
  }
});

/**
 * TV UI:
 *   /
 *   /?rss=https%3A%2F%2Fexample.com%2Ffeed.xml
 */
app.get("/", async (req, res) => {
  try {
    let rssUrl = DEFAULT_RSS_URL;

    if (ALLOW_QUERY_RSS && req.query.rss) {
      const v = validateRssUrl(String(req.query.rss));
      if (!v.ok) return res.status(400).send("Bad rss parameter: " + escapeHtml(v.reason));
      rssUrl = v.url;
    }

    const force = req.query.refresh === "1";
    const feed = await getFeed(rssUrl, force);

    const channelTitle = feed?.title || "TV Channel";

    const episodes = (feed.items || [])
      .slice(0, EP_LIMIT)
      .map((it, idx) => {
        const media = pickMedia(it);
        const mediaUrl = media.url || "";
        const kind = inferKind(mediaUrl, media.type);

        const dateStr = it.isoDate
          ? new Date(it.isoDate).toLocaleDateString(undefined, { year: "numeric", month: "short", day: "2-digit" })
          : (it.pubDate || "");

        return {
          id: idx,
          title: it.title || "Untitled Episode",
          date: dateStr,
          description: safeTruncate(it.contentSnippet || it.content || "", 340),
          mediaUrl,
          mediaType: media.type || "",
          kind,
          imageUrl: pickImageUrl(it),
          duration: it.duration || "",
        };
      })
      .filter((e) => !!e.mediaUrl);

    const html = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>${escapeHtml(channelTitle)}</title>
  <style>
    :root { color-scheme: dark; --highlight:#4b7cff; --bg:#0b0b0f; --surface:#141421; --text:#fff; --muted:#a6a6b3; }
    body { margin:0; font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; background:var(--bg); color:var(--text); overflow:hidden; }
    header { padding:18px 24px; border-bottom:1px solid #222; display:flex; justify-content:space-between; align-items:center; background:#000; height:72px; box-sizing:border-box; }
    header h1 { margin:0; font-size:22px; font-weight:800; letter-spacing:-0.3px; }
    header .hint { opacity:.75; font-size:12px; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; display:none; }
    @media (min-width: 900px) { header .hint { display:block; } }

    .wrap { height: calc(100vh - 72px); display:grid; grid-template-columns: 1fr; gap:0; }
    @media (min-width: 1000px) { .wrap { grid-template-columns: 2fr 1fr; padding:14px; gap:14px; } }

    .player { background:#000; position:relative; display:flex; flex-direction:column; overflow:hidden; }
    @media (min-width: 1000px) { .player { border-radius:16px; border:1px solid #222; } }

    .stage { flex:1; position:relative; display:flex; align-items:center; justify-content:center; background:#000; }
    .poster { position:absolute; inset:0; background-size:cover; background-position:center; opacity:.25; }
    .posterOverlay { position:absolute; inset:0; background: linear-gradient(180deg, rgba(0,0,0,.55), rgba(0,0,0,.85)); }

    .artWrap { position:absolute; inset:0; display:flex; align-items:center; justify-content:center; pointer-events:none; }
    .art { width:min(56vh, 70vw); aspect-ratio:1/1; border-radius:18px; box-shadow:0 20px 60px rgba(0,0,0,.6); background:#111; overflow:hidden; border:1px solid #222; }
    .art img { width:100%; height:100%; object-fit:cover; display:block; }

    video, audio { width:100%; outline:none; }
    video { height:100%; }

    .controlsRow { position:absolute; left:18px; right:18px; bottom:18px; z-index:4; }
    .meta { padding:18px; background:var(--surface); border-top:1px solid #222; min-height:120px; }
    .meta .title { font-size:20px; font-weight:800; margin:0 0 8px 0; }
    .meta .sub { font-size:14px; color:var(--muted); margin:0; line-height:1.45; }
    .meta .tiny { margin-top:10px; font-size:12px; color:#7f7f8d; }

    .list { background:var(--bg); overflow-y:auto; border-top:1px solid #222; }
    @media (min-width: 1000px) { .list { border:1px solid #222; border-radius:16px; } }

    .ep { display:flex; gap:14px; padding:14px; border-bottom:1px solid #1c1c1c; cursor:pointer; background:transparent; border:none; width:100%; color:inherit; text-align:left; }
    .ep:hover { background:#13131a; }
    .ep:focus { outline:3px solid rgba(75,124,255,.55); outline-offset:-3px; }
    .ep.active { background: var(--surface); border-left: 6px solid var(--highlight); padding-left:8px; }

    .thumb { width:120px; height:68px; background:#111; border-radius:10px; flex-shrink:0; overflow:hidden; border:1px solid #222; }
    .thumb img { width:100%; height:100%; object-fit:cover; }
    .thumb .placeholder { width:100%; height:100%; display:flex; align-items:center; justify-content:center; color:#333; font-size:20px; font-weight:800; background:#111; }

    .info { flex:1; min-width:0; }
    .t { font-size:15px; font-weight:800; margin:0 0 6px 0; line-height:1.2; overflow:hidden; text-overflow:ellipsis; display:-webkit-box; -webkit-line-clamp:2; -webkit-box-orient:vertical; }
    .d { font-size:12px; color:#8f8f9c; display:flex; gap:10px; flex-wrap:wrap; }
    .pill { font-size:11px; padding:2px 8px; border:1px solid #2a2a35; border-radius:999px; color:#bdbdc9; }

    .bar { padding:10px 14px; background:#0f0f16; border-bottom:1px solid #1f1f2a; font-size:12px; color:#9a9aac; display:flex; gap:10px; flex-wrap:wrap; }
    .bar code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; color:#c7c7d6; }

    ::-webkit-scrollbar { width:10px; }
    ::-webkit-scrollbar-track { background:#0b0b0f; }
    ::-webkit-scrollbar-thumb { background:#333; border-radius:999px; }
  </style>
</head>
<body>
  <header>
    <h1>${escapeHtml(channelTitle)}</h1>
    <div class="hint">REMOTE/KEYS: ↑↓ Select • ENTER Play • SPACE Pause/Play • F Fullscreen (video)</div>
  </header>

  <div class="bar">
    <span>Feed:</span>
    <code>${escapeHtml(rssUrl)}</code>
    <span>•</span>
    <span>Refresh: add <code>?refresh=1</code></span>
    ${ALLOW_QUERY_RSS ? `<span>•</span><span>Try another feed: <code>?rss=https%3A%2F%2Fexample.com%2Ffeed.xml</code></span>` : ""}
  </div>

  <div class="wrap">
    <section class="player">
      <div class="stage">
        <div id="posterBg" class="poster"></div>
        <div class="posterOverlay"></div>

        <div class="artWrap" id="artWrap" aria-hidden="true">
          <div class="art"><img id="artImg" alt="" /></div>
        </div>

        <video id="videoEl" controls playsinline style="display:none;"></video>

        <div class="controlsRow" id="audioRow" style="display:none;">
          <audio id="audioEl" controls></audio>
        </div>
      </div>

      <div class="meta">
        <h2 id="epTitle" class="title">Select an episode…</h2>
        <p id="epDesc" class="sub"></p>
        <div class="tiny" id="epMeta"></div>
      </div>
    </section>

    <section class="list" id="playlist" tabindex="0" aria-label="Episode list"></section>
  </div>

  <script>
    const episodes = ${JSON.stringify(episodes)};

    const playlist = document.getElementById('playlist');
    const epTitle = document.getElementById('epTitle');
    const epDesc = document.getElementById('epDesc');
    const epMeta = document.getElementById('epMeta');

    const videoEl = document.getElementById('videoEl');
    const audioEl = document.getElementById('audioEl');
    const audioRow = document.getElementById('audioRow');

    const posterBg = document.getElementById('posterBg');
    const artImg = document.getElementById('artImg');
    const artWrap = document.getElementById('artWrap');

    let currentIndex = 0;

    function esc(s) {
      if (!s) return '';
      return String(s)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
    }

    function setActive(i) {
      document.querySelectorAll('.ep').forEach(el => el.classList.remove('active'));
      const btn = document.getElementById('ep-' + i);
      if (btn) btn.classList.add('active');
    }

    function renderPlaylist() {
      playlist.innerHTML = episodes.map((ep, i) => {
        const thumb = ep.imageUrl
          ? '<img src="' + esc(ep.imageUrl) + '" loading="lazy" alt=""/>'
          : '<div class="placeholder">' + (episodes.length - i) + '</div>';

        const dur = ep.duration ? '<span class="pill">' + esc(ep.duration) + '</span>' : '';
        const kind = '<span class="pill">' + (ep.kind === 'video' ? 'Video' : 'Audio') + '</span>';

        return (
          '<button class="ep" id="ep-' + i + '" type="button" onclick="playIndex(' + i + ')">' +
            '<div class="thumb">' + thumb + '</div>' +
            '<div class="info">' +
              '<div class="t">' + esc(ep.title) + '</div>' +
              '<div class="d"><span>' + esc(ep.date || '') + '</span>' + kind + dur + '</div>' +
            '</div>' +
          '</button>'
        );
      }).join('');
    }

    function showArtwork(url) {
      const u = url || '';
      posterBg.style.backgroundImage = u ? ('url("' + esc(u) + '")') : 'none';
      artImg.src = u || '';
      artWrap.style.display = u ? 'flex' : 'none';
    }

    function stopAll() {
      try { videoEl.pause(); } catch(e) {}
      try { audioEl.pause(); } catch(e) {}
      videoEl.removeAttribute('src');
      audioEl.removeAttribute('src');
      videoEl.load();
      audioEl.load();
    }

    function playIndex(i) {
      if (i < 0 || i >= episodes.length) return;

      currentIndex = i;
      const ep = episodes[i];

      setActive(i);

      const btn = document.getElementById('ep-' + i);
      if (btn) {
        btn.focus();
        btn.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
      }

      epTitle.textContent = ep.title || 'Untitled Episode';
      epDesc.textContent = ep.description || '';
      epMeta.textContent = [ep.date, ep.mediaType].filter(Boolean).join(' • ');

      showArtwork(ep.imageUrl);

      stopAll();

      if (ep.kind === 'video') {
        audioRow.style.display = 'none';
        audioEl.style.display = 'none';
        videoEl.style.display = 'block';
        videoEl.src = ep.mediaUrl;
        videoEl.poster = ep.imageUrl || "";
        videoEl.play().catch(() => {});
      } else {
        videoEl.style.display = 'none';
        audioRow.style.display = 'block';
        audioEl.style.display = 'block';
        audioEl.src = ep.mediaUrl;
        audioEl.play().catch(() => {});
      }
    }

    // Remote/keyboard controls
    document.addEventListener('keydown', (e) => {
      const code = e.code;

      if (code === 'ArrowDown') {
        e.preventDefault();
        const next = Math.min(currentIndex + 1, episodes.length - 1);
        currentIndex = next;
        const n = document.getElementById('ep-' + next);
        if (n) { n.focus(); n.scrollIntoView({ behavior: 'smooth', block: 'nearest' }); }
        return;
      }

      if (code === 'ArrowUp') {
        e.preventDefault();
        const prev = Math.max(currentIndex - 1, 0);
        currentIndex = prev;
        const p = document.getElementById('ep-' + prev);
        if (p) { p.focus(); p.scrollIntoView({ behavior: 'smooth', block: 'nearest' }); }
        return;
      }

      if (code === 'Enter') {
        e.preventDefault();
        playIndex(currentIndex);
        return;
      }

      if (code === 'Space') {
        e.preventDefault();
        if (videoEl.style.display === 'block') {
          videoEl.paused ? videoEl.play().catch(()=>{}) : videoEl.pause();
        } else {
          audioEl.paused ? audioEl.play().catch(()=>{}) : audioEl.pause();
        }
        return;
      }

      if (code === 'KeyF') {
        if (videoEl.style.display === 'block') {
          if (document.fullscreenElement) document.exitFullscreen();
          else videoEl.requestFullscreen?.();
        }
        return;
      }
    });

    videoEl.addEventListener('ended', () => playIndex(Math.min(currentIndex + 1, episodes.length - 1)));
    audioEl.addEventListener('ended', () => playIndex(Math.min(currentIndex + 1, episodes.length - 1)));

    renderPlaylist();

    if (episodes.length > 0) {
      // Highlight first episode without autoplay
      setActive(0);
      const ep = episodes[0];
      epTitle.textContent = ep.title || 'Untitled Episode';
      epDesc.textContent = ep.description || '';
      epMeta.textContent = [ep.date, ep.mediaType].filter(Boolean).join(' • ');
      showArtwork(ep.imageUrl);
    }
  </script>
</body>
</html>`;

    res.setHeader("Content-Type", "text/html; charset=utf-8");
    res.setHeader("Cache-Control", "public, max-age=60");
    res.send(html);
  } catch (err) {
    console.error(err);
    res.status(500).send("Error fetching/parsing RSS feed.");
  }
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Default RSS: ${DEFAULT_RSS_URL}`);
  console.log(`ALLOW_QUERY_RSS: ${ALLOW_QUERY_RSS}`);
});
