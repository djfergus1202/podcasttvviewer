# RSS → HTML TV Channel (Express)

This project turns **any RSS feed** (podcast or video) into a **TV-friendly “channel” webpage**:
- Full-screen friendly UI (“10-foot UI”)
- Remote/keyboard navigation (↑ ↓, Enter, Space, F fullscreen for video)
- Auto-detects **audio vs video** (MP3 → `<audio>`, MP4/HLS → `<video>`)
- Includes a JSON API endpoint for episode metadata

## Quick start (local)

```bash
npm install
npm start
```

Open:
- `http://localhost:3000/`

## Use any RSS feed

By default, the server uses `RSS_URL` from environment variables.

### Option A — set environment variable (recommended)

Create `.env` (or set in your platform UI):

```bash
RSS_URL="https://example.com/feed.xml"
```

### Option B — pass feed URL at runtime (query parameter)

This is enabled by default (`ALLOW_QUERY_RSS=1`).

Example:

```
http://localhost:3000/?rss=https%3A%2F%2Fexample.com%2Ffeed.xml
```

Force refresh (bypass cache):

```
http://localhost:3000/?rss=...&refresh=1
```

## JSON API

- `GET /api/episodes.json`
- `GET /api/episodes.json?rss=ENCODED_URL`
- Add `&refresh=1` to bypass cache

## Environment variables

| Variable | Default | Purpose |
|---|---:|---|
| `RSS_URL` | (sample anchor URL) | Default feed when no `?rss=` is used |
| `ALLOW_QUERY_RSS` | `1` | Allow selecting feed via `?rss=` query parameter |
| `RSS_DOMAIN_ALLOWLIST` | empty | Comma-separated domain allowlist for `?rss=` (recommended if public) |
| `EP_LIMIT` | `100` | Max episodes displayed |
| `CACHE_TTL_MS` | `300000` | Feed cache time (ms) |
| `PORT` | `3000` | Server port |

## Security note (important if public)

Allowing arbitrary `?rss=` means your server will fetch URLs you provide. This repo includes **basic SSRF guardrails**
(blocks obvious localhost/private IP literals), but DNS-based SSRF can still exist.

If you deploy publicly:
1. Prefer `ALLOW_QUERY_RSS=0`, and set only `RSS_URL`.
2. Or set `RSS_DOMAIN_ALLOWLIST=yourdomain.com,spotify.com,apple.com,...` to restrict allowed hosts.
3. Consider adding network-level egress restrictions in your hosting provider.

## Deploy (Render / Railway / Fly / etc.)

Set environment variables:
- `RSS_URL` to your feed
- `ALLOW_QUERY_RSS=1` or `0` depending on your security posture

Then deploy as a standard Node web service:
- Build: `npm install`
- Start: `npm start`

## License
MIT
