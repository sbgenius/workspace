// Cloudflare Worker for the gphotos clone (v2).
// The worker never sees your password: it gets SHA-256(password) as hex, uses it
// to AES-GCM-decrypt the PAT stored in <user>/gphotos/vault.json, and proxies to GitHub.
//
// Routes
//   POST /login        verify credentials, return the vault salt
//   /gh/<path>         GitHub REST API (api.github.com), restricted to <user>/gphotos (plus GET /gh/rate_limit)
//   /up/<path>         GitHub upload host (uploads.github.com), restricted to <user>/gphotos
//   GET /dl/<tag>/<name>  public release-asset download (no token, no REST API quota)
const CORS = {
  'Access-Control-Allow-Origin': '*', // set to your site origin once deployed
  'Access-Control-Allow-Headers': '*',
  'Access-Control-Allow-Methods': 'GET,POST,PATCH,DELETE,OPTIONS',
};
const R = (body, status = 200, h = {}) => new Response(body, { status, headers: { ...CORS, ...h } });

async function getToken(user, keyHex) {
  if (!/^[\w-]{1,39}$/.test(user) || !/^[0-9a-f]{64}$/.test(keyHex)) throw 0;
  // the query string rotates every 30s so a replaced token is picked up quickly (raw.githubusercontent caches per URL)
  const r = await fetch(`https://raw.githubusercontent.com/${user}/gphotos/HEAD/vault.json?v=${Math.floor(Date.now() / 30000)}`, { cf: { cacheTtl: 30 } });
  if (!r.ok) throw 0;
  const v = await r.json();
  const key = await crypto.subtle.importKey('raw', Uint8Array.from(keyHex.match(/../g), (h) => parseInt(h, 16)), 'AES-GCM', false, ['decrypt']);
  const b = Uint8Array.from(atob(v.tok), (c) => c.charCodeAt(0));
  const t = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b.slice(0, 12) }, key, b.slice(12));
  return { token: new TextDecoder().decode(t), salt: v.salt };
}

export default {
  async fetch(req) {
    if (req.method === 'OPTIONS') return R(null, 204);
    const url = new URL(req.url);
    const user = req.headers.get('X-User') || '', keyHex = req.headers.get('X-Key') || '';
    let auth;
    try { auth = await getToken(user, keyHex); } catch { return R('unauthorized', 401); }
    if (url.pathname === '/login') {
      // also verify the decrypted token actually works
      const me = await fetch('https://api.github.com/user', { headers: { Authorization: 'Bearer ' + auth.token, 'User-Agent': 'gphotos-worker' } });
      return me.ok ? R(JSON.stringify({ salt: auth.salt }), 200, { 'Content-Type': 'application/json' }) : R('bad token', 401);
    }

    // Public release downloads. Everything in the repo is encrypted client-side, and the repo is public,
    // so no token is sent. Downloads from github.com do not count against the REST API rate limit.
    const dl = url.pathname.match(/^\/dl\/([\w.-]{1,100})\/([\w.-]{1,100})$/);
    if (dl) {
      if (req.method !== 'GET') return R('method not allowed', 405);
      const up = await fetch(`https://github.com/${user}/gphotos/releases/download/${dl[1]}/${dl[2]}`, {
        headers: { 'User-Agent': 'gphotos-worker' },
        redirect: 'follow',
      });
      if (!up.ok) return R(null, up.status);
      // asset names are unique per upload, so the bytes behind a URL never change
      return R(up.body, 200, {
        'Content-Type': 'application/octet-stream',
        'Cache-Control': 'private, max-age=31536000, immutable',
      });
    }

    const m = url.pathname.match(/^\/(gh|up)\/(.*)$/);
    if (!m) return R('not found', 404);
    const target = new URL(`https://${m[1] === 'gh' ? 'api.github.com' : 'uploads.github.com'}/${m[2]}${url.search}`);
    const base = `/repos/${user.toLowerCase()}/gphotos`;
    const pl = target.pathname.toLowerCase();
    const rate = m[1] === 'gh' && m[2] === 'rate_limit' && req.method === 'GET'; // free quota lookup
    if (!rate && pl !== base && !pl.startsWith(base + '/')) return R('forbidden', 403); // only the gphotos repo
    const isAsset = req.headers.get('Accept') === 'application/octet-stream';
    const headers = new Headers({
      Authorization: 'Bearer ' + auth.token,
      'User-Agent': 'gphotos-worker',
      Accept: req.headers.get('Accept') || 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
    });
    if (req.headers.get('Content-Type')) headers.set('Content-Type', req.headers.get('Content-Type'));
    const hasBody = !['GET', 'HEAD', 'DELETE'].includes(req.method);
    const up = await fetch(target, { method: req.method, headers, body: hasBody ? await req.arrayBuffer() : undefined, redirect: 'follow' });
    return R(up.status === 204 ? null : up.body, up.status, {
      'Content-Type': up.headers.get('Content-Type') || 'application/json',
      ...(isAsset && up.ok ? { 'Cache-Control': 'private, max-age=31536000, immutable' } : {}),
    });
  },
};
