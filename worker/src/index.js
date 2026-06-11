const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, X-Admin-Usr, X-Admin-Pwd',
};

async function ensureUsersTable(env) {
  await env.DB.exec(
    'CREATE TABLE IF NOT EXISTS users (usr_hash TEXT PRIMARY KEY, pwd_hash TEXT NOT NULL, label TEXT NOT NULL, is_admin INTEGER NOT NULL DEFAULT 0)'
  );
}

async function verifyAdmin(request, env) {
  const usr = request.headers.get('X-Admin-Usr') || '';
  const pwd = request.headers.get('X-Admin-Pwd') || '';
  if (!usr || !pwd) return false;
  const row = await env.DB
    .prepare('SELECT 1 FROM users WHERE usr_hash = ? AND pwd_hash = ? AND is_admin = 1')
    .bind(usr, pwd).first();
  return !!row;
}

export default {
  async fetch(request, env) {
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: CORS });
    }

    const url = new URL(request.url);
    const path = url.pathname;

    try {
      // ── POST /auth — validate credentials (never exposes hashes) ──
      if (path === '/auth' && request.method === 'POST') {
        await ensureUsersTable(env);
        const body = await request.json();
        const row = await env.DB
          .prepare('SELECT label, is_admin FROM users WHERE usr_hash = ? AND pwd_hash = ?')
          .bind(body.usrHash, body.pwdHash).first();
        if (!row) return Response.json({ valid: false }, { headers: CORS });
        return Response.json({ valid: true, label: row.label, isAdmin: row.is_admin === 1 }, { headers: CORS });
      }

      // ── /users ──
      if (path === '/users') {
        await ensureUsersTable(env);

        // GET /users — list all users (admin only)
        if (request.method === 'GET') {
          if (!await verifyAdmin(request, env)) {
            return Response.json({ error: 'Unauthorized' }, { status: 401, headers: CORS });
          }
          const { results } = await env.DB
            .prepare('SELECT usr_hash, label, is_admin FROM users ORDER BY label')
            .all();
          return Response.json(results, { headers: CORS });
        }

        // POST /users — add or update user (admin only)
        if (request.method === 'POST') {
          if (!await verifyAdmin(request, env)) {
            return Response.json({ error: 'Unauthorized' }, { status: 401, headers: CORS });
          }
          const body = await request.json();
          await env.DB
            .prepare('INSERT OR REPLACE INTO users (usr_hash, pwd_hash, label, is_admin) VALUES (?, ?, ?, ?)')
            .bind(body.usrHash, body.pwdHash, body.label, body.isAdmin ? 1 : 0)
            .run();
          return Response.json({ ok: true }, { headers: CORS });
        }
      }

      // ── DELETE /users/:hash — remove user (admin only) ──
      const mu = path.match(/^\/users\/([^/]+)$/);
      if (mu && request.method === 'DELETE') {
        await ensureUsersTable(env);
        if (!await verifyAdmin(request, env)) {
          return Response.json({ error: 'Unauthorized' }, { status: 401, headers: CORS });
        }
        await env.DB
          .prepare('DELETE FROM users WHERE usr_hash = ?')
          .bind(decodeURIComponent(mu[1])).run();
        return Response.json({ ok: true }, { headers: CORS });
      }

      // ── GET /months — list months ──
      if (path === '/months' && request.method === 'GET') {
        const { results } = await env.DB
          .prepare('SELECT key, label, updated_at FROM months ORDER BY key')
          .all();
        return Response.json(results, { headers: CORS });
      }

      // ── /months/:key ──
      const m = path.match(/^\/months\/([^/]+)$/);
      if (m) {
        const key = decodeURIComponent(m[1]);

        if (request.method === 'GET') {
          const row = await env.DB
            .prepare('SELECT data FROM months WHERE key = ?')
            .bind(key).first();
          if (!row) return new Response('Not found', { status: 404, headers: CORS });
          return new Response(row.data, {
            headers: { ...CORS, 'Content-Type': 'application/json' },
          });
        }

        if (request.method === 'PUT') {
          const body = await request.text();
          const parsed = JSON.parse(body);
          const label = parsed.label || key;
          await env.DB
            .prepare(
              'INSERT OR REPLACE INTO months (key, label, data, updated_at) VALUES (?, ?, ?, datetime("now"))'
            )
            .bind(key, label, body).run();
          return Response.json({ ok: true }, { headers: CORS });
        }

        if (request.method === 'DELETE') {
          await env.DB
            .prepare('DELETE FROM months WHERE key = ?')
            .bind(key).run();
          return Response.json({ ok: true }, { headers: CORS });
        }
      }

      return new Response('Not found', { status: 404, headers: CORS });
    } catch (err) {
      return Response.json({ error: err.message }, { status: 500, headers: CORS });
    }
  },
};
