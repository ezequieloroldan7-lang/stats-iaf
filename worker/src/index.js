const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
};

export default {
  async fetch(request, env) {
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: CORS });
    }

    const url = new URL(request.url);
    const path = url.pathname;

    try {
      // GET /months — lista todos los meses (key, label, updated_at)
      if (path === '/months' && request.method === 'GET') {
        const { results } = await env.DB
          .prepare('SELECT key, label, updated_at FROM months ORDER BY key')
          .all();
        return Response.json(results, { headers: CORS });
      }

      // /months/:key
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
            .bind(key, label, body)
            .run();
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
