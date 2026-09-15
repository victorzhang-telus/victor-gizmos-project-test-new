// BI Explorer worker: Google OAuth (PKCE) code exchange + BigQuery proxy.
// Every call runs with the signed-in user's own access token, so BigQuery IAM
// decides what they can see. The worker holds no service account.

function json(body, init = {}) {
  return new Response(JSON.stringify(body), {
    ...init,
    headers: { 'Content-Type': 'application/json', ...(init.headers || {}) },
  });
}

// Backstop: only read-only statements may run. IAM is the real guarantee, but
// this keeps the app itself from ever issuing DML/DDL.
function isReadOnly(sql) {
  return /^\s*(select|with)\b/i.test(sql);
}

function bqError(status, data, fallback) {
  return {
    error: data?.error?.message || fallback,
    status: status === 401 ? 401 : status === 403 ? 403 : 502,
  };
}

async function bqGet(url, accessToken) {
  let res;
  try {
    res = await fetch(url, { headers: { Authorization: `Bearer ${accessToken}` } });
  } catch (err) {
    const detail = err.cause?.code || err.cause?.message || err.message;
    return { error: `Could not reach BigQuery: ${detail}`, status: 502 };
  }
  const data = await res.json().catch(() => ({}));
  if (!res.ok) return bqError(res.status, data, `BigQuery error (${res.status})`);
  return { data };
}

// Follow pageTokens so projects with many datasets/tables list fully (capped).
async function bqGetPaged(baseUrl, accessToken, extract) {
  const items = [];
  let pageToken = '';
  for (let page = 0; page < 10; page++) {
    const url = `${baseUrl}?maxResults=1000${pageToken ? `&pageToken=${pageToken}` : ''}`;
    const out = await bqGet(url, accessToken);
    if (out.error) return out;
    items.push(...extract(out.data));
    pageToken = out.data.nextPageToken;
    if (!pageToken) break;
  }
  return { items };
}

// GCP project ids: lowercase letters, digits, hyphens (legacy ones may carry
// a domain prefix like "example.com:id").
const PROJECT_ID = /^[a-z0-9.:-]{4,64}$/;

async function runBigQuery(env, project, sql, accessToken) {
  const url = `https://bigquery.googleapis.com/bigquery/v2/projects/${project}/queries`;
  let res;
  try {
    res = await fetch(url, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${accessToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        query: sql,
        location: env.BQ_LOCATION,
        useLegacySql: false,
        maxResults: parseInt(env.MAX_ROWS || '200', 10),
        timeoutMs: 30000,
      }),
    });
  } catch (err) {
    const detail = err.cause?.code || err.cause?.message || err.message;
    return { error: `Could not reach BigQuery: ${detail}`, status: 502 };
  }
  const data = await res.json().catch(() => ({}));
  if (!res.ok) return bqError(res.status, data, `BigQuery error (${res.status})`);
  if (data.jobComplete === false) {
    return { error: 'Query did not complete within the timeout', status: 504 };
  }
  const fields = data.schema?.fields ?? [];
  const rows = (data.rows ?? []).map((row) =>
    Object.fromEntries(fields.map((f, i) => [f.name, row.f[i]?.v ?? null]))
  );
  return {
    result: {
      fields: fields.map((f) => ({ name: f.name, type: f.type })),
      rows,
      totalRows: parseInt(data.totalRows ?? '0', 10),
      bytesProcessed: parseInt(data.totalBytesProcessed ?? '0', 10),
    },
  };
}

function getBearer(request) {
  const auth = request.headers.get('Authorization') || '';
  return auth.startsWith('Bearer ') ? auth.slice(7) : null;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // Gizmos SSO gate: the loader authenticates before us and injects identity
    // headers. Fail closed if they're missing (DEV_MODE covers local dev).
    const gizmosUser = request.headers.get('x-gizmos-user');
    if (url.pathname.startsWith('/api/') && !gizmosUser && env.DEV_MODE !== 'true') {
      return json({ error: 'Unauthorized' }, { status: 401 });
    }

    // ── GET /api/config — public app config for the frontend ──
    // Google auth is handled by the bq-auth broker app; this app owns no
    // OAuth client and no secrets.
    if (url.pathname === '/api/config' && request.method === 'GET') {
      return json({ brokerUrl: env.BQ_AUTH_URL });
    }

    // ── BI layer routes (Gizmos SSO only — no Google token needed) ──
    // Whitelist + per-user saved choice, per GIZMOS-BI-LAYER-ADMIN.md.
    // KV keys: 'bi_layers' (global whitelist), 'user_bi_layer:{email}'.

    // Admin = the app's owner/admins (x-gizmos-role, platform-verified — i.e.
    // whoever deployed/administers the app), plus optional ADMIN_EMAILS extras.
    const isAdmin =
      ['owner', 'admin'].includes(request.headers.get('x-gizmos-role') || '')
      || String(env.ADMIN_EMAILS || '').split(',').map((e) => e.trim()).filter(Boolean).includes(gizmosUser)
      || env.DEV_MODE === 'true';

    // Seed whitelist from wrangler.toml BI_LAYERS ("id|Label, id|Label" — label
    // optional). KV wins once an admin saves; the var only feeds first load.
    const seedLayers = () => ({
      bi_layers: String(env.BI_LAYERS || '').split(',').map((s) => s.trim()).filter(Boolean)
        .map((s) => {
          const [id, label] = s.split('|').map((x) => x.trim());
          return { project_id: id, label: label || id };
        }),
    });

    // ── GET /api/admin/bi-layers — the whitelist (all authenticated users) ──
    // The whitelist LIVES IN KV. An empty KV is seeded once from the
    // wrangler.toml BI_LAYERS var (written through, not just served), so the
    // seed becomes real KV data on the first request after deploy.
    if (url.pathname === '/api/admin/bi-layers' && request.method === 'GET') {
      try {
        let stored = env.ADMIN_CONFIG
          ? await env.ADMIN_CONFIG.get('bi_layers', { type: 'json' })
          : null;
        if (!stored) {
          stored = seedLayers();
          if (env.ADMIN_CONFIG && stored.bi_layers.length) {
            await env.ADMIN_CONFIG.put('bi_layers', JSON.stringify(stored));
            console.log(`bi_layers seeded into KV from BI_LAYERS var: ${stored.bi_layers.map((l) => l.project_id).join(', ')}`);
          }
        }
        return json({ ...stored, isAdmin });
      } catch { return json({ ...seedLayers(), isAdmin }); }
    }

    // ── POST /api/admin/bi-layers/reset — wipe KV back to the toml seed ──
    if (url.pathname === '/api/admin/bi-layers/reset' && request.method === 'POST') {
      if (!isAdmin) return json({ error: 'Admin access only' }, { status: 403 });
      if (!env.ADMIN_CONFIG) return json({ error: 'KV not configured' }, { status: 503 });
      await env.ADMIN_CONFIG.delete('bi_layers');
      console.log(`bi_layers reset to seed by ${gizmosUser}`);
      return json({ ok: true, ...seedLayers() });
    }

    // ── POST /api/admin/bi-layers — save the whitelist (admin only) ──
    if (url.pathname === '/api/admin/bi-layers' && request.method === 'POST') {
      if (!isAdmin) return json({ error: 'Admin access only' }, { status: 403 });
      if (!env.ADMIN_CONFIG) return json({ error: 'KV not configured' }, { status: 503 });
      let body;
      try { body = JSON.parse(await request.text()); } catch { return json({ error: 'Invalid JSON' }, { status: 400 }); }
      if (!Array.isArray(body.bi_layers)) return json({ error: 'bi_layers must be an array' }, { status: 400 });
      for (const l of body.bi_layers) {
        if (!PROJECT_ID.test(l?.project_id || '')) {
          return json({ error: `Invalid project id: ${l?.project_id}` }, { status: 400 });
        }
      }
      await env.ADMIN_CONFIG.put('bi_layers', JSON.stringify(body));
      console.log(`bi_layers whitelist saved by ${gizmosUser}: ${body.bi_layers.map((l) => l.project_id).join(', ')}`);
      return json({ ok: true });
    }

    // ── GET /api/user/bi-layer — this user's saved choice (or null) ──
    if (url.pathname === '/api/user/bi-layer' && request.method === 'GET') {
      try {
        const saved = env.ADMIN_CONFIG
          ? await env.ADMIN_CONFIG.get(`user_bi_layer:${gizmosUser}`, { type: 'json' })
          : null;
        return json(saved || null);
      } catch { return json(null); }
    }

    // ── POST /api/user/bi-layer — save this user's choice (persists) ──
    if (url.pathname === '/api/user/bi-layer' && request.method === 'POST') {
      if (!env.ADMIN_CONFIG) return json({ error: 'KV not configured' }, { status: 503 });
      let body;
      try { body = JSON.parse(await request.text()); } catch { return json({ error: 'Invalid JSON' }, { status: 400 }); }
      if (!body.project_id || typeof body.project_id !== 'string' || !PROJECT_ID.test(body.project_id.trim())) {
        return json({ error: 'Valid project_id required' }, { status: 400 });
      }
      const entry = { project_id: body.project_id.trim(), label: (body.label || body.project_id).trim() };
      await env.ADMIN_CONFIG.put(`user_bi_layer:${gizmosUser}`, JSON.stringify(entry));
      console.log(`bi layer for ${gizmosUser}: ${entry.project_id}`);
      return json({ ok: true });
    }

    // ── GET /api/admin/user-layers — every user's choice (admin only) ──
    if (url.pathname === '/api/admin/user-layers' && request.method === 'GET') {
      if (!isAdmin) return json({ error: 'Admin access only' }, { status: 403 });
      if (!env.ADMIN_CONFIG) return json({ user_layers: [] });
      try {
        const list = await env.ADMIN_CONFIG.list({ prefix: 'user_bi_layer:' });
        const entries = [];
        for (const key of list.keys) {
          const email = key.name.replace('user_bi_layer:', '');
          const data = await env.ADMIN_CONFIG.get(key.name, { type: 'json' });
          if (data) entries.push({ email, project_id: data.project_id, label: data.label });
        }
        return json({ user_layers: entries });
      } catch (e) { return json({ user_layers: [], error: e.message }); }
    }

    // All routes below require the user's Google token.
    const accessToken = getBearer(request);
    if (url.pathname.startsWith('/api/') && !accessToken) {
      return json({ error: 'Google sign-in required' }, { status: 401 });
    }

    // The browse/query routes below all take an explicit billing project —
    // the user's chosen BI layer (no discovery/probing; see the BI layer routes).
    const project = url.searchParams.get('project') || '';

    // ── GET /api/datasets?project=ID — list datasets in the project ──
    if (url.pathname === '/api/datasets' && request.method === 'GET') {
      if (!PROJECT_ID.test(project)) return json({ error: 'Valid project parameter required' }, { status: 400 });
      const out = await bqGetPaged(
        `https://bigquery.googleapis.com/bigquery/v2/projects/${project}/datasets`,
        accessToken,
        (d) => (d.datasets ?? []).map((x) => ({
          id: x.datasetReference.datasetId,
          location: x.location ?? '',
        })),
      );
      if (out.error) {
        console.error(`datasets failed for ${gizmosUser}: ${out.error}`);
        return json({ error: out.error }, { status: out.status });
      }
      console.log(`datasets listed for ${gizmosUser}: ${out.items.length}`);
      return json({ datasets: out.items });
    }

    // ── GET /api/tables?project=ID&dataset=ID — list tables in a dataset ──
    if (url.pathname === '/api/tables' && request.method === 'GET') {
      if (!PROJECT_ID.test(project)) return json({ error: 'Valid project parameter required' }, { status: 400 });
      const dataset = url.searchParams.get('dataset');
      if (!dataset || !/^[\w$]+$/.test(dataset)) {
        return json({ error: 'Valid dataset parameter required' }, { status: 400 });
      }
      const out = await bqGetPaged(
        `https://bigquery.googleapis.com/bigquery/v2/projects/${project}/datasets/${dataset}/tables`,
        accessToken,
        (d) => (d.tables ?? []).map((x) => ({
          id: x.tableReference.tableId,
          type: x.type ?? 'TABLE',
        })),
      );
      if (out.error) return json({ error: out.error }, { status: out.status });
      return json({ tables: out.items });
    }

    // ── POST /api/query — run user-edited SQL as the user ──
    if (url.pathname === '/api/query' && request.method === 'POST') {
      let body;
      try {
        body = await request.json();
      } catch {
        body = {};
      }
      const sql = (body.sql || '').trim();
      const billingProject = (body.project || '').trim();
      if (!sql) return json({ error: 'sql is required' }, { status: 400 });
      if (!PROJECT_ID.test(billingProject)) {
        return json({ error: 'Valid billing project is required' }, { status: 400 });
      }
      if (!isReadOnly(sql)) {
        return json({ error: 'Only read-only SELECT queries are allowed' }, { status: 400 });
      }
      const out = await runBigQuery(env, billingProject, sql, accessToken);
      if (out.error) {
        console.error(`query failed for ${gizmosUser}: ${out.error}`);
        return json({ error: out.error }, { status: out.status });
      }
      console.log(`query ok for ${gizmosUser}: ${out.result.rows.length} rows, ${out.result.bytesProcessed} bytes`);
      return json(out.result);
    }

    if (url.pathname.startsWith('/api/')) {
      return json({ error: 'Not found' }, { status: 404 });
    }

    // Non-API paths are served by the Gizmos static loader (index.html etc.).
    return new Response('Not found', { status: 404 });
  },
};
