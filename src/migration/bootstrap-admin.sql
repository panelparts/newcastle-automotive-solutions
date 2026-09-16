/**
 * Xero connector worker for the Newcastle Automotive Solutions app.
 *
 * This is a small Cloudflare Worker that does the parts a browser page can't
 * safely do itself: hold the Xero app's client secret, complete the OAuth2
 * login, and call Xero's Accounting API to create real invoices.
 *
 * There is no per-user login in the app itself, so this worker manages a
 * single shared Xero connection (one Xero organisation) in a KV namespace —
 * that matches the app's own "anyone with the link can use it" design.
 *
 * Endpoints:
 *   GET  /connect?return=<url>          -> redirects the browser into Xero's login
 *   GET  /callback                       -> Xero redirects back here after login
 *   GET  /status                         -> { connected, tenantName, connectedAt }
 *   POST /disconnect                     -> forgets the stored connection
 *        Also requires `Authorization: Bearer <TASK_TOKEN>`.
 *   POST /invoices                       -> creates a draft invoice in Xero
 *        Requires `Authorization: Bearer <TASK_TOKEN>` — called by the
 *        standalone Newcastle Automotive Solutions backend, server-to-server.
 *   GET  /task/create-invoice?token=&payload=  -> same as POST /invoices, but
 *        GET-only with the JSON payload base64url-encoded in the query string.
 *        This exists because the app itself (a published Claude Artifact) is
 *        never allowed to call this Worker directly — Claude's Artifact
 *        hosting blocks outbound network calls from the page for security.
 *        Instead the app just marks an invoice "queued", and a scheduled
 *        Claude task calls this endpoint in the background to actually send
 *        it — see SETUP.md "Automatic Xero push" for the full explanation.
 *   GET  /task/attach-photo?token=&invoiceId=&photoUrl=&filename=
 *        Legacy path, kept for backwards compatibility with the old
 *        Claude-Artifact version of the app (see SETUP.md "Automatic Xero
 *        push") — attaches one already-uploaded photo, fetched server-side
 *        from photoUrl, to an existing Xero invoice.
 *   PUT  /internal/invoices/{invoiceId}/attachments/{filename}
 *        The current path, used by the standalone Newcastle Automotive Solutions backend (its
 *        own Worker, not a Claude Artifact) — same idea as /task/attach-photo
 *        but the caller PUTs the photo's raw bytes directly (it already has
 *        them from its own storage) instead of handing over a URL to fetch.
 *        Authenticated the same way, via `Authorization: Bearer <TASK_TOKEN>`.
 *
 * Required bindings (see SETUP.md):
 *   KV secret/vars   XERO_CLIENT_ID, XERO_CLIENT_SECRET, TASK_TOKEN
 *   KV namespace     XERO_KV
 *   optional var     ALLOWED_ORIGIN (defaults to "*")
 *   optional var     DEFAULT_ACCOUNT_CODE (defaults to "200")
 */

const XERO_AUTHORIZE_URL = 'https://login.xero.com/identity/connect/authorize';
const XERO_TOKEN_URL = 'https://identity.xero.com/connect/token';
const XERO_CONNECTIONS_URL = 'https://api.xero.com/connections';
const XERO_API_BASE = 'https://api.xero.com/api.xro/2.0';
const SCOPES = 'openid profile email accounting.invoices accounting.contacts offline_access';
const CONNECTION_KEY = 'connection';
const STATE_TTL_SECONDS = 600; // 10 minutes to complete the Xero login

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    if (request.method === 'OPTIONS') {
      return corsResponse(env, new Response(null, { status: 204 }));
    }

    try {
      if (url.pathname === '/connect' && request.method === 'GET') {
        return await handleConnect(url, env);
      }
      if (url.pathname === '/callback' && request.method === 'GET') {
        return await handleCallback(url, env);
      }
      if (url.pathname === '/status' && request.method === 'GET') {
        return await handleStatus(env);
      }
      if (url.pathname === '/disconnect' && request.method === 'POST') {
        return await handleDisconnect(request, env);
      }
      if (url.pathname === '/invoices' && request.method === 'POST') {
        return await handleCreateInvoice(request, env);
      }
      if (url.pathname === '/task/create-invoice' && request.method === 'GET') {
        return await handleTaskCreateInvoice(url, env);
      }
      if (url.pathname === '/task/attach-photo' && request.method === 'GET') {
        return await handleTaskAttachPhoto(url, env);
      }
      const internalAttachMatch = url.pathname.match(/^\/internal\/invoices\/([^/]+)\/attachments\/([^/]+)$/);
      if (internalAttachMatch && request.method === 'PUT') {
        return await handleInternalAttach(request, env, internalAttachMatch[1], internalAttachMatch[2]);
      }
      return corsResponse(env, json({ error: 'not_found' }, 404));
    } catch (err) {
      return corsResponse(env, json({ error: 'server_error', message: String((err && err.message) || err) }, 500));
    }
  },
};

/* ---------------------------- OAuth: connect ---------------------------- */

async function handleConnect(url, env) {
  requireEnv(env, ['XERO_CLIENT_ID', 'XERO_CLIENT_SECRET']);
  const returnUrl = url.searchParams.get('return') || '';
  const state = randomToken();
  await env.XERO_KV.put('state:' + state, JSON.stringify({ returnUrl }), {
    expirationTtl: STATE_TTL_SECONDS,
  });

  const redirectUri = url.origin + '/callback';
  const authorizeUrl = new URL(XERO_AUTHORIZE_URL);
  authorizeUrl.searchParams.set('response_type', 'code');
  authorizeUrl.searchParams.set('client_id', env.XERO_CLIENT_ID);
  authorizeUrl.searchParams.set('redirect_uri', redirectUri);
  authorizeUrl.searchParams.set('scope', SCOPES);
  authorizeUrl.searchParams.set('state', state);

  return Response.redirect(authorizeUrl.toString(), 302);
}

/* --------------------------- OAuth: callback ---------------------------- */

async function handleCallback(url, env) {
  const code = url.searchParams.get('code');
  const state = url.searchParams.get('state');
  const errorParam = url.searchParams.get('error');

  const stateRaw = state ? await env.XERO_KV.get('state:' + state) : null;
  const stateData = stateRaw ? JSON.parse(stateRaw) : { returnUrl: '' };
  if (state) await env.XERO_KV.delete('state:' + state);

  if (errorParam || !code || !stateRaw) {
    return bounceBack(stateData.returnUrl, 'error', errorParam || 'missing_code_or_state');
  }

  const redirectUri = url.origin + '/callback';
  let tokenRes;
  try {
    tokenRes = await exchangeCodeForTokens(env, code, redirectUri);
  } catch (err) {
    return bounceBack(stateData.returnUrl, 'error', 'token_exchange_failed');
  }

  let tenant;
  try {
    tenant = await fetchPrimaryTenant(tokenRes.access_token);
  } catch (err) {
    return bounceBack(stateData.returnUrl, 'error', 'no_xero_organisation');
  }

  await env.XERO_KV.put(
    CONNECTION_KEY,
    JSON.stringify({
      tenantId: tenant.tenantId,
      tenantName: tenant.tenantName,
      refreshToken: tokenRes.refresh_token,
      connectedAt: Date.now(),
    })
  );

  return bounceBack(stateData.returnUrl, 'connected', tenant.tenantName);
}

function bounceBack(returnUrl, xeroParam, extra) {
  if (!returnUrl) {
    return json({ xero: xeroParam, detail: extra });
  }
  const dest = new URL(returnUrl);
  dest.searchParams.set('xero', xeroParam);
  if (extra) dest.searchParams.set('xeroDetail', extra);
  return Response.redirect(dest.toString(), 302);
}

async function exchangeCodeForTokens(env, code, redirectUri) {
  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    code,
    redirect_uri: redirectUri,
  });
  const res = await fetch(XERO_TOKEN_URL, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      Authorization: basicAuth(env.XERO_CLIENT_ID, env.XERO_CLIENT_SECRET),
    },
    body: body.toString(),
  });
  if (!res.ok) throw new Error('token exchange failed: ' + res.status);
  return res.json();
}

async function fetchPrimaryTenant(accessToken) {
  const res = await fetch(XERO_CONNECTIONS_URL, {
    headers: { Authorization: 'Bearer ' + accessToken },
  });
  if (!res.ok) throw new Error('connections lookup failed: ' + res.status);
  const connections = await res.json();
  if (!connections || !connections.length) throw new Error('no tenants');
  return { tenantId: connections[0].tenantId, tenantName: connections[0].tenantName };
}

/* ------------------------------- status --------------------------------- */

async function handleStatus(env) {
  const raw = await env.XERO_KV.get(CONNECTION_KEY);
  if (!raw) return corsResponse(env, json({ connected: false }));
  const conn = JSON.parse(raw);
  return corsResponse(
    env,
    json({ connected: true, tenantName: conn.tenantName, connectedAt: conn.connectedAt })
  );
}

async function handleDisconnect(request, env) {
  requireEnv(env, ['TASK_TOKEN']);
  const auth = request.headers.get('Authorization') || '';
  const token = auth.replace(/^Bearer\s+/i, '');
  if (token !== env.TASK_TOKEN) {
    return corsResponse(env, json({ ok: false, error: 'unauthorized' }, 401));
  }
  await env.XERO_KV.delete(CONNECTION_KEY);
  return corsResponse(env, json({ ok: true }));
}

/* ----------------------------- invoices ---------------------------------- */

async function handleCreateInvoice(request, env) {
  requireEnv(env, ['TASK_TOKEN']);
  const auth = request.headers.get('Authorization') || '';
  const token = auth.replace(/^Bearer\s+/i, '');
  if (token !== env.TASK_TOKEN) {
    return corsResponse(env, json({ ok: false, error: 'unauthorized' }, 401));
  }
  let payload;
  try {
    payload = await request.json();
  } catch (err) {
    return corsResponse(env, json({ ok: false, error: 'invalid_json' }, 400));
  }
  const result = await createInvoiceCore(env, payload);
  return corsResponse(env, json(result.body, result.status));
}

/**
 * GET-based invoice creation for a background job that can't make a POST
 * request (e.g. Claude's own scheduled-task runner, which can only issue
 * simple GET fetches to this Worker — see SETUP.md "Automatic Xero push").
 * Protected by a shared-secret token so it can't be triggered by anyone
 * who merely knows the URL.
 */
async function handleTaskCreateInvoice(url, env) {
  requireEnv(env, ['TASK_TOKEN']);
  const token = url.searchParams.get('token') || '';
  if (token !== env.TASK_TOKEN) {
    return corsResponse(env, json({ ok: false, error: 'unauthorized' }, 401));
  }
  const encoded = url.searchParams.get('payload') || '';
  let payload;
  try {
    payload = JSON.parse(decodeURIComponent(escape(atob(encoded.replace(/-/g, '+').replace(/_/g, '/')))));
  } catch (err) {
    return corsResponse(env, json({ ok: false, error: 'invalid_payload' }, 400));
  }
  const result = await createInvoiceCore(env, payload);
  return corsResponse(env, json(result.body, result.status));
}

async function createInvoiceCore(env, payload) {
  requireEnv(env, ['XERO_CLIENT_ID', 'XERO_CLIENT_SECRET']);
  const raw = await env.XERO_KV.get(CONNECTION_KEY);
  if (!raw) return { status: 409, body: { ok: false, error: 'not_connected' } };
  const conn = JSON.parse(raw);

  const customerName = (payload.customerName || '').trim() || 'Unknown customer';
  const lineItems = Array.isArray(payload.lineItems) ? payload.lineItems : [];
  if (!lineItems.length) {
    return { status: 400, body: { ok: false, error: 'no_line_items' } };
  }
  const accountCode = payload.accountCode || env.DEFAULT_ACCOUNT_CODE || '200';
  const invoiceDate = payload.date || new Date().toISOString().slice(0, 10);
  const dueDate = payload.dueDate || invoiceDate;

  let accessToken;
  try {
    const refreshed = await refreshAccessToken(env, conn.refreshToken);
    accessToken = refreshed.access_token;
    // Xero rotates refresh tokens on every use — persist the new one or the
    // next call will fail.
    conn.refreshToken = refreshed.refresh_token;
    await env.XERO_KV.put(CONNECTION_KEY, JSON.stringify(conn));
  } catch (err) {
    return { status: 401, body: { ok: false, error: 'reauth_required' } };
  }

  let contactId;
  try {
    contactId = await ensureContact(accessToken, conn.tenantId, customerName);
  } catch (err) {
    return { status: 502, body: { ok: false, error: 'contact_failed', message: String(err.message || err) } };
  }

  const invoiceBody = {
    Type: 'ACCREC',
    Contact: { ContactID: contactId },
    Date: invoiceDate,
    DueDate: dueDate,
    Reference: payload.reference || '',
    LineAmountType: 'Exclusive',
    Status: payload.authorise ? 'AUTHORISED' : 'DRAFT',
    LineItems: lineItems.map((li) => ({
      Description: String(li.description || 'Item').slice(0, 4000),
      Quantity: li.quantity != null ? li.quantity : 1,
      UnitAmount: Number(li.amount) || 0,
      AccountCode: li.accountCode || accountCode,
      TaxType: 'OUTPUT',
    })),
  };

  let createRes;
  try {
    createRes = await xeroApiFetch(accessToken, conn.tenantId, '/Invoices', {
      method: 'POST',
      body: JSON.stringify({ Invoices: [invoiceBody] }),
    });
  } catch (err) {
    return { status: 502, body: { ok: false, error: 'invoice_failed', message: String(err.message || err) } };
  }

  const created = (createRes.Invoices || [])[0];
  if (!created) {
    return { status: 502, body: { ok: false, error: 'invoice_not_returned' } };
  }

  return {
    status: 200,
    body: {
      ok: true,
      invoiceId: created.InvoiceID,
      invoiceNumber: created.InvoiceNumber,
      invoiceUrl: 'https://go.xero.com/AccountsReceivable/View.aspx?InvoiceID=' + created.InvoiceID,
    },
  };
}

/**
 * Attaches one photo to an already-created Xero invoice. The photo itself is
 * never routed through the calling GET request (its bytes would be far too
 * large for a query string) — instead this Worker fetches it directly,
 * server-side, from photoUrl (a Claude Artifact 'assets' URL, which this
 * Worker — unlike the app page — has no CSP restriction against calling),
 * then re-uploads those same bytes to Xero's Attachments API.
 */
async function handleTaskAttachPhoto(url, env) {
  requireEnv(env, ['TASK_TOKEN']);
  const token = url.searchParams.get('token') || '';
  if (token !== env.TASK_TOKEN) {
    return corsResponse(env, json({ ok: false, error: 'unauthorized' }, 401));
  }
  const invoiceId = url.searchParams.get('invoiceId') || '';
  const photoUrl = url.searchParams.get('photoUrl') || '';
  const filename = (url.searchParams.get('filename') || 'photo.jpg').replace(/[^A-Za-z0-9_.-]/g, '_') || 'photo.jpg';
  if (!invoiceId || !photoUrl) {
    return corsResponse(env, json({ ok: false, error: 'missing_params' }, 400));
  }

  requireEnv(env, ['XERO_CLIENT_ID', 'XERO_CLIENT_SECRET']);
  const raw = await env.XERO_KV.get(CONNECTION_KEY);
  if (!raw) return corsResponse(env, json({ ok: false, error: 'not_connected' }, 409));
  const conn = JSON.parse(raw);

  let accessToken;
  try {
    const refreshed = await refreshAccessToken(env, conn.refreshToken);
    accessToken = refreshed.access_token;
    conn.refreshToken = refreshed.refresh_token;
    await env.XERO_KV.put(CONNECTION_KEY, JSON.stringify(conn));
  } catch (err) {
    return corsResponse(env, json({ ok: false, error: 'reauth_required' }, 401));
  }

  let photoRes;
  try {
    photoRes = await fetch(photoUrl);
    if (!photoRes.ok) throw new Error('status ' + photoRes.status);
  } catch (err) {
    return corsResponse(env, json({ ok: false, error: 'photo_fetch_failed', message: String((err && err.message) || err) }, 502));
  }
  const contentType = photoRes.headers.get('Content-Type') || 'image/jpeg';
  const bodyBuf = await photoRes.arrayBuffer();

  let attachRes;
  try {
    attachRes = await fetch(
      XERO_API_BASE + '/Invoices/' + encodeURIComponent(invoiceId) + '/Attachments/' + encodeURIComponent(filename),
      {
        method: 'PUT', // create-or-update: safe to retry with the same filename
        headers: {
          Authorization: 'Bearer ' + accessToken,
          'Xero-tenant-id': conn.tenantId,
          'Content-Type': contentType,
          Accept: 'application/json',
        },
        body: bodyBuf,
      }
    );
  } catch (err) {
    return corsResponse(env, json({ ok: false, error: 'attach_failed', message: String((err && err.message) || err) }, 502));
  }
  if (!attachRes.ok) {
    const text = await attachRes.text().catch(() => '');
    return corsResponse(env, json({ ok: false, error: 'attach_rejected', message: text.slice(0, 300) }, 502));
  }
  const attachData = await attachRes.json().catch(() => null);
  const created = attachData && attachData.Attachments && attachData.Attachments[0];
  return corsResponse(env, json({ ok: true, attachmentId: created ? created.AttachmentID : null, filename: filename }));
}

/**
 * Server-to-server attachment upload for the new standalone Newcastle Automotive Solutions
 * backend (which replaced the Claude Artifact version of the app) — the
 * caller already has the photo's raw bytes in hand (from its own R2
 * storage) and PUTs them directly, so there's no URL to fetch and no
 * base64-in-a-query-string payload at all. Authenticated with the same
 * shared secret as the /task/* endpoints above (TASK_TOKEN), sent as a
 * normal Authorization header this time since this is a real HTTP client,
 * not a GET-only fetch tool.
 */
async function handleInternalAttach(request, env, invoiceId, filename) {
  requireEnv(env, ['TASK_TOKEN']);
  const auth = request.headers.get('Authorization') || '';
  const token = auth.replace(/^Bearer\s+/i, '');
  if (token !== env.TASK_TOKEN) {
    return corsResponse(env, json({ ok: false, error: 'unauthorized' }, 401));
  }
  const contentType = request.headers.get('Content-Type') || 'image/jpeg';
  const bodyBuf = await request.arrayBuffer();

  requireEnv(env, ['XERO_CLIENT_ID', 'XERO_CLIENT_SECRET']);
  const raw = await env.XERO_KV.get(CONNECTION_KEY);
  if (!raw) return corsResponse(env, json({ ok: false, error: 'not_connected' }, 409));
  const conn = JSON.parse(raw);

  let accessToken;
  try {
    const refreshed = await refreshAccessToken(env, conn.refreshToken);
    accessToken = refreshed.access_token;
    conn.refreshToken = refreshed.refresh_token;
    await env.XERO_KV.put(CONNECTION_KEY, JSON.stringify(conn));
  } catch (err) {
    return corsResponse(env, json({ ok: false, error: 'reauth_required' }, 401));
  }

  let attachRes;
  try {
    attachRes = await fetch(
      XERO_API_BASE + '/Invoices/' + encodeURIComponent(invoiceId) + '/Attachments/' + encodeURIComponent(filename),
      {
        method: 'PUT', // create-or-update: safe to retry with the same filename
        headers: {
          Authorization: 'Bearer ' + accessToken,
          'Xero-tenant-id': conn.tenantId,
          'Content-Type': contentType,
          Accept: 'application/json',
        },
        body: bodyBuf,
      }
    );
  } catch (err) {
    return corsResponse(env, json({ ok: false, error: 'attach_failed', message: String((err && err.message) || err) }, 502));
  }
  if (!attachRes.ok) {
    const text = await attachRes.text().catch(() => '');
    return corsResponse(env, json({ ok: false, error: 'attach_rejected', message: text.slice(0, 300) }, 502));
  }
  const attachData = await attachRes.json().catch(() => null);
  const created = attachData && attachData.Attachments && attachData.Attachments[0];
  return corsResponse(env, json({ ok: true, attachmentId: created ? created.AttachmentID : null, filename: filename }));
}

async function refreshAccessToken(env, refreshToken) {
  const body = new URLSearchParams({ grant_type: 'refresh_token', refresh_token: refreshToken });
  const res = await fetch(XERO_TOKEN_URL, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      Authorization: basicAuth(env.XERO_CLIENT_ID, env.XERO_CLIENT_SECRET),
    },
    body: body.toString(),
  });
  if (!res.ok) throw new Error('refresh failed: ' + res.status);
  return res.json();
}

async function ensureContact(accessToken, tenantId, name) {
  const escaped = name.replace(/"/g, '\\"');
  const query = 'Name=="' + escaped + '"';
  const found = await xeroApiFetch(accessToken, tenantId, '/Contacts?where=' + encodeURIComponent(query));
  const existing = (found.Contacts || [])[0];
  if (existing) return existing.ContactID;

  const createdRes = await xeroApiFetch(accessToken, tenantId, '/Contacts', {
    method: 'PUT',
    body: JSON.stringify({ Contacts: [{ Name: name }] }),
  });
  const created = (createdRes.Contacts || [])[0];
  if (!created) throw new Error('contact not returned');
  return created.ContactID;
}

async function xeroApiFetch(accessToken, tenantId, path, opts) {
  const res = await fetch(XERO_API_BASE + path, {
    method: (opts && opts.method) || 'GET',
    headers: {
      Authorization: 'Bearer ' + accessToken,
      'Xero-tenant-id': tenantId,
      'Content-Type': 'application/json',
      Accept: 'application/json',
    },
    body: opts && opts.body,
  });
  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new Error('Xero API ' + path + ' -> ' + res.status + ' ' + text.slice(0, 300));
  }
  return res.json();
}

/* -------------------------------- utils ---------------------------------- */

function basicAuth(id, secret) {
  return 'Basic ' + btoa(id + ':' + secret);
}
function randomToken() {
  const bytes = crypto.getRandomValues(new Uint8Array(24));
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}
function json(obj, status) {
  return new Response(JSON.stringify(obj), {
    status: status || 200,
    headers: { 'Content-Type': 'application/json' },
  });
}
function corsResponse(env, res) {
  const headers = new Headers(res.headers);
  headers.set('Access-Control-Allow-Origin', env.ALLOWED_ORIGIN || '*');
  headers.set('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  headers.set('Access-Control-Allow-Headers', 'Content-Type');
  return new Response(res.body, { status: res.status, headers });
}
function requireEnv(env, keys) {
  const missing = keys.filter((k) => !env[k]);
  if (missing.length) throw new Error('Missing worker config: ' + missing.join(', '));
}
