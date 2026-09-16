/**
 * Newcastle Automotive Solutions — standalone backend.
 *
 * Replaces the Claude Artifact 'db'/'assets' capabilities this app used to
 * run on. Serves the app's static frontend (via the Workers "assets"
 * binding — see wrangler.jsonc) and a small JSON API backed by D1 (data)
 * and R2 (photos), with real staff login (email + password, session
 * cookies) gating everything.
 *
 * Xero: this Worker talks to the existing `nas-xero-connector` Worker
 * server-to-server (a plain HTTPS call, no browser CSP or Claude tooling
 * in the path at all) — see xeroCreateInvoice()/xeroAttachPhoto() below.
 * That's the fix for the "long URL gets rejected" problem the Artifact-based
 * version hit: there is no URL-encoded payload anywhere in this design.
 *
 * Required bindings (see DEPLOY.md):
 *   D1 database        DB
 *   R2 bucket          PHOTOS
 *   var                XERO_WORKER_URL   (the nas-xero-connector Worker's URL)
 *   secret             XERO_INTERNAL_TOKEN  (must equal TASK_TOKEN on that
 *                       Worker — see DEPLOY.md; this is what lets this
 *                       backend create invoices / attach photos / disconnect
 *                       Xero without anyone else who finds the connector's
 *                       URL being able to do the same)
 *
 * Session tokens are random 32-byte values stored in D1 (sessions table)
 * with an expiry — there is no separate signing secret to configure.
 */

const SESSION_COOKIE = 'bb_session';
const SESSION_DAYS = 30;

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (!url.pathname.startsWith('/api/')) {
      // Static assets (the app itself) are served automatically by the
      // Workers assets binding before this fetch() even runs, for any
      // request that matches a real file. Anything else non-API falls
      // through to here — hand it index.html so client-side routing (if
      // any is added later) still works.
      return env.ASSETS.fetch(request);
    }

    try {
      return await routeApi(request, env, url);
    } catch (err) {
      return json({ error: 'server_error', message: String((err && err.message) || err) }, 500);
    }
  },
};

async function routeApi(request, env, url) {
  const path = url.pathname.replace(/^\/api/, '');
  const method = request.method;

  if (path === '/login' && method === 'POST') return handleLogin(request, env);
  if (path === '/logout' && method === 'POST') return handleLogout(request, env);
  if (path === '/me' && method === 'GET') return handleMe(request, env);

  // Everything else requires a signed-in session.
  const user = await getSessionUser(request, env);
  if (!user) return json({ error: 'unauthorized' }, 401);

  if (path === '/users' && method === 'GET') return listUsers(env, user);
  if (path === '/users' && method === 'POST') return createUser(request, env, user);
  if (path.match(/^\/users\/[^/]+$/) && method === 'DELETE') return deactivateUser(path, env, user);

  const collMatch = path.match(/^\/collections\/([a-z]+)(?:\/([^/]+))?$/);
  if (collMatch) {
    const [, coll, id] = collMatch;
    if (!COLLECTIONS[coll]) return json({ error: 'unknown_collection' }, 404);
    if (method === 'GET' && !id) return listCollection(coll, env);
    if (method === 'PUT' && id) return upsertCollection(coll, id, request, env);
    if (method === 'DELETE' && id) return deleteCollection(coll, id, env);
  }

  if (path === '/photos' && method === 'POST') return uploadPhoto(request, env, user);
  if (path.match(/^\/photos\/[^/]+$/) && method === 'GET') return servePhoto(path, env);

  if (path === '/xero/status' && method === 'GET') return xeroProxy(env, '/status', 'GET');
  if (path === '/xero/disconnect' && method === 'POST') return xeroProxy(env, '/disconnect', 'POST');
  if (path === '/xero/connect-url' && method === 'GET') return xeroConnectUrl(request, env);

  if (path.match(/^\/invoices\/[^/]+\/send$/) && method === 'POST') {
    const id = path.split('/')[2];
    return sendInvoiceToXero(id, env);
  }

  return json({ error: 'not_found' }, 404);
}

/* ============================ auth ============================ */

async function handleLogin(request, env) {
  let body;
  try { body = await request.json(); } catch (e) { return json({ error: 'invalid_json' }, 400); }
  const email = String(body.email || '').trim().toLowerCase();
  const password = String(body.password || '');
  if (!email || !password) return json({ error: 'missing_credentials' }, 400);

  const row = await env.DB.prepare('SELECT * FROM users WHERE email = ? AND active = 1').bind(email).first();
  if (!row) return json({ error: 'invalid_login' }, 401);

  const ok = await verifyPassword(password, row.password_salt, row.password_hash);
  if (!ok) return json({ error: 'invalid_login' }, 401);

  const token = randomToken();
  const now = Date.now();
  const expires = now + SESSION_DAYS * 24 * 60 * 60 * 1000;
  await env.DB.prepare('INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)')
    .bind(token, row.id, now, expires).run();

  const res = json({ id: row.id, name: row.name, email: row.email, role: row.role });
  res.headers.append('Set-Cookie', sessionCookie(token, expires));
  return res;
}

async function handleLogout(request, env) {
  const token = getCookie(request, SESSION_COOKIE);
  if (token) await env.DB.prepare('DELETE FROM sessions WHERE token = ?').bind(token).run();
  const res = json({ ok: true });
  res.headers.append('Set-Cookie', sessionCookie('', 0));
  return res;
}

async function handleMe(request, env) {
  const user = await getSessionUser(request, env);
  if (!user) return json({ error: 'unauthorized' }, 401);
  return json({ id: user.id, name: user.name, email: user.email, role: user.role });
}

async function getSessionUser(request, env) {
  const token = getCookie(request, SESSION_COOKIE);
  if (!token) return null;
  const row = await env.DB.prepare(
    `SELECT users.* FROM sessions JOIN users ON users.id = sessions.user_id
     WHERE sessions.token = ? AND sessions.expires_at > ? AND users.active = 1`
  ).bind(token, Date.now()).first();
  return row || null;
}

function sessionCookie(token, expiresMs) {
  const expires = new Date(expiresMs || 0).toUTCString();
  return `${SESSION_COOKIE}=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Expires=${expires}`;
}
function getCookie(request, name) {
  const header = request.headers.get('Cookie') || '';
  const m = header.match(new RegExp('(?:^|; )' + name + '=([^;]+)'));
  return m ? decodeURIComponent(m[1]) : null;
}

/* -------- password hashing: PBKDF2-SHA256 via Web Crypto -------- */
async function hashPassword(password, saltHex) {
  const salt = saltHex ? hexToBytes(saltHex) : crypto.getRandomValues(new Uint8Array(16));
  const keyMaterial = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: 120000, hash: 'SHA-256' },
    keyMaterial,
    256
  );
  return { hash: bytesToHex(new Uint8Array(bits)), salt: bytesToHex(salt) };
}
async function verifyPassword(password, saltHex, expectedHashHex) {
  const { hash } = await hashPassword(password, saltHex);
  return timingSafeEqual(hash, expectedHashHex);
}
function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}
function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  return bytes;
}
function bytesToHex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}
function randomToken() {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return bytesToHex(bytes);
}

/* ============================ users (admin) ============================ */

async function listUsers(env, user) {
  if (user.role !== 'admin') return json({ error: 'forbidden' }, 403);
  const { results } = await env.DB.prepare('SELECT id, staff_id, name, email, role, active, created_at FROM users').all();
  return json({ users: results });
}
async function createUser(request, env, user) {
  if (user.role !== 'admin') return json({ error: 'forbidden' }, 403);
  let body;
  try { body = await request.json(); } catch (e) { return json({ error: 'invalid_json' }, 400); }
  const name = String(body.name || '').trim();
  const email = String(body.email || '').trim().toLowerCase();
  const password = String(body.password || '');
  const role = body.role === 'admin' ? 'admin' : 'staff';
  const staffId = body.staffId || null;
  if (!name || !email || password.length < 8) {
    return json({ error: 'invalid_fields', message: 'name, email and an 8+ character password are required' }, 400);
  }
  const { hash, salt } = await hashPassword(password, null);
  const id = 'u_' + randomToken().slice(0, 12);
  try {
    await env.DB.prepare(
      'INSERT INTO users (id, staff_id, name, email, password_hash, password_salt, role, active, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?)'
    ).bind(id, staffId, name, email, hash, salt, role, Date.now()).run();
  } catch (err) {
    return json({ error: 'email_taken' }, 409);
  }
  return json({ id, name, email, role });
}
async function deactivateUser(path, env, user) {
  if (user.role !== 'admin') return json({ error: 'forbidden' }, 403);
  const id = path.split('/')[2];
  await env.DB.prepare('UPDATE users SET active = 0 WHERE id = ?').bind(id).run();
  await env.DB.prepare('DELETE FROM sessions WHERE user_id = ?').bind(id).run();
  return json({ ok: true });
}

/* ============================ generic collections ============================ */
/* Each entry maps the app's flat document shape (what the original
   Artifact-hosted app already reads/writes) to and from its D1 table's
   columns. Adding a field
   to a document is just adding it to both directions here + a column in
   schema.sql — the rest of the app (and this file's HTTP layer) don't change. */

const COLLECTIONS = {
  staff: {
    table: 'staff',
    toRow: (d) => ({ id: d.id, name: d.name, role: d.role || '', color: d.color || '', phone: d.phone || '', active: d.active === false ? 0 : 1, created_at: d.createdAt || Date.now() }),
    toDoc: (r) => ({ id: r.id, name: r.name, role: r.role, color: r.color, phone: r.phone, active: !!r.active, createdAt: r.created_at }),
  },
  customers: {
    table: 'customers',
    toRow: (d) => ({ id: d.id, name: d.name, phone: d.phone || '', email: d.email || '', address: d.address || '', notes: d.notes || '', vehicles_json: JSON.stringify(d.vehicles || []), created_at: d.createdAt || Date.now() }),
    toDoc: (r) => ({ id: r.id, name: r.name, phone: r.phone, email: r.email, address: r.address, notes: r.notes, vehicles: JSON.parse(r.vehicles_json || '[]'), createdAt: r.created_at }),
  },
  bookings: {
    table: 'bookings',
    toRow: (d) => ({
      id: d.id, date: d.date || '', start: d.start || '', end: d.end || '', staff_id: d.staffId || '',
      job_type: d.jobType || '', reference: d.reference || '', customer_id: d.customerId || null,
      customer_json: JSON.stringify(d.customer || {}), vehicle_json: JSON.stringify(d.vehicle || {}),
      address: d.address || '', rate: Number(d.rate) || 0, notes: d.notes || '',
      service_items_json: JSON.stringify(d.serviceItems || []), status: d.status || 'booked', created_at: d.createdAt || Date.now(),
    }),
    toDoc: (r) => ({
      id: r.id, date: r.date, start: r.start, end: r.end, staffId: r.staff_id, jobType: r.job_type,
      reference: r.reference, customerId: r.customer_id, customer: JSON.parse(r.customer_json || '{}'),
      vehicle: JSON.parse(r.vehicle_json || '{}'), address: r.address, rate: r.rate, notes: r.notes,
      serviceItems: JSON.parse(r.service_items_json || '[]'), status: r.status, createdAt: r.created_at,
    }),
  },
  timeEntries: {
    table: 'time_entries',
    toRow: (d) => ({ id: d.id, booking_id: d.bookingId || '', staff_id: d.staffId || '', minutes: Number(d.minutes) || 0, item_id: d.itemId || null, note: d.note || '', date: d.date || '', created_at: d.createdAt || Date.now() }),
    toDoc: (r) => ({ id: r.id, bookingId: r.booking_id, staffId: r.staff_id, minutes: r.minutes, itemId: r.item_id, note: r.note, date: r.date, createdAt: r.created_at }),
  },
  invoices: {
    table: 'invoices',
    toRow: (d) => ({
      id: d.id, booking_id: d.bookingId || '', customer_name: d.customerName || '', reference: d.reference || '',
      line_items_json: JSON.stringify(d.lineItems || []), subtotal: Number(d.subtotal) || 0, gst: Number(d.gst) || 0,
      total: Number(d.total) || 0, photos_json: JSON.stringify(d.photos || []), photos_pending: d.photosPending ? 1 : 0,
      status: d.status || 'draft', created_at: d.createdAt || Date.now(), sent_at: d.sentAt || null,
      xero_invoice_id: d.xeroInvoiceId || null, xero_invoice_number: d.xeroInvoiceNumber || null, xero_invoice_url: d.xeroInvoiceUrl || null,
    }),
    toDoc: (r) => ({
      id: r.id, bookingId: r.booking_id, customerName: r.customer_name, reference: r.reference,
      lineItems: JSON.parse(r.line_items_json || '[]'), subtotal: r.subtotal, gst: r.gst, total: r.total,
      photos: JSON.parse(r.photos_json || '[]'), photosPending: !!r.photos_pending, status: r.status,
      createdAt: r.created_at, sentAt: r.sent_at, xeroInvoiceId: r.xero_invoice_id, xeroInvoiceNumber: r.xero_invoice_number, xeroInvoiceUrl: r.xero_invoice_url,
    }),
  },
  services: {
    table: 'services',
    toRow: (d) => ({ id: d.id, code: d.code || '', name: d.name || '', sales_description: d.salesDescription || '', sales_price: Number(d.salesPrice) || 0, cost_price: Number(d.costPrice) || 0, tax_rate: d.taxRate || '', standard_time_minutes: d.standardTimeMinutes != null ? Number(d.standardTimeMinutes) : null, active: d.active === false ? 0 : 1 }),
    toDoc: (r) => ({ id: r.id, code: r.code, name: r.name, salesDescription: r.sales_description, salesPrice: r.sales_price, costPrice: r.cost_price, taxRate: r.tax_rate, standardTimeMinutes: r.standard_time_minutes, active: !!r.active }),
  },
  products: {
    table: 'products',
    toRow: (d) => ({ id: d.id, code: d.code || '', name: d.name || '', sales_description: d.salesDescription || '', sales_price: Number(d.salesPrice) || 0, cost_price: Number(d.costPrice) || 0, tax_rate: d.taxRate || '', qty_in_stock: d.qtyInStock != null ? Number(d.qtyInStock) : null, active: d.active === false ? 0 : 1 }),
    toDoc: (r) => ({ id: r.id, code: r.code, name: r.name, salesDescription: r.sales_description, salesPrice: r.sales_price, costPrice: r.cost_price, taxRate: r.tax_rate, qtyInStock: r.qty_in_stock, active: !!r.active }),
  },
  settings: {
    table: 'settings',
    toRow: (d) => ({ id: d.id || 'company', company_name: d.companyName || '', abn: d.abn || '', phone: d.phone || '', email: d.email || '', address: d.address || '', labour_rate: Number(d.labourRate) || 0, xero_worker_url: d.xeroWorkerUrl || '' }),
    toDoc: (r) => ({ id: r.id, companyName: r.company_name, abn: r.abn, phone: r.phone, email: r.email, address: r.address, labourRate: r.labour_rate, xeroWorkerUrl: r.xero_worker_url }),
  },
};

async function listCollection(coll, env) {
  const def = COLLECTIONS[coll];
  const { results } = await env.DB.prepare(`SELECT * FROM ${def.table}`).all();
  return json({ docs: results.map(def.toDoc) });
}
async function upsertCollection(coll, id, request, env) {
  const def = COLLECTIONS[coll];
  let doc;
  try { doc = await request.json(); } catch (e) { return json({ error: 'invalid_json' }, 400); }
  doc.id = id;
  const row = def.toRow(doc);
  const cols = Object.keys(row);
  const placeholders = cols.map(() => '?').join(', ');
  const updates = cols.filter((c) => c !== 'id').map((c) => `${c} = excluded.${c}`).join(', ');
  const sql = `INSERT INTO ${def.table} (${cols.join(', ')}) VALUES (${placeholders})
               ON CONFLICT(id) DO UPDATE SET ${updates}`;
  await env.DB.prepare(sql).bind(...cols.map((c) => row[c])).run();
  return json({ ok: true, id });
}
async function deleteCollection(coll, id, env) {
  const def = COLLECTIONS[coll];
  await env.DB.prepare(`DELETE FROM ${def.table} WHERE id = ?`).bind(id).run();
  return json({ ok: true });
}

/* ============================ photos (R2) ============================ */

async function uploadPhoto(request, env, user) {
  const contentType = request.headers.get('Content-Type') || 'image/jpeg';
  if (contentType.indexOf('image/') !== 0) return json({ error: 'not_an_image' }, 400);
  const id = 'ph_' + randomToken().slice(0, 16);
  const key = 'invoice-photos/' + id;
  const body = await request.arrayBuffer();
  if (body.byteLength > 8 * 1024 * 1024) return json({ error: 'too_large' }, 413);
  await env.PHOTOS.put(key, body, { httpMetadata: { contentType } });
  await env.DB.prepare('INSERT INTO photos (id, r2_key, content_type, uploaded_by, created_at) VALUES (?, ?, ?, ?, ?)')
    .bind(id, key, contentType, user.id, Date.now()).run();
  return json({ id, url: '/api/photos/' + id, contentType });
}
async function servePhoto(path, env) {
  const id = path.split('/')[2];
  const row = await env.DB.prepare('SELECT * FROM photos WHERE id = ?').bind(id).first();
  if (!row) return json({ error: 'not_found' }, 404);
  const obj = await env.PHOTOS.get(row.r2_key);
  if (!obj) return json({ error: 'not_found' }, 404);
  return new Response(obj.body, { headers: { 'Content-Type': row.content_type, 'Cache-Control': 'private, max-age=3600' } });
}

/* ============================ Xero ============================ */
/* Talks directly to the existing nas-xero-connector Worker — plain
   server-to-server HTTPS, no URL-encoded payload tricks needed here since
   neither a browser CSP nor Claude's own tools are anywhere in this path. */

async function xeroProxy(env, path, method) {
  const headers = {};
  if (method === 'POST') headers.Authorization = 'Bearer ' + env.XERO_INTERNAL_TOKEN;
  const res = await fetch(env.XERO_WORKER_URL + path, { method, headers });
  const body = await res.text();
  return new Response(body, { status: res.status, headers: { 'Content-Type': 'application/json' } });
}

async function xeroConnectUrl(request, env) {
  const returnUrl = new URL(request.url).searchParams.get('return') || '';
  const target = env.XERO_WORKER_URL + '/connect?return=' + encodeURIComponent(returnUrl);
  return json({ url: target });
}

async function sendInvoiceToXero(id, env) {
  const def = COLLECTIONS.invoices;
  const row = await env.DB.prepare('SELECT * FROM invoices WHERE id = ?').bind(id).first();
  if (!row) return json({ error: 'not_found' }, 404);
  const doc = def.toDoc(row);
  if (doc.status === 'sent') return json({ ok: true, invoice: doc }); // already sent, idempotent

  const payload = {
    customerName: doc.customerName,
    reference: doc.reference,
    lineItems: doc.lineItems.map((li) => ({ description: li.desc, amount: li.amount })),
  };
  let xeroRes, xeroBody;
  try {
    xeroRes = await fetch(env.XERO_WORKER_URL + '/invoices', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: 'Bearer ' + env.XERO_INTERNAL_TOKEN,
      },
      body: JSON.stringify(payload),
    });
    xeroBody = await xeroRes.json();
  } catch (err) {
    return json({ error: 'xero_unreachable', message: String((err && err.message) || err) }, 502);
  }
  if (!xeroRes.ok || !xeroBody.ok) {
    return json({ error: 'xero_rejected', detail: xeroBody }, 502);
  }

  const now = Date.now();
  await env.DB.prepare(
    'UPDATE invoices SET status = ?, sent_at = ?, xero_invoice_id = ?, xero_invoice_number = ?, xero_invoice_url = ? WHERE id = ?'
  ).bind('sent', now, xeroBody.invoiceId, xeroBody.invoiceNumber, xeroBody.invoiceUrl, id).run();

  // Attach any photos synchronously too — straight from R2, no chunking or
  // URL tricks needed since this Worker is talking to the Xero connector
  // directly.
  const photosAttached = [];
  for (let i = 0; i < doc.photos.length; i++) {
    const p = doc.photos[i];
    if (!p.assetId && !p.photoId) continue; // nothing stored for this one
    const photoId = p.photoId || p.assetId;
    const attached = await attachPhotoToXero(env, xeroBody.invoiceId, photoId, 'photo-' + (i + 1) + '.jpg');
    photosAttached.push(Object.assign({}, p, { xeroAttached: attached }));
  }
  if (photosAttached.length) {
    await env.DB.prepare('UPDATE invoices SET photos_json = ?, photos_pending = 0 WHERE id = ?')
      .bind(JSON.stringify(photosAttached), id).run();
  }

  const updatedRow = await env.DB.prepare('SELECT * FROM invoices WHERE id = ?').bind(id).first();
  return json({ ok: true, invoice: def.toDoc(updatedRow) });
}

async function attachPhotoToXero(env, xeroInvoiceId, photoId, filename) {
  const row = await env.DB.prepare('SELECT * FROM photos WHERE id = ?').bind(photoId).first();
  if (!row) return false;
  const obj = await env.PHOTOS.get(row.r2_key);
  if (!obj) return false;
  try {
    const res = await fetch(
      env.XERO_WORKER_URL + '/internal/invoices/' + encodeURIComponent(xeroInvoiceId) + '/attachments/' + encodeURIComponent(filename),
      {
        method: 'PUT',
        headers: {
          Authorization: 'Bearer ' + env.XERO_INTERNAL_TOKEN,
          'Content-Type': row.content_type,
        },
        body: obj.body,
      }
    );
    return res.ok;
  } catch (err) {
    return false;
  }
}

/* ============================ utils ============================ */

function json(obj, status) {
  return new Response(JSON.stringify(obj), { status: status || 200, headers: { 'Content-Type': 'application/json' } });
}
