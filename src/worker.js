/**
 * Newcastle Automotive Solutions — standalone backend.
 *
 * Replaces the Claude Artifact 'db'/'assets' capabilities this app used to
 * run on. Serves the app's static frontend (via the Workers "assets"
 * binding — see wrangler.jsonc) and a small JSON API backed by D1 (data)
 * and R2 (photos), with real staff login (email + password, session
 * cookies) gating everything.
 *
 * Xero: this Worker talks to the existing `nas-xero-connector` Worker via a
 * Cloudflare **Service Binding** (env.XERO_WORKER — see wrangler.jsonc),
 * not a plain fetch() to its public URL. That matters: Cloudflare blocks a
 * Worker from fetch()-ing another Worker's *.workers.dev address directly
 * (Cloudflare error 1042 — a loop-prevention rule, not a config mistake),
 * so the original plain-fetch design could never have worked on the free
 * workers.dev domain both Workers run on here. A service binding calls the
 * other Worker's fetch() handler directly inside Cloudflare's network,
 * bypassing that restriction entirely (and it's the officially-recommended
 * way to do Worker-to-Worker calls in the same account regardless). The one
 * exception is the "Connect to Xero" button, which still needs the
 * connector's real public URL (XERO_WORKER_URL) because that one has to be
 * a full-page browser redirect, not a server-to-server call.
 *
 * Two-way Xero sync: the connector also pushes back the other direction now
 * — when an invoice is voided, deleted, or paid *in Xero itself*, Xero calls
 * the connector's /webhook endpoint, which looks up that invoice and calls
 * this Worker's POST /api/internal/xero-invoice-status with the result. That
 * route is authenticated with its own shared secret (WEBHOOK_FORWARD_TOKEN)
 * rather than a session cookie, since the caller is the connector Worker,
 * not a signed-in browser — see receiveXeroInvoiceStatus() below and
 * DEPLOY.md "Part 4B" for the one-time setup this needs in Xero's developer
 * portal.
 *
 * Customers also sync two ways with Xero Contacts now (added 2026-09-16, to
 * stop customers getting duplicated in Xero): every customer save here also
 * pushes to/links a Xero contact (syncCustomerToXero()), and an edit made to
 * that contact in Xero flows back via the same webhook mechanism (POST
 * /api/internal/xero-contact-update, handled by receiveXeroContactUpdate()).
 * Policy on a conflict: the app wins — see the doc comment above those two
 * functions for exactly how.
 *
 * Required bindings (see DEPLOY.md):
 *   D1 database        DB
 *   R2 bucket          PHOTOS
 *   service binding    XERO_WORKER   → the nas-xero-connector Worker
 *   var                XERO_WORKER_URL   (nas-xero-connector's public URL —
 *                       only used for the OAuth "Connect to Xero" redirect)
 *   secret             XERO_INTERNAL_TOKEN  (must equal TASK_TOKEN on that
 *                       Worker — see DEPLOY.md; this is what lets this
 *                       backend create invoices / attach photos / disconnect
 *                       Xero without anyone else who finds the connector's
 *                       URL being able to do the same)
 *   secret             WEBHOOK_FORWARD_TOKEN  (must equal APP_WEBHOOK_FORWARD_TOKEN
 *                       on the connector Worker — authenticates the reverse,
 *                       Xero-changed-something-so-tell-the-app direction)
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

  // Called by the Xero connector Worker, not a browser — its own shared-secret
  // check stands in for the session check every other route below needs.
  if (path === '/internal/xero-invoice-status' && method === 'POST') return receiveXeroInvoiceStatus(request, env);
  if (path === '/internal/xero-contact-update' && method === 'POST') return receiveXeroContactUpdate(request, env);

  // Everything else requires a signed-in session.
  const user = await getSessionUser(request, env);
  if (!user) return json({ error: 'unauthorized' }, 401);

  if (path === '/users' && method === 'GET') return listUsers(env, user);
  if (path === '/users' && method === 'POST') return createUser(request, env, user);
  if (path.match(/^\/users\/[^/]+$/) && method === 'DELETE') return deactivateUser(path, env, user);
  if (path === '/me/password' && method === 'POST') return changeOwnPassword(request, env, user);

  const collMatch = path.match(/^\/collections\/([a-zA-Z]+)(?:\/([^/]+))?$/);
  if (collMatch) {
    const [, coll, id] = collMatch;
    if (!COLLECTIONS[coll]) return json({ error: 'unknown_collection' }, 404);
    if (method === 'GET' && !id) return listCollection(coll, env);
    if (method === 'PUT' && id) {
      const result = await upsertCollection(coll, id, request, env);
      if (coll === 'customers') {
        // Best-effort, fire-and-forget-but-awaited: a customer save always
        // succeeds locally even if Xero is unreachable right now — this just
        // links/updates the matching Xero contact when it can. See "Customers
        // <-> Xero" below for why this lives here rather than in
        // upsertCollection() itself (that stays fully generic).
        try { await syncCustomerToXero(env, id); } catch (err) { /* retried on next save */ }
      }
      return result;
    }
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

  // One-off data-recovery route (2026-09-17) — see restoreCatalogPrices()
  // below for why this exists. Admin-only; safe to leave in and safe to
  // call more than once (it always sets the same known-correct numbers).
  if (path === '/internal/restore-catalog-prices' && method === 'GET') {
    if (user.role !== 'admin') return json({ error: 'forbidden' }, 403);
    return restoreCatalogPrices(env);
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

/* -------- password hashing: PBKDF2-SHA256 via Web Crypto --------
   Cloudflare Workers' PBKDF2 implementation caps iterations at 100,000
   (deriveBits throws "iteration counts above 100000 are not supported" for
   anything higher) — 100,000 is the max this runtime allows, so that's
   what's used here. */
const PBKDF2_ITERATIONS = 100000;
async function hashPassword(password, saltHex) {
  const salt = saltHex ? hexToBytes(saltHex) : crypto.getRandomValues(new Uint8Array(16));
  const keyMaterial = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
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
async function changeOwnPassword(request, env, user) {
  let body;
  try { body = await request.json(); } catch (e) { return json({ error: 'invalid_json' }, 400); }
  const currentPassword = String(body.currentPassword || '');
  const newPassword = String(body.newPassword || '');
  if (!currentPassword || newPassword.length < 8) {
    return json({ error: 'invalid_fields', message: 'current password and an 8+ character new password are required' }, 400);
  }
  const ok = await verifyPassword(currentPassword, user.password_salt, user.password_hash);
  if (!ok) return json({ error: 'invalid_current_password' }, 401);
  const { hash, salt } = await hashPassword(newPassword, null);
  await env.DB.prepare('UPDATE users SET password_hash = ?, password_salt = ? WHERE id = ?').bind(hash, salt, user.id).run();
  // Sign out every other session for this account so a changed password
  // actually locks out anyone who had the old one, rather than leaving
  // existing logged-in sessions valid indefinitely.
  const keepToken = getCookie(request, SESSION_COOKIE);
  await env.DB.prepare('DELETE FROM sessions WHERE user_id = ? AND token != ?').bind(user.id, keepToken || '').run();
  return json({ ok: true });
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
    // xero_contact_id / updated_at power the two-way Xero contact sync (see
    // syncCustomerToXero() / receiveXeroContactUpdate() below) — updated_at
    // is always stamped fresh here (not doc-controlled) so it reflects the
    // true last app-side write time, which is what "app wins on conflict"
    // is compared against.
    toRow: (d) => ({ id: d.id, name: d.name, phone: d.phone || '', email: d.email || '', address: d.address || '', notes: d.notes || '', vehicles_json: JSON.stringify(d.vehicles || []), created_at: d.createdAt || Date.now(), xero_contact_id: d.xeroContactId || null, updated_at: Date.now() }),
    toDoc: (r) => ({ id: r.id, name: r.name, phone: r.phone, email: r.email, address: r.address, notes: r.notes, vehicles: JSON.parse(r.vehicles_json || '[]'), createdAt: r.created_at, xeroContactId: r.xero_contact_id, updatedAt: r.updated_at }),
  },
  bookings: {
    table: 'bookings',
    toRow: (d) => ({
      id: d.id, date: d.date || '', start: d.start || '', end: d.end || '', staff_id: d.staffId || '',
      job_type: d.jobType || '', reference: d.reference || '', customer_id: d.customerId || null,
      customer_json: JSON.stringify(d.customer || {}), vehicle_json: JSON.stringify(d.vehicle || {}),
      address: d.address || '', rate: Number(d.rate) || 0, notes: d.notes || '',
      service_items_json: JSON.stringify(d.serviceItems || []),
      photos_json: JSON.stringify(d.photos || []),
      status: d.status || 'booked', created_at: d.createdAt || Date.now(),
    }),
    toDoc: (r) => ({
      id: r.id, date: r.date, start: r.start, end: r.end, staffId: r.staff_id, jobType: r.job_type,
      reference: r.reference, customerId: r.customer_id, customer: JSON.parse(r.customer_json || '{}'),
      vehicle: JSON.parse(r.vehicle_json || '{}'), address: r.address, rate: r.rate, notes: r.notes,
      serviceItems: JSON.parse(r.service_items_json || '[]'),
      photos: JSON.parse(r.photos_json || '[]'),
      status: r.status, createdAt: r.created_at,
    }),
  },
  timeEntries: {
    table: 'time_entries',
    // billable: whether this time counts toward the job's auto Labour line on
    // an invoice, vs. being logged for the record only (the "Bill this time"
    // checkbox on the Stop timer dialog — see unlinkedMinutesFor() in
    // public/index.html). Defaults true so entries that predate this field
    // keep behaving exactly as they did before.
    toRow: (d) => ({ id: d.id, booking_id: d.bookingId || '', staff_id: d.staffId || '', minutes: Number(d.minutes) || 0, item_id: d.itemId || null, note: d.note || '', date: d.date || '', billable: d.billable === false ? 0 : 1, created_at: d.createdAt || Date.now() }),
    toDoc: (r) => ({ id: r.id, bookingId: r.booking_id, staffId: r.staff_id, minutes: r.minutes, itemId: r.item_id, note: r.note, date: r.date, billable: r.billable == null ? true : !!r.billable, createdAt: r.created_at }),
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
    // Field names here MUST match what public/index.html actually sends/reads
    // (salesUnitPrice / purchasesUnitPrice / durationMins / status), not a
    // "cleaner" renamed version — see the doc comment above this block. This
    // was wrong before (salesPrice/costPrice/active/standardTimeMinutes),
    // which silently zeroed sales/cost price on every single save and made
    // the frontend's own active/archived + standard-time fields no-ops.
    toRow: (d) => ({ id: d.id, code: d.code || '', name: d.name || '', sales_description: d.salesDescription || '', sales_price: Number(d.salesUnitPrice) || 0, cost_price: d.purchasesUnitPrice != null ? Number(d.purchasesUnitPrice) : null, tax_rate: d.taxRate || '', standard_time_minutes: d.durationMins != null ? Number(d.durationMins) : null, active: d.status === 'Archived' ? 0 : 1 }),
    toDoc: (r) => ({ id: r.id, code: r.code, name: r.name, salesDescription: r.sales_description, salesUnitPrice: r.sales_price, purchasesUnitPrice: r.cost_price, taxRate: r.tax_rate, durationMins: r.standard_time_minutes, status: r.active ? 'Active' : 'Archived' }),
  },
  products: {
    table: 'products',
    // Same field-name fix as services above — matches public/index.html's
    // salesUnitPrice / purchasesUnitPrice / quantity / status exactly.
    toRow: (d) => ({ id: d.id, code: d.code || '', name: d.name || '', sales_description: d.salesDescription || '', sales_price: Number(d.salesUnitPrice) || 0, cost_price: d.purchasesUnitPrice != null ? Number(d.purchasesUnitPrice) : null, tax_rate: d.taxRate || '', qty_in_stock: d.quantity != null ? Number(d.quantity) : null, active: d.status === 'Archived' ? 0 : 1 }),
    toDoc: (r) => ({ id: r.id, code: r.code, name: r.name, salesDescription: r.sales_description, salesUnitPrice: r.sales_price, purchasesUnitPrice: r.cost_price, taxRate: r.tax_rate, quantity: r.qty_in_stock, status: r.active ? 'Active' : 'Archived' }),
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

/* ---- one-off price recovery (2026-09-17) ----
 * COLLECTIONS.services/products above used to read the wrong doc field names
 * (salesPrice/costPrice instead of the app's real salesUnitPrice/
 * purchasesUnitPrice) — every save, including the very first time this
 * database was seeded, silently wrote 0 into sales_price/cost_price. That
 * mapping bug is fixed now, but it can't undo rows that were already
 * overwritten. RESTORE_PRICES is exactly the salesUnitPrice/purchasesUnitPrice
 * pair for each of the original 36 services + 24 products, taken from the
 * same Xero inventory export (InventoryItems20260903.csv) this app was first
 * seeded from — [id, salesPrice, costPrice-or-null]. Only sales_price/
 * cost_price are touched; code/name/description/tax rate/active are left
 * exactly as they are now, so anything edited since isn't overwritten. */
const RESTORE_PRICES = {
  services: [['svc-adas-both',485.0,null],['svc-adas-both-terr-koul',550.0,null],['svc-adas-dynamic',265.0,null],['svc-adas-dynamic-terr-koul',395.0,null],['svc-adas-static',385.0,null],['svc-adas-static-terr-koul',395.0,null],['svc-batt-remove',175.0,null],['svc-brk-f',175.0,null],['svc-brk-r',175.0,null],['svc-disc-10',0.0,null],['svc-disc-30',0.0,null],['svc-el',9.5,null],['svc-ev-de-power-re-power-service',175.0,null],['svc-hire',0.0,0.0],['svc-lab',175.0,null],['svc-lab-hire',60.0,null],['svc-labour',80.0,0.0],['svc-late-fee',55.0,null],['svc-manufacturer-genuine-info',65.0,55.0],['svc-note',0.0,null],['svc-press',65.0,null],['svc-prog',395.0,null],['svc-programming-radar',365.0,null],['svc-rear-diff',175.0,0.0],['svc-rego',120.0,null],['svc-report',440.0,null],['svc-scan',135.0,null],['svc-scan-check',175.0,0.0],['svc-service',150.0,0.0],['svc-stolen',650.0,null],['svc-subframe',175.0,null],['svc-susp-4wd-l-h-f',650.0,null],['svc-susp-4wd-r-h-f',650.0,null],['svc-susp-l-h-f',495.0,null],['svc-susp-r-h-f',495.0,null],['svc-travel',1.0,null]],
  products: [['prod-75w85',30.0,22.0],['prod-75w85-fs',70.0,37.67],['prod-80w90',25.0,20.35],['prod-adblue',110.0,100.0],['prod-brake-fuid',19.0,13.5],['prod-cable',45.0,0.0],['prod-cons',12.0,2.0],['prod-coolant',12.0,7.0],['prod-cvt-fluid',110.0,73.97],['prod-dex-3',32.5,25.0],['prod-eng-oil',25.0,18.92],['prod-engine',6200.0,5000.0],['prod-fuel-diesel',1.95,1.9],['prod-fuel-unleaded',20.0,20.0],['prod-fuse',10.0,0.0],['prod-fuse-connector',20.0,15.19],['prod-h11',106.95,31.95],['prod-h7',45.0,34.5],['prod-harness',20.0,13.99],['prod-led-light',100.0,19.95],['prod-oil-filter',15.0,3.3],['prod-plug',5.5,0.22],['prod-spw',1.5,0.35],['prod-tubing',15.0,0.0]],
};
async function restoreCatalogPrices(env) {
  const stmts = [];
  for (const [id, salesPrice, costPrice] of RESTORE_PRICES.services) {
    stmts.push(env.DB.prepare('UPDATE services SET sales_price = ?, cost_price = ? WHERE id = ?').bind(salesPrice, costPrice, id));
  }
  for (const [id, salesPrice, costPrice] of RESTORE_PRICES.products) {
    stmts.push(env.DB.prepare('UPDATE products SET sales_price = ?, cost_price = ? WHERE id = ?').bind(salesPrice, costPrice, id));
  }
  const results = await env.DB.batch(stmts);
  const changed = results.reduce((sum, r) => sum + (r.meta && r.meta.changes ? r.meta.changes : 0), 0);
  return json({ ok: true, servicesUpdated: RESTORE_PRICES.services.length, productsUpdated: RESTORE_PRICES.products.length, rowsChanged: changed });
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
  const res = await env.XERO_WORKER.fetch('https://xero-worker.internal' + path, { method, headers });
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
    xeroRes = await env.XERO_WORKER.fetch('https://xero-worker.internal/invoices', {
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
  //
  // Every photo in doc.photos is kept in the rewritten list below (2026-09-17
  // fix) — the previous version only kept photos that had an assetId, so any
  // photo that failed to upload to R2 in the first place (no assetId at all)
  // silently vanished from the invoice's own saved record the moment it was
  // sent, on top of never reaching Xero. Now every photo keeps its place;
  // ones with nothing to attach just get xeroAttached:false, xeroAttachError
  // set to why.
  const photoErrors = [];
  const photosAttached = doc.photos.map((p, i) => ({ p, i }));
  for (const { p, i } of photosAttached) {
    const photoId = p.photoId || p.assetId;
    if (!photoId) {
      p.xeroAttached = false;
      p.xeroAttachError = 'never_uploaded';
      photoErrors.push('photo ' + (i + 1) + ': never finished uploading');
      continue;
    }
    const result = await attachPhotoToXero(env, xeroBody.invoiceId, photoId, 'photo-' + (i + 1) + '.jpg');
    p.xeroAttached = result.ok;
    p.xeroAttachError = result.ok ? null : result.error;
    if (!result.ok) photoErrors.push('photo ' + (i + 1) + ': ' + result.error);
  }
  if (doc.photos.length) {
    await env.DB.prepare('UPDATE invoices SET photos_json = ?, photos_pending = 0 WHERE id = ?')
      .bind(JSON.stringify(doc.photos), id).run();
  }

  const updatedRow = await env.DB.prepare('SELECT * FROM invoices WHERE id = ?').bind(id).first();
  const finalDoc = def.toDoc(updatedRow);

  // 2026-09-18, at the user's request: also email the invoice's photos
  // straight to the customer, the moment the invoice is sent — see
  // emailPhotosToCustomer() below for exactly what it does and doesn't do.
  // This must never block or fail the invoice send itself (the invoice is
  // already sent to Xero above by this point) — any problem here comes back
  // as `photoEmail` on the response for the frontend to show as a toast,
  // the same non-fatal pattern as `photoErrors` above.
  const photoEmail = await emailPhotosToCustomer(env, finalDoc).catch((err) => ({
    sent: false,
    reason: 'exception',
    detail: String((err && err.message) || err),
  }));

  return json({ ok: true, invoice: finalDoc, photoErrors: photoErrors.length ? photoErrors : undefined, photoEmail });
}

/* ============================ Email photos to customer ============================ */
/* Built 2026-09-18, at the user's request ("automatically send the attached
 * images to the clients email on file"), triggered from sendInvoiceToXero()
 * above at the moment an invoice is sent — not when photos are first
 * attached to a booking, and not as a separate manual button.
 *
 * Uses Resend (https://resend.com) — a plain HTTPS API call, no SDK needed,
 * which suits a Cloudflare Worker well. Two things this depends on, neither
 * of which this code can do for you:
 *   secret   RESEND_API_KEY     (Settings -> Variables and Secrets)
 *   var      EMAIL_FROM_ADDRESS (wrangler.jsonc "vars" — must be on a domain
 *                                verified with Resend; Resend will silently
 *                                refuse to deliver to a real customer address
 *                                from an unverified domain, only to the
 *                                account owner's own address, which is why
 *                                this can't just default to resend.dev)
 *   var      EMAIL_FROM_NAME    (wrangler.jsonc "vars" — display name only)
 * See DEPLOY.md "Part 6" for the one-time Resend/DNS setup this needs.
 *
 * Deliberately quiet about most non-problems: no photos on the invoice, no
 * booking linked, no customer linked, or no email on file for that customer
 * are all just "nothing to do here" (sent: false, reason: <why>), not
 * errors — plenty of bookings/customers legitimately have no email on file.
 * A real send failure (Resend rejects it, secret missing, etc.) is reported
 * back so the frontend can toast it, but never throws past this function.
 */
async function emailPhotosToCustomer(env, invoiceDoc) {
  if (!invoiceDoc.photos || !invoiceDoc.photos.length) {
    return { sent: false, reason: 'no_photos' };
  }
  if (!invoiceDoc.bookingId) {
    return { sent: false, reason: 'no_booking_linked' };
  }
  const booking = await env.DB.prepare('SELECT customer_id FROM bookings WHERE id = ?')
    .bind(invoiceDoc.bookingId).first();
  if (!booking || !booking.customer_id) {
    return { sent: false, reason: 'no_customer_linked' };
  }
  const customer = await env.DB.prepare('SELECT email FROM customers WHERE id = ?')
    .bind(booking.customer_id).first();
  if (!customer || !customer.email) {
    return { sent: false, reason: 'no_email_on_file' };
  }
  if (!env.RESEND_API_KEY || !env.EMAIL_FROM_ADDRESS) {
    return { sent: false, reason: 'email_not_configured' };
  }

  const attachments = [];
  for (let i = 0; i < invoiceDoc.photos.length; i++) {
    const p = invoiceDoc.photos[i];
    const photoId = p.photoId || p.assetId;
    if (!photoId) continue; // same "never finished uploading" case as the Xero attach loop above
    const row = await env.DB.prepare('SELECT * FROM photos WHERE id = ?').bind(photoId).first();
    if (!row) continue;
    const obj = await env.PHOTOS.get(row.r2_key);
    if (!obj) continue;
    const buf = await obj.arrayBuffer();
    attachments.push({
      filename: 'photo-' + (i + 1) + '.jpg',
      content: arrayBufferToBase64(buf),
      content_type: row.content_type || 'image/jpeg',
    });
  }
  if (!attachments.length) {
    return { sent: false, reason: 'no_photo_bytes_available' };
  }

  const fromName = env.EMAIL_FROM_NAME || 'Newcastle Automotive Solutions';
  const jobRef = invoiceDoc.reference || invoiceDoc.xeroInvoiceNumber || invoiceDoc.id;
  const html =
    '<p>Hi ' + escapeHtml(invoiceDoc.customerName || '') + ',</p>' +
    '<p>Here ' + (attachments.length === 1 ? 'is a photo' : 'are ' + attachments.length + ' photos') +
    ' from your recent job' + (jobRef ? ' (ref: ' + escapeHtml(String(jobRef)) + ')' : '') + '.</p>' +
    '<p>' + escapeHtml(fromName) + '</p>';

  let res, body;
  try {
    res = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        Authorization: 'Bearer ' + env.RESEND_API_KEY,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        from: fromName + ' <' + env.EMAIL_FROM_ADDRESS + '>',
        to: [customer.email],
        subject: 'Photos from your job' + (jobRef ? ' — ' + jobRef : ''),
        html,
        attachments,
      }),
    });
    body = await res.json().catch(() => ({}));
  } catch (err) {
    return { sent: false, reason: 'network_error', detail: String((err && err.message) || err) };
  }
  if (!res.ok) {
    return { sent: false, reason: 'resend_rejected', detail: (body && body.message) || ('http_' + res.status) };
  }
  return { sent: true, to: customer.email, count: attachments.length };
}

function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  const chunkSize = 0x8000; // avoid blowing the call stack on String.fromCharCode.apply for large photos
  for (let i = 0; i < bytes.length; i += chunkSize) {
    binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunkSize));
  }
  return btoa(binary);
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

/* ============================ Customers <-> Xero ============================ */
/* Two-way sync, added 2026-09-16 at the user's request, to stop customers
   getting duplicated in Xero. Policy: "app wins" on a conflict — a customer
   edited in the app always overwrites Xero on the next save, and an
   incoming Xero-side edit is only applied here if it's newer than this
   app's own last save (compared via customers.updated_at, stamped fresh on
   every app-side write — see COLLECTIONS.customers.toRow above). A brand
   new Xero contact is never auto-imported as a customer (only a contact
   already linked to one of our customers gets pulled), so Xero contacts for
   suppliers or other payees don't pollute the customer list. */

async function syncCustomerToXero(env, customerId) {
  const row = await env.DB.prepare('SELECT * FROM customers WHERE id = ?').bind(customerId).first();
  if (!row) return;
  const payload = { contactId: row.xero_contact_id || null, name: row.name, email: row.email || '', phone: row.phone || '', address: row.address || '' };
  let res, body;
  try {
    res = await env.XERO_WORKER.fetch('https://xero-worker.internal/contacts', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + env.XERO_INTERNAL_TOKEN },
      body: JSON.stringify(payload),
    });
    body = await res.json();
  } catch (err) {
    return; // Xero/connector unreachable right now — the next customer save retries this
  }
  if (res.ok && body.ok && body.contactId && body.contactId !== row.xero_contact_id) {
    await env.DB.prepare('UPDATE customers SET xero_contact_id = ? WHERE id = ?').bind(body.contactId, customerId).run();
  }
}

/**
 * Receives the "this contact changed in Xero" relay from the connector
 * Worker's /webhook handler. Only ever updates a customer already linked to
 * this Xero contact (never creates a new one) and only if the app's own
 * copy isn't newer — see the policy note above.
 */
async function receiveXeroContactUpdate(request, env) {
  const auth = request.headers.get('Authorization') || '';
  const token = auth.replace(/^Bearer\s+/i, '');
  if (!env.WEBHOOK_FORWARD_TOKEN || token !== env.WEBHOOK_FORWARD_TOKEN) {
    return json({ error: 'unauthorized' }, 401);
  }
  let body;
  try { body = await request.json(); } catch (e) { return json({ error: 'invalid_json' }, 400); }
  const xeroContactId = String(body.xeroContactId || '');
  if (!xeroContactId) return json({ error: 'missing_fields' }, 400);

  const row = await env.DB.prepare('SELECT * FROM customers WHERE xero_contact_id = ?').bind(xeroContactId).first();
  if (!row) return json({ ok: true, matched: false }); // not linked to any customer here — app-wins policy: never auto-import

  const xeroUpdatedAt = body.xeroUpdatedAt ? new Date(body.xeroUpdatedAt).getTime() : 0;
  if (row.updated_at && xeroUpdatedAt && row.updated_at >= xeroUpdatedAt) {
    return json({ ok: true, matched: true, skipped: 'app_newer' }); // app wins — this app-side edit came after Xero's
  }

  await env.DB.prepare(
    'UPDATE customers SET name = ?, email = ?, phone = ?, address = ?, updated_at = ? WHERE id = ?'
  ).bind(body.name || row.name, body.email || '', body.phone || '', body.address || '', xeroUpdatedAt || Date.now(), row.id).run();
  return json({ ok: true, matched: true, updated: true });
}

/**
 * Receives the "this invoice changed in Xero" relay from the connector
 * Worker's /webhook handler (see the doc comment at the top of this file).
 * Maps Xero's own Status values onto this app's much smaller status set:
 * VOIDED/DELETED both become this app's 'void' (see the "Mark as void"
 * feature — this is the automatic version of the same thing), and PAID
 * becomes 'paid'. AUTHORISED/SUBMITTED/DRAFT on the Xero side don't need any
 * change here — this app's own 'sent' already covers all of those.
 */
async function receiveXeroInvoiceStatus(request, env) {
  const auth = request.headers.get('Authorization') || '';
  const token = auth.replace(/^Bearer\s+/i, '');
  if (!env.WEBHOOK_FORWARD_TOKEN || token !== env.WEBHOOK_FORWARD_TOKEN) {
    return json({ error: 'unauthorized' }, 401);
  }
  let body;
  try { body = await request.json(); } catch (e) { return json({ error: 'invalid_json' }, 400); }
  const xeroInvoiceId = String(body.xeroInvoiceId || '');
  const xeroStatus = String(body.xeroStatus || '').toUpperCase();
  if (!xeroInvoiceId || !xeroStatus) return json({ error: 'missing_fields' }, 400);

  const row = await env.DB.prepare('SELECT * FROM invoices WHERE xero_invoice_id = ?').bind(xeroInvoiceId).first();
  if (!row) return json({ ok: true, matched: false }); // not (yet) one of ours — nothing to do

  let newStatus = null;
  if (xeroStatus === 'VOIDED' || xeroStatus === 'DELETED') newStatus = 'void';
  else if (xeroStatus === 'PAID') newStatus = 'paid';

  if (newStatus && newStatus !== row.status) {
    await env.DB.prepare('UPDATE invoices SET status = ? WHERE id = ?').bind(newStatus, row.id).run();
  }
  return json({ ok: true, matched: true, status: newStatus || row.status });
}

// Returns {ok, error} instead of a plain boolean (2026-09-17) — the previous
// version collapsed every failure reason (missing photo row, missing R2
// object, the connector/Xero rejecting the PUT, a network error) into a bare
// `false`, so when the user reported photos never showing up on the actual
// Xero invoice there was nothing in this app to point at why. The real cause
// turned out to be a missing OAuth scope (see the SCOPES comment in
// xero-worker/worker.js) — Xero's Attachments API was silently 403-ing every
// call — but that fix only helps *future* connections; this change makes the
// next failure (of any kind) visible instead of silent.
async function attachPhotoToXero(env, xeroInvoiceId, photoId, filename) {
  const row = await env.DB.prepare('SELECT * FROM photos WHERE id = ?').bind(photoId).first();
  if (!row) return { ok: false, error: 'photo_row_missing' };
  const obj = await env.PHOTOS.get(row.r2_key);
  if (!obj) return { ok: false, error: 'r2_object_missing' };
  try {
    const res = await env.XERO_WORKER.fetch(
      'https://xero-worker.internal/internal/invoices/' + encodeURIComponent(xeroInvoiceId) + '/attachments/' + encodeURIComponent(filename),
      {
        method: 'PUT',
        headers: {
          Authorization: 'Bearer ' + env.XERO_INTERNAL_TOKEN,
          'Content-Type': row.content_type,
        },
        body: obj.body,
      }
    );
    if (res.ok) return { ok: true, error: null };
    const detail = await res.text().catch(() => '');
    return { ok: false, error: (detail || ('http_' + res.status)).slice(0, 300) };
  } catch (err) {
    return { ok: false, error: String((err && err.message) || err).slice(0, 300) };
  }
}

/* ============================ utils ============================ */

function json(obj, status) {
  return new Response(JSON.stringify(obj), { status: status || 200, headers: { 'Content-Type': 'application/json' } });
}
