/**
 * Newcastle Automotive Solutions — customer portal backend (added 2026-10-06).
 *
 * What this is: existing customers and fleet clients get their own login
 * (invite-only — a customer can never sign themselves up) to a separate
 * portal page (public/portal/index.html). From there they can submit job
 * requests with a preferred date/time, vehicle, description and photos, then
 * follow the request's status. Staff review each request in the app's new
 * "Requests" tab, can change the date/time/technician, and approve or decline
 * it. Approving creates the real booking on the schedule and emails the
 * customer the confirmed (or adjusted) booking, with a calendar file.
 *
 * Isolation (the important part): customer logins live in their own tables
 * (customer_users / customer_sessions), use their own cookie
 * (nas_portal, Path=/api/portal so the browser never even sends it to a staff
 * route) and are only ever checked by the /api/portal/* handlers in this
 * file. A customer session can therefore never reach a staff route, and a
 * staff session is never accepted by a portal route. Every portal query is
 * scoped by the signed-in login's own customer_id taken from the database —
 * never from anything the browser sends.
 *
 * Needs three new D1 tables (see migration/portal.sql): customer_users,
 * customer_sessions, job_requests, plus rate_limits. Email uses the same
 * Resend setup as the rest of the app (RESEND_API_KEY secret,
 * EMAIL_FROM_ADDRESS / EMAIL_FROM_NAME vars). Everything degrades quietly if
 * email isn't configured — the staff member is told, nothing crashes.
 */

const PORTAL_COOKIE = 'nas_portal';
const PORTAL_SESSION_DAYS = 14;
const INVITE_HOURS = 24 * 7;
const RESET_HOURS = 2;
const MIN_PASSWORD = 10;
const MAX_PHOTOS = 6;
const MAX_PHOTO_BYTES = 6 * 1024 * 1024;
const JOB_TYPES = ['mechanical', 'adas', 'both'];
const JOB_TYPE_LABEL = { mechanical: 'Mechanical', adas: 'ADAS Calibration', both: 'Mechanical + ADAS' };
// Default job length when staff approve a request — only a starting point in
// the review form, staff can change it before approving.
const DEFAULT_MINUTES = { mechanical: 90, adas: 120, both: 210 };
const TZ = 'Australia/Sydney';
const PBKDF2_ITERATIONS = 100000;

/* ============================ small helpers ============================ */

function json(obj, status, extraHeaders) {
  const headers = Object.assign({ 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }, extraHeaders || {});
  return new Response(JSON.stringify(obj), { status: status || 200, headers });
}
function escapeHtml(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}
function bytesToHex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}
function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  return bytes;
}
function randomHex(n) {
  return bytesToHex(crypto.getRandomValues(new Uint8Array(n)));
}
async function sha256Hex(str) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
  return bytesToHex(new Uint8Array(buf));
}
function timingSafeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}
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
const DUMMY_SALT = '00112233445566778899aabbccddeeff';
function getCookie(request, name) {
  const header = request.headers.get('Cookie') || '';
  const m = header.match(new RegExp('(?:^|; )' + name + '=([^;]+)'));
  return m ? decodeURIComponent(m[1]) : null;
}
function portalCookie(token, expiresMs) {
  const expires = new Date(expiresMs || 0).toUTCString();
  // Path=/api/portal: the browser only ever sends this cookie to portal
  // routes. SameSite=Strict: never sent on a request started by another site.
  return `${PORTAL_COOKIE}=${token}; Path=/api/portal; HttpOnly; Secure; SameSite=Strict; Expires=${expires}`;
}
async function readJson(request, maxBytes) {
  try {
    const text = await request.text();
    if (text.length > (maxBytes || 65536)) return null;
    const v = JSON.parse(text || '{}');
    return v && typeof v === 'object' && !Array.isArray(v) ? v : null;
  } catch (e) {
    return null;
  }
}
function str(v, max) {
  return String(v == null ? '' : v).trim().slice(0, max);
}
function validEmail(e) {
  return /^[^\s@<>"']+@[^\s@<>"']+\.[^\s@<>"']+$/.test(e) && e.length <= 200;
}
function validDate(s) {
  if (typeof s !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(s)) return false;
  const d = new Date(s + 'T00:00:00Z');
  return !isNaN(d.getTime()) && d.toISOString().slice(0, 10) === s;
}
function validTime(s) {
  return typeof s === 'string' && /^([01]\d|2[0-3]):[0-5]\d$/.test(s);
}
function todayISO() {
  return new Date().toLocaleDateString('en-CA', { timeZone: TZ }); // en-CA prints YYYY-MM-DD
}
function addDaysISO(iso, n) {
  const d = new Date(iso + 'T00:00:00Z');
  d.setUTCDate(d.getUTCDate() + n);
  return d.toISOString().slice(0, 10);
}
function addMinutesToTime(hhmm, mins) {
  const total = Math.min(23 * 60 + 59, Number(hhmm.slice(0, 2)) * 60 + Number(hhmm.slice(3, 5)) + mins);
  return String(Math.floor(total / 60)).padStart(2, '0') + ':' + String(total % 60).padStart(2, '0');
}
function fmtDateLong(iso) {
  return new Date(iso + 'T00:00:00Z').toLocaleDateString('en-AU', { timeZone: 'UTC', weekday: 'long', day: 'numeric', month: 'long', year: 'numeric' });
}
function fmtTime12(t) {
  const h = Number(t.slice(0, 2));
  const m = t.slice(3, 5);
  return ((h % 12) || 12) + ':' + m + (h >= 12 ? ' pm' : ' am');
}
function newId(prefix) {
  return prefix + '_' + randomHex(8);
}
function jparse(s, fallback) {
  try { return JSON.parse(s || ''); } catch (e) { return fallback; }
}

/* A small fixed-window counter in D1 — stops password guessing, invite/reset
   email spam and request flooding without needing any extra service. */
async function rateLimit(env, key, limit, windowSeconds) {
  const now = Date.now();
  const resetAt = now + windowSeconds * 1000;
  const row = await env.DB.prepare(
    `INSERT INTO rate_limits (key, count, reset_at) VALUES (?, 1, ?)
     ON CONFLICT(key) DO UPDATE SET
       count = CASE WHEN reset_at < ? THEN 1 ELSE count + 1 END,
       reset_at = CASE WHEN reset_at < ? THEN ? ELSE reset_at END
     RETURNING count`
  ).bind(key, resetAt, now, now, resetAt).first();
  return !!row && row.count <= limit;
}
function clientIp(request) {
  return request.headers.get('CF-Connecting-IP') || 'unknown';
}

/* ============================ email ============================ */

async function getCompany(env) {
  let row = null;
  try {
    row = await env.DB.prepare("SELECT company_name, phone, email FROM settings WHERE id = 'company'").first();
  } catch (e) { /* settings row may not exist yet */ }
  return {
    name: (row && row.company_name) || env.EMAIL_FROM_NAME || 'Newcastle Automotive Solutions',
    phone: (row && row.phone) || '',
    email: (row && row.email) || env.NOTIFY_EMAIL || '',
  };
}

async function sendEmail(env, msg) {
  if (!env.RESEND_API_KEY || !env.EMAIL_FROM_ADDRESS) return { ok: false, reason: 'email_not_configured' };
  const company = await getCompany(env);
  const fromName = env.EMAIL_FROM_NAME || company.name;
  const payload = {
    from: fromName + ' <' + env.EMAIL_FROM_ADDRESS + '>',
    to: [msg.to],
    subject: msg.subject,
    html: msg.html,
  };
  if (msg.text) payload.text = msg.text;
  if (company.email) payload.reply_to = company.email;
  if (msg.attachments && msg.attachments.length) payload.attachments = msg.attachments;
  try {
    const res = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: { Authorization: 'Bearer ' + env.RESEND_API_KEY, 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const body = await res.json().catch(() => ({}));
    if (!res.ok) return { ok: false, reason: 'resend_rejected', detail: (body && body.message) || 'http_' + res.status };
    return { ok: true };
  } catch (err) {
    return { ok: false, reason: 'network_error', detail: String((err && err.message) || err) };
  }
}

function emailShell(company, heading, bodyHtml) {
  return (
    '<div style="font-family:-apple-system,Segoe UI,Roboto,Arial,sans-serif;max-width:560px;margin:0 auto;color:#151a22">' +
    '<div style="border-top:4px solid #ff6a1a;padding:18px 0 4px"><div style="font-size:13px;color:#5b6573">' + escapeHtml(company.name) + '</div>' +
    '<h2 style="margin:6px 0 14px;font-size:20px">' + escapeHtml(heading) + '</h2></div>' +
    bodyHtml +
    '<p style="margin-top:22px;font-size:13px;color:#5b6573">' + escapeHtml(company.name) +
    (company.phone ? ' · ' + escapeHtml(company.phone) : '') + '</p></div>'
  );
}
function detailsTable(rows) {
  return (
    '<table style="border-collapse:collapse;width:100%;margin:10px 0">' +
    rows.filter((r) => r && r[1]).map((r) =>
      '<tr><td style="padding:6px 10px 6px 0;color:#5b6573;vertical-align:top;white-space:nowrap">' + escapeHtml(r[0]) +
      '</td><td style="padding:6px 0;font-weight:600">' + escapeHtml(r[1]) + '</td></tr>'
    ).join('') + '</table>'
  );
}
function buttonLink(href, label) {
  return '<p style="margin:18px 0"><a href="' + escapeHtml(href) + '" style="background:#ff6a1a;color:#fff;text-decoration:none;padding:11px 20px;border-radius:8px;font-weight:700;display:inline-block">' +
    escapeHtml(label) + '</a></p>' +
    '<p style="font-size:12px;color:#5b6573;word-break:break-all">If the button does not work, paste this into your browser:<br>' + escapeHtml(href) + '</p>';
}

function icsEscape(s) {
  return String(s || '').replace(/\\/g, '\\\\').replace(/;/g, '\\;').replace(/,/g, '\\,').replace(/\r?\n/g, '\\n');
}
function buildIcs(booking, company) {
  const stamp = new Date().toISOString().replace(/[-:]/g, '').replace(/\.\d{3}/, '');
  const dt = (d, t) => d.replace(/-/g, '') + 'T' + t.replace(':', '') + '00';
  return [
    'BEGIN:VCALENDAR', 'VERSION:2.0', 'PRODID:-//Newcastle Automotive Solutions//Portal//EN', 'CALSCALE:GREGORIAN', 'METHOD:PUBLISH',
    'BEGIN:VEVENT',
    'UID:booking-' + booking.id + '@newcastle-automotive-solutions',
    'DTSTAMP:' + stamp,
    'DTSTART:' + dt(booking.date, booking.start), // floating local time — same wall-clock time wherever it is opened
    'DTEND:' + dt(booking.date, booking.end),
    'SUMMARY:' + icsEscape(company.name + ' — ' + (JOB_TYPE_LABEL[booking.jobType] || 'Job')),
    'LOCATION:' + icsEscape(booking.address),
    'DESCRIPTION:' + icsEscape('Vehicle: ' + booking.vehicleText + (booking.reference ? '\nRef: ' + booking.reference : '')),
    'END:VEVENT', 'END:VCALENDAR',
  ].join('\r\n');
}
function toBase64(str) {
  const bytes = new TextEncoder().encode(str);
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}

/* ============================ docs ============================ */

function vehicleText(v) {
  return [v && v.rego, v && v.makeModel].filter(Boolean).join(' — ');
}

// What the customer is allowed to see of their own request — no internal
// notes, no staff last names, no booking/invoice internals.
function requestForPortal(r) {
  const photos = jparse(r.photos_json, []);
  return {
    id: r.id,
    ref: r.ref,
    jobType: r.job_type,
    vehicle: jparse(r.vehicle_json, {}),
    address: r.address,
    contactPhone: r.contact_phone || '',
    reference: r.reference || '',
    description: r.description,
    preferredDate: r.preferred_date,
    preferredStart: r.preferred_start,
    flexible: !!r.flexible,
    photos: photos.map((id) => ({ id, url: '/api/portal/photos/' + id })),
    status: r.status,
    createdAt: r.created_at,
    decidedAt: r.decided_at || null,
    approvedDate: r.approved_date || null,
    approvedStart: r.approved_start || null,
    approvedEnd: r.approved_end || null,
    adjusted: !!r.adjusted,
    staffMessage: r.staff_message || '',
    staffFirstName: r.staff_name ? String(r.staff_name).split(/\s+/)[0] : '',
  };
}

// The full record, for the staff-side Requests screen (served through the
// existing generic /api/collections/jobRequests list route).
function jobRequestToDoc(r) {
  const photos = jparse(r.photos_json, []);
  return {
    id: r.id,
    ref: r.ref,
    customerId: r.customer_id,
    requestedBy: r.requested_by,
    requesterName: r.requester_name,
    requesterEmail: r.requester_email,
    jobType: r.job_type,
    vehicle: jparse(r.vehicle_json, {}),
    address: r.address,
    contactPhone: r.contact_phone || '',
    reference: r.reference || '',
    description: r.description,
    preferredDate: r.preferred_date,
    preferredStart: r.preferred_start,
    flexible: !!r.flexible,
    photos: photos.map((id) => ({ id, url: '/api/photos/' + id })),
    status: r.status,
    createdAt: r.created_at,
    decidedAt: r.decided_at || null,
    decidedBy: r.decided_by || '',
    approvedDate: r.approved_date || null,
    approvedStart: r.approved_start || null,
    approvedEnd: r.approved_end || null,
    approvedStaffId: r.approved_staff_id || null,
    adjusted: !!r.adjusted,
    staffMessage: r.staff_message || '',
    bookingId: r.booking_id || null,
  };
}

/* ============================ sessions ============================ */

async function getPortalUser(request, env) {
  const token = getCookie(request, PORTAL_COOKIE);
  if (!token || !/^[0-9a-f]{64}$/.test(token)) return null;
  const th = await sha256Hex(token);
  const row = await env.DB.prepare(
    `SELECT cu.* FROM customer_sessions s JOIN customer_users cu ON cu.id = s.user_id
     WHERE s.token_hash = ? AND s.expires_at > ? AND cu.active = 1`
  ).bind(th, Date.now()).first();
  return row || null;
}
async function startSession(env, user, extraHeaders) {
  const token = randomHex(32);
  const now = Date.now();
  const expires = now + PORTAL_SESSION_DAYS * 24 * 3600 * 1000;
  await env.DB.prepare('INSERT INTO customer_sessions (token_hash, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)')
    .bind(await sha256Hex(token), user.id, now, expires).run();
  await env.DB.prepare('UPDATE customer_users SET last_login_at = ? WHERE id = ?').bind(now, user.id).run();
  return portalCookie(token, expires);
}

/* ============================ portal routes ============================ */

export async function handlePortalApi(request, env, ctx, url, path) {
  const method = request.method;

  // Belt and braces on top of SameSite=Strict: a state-changing request from
  // a browser always carries an Origin header — if it isn't this site, refuse.
  if (method !== 'GET') {
    const origin = request.headers.get('Origin');
    if (origin && origin !== url.origin) return json({ error: 'bad_origin' }, 403);
  }

  // ---- no session needed ----
  if (path === '/portal/login' && method === 'POST') return portalLogin(request, env);
  if (path === '/portal/token-info' && method === 'POST') return portalTokenInfo(request, env);
  if (path === '/portal/set-password' && method === 'POST') return portalSetPassword(request, env);
  if (path === '/portal/forgot' && method === 'POST') return portalForgot(request, env, ctx, url);
  if (path === '/portal/logout' && method === 'POST') {
    const token = getCookie(request, PORTAL_COOKIE);
    if (token && /^[0-9a-f]{64}$/.test(token)) {
      await env.DB.prepare('DELETE FROM customer_sessions WHERE token_hash = ?').bind(await sha256Hex(token)).run();
    }
    return json({ ok: true }, 200, { 'Set-Cookie': portalCookie('', 0) });
  }

  // ---- session required ----
  const user = await getPortalUser(request, env);
  if (!user) return json({ error: 'unauthorized' }, 401);

  if (path === '/portal/me' && method === 'GET') return portalMe(env, user);
  if (path === '/portal/password' && method === 'POST') return portalChangePassword(request, env, user);
  if (path === '/portal/requests' && method === 'POST') return portalCreateRequest(request, env, ctx, user, url);
  const cancelMatch = path.match(/^\/portal\/requests\/([A-Za-z0-9_]+)\/cancel$/);
  if (cancelMatch && method === 'POST') return portalCancelRequest(env, ctx, user, cancelMatch[1]);
  if (path === '/portal/photos' && method === 'POST') return portalUploadPhoto(request, env, user);
  const photoMatch = path.match(/^\/portal\/photos\/([A-Za-z0-9_]+)$/);
  if (photoMatch && method === 'GET') return portalServePhoto(env, user, photoMatch[1]);

  return json({ error: 'not_found' }, 404);
}

async function portalLogin(request, env) {
  const body = await readJson(request, 4096);
  if (!body) return json({ error: 'invalid_json' }, 400);
  const email = str(body.email, 200).toLowerCase();
  const password = String(body.password || '').slice(0, 200);
  if (!email || !password) return json({ error: 'missing_credentials' }, 400);

  // Clean out stale counters now and then so the table never grows.
  if (Math.random() < 0.05) {
    await env.DB.prepare('DELETE FROM rate_limits WHERE reset_at < ?').bind(Date.now()).run().catch(() => {});
    await env.DB.prepare('DELETE FROM customer_sessions WHERE expires_at < ?').bind(Date.now()).run().catch(() => {});
  }
  const okIp = await rateLimit(env, 'login:ip:' + clientIp(request), 40, 900);
  const okEmail = await rateLimit(env, 'login:email:' + email, 8, 900);
  if (!okIp || !okEmail) return json({ error: 'too_many_attempts' }, 429);

  const row = await env.DB.prepare('SELECT * FROM customer_users WHERE email = ? AND active = 1').bind(email).first();
  // Always do the same amount of hashing work whether or not the account
  // exists, so response time doesn't reveal which emails have logins.
  const check = await hashPassword(password, row && row.password_salt ? row.password_salt : DUMMY_SALT);
  if (!row || !row.password_hash || !timingSafeEqual(check.hash, row.password_hash)) {
    return json({ error: 'invalid_login' }, 401);
  }
  const cookie = await startSession(env, row);
  return json({ ok: true }, 200, { 'Set-Cookie': cookie });
}

async function findUserByToken(env, token, kind) {
  if (typeof token !== 'string' || !/^[0-9a-f]{64}$/.test(token)) return null;
  const th = await sha256Hex(token);
  const row = await env.DB.prepare(
    'SELECT * FROM customer_users WHERE token_hash = ? AND token_expires > ? AND active = 1'
  ).bind(th, Date.now()).first();
  if (!row) return null;
  if (kind && row.token_kind !== kind) return null;
  return row;
}

async function portalTokenInfo(request, env) {
  const body = await readJson(request, 4096);
  if (!body) return json({ error: 'invalid_json' }, 400);
  if (!(await rateLimit(env, 'token:ip:' + clientIp(request), 30, 900))) return json({ error: 'too_many_attempts' }, 429);
  const row = await findUserByToken(env, body.token);
  if (!row) return json({ error: 'invalid_or_expired' }, 400);
  const cust = await env.DB.prepare('SELECT name FROM customers WHERE id = ?').bind(row.customer_id).first();
  return json({ ok: true, kind: row.token_kind, name: row.name, email: row.email, customerName: cust ? cust.name : '' });
}

async function portalSetPassword(request, env) {
  const body = await readJson(request, 4096);
  if (!body) return json({ error: 'invalid_json' }, 400);
  if (!(await rateLimit(env, 'token:ip:' + clientIp(request), 30, 900))) return json({ error: 'too_many_attempts' }, 429);
  const password = String(body.password || '');
  if (password.length < MIN_PASSWORD || password.length > 200) {
    return json({ error: 'weak_password', message: 'Password must be at least ' + MIN_PASSWORD + ' characters.' }, 400);
  }
  const row = await findUserByToken(env, body.token);
  if (!row) return json({ error: 'invalid_or_expired' }, 400);
  if (password.toLowerCase() === row.email.toLowerCase()) {
    return json({ error: 'weak_password', message: 'Password cannot be your email address.' }, 400);
  }
  const { hash, salt } = await hashPassword(password, null);
  // Single use: the token is cleared the moment it's used. Any other
  // signed-in session for this login is dropped too (a reset must lock out
  // whoever had the old password).
  await env.DB.prepare(
    'UPDATE customer_users SET password_hash = ?, password_salt = ?, token_hash = NULL, token_kind = NULL, token_expires = NULL WHERE id = ?'
  ).bind(hash, salt, row.id).run();
  await env.DB.prepare('DELETE FROM customer_sessions WHERE user_id = ?').bind(row.id).run();
  const cookie = await startSession(env, row);
  return json({ ok: true }, 200, { 'Set-Cookie': cookie });
}

async function portalForgot(request, env, ctx, url) {
  const body = await readJson(request, 4096);
  if (!body) return json({ error: 'invalid_json' }, 400);
  const email = str(body.email, 200).toLowerCase();
  // Same answer whether or not the email has a login — never reveal who does.
  const generic = json({ ok: true });
  if (!validEmail(email)) return generic;
  if (!(await rateLimit(env, 'forgot:ip:' + clientIp(request), 10, 3600))) return generic;
  if (!(await rateLimit(env, 'forgot:email:' + email, 3, 3600))) return generic;
  const row = await env.DB.prepare('SELECT * FROM customer_users WHERE email = ? AND active = 1').bind(email).first();
  if (!row) return generic;
  const work = issueToken(env, row, 'reset', url.origin);
  if (ctx && ctx.waitUntil) ctx.waitUntil(work); else await work;
  return generic;
}

async function issueToken(env, row, kind, origin) {
  const token = randomHex(32);
  const hours = kind === 'invite' ? INVITE_HOURS : RESET_HOURS;
  await env.DB.prepare('UPDATE customer_users SET token_hash = ?, token_kind = ?, token_expires = ? WHERE id = ?')
    .bind(await sha256Hex(token), kind, Date.now() + hours * 3600 * 1000, row.id).run();
  const company = await getCompany(env);
  // The token goes in the URL *fragment* (#t=...), which browsers never send
  // to any server, so it can't end up in access logs or Referer headers.
  const link = origin + '/portal/#t=' + token;
  let heading, bodyHtml, subject;
  if (kind === 'invite') {
    subject = 'Your ' + company.name + ' customer portal login';
    heading = 'Set up your customer portal login';
    bodyHtml =
      '<p>Hi ' + escapeHtml(row.name) + ',</p>' +
      '<p>' + escapeHtml(company.name) + ' has set you up with a customer portal login, where you can request jobs, pick a preferred date and time, and follow their progress.</p>' +
      buttonLink(link, 'Create your password') +
      '<p style="font-size:13px;color:#5b6573">This link works once and expires in ' + Math.round(INVITE_HOURS / 24) + ' days. Your login email is <strong>' + escapeHtml(row.email) + '</strong>.</p>';
  } else {
    subject = 'Reset your ' + company.name + ' portal password';
    heading = 'Reset your password';
    bodyHtml =
      '<p>Hi ' + escapeHtml(row.name) + ',</p>' +
      '<p>Someone asked to reset the password for this portal login. If that was you, use the button below. If not, you can ignore this email — your password has not changed.</p>' +
      buttonLink(link, 'Choose a new password') +
      '<p style="font-size:13px;color:#5b6573">This link works once and expires in ' + RESET_HOURS + ' hours.</p>';
  }
  return sendEmail(env, { to: row.email, subject, html: emailShell(company, heading, bodyHtml) });
}

async function portalChangePassword(request, env, user) {
  const body = await readJson(request, 4096);
  if (!body) return json({ error: 'invalid_json' }, 400);
  if (!(await rateLimit(env, 'pwchange:user:' + user.id, 10, 900))) return json({ error: 'too_many_attempts' }, 429);
  const current = String(body.currentPassword || '');
  const next = String(body.newPassword || '');
  if (next.length < MIN_PASSWORD || next.length > 200) return json({ error: 'weak_password', message: 'Password must be at least ' + MIN_PASSWORD + ' characters.' }, 400);
  const check = await hashPassword(current, user.password_salt || DUMMY_SALT);
  if (!user.password_hash || !timingSafeEqual(check.hash, user.password_hash)) return json({ error: 'invalid_current_password' }, 401);
  const { hash, salt } = await hashPassword(next, null);
  await env.DB.prepare('UPDATE customer_users SET password_hash = ?, password_salt = ? WHERE id = ?').bind(hash, salt, user.id).run();
  const keep = getCookie(request, PORTAL_COOKIE);
  await env.DB.prepare('DELETE FROM customer_sessions WHERE user_id = ? AND token_hash != ?').bind(user.id, keep ? await sha256Hex(keep) : '').run();
  return json({ ok: true });
}

async function portalMe(env, user) {
  const customer = await env.DB.prepare('SELECT id, name, phone, email, address, vehicles_json FROM customers WHERE id = ?').bind(user.customer_id).first();
  const company = await getCompany(env);
  const reqRows = await env.DB.prepare(
    `SELECT r.*, st.name AS staff_name FROM job_requests r
     LEFT JOIN staff st ON st.id = r.approved_staff_id
     WHERE r.customer_id = ? ORDER BY r.created_at DESC LIMIT 100`
  ).bind(user.customer_id).all();
  const today = todayISO();
  const bookRows = await env.DB.prepare(
    `SELECT b.id, b.date, b.start, b.end, b.job_type, b.vehicle_json, b.address, b.status, b.reference, st.name AS staff_name
     FROM bookings b LEFT JOIN staff st ON st.id = b.staff_id
     WHERE b.customer_id = ? AND b.date >= ? AND b.status IN ('booked','in_progress','on_hold')
     ORDER BY b.date, b.start LIMIT 50`
  ).bind(user.customer_id, today).all();
  return json({
    user: { id: user.id, name: user.name, email: user.email },
    customer: customer
      ? { name: customer.name, phone: customer.phone || '', email: customer.email || '', address: customer.address || '', vehicles: jparse(customer.vehicles_json, []) }
      : null,
    company: { name: company.name, phone: company.phone, email: company.email },
    jobTypes: JOB_TYPES.map((id) => ({ id, label: JOB_TYPE_LABEL[id] })),
    today,
    requests: reqRows.results.map(requestForPortal),
    bookings: bookRows.results.map((b) => ({
      id: b.id, date: b.date, start: b.start, end: b.end, jobType: b.job_type, vehicle: jparse(b.vehicle_json, {}),
      address: b.address, status: b.status, reference: b.reference,
      staffFirstName: b.staff_name ? String(b.staff_name).split(/\s+/)[0] : '',
    })),
  });
}

async function portalCreateRequest(request, env, ctx, user, url) {
  const body = await readJson(request, 32768);
  if (!body) return json({ error: 'invalid_json' }, 400);

  const jobType = str(body.jobType, 20);
  const vehicle = { rego: str(body.vehicle && body.vehicle.rego, 12).toUpperCase(), makeModel: str(body.vehicle && body.vehicle.makeModel, 80) };
  const address = str(body.address, 200);
  const contactPhone = str(body.contactPhone, 30);
  const reference = str(body.reference, 60).toUpperCase();
  const description = str(body.description, 2000);
  const preferredDate = str(body.preferredDate, 10);
  const preferredStart = str(body.preferredStart, 5);
  const flexible = body.flexible ? 1 : 0;
  const photoIds = Array.isArray(body.photoIds) ? body.photoIds.map((p) => str(p, 40)) : [];

  const errors = {};
  if (JOB_TYPES.indexOf(jobType) === -1) errors.jobType = 'Choose a job type.';
  if (!vehicle.rego) errors.rego = 'Enter the registration.';
  if (!vehicle.makeModel) errors.makeModel = 'Enter the make and model.';
  if (!address) errors.address = 'Enter where the vehicle will be.';
  if (description.length < 5) errors.description = 'Tell us a little about the job.';
  if (!validDate(preferredDate)) errors.preferredDate = 'Pick a date.';
  else if (preferredDate < todayISO()) errors.preferredDate = 'Pick a date that is today or later.';
  else if (preferredDate > addDaysISO(todayISO(), 365)) errors.preferredDate = 'Pick a date within the next year.';
  if (!validTime(preferredStart) || preferredStart < '05:00' || preferredStart > '20:00') errors.preferredStart = 'Pick a start time between 5:00 am and 8:00 pm.';
  if (photoIds.length > MAX_PHOTOS) errors.photos = 'Up to ' + MAX_PHOTOS + ' photos.';
  if (Object.keys(errors).length) return json({ error: 'invalid_fields', fields: errors }, 400);

  if (!(await rateLimit(env, 'newreq:user:' + user.id, 10, 86400))) return json({ error: 'too_many_requests' }, 429);
  const pending = await env.DB.prepare("SELECT COUNT(*) AS n FROM job_requests WHERE requested_by = ? AND status = 'pending'").bind(user.id).first();
  if (pending && pending.n >= 10) return json({ error: 'too_many_pending' }, 429);

  // Photos must be ones this customer's own logins uploaded — never an id
  // guessed from somewhere else.
  const uniquePhotos = Array.from(new Set(photoIds));
  for (const pid of uniquePhotos) {
    const own = await env.DB.prepare(
      `SELECT p.id FROM photos p JOIN customer_users u ON ('cu:' || u.id) = p.uploaded_by
       WHERE p.id = ? AND u.customer_id = ?`
    ).bind(pid, user.customer_id).first();
    if (!own) return json({ error: 'invalid_fields', fields: { photos: 'One of the photos could not be found — please re-add it.' } }, 400);
  }

  const id = newId('jr');
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let ref = '';
  for (let attempt = 0; attempt < 5; attempt++) {
    const bytes = crypto.getRandomValues(new Uint8Array(5));
    ref = 'REQ-' + Array.from(bytes, (b) => alphabet[b % alphabet.length]).join('');
    const clash = await env.DB.prepare('SELECT 1 AS x FROM job_requests WHERE ref = ?').bind(ref).first();
    if (!clash) break;
  }
  const now = Date.now();
  await env.DB.prepare(
    `INSERT INTO job_requests (id, ref, customer_id, requested_by, requester_name, requester_email, job_type, vehicle_json, address,
       contact_phone, reference, description, preferred_date, preferred_start, flexible, photos_json, status, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?)`
  ).bind(id, ref, user.customer_id, user.id, user.name, user.email, jobType, JSON.stringify(vehicle), address,
    contactPhone, reference, description, preferredDate, preferredStart, flexible, JSON.stringify(uniquePhotos), now).run();

  const row = await env.DB.prepare('SELECT r.*, NULL AS staff_name FROM job_requests r WHERE r.id = ?').bind(id).first();
  const work = notifyStaffNewRequest(env, row, url.origin).catch(() => {});
  if (ctx && ctx.waitUntil) ctx.waitUntil(work); else await work;
  return json({ ok: true, request: requestForPortal(row) });
}

async function notifyStaffNewRequest(env, row, origin) {
  const company = await getCompany(env);
  if (!company.email) return;
  const cust = await env.DB.prepare('SELECT name FROM customers WHERE id = ?').bind(row.customer_id).first();
  const veh = jparse(row.vehicle_json, {});
  const html = emailShell(company, 'New job request ' + row.ref,
    '<p><strong>' + escapeHtml(cust ? cust.name : 'A customer') + '</strong> (' + escapeHtml(row.requester_name) + ') has submitted a job request through the portal.</p>' +
    detailsTable([
      ['Job type', JOB_TYPE_LABEL[row.job_type]],
      ['Vehicle', vehicleText(veh)],
      ['Wants', fmtDateLong(row.preferred_date) + ' at ' + fmtTime12(row.preferred_start) + (row.flexible ? ' (flexible)' : '')],
      ['Where', row.address],
      ['Their reference', row.reference],
      ['Phone', row.contact_phone],
      ['Details', row.description],
      ['Photos', jparse(row.photos_json, []).length ? String(jparse(row.photos_json, []).length) : ''],
    ]) +
    buttonLink(origin + '/', 'Open the app — Requests tab'));
  await sendEmail(env, { to: company.email, subject: 'New job request ' + row.ref + ' — ' + (cust ? cust.name : 'customer'), html });
}

async function portalCancelRequest(env, ctx, user, id) {
  const row = await env.DB.prepare('SELECT * FROM job_requests WHERE id = ? AND customer_id = ?').bind(id, user.customer_id).first();
  if (!row) return json({ error: 'not_found' }, 404);
  if (row.status !== 'pending') return json({ error: 'not_pending', message: 'Only requests still waiting for review can be cancelled here. Please call us to change a confirmed booking.' }, 409);
  const res = await env.DB.prepare("UPDATE job_requests SET status = 'cancelled', decided_at = ?, decided_by = ? WHERE id = ? AND status = 'pending'")
    .bind(Date.now(), 'customer', id).run();
  if (!res.meta || res.meta.changes !== 1) return json({ error: 'not_pending' }, 409);
  const company = await getCompany(env);
  if (company.email) {
    const work = sendEmail(env, {
      to: company.email,
      subject: 'Job request ' + row.ref + ' cancelled by customer',
      html: emailShell(company, 'Request cancelled', '<p>' + escapeHtml(row.requester_name) + ' cancelled request <strong>' + escapeHtml(row.ref) + '</strong> before it was reviewed.</p>'),
    }).catch(() => {});
    if (ctx && ctx.waitUntil) ctx.waitUntil(work);
  }
  return json({ ok: true });
}

function sniffImage(bytes) {
  if (bytes.length > 3 && bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff) return 'image/jpeg';
  if (bytes.length > 8 && bytes[0] === 0x89 && bytes[1] === 0x50 && bytes[2] === 0x4e && bytes[3] === 0x47) return 'image/png';
  if (bytes.length > 12 && bytes[0] === 0x52 && bytes[1] === 0x49 && bytes[2] === 0x46 && bytes[3] === 0x46 &&
      bytes[8] === 0x57 && bytes[9] === 0x45 && bytes[10] === 0x42 && bytes[11] === 0x50) return 'image/webp';
  return null;
}

async function portalUploadPhoto(request, env, user) {
  if (!(await rateLimit(env, 'photo:user:' + user.id, 60, 86400))) return json({ error: 'too_many_photos' }, 429);
  const declared = (request.headers.get('Content-Type') || '').split(';')[0].trim().toLowerCase();
  if (['image/jpeg', 'image/png', 'image/webp'].indexOf(declared) === -1) return json({ error: 'not_an_image' }, 400);
  const body = await request.arrayBuffer();
  if (body.byteLength > MAX_PHOTO_BYTES) return json({ error: 'too_large' }, 413);
  // Trust the file's own bytes, not just the header the browser claimed.
  const real = sniffImage(new Uint8Array(body.slice(0, 16)));
  if (!real) return json({ error: 'not_an_image' }, 400);
  const id = 'ph_' + randomHex(8);
  const key = 'portal-photos/' + id;
  await env.PHOTOS.put(key, body, { httpMetadata: { contentType: real } });
  await env.DB.prepare('INSERT INTO photos (id, r2_key, content_type, uploaded_by, created_at) VALUES (?, ?, ?, ?, ?)')
    .bind(id, key, real, 'cu:' + user.id, Date.now()).run();
  return json({ id, url: '/api/portal/photos/' + id });
}

async function portalServePhoto(env, user, id) {
  const row = await env.DB.prepare(
    `SELECT p.* FROM photos p JOIN customer_users u ON ('cu:' || u.id) = p.uploaded_by
     WHERE p.id = ? AND u.customer_id = ?`
  ).bind(id, user.customer_id).first();
  if (!row) return json({ error: 'not_found' }, 404);
  const obj = await env.PHOTOS.get(row.r2_key);
  if (!obj) return json({ error: 'not_found' }, 404);
  return new Response(obj.body, {
    headers: {
      'Content-Type': row.content_type,
      'Cache-Control': 'private, max-age=3600',
      'X-Content-Type-Options': 'nosniff',
      'Content-Security-Policy': "default-src 'none'; sandbox",
    },
  });
}

/* ============================ staff-side routes ============================ */
/* Called from routeApi() in worker.js AFTER the staff session check has
   already passed, so `user` is always a signed-in staff user here. Returns
   null when the path isn't one of these, so routing carries on. */

export async function handleStaffPortalApi(request, env, ctx, url, path, user, deps) {
  const method = request.method;

  const approve = path.match(/^\/requests\/([A-Za-z0-9_]+)\/approve$/);
  if (approve && method === 'POST') return staffApproveRequest(request, env, user, approve[1], url, deps);
  const decline = path.match(/^\/requests\/([A-Za-z0-9_]+)\/decline$/);
  if (decline && method === 'POST') return staffDeclineRequest(request, env, user, decline[1], url);

  // Portal logins are an admin job, same as staff logins.
  const listUsers = path.match(/^\/customers\/([A-Za-z0-9_]+)\/portal-users$/);
  if (listUsers && method === 'GET') {
    if (user.role !== 'admin') return json({ error: 'forbidden' }, 403);
    const { results } = await env.DB.prepare(
      'SELECT id, name, email, active, password_hash IS NOT NULL AS has_password, token_kind, token_expires, last_login_at, created_at FROM customer_users WHERE customer_id = ? ORDER BY created_at'
    ).bind(listUsers[1]).all();
    return json({ users: results.map((u) => ({
      id: u.id, name: u.name, email: u.email, active: !!u.active, hasPassword: !!u.has_password,
      invitePending: !u.has_password && u.token_kind === 'invite', lastLoginAt: u.last_login_at, createdAt: u.created_at,
    })) });
  }
  const invite = path.match(/^\/customers\/([A-Za-z0-9_]+)\/portal-invite$/);
  if (invite && method === 'POST') {
    if (user.role !== 'admin') return json({ error: 'forbidden' }, 403);
    return staffInvite(request, env, user, invite[1], url);
  }
  const resend = path.match(/^\/portal-users\/([A-Za-z0-9_]+)\/resend-invite$/);
  if (resend && method === 'POST') {
    if (user.role !== 'admin') return json({ error: 'forbidden' }, 403);
    const row = await env.DB.prepare('SELECT * FROM customer_users WHERE id = ? AND active = 1').bind(resend[1]).first();
    if (!row) return json({ error: 'not_found' }, 404);
    if (!(await rateLimit(env, 'resend:user:' + row.id, 5, 3600))) return json({ error: 'too_many_attempts' }, 429);
    const kind = row.password_hash ? 'reset' : 'invite';
    const r = await issueToken(env, row, kind, url.origin);
    return json({ ok: r.ok, reason: r.reason, detail: r.detail, kind });
  }
  const remove = path.match(/^\/portal-users\/([A-Za-z0-9_]+)$/);
  if (remove && method === 'DELETE') {
    if (user.role !== 'admin') return json({ error: 'forbidden' }, 403);
    await env.DB.prepare('UPDATE customer_users SET active = 0, token_hash = NULL, token_kind = NULL, token_expires = NULL WHERE id = ?').bind(remove[1]).run();
    await env.DB.prepare('DELETE FROM customer_sessions WHERE user_id = ?').bind(remove[1]).run();
    return json({ ok: true });
  }
  return null;
}

async function staffInvite(request, env, adminUser, customerId, url) {
  const body = await readJson(request, 4096);
  if (!body) return json({ error: 'invalid_json' }, 400);
  const name = str(body.name, 100);
  const email = str(body.email, 200).toLowerCase();
  if (!name || !validEmail(email)) return json({ error: 'invalid_fields', message: 'A name and a valid email are required.' }, 400);
  const cust = await env.DB.prepare('SELECT id FROM customers WHERE id = ?').bind(customerId).first();
  if (!cust) return json({ error: 'not_found' }, 404);
  const existing = await env.DB.prepare('SELECT * FROM customer_users WHERE email = ?').bind(email).first();
  if (existing && existing.customer_id !== customerId) {
    return json({ error: 'email_in_use', message: 'That email already has a portal login for a different customer.' }, 409);
  }
  let row = existing;
  if (existing) {
    // Re-inviting a removed/forgotten login: reactivate it and reissue a link.
    await env.DB.prepare('UPDATE customer_users SET active = 1, name = ? WHERE id = ?').bind(name, existing.id).run();
    row = Object.assign({}, existing, { name });
  } else {
    const id = newId('cu');
    await env.DB.prepare(
      'INSERT INTO customer_users (id, customer_id, name, email, active, invited_by, created_at) VALUES (?, ?, ?, ?, 1, ?, ?)'
    ).bind(id, customerId, name, email, adminUser.id, Date.now()).run();
    row = { id, customer_id: customerId, name, email };
  }
  const full = await env.DB.prepare('SELECT * FROM customer_users WHERE id = ?').bind(row.id).first();
  const r = await issueToken(env, full, full.password_hash ? 'reset' : 'invite', url.origin);
  return json({ ok: true, id: row.id, emailSent: r.ok, emailReason: r.reason, emailDetail: r.detail });
}

async function loadRequestForStaff(env, id) {
  return env.DB.prepare('SELECT r.*, NULL AS staff_name FROM job_requests r WHERE r.id = ?').bind(id).first();
}

async function staffApproveRequest(request, env, user, id, url, deps) {
  const body = await readJson(request, 8192);
  if (!body) return json({ error: 'invalid_json' }, 400);
  const row = await loadRequestForStaff(env, id);
  if (!row) return json({ error: 'not_found' }, 404);
  if (row.status !== 'pending') return json({ error: 'already_decided', status: row.status }, 409);

  const date = str(body.date, 10), start = str(body.start, 5), end = str(body.end, 5);
  const staffId = str(body.staffId, 60);
  const message = str(body.message, 1000);
  if (!validDate(date) || !validTime(start) || !validTime(end) || end <= start) {
    return json({ error: 'invalid_fields', message: 'Pick a valid date, start time and a finish time after the start.' }, 400);
  }
  const tech = await env.DB.prepare('SELECT id, name FROM staff WHERE id = ? AND active = 1').bind(staffId).first();
  if (!tech) return json({ error: 'invalid_fields', message: 'Pick a staff member.' }, 400);

  const clash = await env.DB.prepare(
    `SELECT id, start, end, customer_json FROM bookings
     WHERE staff_id = ? AND date = ? AND status NOT IN ('completed','invoiced') AND start < ? AND ? < end`
  ).bind(staffId, date, end, start).all();
  if (clash.results.length && !body.force) {
    return json({
      error: 'overlap',
      with: clash.results.map((c) => ({ start: c.start, end: c.end, customer: (jparse(c.customer_json, {}).name) || '' })),
    }, 409);
  }

  // Claim the request first (only succeeds if it is still pending) so two
  // staff approving at the same moment can't create two bookings.
  const adjusted = date !== row.preferred_date || start !== row.preferred_start ? 1 : 0;
  const claim = await env.DB.prepare(
    `UPDATE job_requests SET status = 'approved', decided_at = ?, decided_by = ?, approved_date = ?, approved_start = ?, approved_end = ?,
       approved_staff_id = ?, adjusted = ?, staff_message = ? WHERE id = ? AND status = 'pending'`
  ).bind(Date.now(), user.name || 'staff', date, start, end, staffId, adjusted, message, id).run();
  if (!claim.meta || claim.meta.changes !== 1) return json({ error: 'already_decided' }, 409);

  const cust = await env.DB.prepare('SELECT id, name, phone FROM customers WHERE id = ?').bind(row.customer_id).first();
  const company = await getCompany(env);
  const settings = await env.DB.prepare("SELECT labour_rate FROM settings WHERE id = 'company'").first().catch(() => null);
  const veh = jparse(row.vehicle_json, {});
  const photoCount = jparse(row.photos_json, []).length;
  const bookingId = newId('b');
  const bookingDoc = {
    id: bookingId, date, start, end, staffId, jobType: row.job_type,
    reference: row.reference || row.ref,
    customerId: row.customer_id,
    customer: { name: cust ? cust.name : row.requester_name, phone: row.contact_phone || (cust && cust.phone) || '' },
    vehicle: { rego: veh.rego || '', makeModel: veh.makeModel || '' },
    address: row.address,
    rate: settings && settings.labour_rate ? Number(settings.labour_rate) : 0,
    notes: 'Portal request ' + row.ref + ' from ' + row.requester_name + ':\n' + row.description +
      (photoCount ? '\n(' + photoCount + ' photo' + (photoCount === 1 ? '' : 's') + ' supplied by the customer — open the Requests tab to view.)' : ''),
    serviceItems: [],
    // Customer-supplied photos deliberately stay on the request, not on the
    // booking: booking photos are copied onto the invoice (and from there to
    // Xero and the customer's email), which isn't wanted for their own photos.
    photos: [],
    status: 'booked',
    createdAt: Date.now(),
  };
  try {
    await deps.saveDoc(env, 'bookings', bookingDoc);
  } catch (err) {
    // Put the request back so nothing is left half-done.
    await env.DB.prepare("UPDATE job_requests SET status = 'pending', decided_at = NULL, decided_by = NULL, adjusted = 0 WHERE id = ?").bind(id).run();
    return json({ error: 'booking_failed', message: String((err && err.message) || err) }, 500);
  }
  await env.DB.prepare('UPDATE job_requests SET booking_id = ? WHERE id = ?').bind(bookingId, id).run();

  const mail = await emailCustomerDecision(env, company, row, {
    approved: true, adjusted: !!adjusted, date, start, end, techName: tech.name, message,
    booking: { id: bookingId, date, start, end, jobType: row.job_type, address: row.address, reference: bookingDoc.reference, vehicleText: vehicleText(veh) },
  }, url.origin);
  return json({ ok: true, bookingId, adjusted: !!adjusted, emailSent: mail.ok, emailReason: mail.reason, emailDetail: mail.detail });
}

async function staffDeclineRequest(request, env, user, id, url) {
  const body = await readJson(request, 8192);
  if (!body) return json({ error: 'invalid_json' }, 400);
  const message = str(body.message, 1000);
  const row = await loadRequestForStaff(env, id);
  if (!row) return json({ error: 'not_found' }, 404);
  const claim = await env.DB.prepare(
    "UPDATE job_requests SET status = 'declined', decided_at = ?, decided_by = ?, staff_message = ? WHERE id = ? AND status = 'pending'"
  ).bind(Date.now(), user.name || 'staff', message, id).run();
  if (!claim.meta || claim.meta.changes !== 1) return json({ error: 'already_decided', status: row.status }, 409);
  const company = await getCompany(env);
  const mail = await emailCustomerDecision(env, company, row, { approved: false, message }, url.origin);
  return json({ ok: true, emailSent: mail.ok, emailReason: mail.reason, emailDetail: mail.detail });
}

async function emailCustomerDecision(env, company, row, d, origin) {
  const veh = jparse(row.vehicle_json, {});
  const portalLink = origin + '/portal/';
  let subject, heading, bodyHtml;
  const attachments = [];
  if (d.approved) {
    subject = (d.adjusted ? 'Your booking is confirmed (new time) — ' : 'Your booking is confirmed — ') + row.ref;
    heading = d.adjusted ? 'Your booking is confirmed — with a change' : 'Your booking is confirmed';
    bodyHtml =
      '<p>Hi ' + escapeHtml(row.requester_name) + ',</p>' +
      (d.adjusted
        ? '<p>Thanks for your request. We can\'t do the exact time you asked for, so we have booked you in for the time below instead. ' +
          '<span style="color:#5b6573">(You asked for ' + escapeHtml(fmtDateLong(row.preferred_date)) + ' at ' + escapeHtml(fmtTime12(row.preferred_start)) + '.)</span></p>'
        : '<p>Thanks for your request — we have booked you in as asked.</p>') +
      detailsTable([
        ['Date', fmtDateLong(d.date)],
        ['Time', fmtTime12(d.start) + ' – ' + fmtTime12(d.end)],
        ['Job', JOB_TYPE_LABEL[row.job_type]],
        ['Vehicle', vehicleText(veh)],
        ['Where', row.address],
        ['Technician', d.techName ? String(d.techName).split(/\s+/)[0] : ''],
        ['Your reference', row.reference],
        ['Request', row.ref],
      ]) +
      (d.message ? '<p style="background:#f3f5f8;padding:10px 12px;border-radius:8px"><strong>Note from us:</strong><br>' + escapeHtml(d.message).replace(/\n/g, '<br>') + '</p>' : '') +
      '<p>If this time doesn\'t suit, please reply to this email' + (company.phone ? ' or call ' + escapeHtml(company.phone) : '') + ' and we\'ll sort it out.</p>' +
      '<p style="font-size:13px;color:#5b6573">A calendar file is attached so you can add it to your diary. You can also see it any time in your <a href="' + escapeHtml(portalLink) + '">customer portal</a>.</p>';
    attachments.push({ filename: 'booking.ics', content: toBase64(buildIcs(d.booking, company)), content_type: 'text/calendar' });
  } else {
    subject = 'About your job request — ' + row.ref;
    heading = 'We couldn\'t book that request';
    bodyHtml =
      '<p>Hi ' + escapeHtml(row.requester_name) + ',</p>' +
      '<p>Thanks for your request (' + escapeHtml(row.ref) + ' — ' + escapeHtml(vehicleText(veh)) + '). Unfortunately we are not able to book it in as submitted.</p>' +
      (d.message ? '<p style="background:#f3f5f8;padding:10px 12px;border-radius:8px"><strong>From us:</strong><br>' + escapeHtml(d.message).replace(/\n/g, '<br>') + '</p>' : '') +
      '<p>Please reply to this email' + (company.phone ? ' or call ' + escapeHtml(company.phone) : '') + ', or submit a new request in your <a href="' + escapeHtml(portalLink) + '">customer portal</a> with a different date.</p>';
  }
  return sendEmail(env, { to: row.requester_email, subject, html: emailShell(company, heading, bodyHtml), attachments });
}

export { jobRequestToDoc, DEFAULT_MINUTES };
