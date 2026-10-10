-- Newcastle Automotive Solutions — D1 schema
-- Replaces the Claude Artifact 'db' capability. Structurally mirrors the
-- document shapes the original Artifact-hosted app already used, with
-- variable/nested bits (vehicles, serviceItems, lineItems, photos) kept as
-- JSON text columns so the existing app logic barely has to change, and
-- everything else promoted to real columns.

CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  staff_id TEXT,                    -- links a login to a staff/tech record, if any
  name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,      -- PBKDF2-SHA256 hash, hex
  password_salt TEXT NOT NULL,      -- random salt, hex
  role TEXT NOT NULL DEFAULT 'staff', -- 'admin' | 'staff'
  active INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
  token TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);

CREATE TABLE IF NOT EXISTS staff (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  role TEXT,
  color TEXT,
  phone TEXT,
  active INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER
);

CREATE TABLE IF NOT EXISTS customers (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  phone TEXT,
  email TEXT,
  address TEXT,
  notes TEXT,
  vehicles_json TEXT NOT NULL DEFAULT '[]',
  created_at INTEGER,
  xero_contact_id TEXT,   -- links this customer to a Xero Contact once synced — see "Customers <-> Xero" in src/worker.js
  updated_at INTEGER      -- stamped on every app-side save; used to decide "app wins" against an incoming Xero webhook update
);

CREATE TABLE IF NOT EXISTS bookings (
  id TEXT PRIMARY KEY,
  date TEXT,
  start TEXT,
  end TEXT,
  staff_id TEXT,
  job_type TEXT,
  reference TEXT,
  customer_id TEXT,
  customer_json TEXT NOT NULL DEFAULT '{}',   -- {name, phone} snapshot at booking time
  vehicle_json TEXT NOT NULL DEFAULT '{}',    -- {rego, makeModel} snapshot at booking time
  address TEXT,
  rate REAL DEFAULT 0,
  notes TEXT,
  service_items_json TEXT NOT NULL DEFAULT '[]',
  status TEXT NOT NULL DEFAULT 'booked',
  created_at INTEGER
);

CREATE TABLE IF NOT EXISTS time_entries (
  id TEXT PRIMARY KEY,
  booking_id TEXT,
  staff_id TEXT,
  minutes INTEGER NOT NULL DEFAULT 0,
  item_id TEXT,
  note TEXT,
  date TEXT,
  billable INTEGER NOT NULL DEFAULT 1,  -- 0 = logged for the record only, doesn't add to the invoice's Labour line
  created_at INTEGER
);

CREATE TABLE IF NOT EXISTS invoices (
  id TEXT PRIMARY KEY,
  booking_id TEXT,
  customer_id TEXT,
  customer_name TEXT,
  reference TEXT,
  line_items_json TEXT NOT NULL DEFAULT '[]',
  subtotal REAL DEFAULT 0,
  gst REAL DEFAULT 0,
  total REAL DEFAULT 0,
  photos_json TEXT NOT NULL DEFAULT '[]',
  photos_pending INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'draft',   -- 'draft' | 'sent' | 'void' | 'paid'  (no 'queued' needed anymore — sending is synchronous; 'void'/'paid' can be set by hand via "Mark as void" or automatically by the Xero webhook sync — see src/worker.js)
  created_at INTEGER,
  sent_at INTEGER,
  xero_invoice_id TEXT,
  xero_invoice_number TEXT,
  xero_invoice_url TEXT
);

CREATE TABLE IF NOT EXISTS services (
  id TEXT PRIMARY KEY,
  code TEXT,
  name TEXT,
  sales_description TEXT,
  sales_price REAL DEFAULT 0,
  cost_price REAL DEFAULT 0,
  tax_rate TEXT,
  standard_time_minutes INTEGER,
  active INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS products (
  id TEXT PRIMARY KEY,
  code TEXT,
  name TEXT,
  sales_description TEXT,
  sales_price REAL DEFAULT 0,
  cost_price REAL DEFAULT 0,
  tax_rate TEXT,
  qty_in_stock REAL,
  active INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS settings (
  id TEXT PRIMARY KEY DEFAULT 'company',
  company_name TEXT,
  abn TEXT,
  phone TEXT,
  email TEXT,
  address TEXT,
  labour_rate REAL DEFAULT 0,
  xero_worker_url TEXT
);

CREATE TABLE IF NOT EXISTS photos (
  id TEXT PRIMARY KEY,
  r2_key TEXT NOT NULL,
  content_type TEXT NOT NULL DEFAULT 'image/jpeg',
  uploaded_by TEXT,
  created_at INTEGER
);

-- ===== Customer portal tables (2026-10-06) — same statements as migration/portal.sql =====
CREATE TABLE IF NOT EXISTS customer_users (
  id TEXT PRIMARY KEY,
  customer_id TEXT NOT NULL,        -- which customer record this login belongs to
  name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT,               -- PBKDF2-SHA256, hex (NULL until invite accepted)
  password_salt TEXT,
  token_hash TEXT,                  -- SHA-256 of the one-time invite / reset link token
  token_kind TEXT,                  -- 'invite' | 'reset'
  token_expires INTEGER,
  active INTEGER NOT NULL DEFAULT 1,
  invited_by TEXT,
  created_at INTEGER NOT NULL,
  last_login_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_cu_customer ON customer_users(customer_id);
CREATE INDEX IF NOT EXISTS idx_cu_token ON customer_users(token_hash);

-- Portal sessions (the cookie holds a random token; only its SHA-256 is stored here).
CREATE TABLE IF NOT EXISTS customer_sessions (
  token_hash TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_cs_user ON customer_sessions(user_id);

-- Job requests submitted from the portal, waiting for (or past) staff review.
CREATE TABLE IF NOT EXISTS job_requests (
  id TEXT PRIMARY KEY,
  ref TEXT NOT NULL,                -- short code shown to customer and staff, e.g. REQ-7KQ2M
  customer_id TEXT NOT NULL,
  requested_by TEXT NOT NULL,       -- customer_users.id
  requester_name TEXT,
  requester_email TEXT,
  job_type TEXT NOT NULL,           -- 'mechanical' | 'adas' | 'both'
  vehicle_json TEXT NOT NULL DEFAULT '{}',
  address TEXT,
  contact_phone TEXT,
  reference TEXT,                   -- the customer's own PO / job number, optional
  description TEXT,
  preferred_date TEXT,              -- YYYY-MM-DD
  preferred_start TEXT,             -- HH:MM
  flexible INTEGER NOT NULL DEFAULT 0,
  photos_json TEXT NOT NULL DEFAULT '[]',
  status TEXT NOT NULL DEFAULT 'pending',   -- 'pending' | 'approved' | 'declined' | 'cancelled'
  created_at INTEGER NOT NULL,
  decided_at INTEGER,
  decided_by TEXT,
  approved_date TEXT,
  approved_start TEXT,
  approved_end TEXT,
  approved_staff_id TEXT,
  adjusted INTEGER NOT NULL DEFAULT 0,      -- 1 = staff changed the date/time the customer asked for
  staff_message TEXT,
  booking_id TEXT
);
CREATE INDEX IF NOT EXISTS idx_jr_customer ON job_requests(customer_id);
CREATE INDEX IF NOT EXISTS idx_jr_status ON job_requests(status);
CREATE UNIQUE INDEX IF NOT EXISTS idx_jr_ref ON job_requests(ref);

-- Counters used to slow down password guessing and email/request flooding.
CREATE TABLE IF NOT EXISTS rate_limits (
  key TEXT PRIMARY KEY,
  count INTEGER NOT NULL,
  reset_at INTEGER NOT NULL
);
