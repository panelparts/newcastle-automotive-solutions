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
