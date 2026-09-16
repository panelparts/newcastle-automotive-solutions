-- Newcastle Automotive Solutions — creates the very first admin login.
--
-- Why this exists: the app's "add a staff login" screen only works once
-- you're already logged in as an admin. The very first admin account has
-- nowhere to come from except a one-off SQL statement run by hand, here,
-- through Cloudflare's D1 console (same "paste this into the dashboard"
-- pattern as everything else in this project).
--
-- This creates one login:
--   email:    nas.newcastle@gmail.com
--   password: h5Pgo3iFE23e
--
-- IMPORTANT — do this straight after running this statement:
--   1. Log in to Newcastle Automotive Solutions with the email/password above.
--   2. Open "Your account" and change the password to one you'll actually
--      use day to day. The value above is a temporary, one-time password —
--      it's sitting in this file in plain text, so treat it as already
--      semi-public and swap it out.
--   3. From then on, add every other staff member's login from inside the
--      app itself (Staff logins, admin only) — you won't need SQL again.
--
-- Run this exactly once. Running it a second time will fail harmlessly
-- (UNIQUE constraint on email) rather than creating a duplicate.

INSERT INTO users (id, staff_id, name, email, password_hash, password_salt, role, active, created_at)
VALUES (
  'u_acfe81a484d7',
  NULL,
  'Admin',
  'nas.newcastle@gmail.com',
  '65faf76abf1f22d82493c83aff686dbf7e97f4e7aacddad1984cf9814cb36321',
  'c6bd490dd1e953c0842a500e9c4134d8',
  'admin',
  1,
  strftime('%s','now') * 1000
);
