/**
 * Zenith Auth - Database Engine
 * Dual-engine support: Embedded SQLite 3 (local) & PostgreSQL (Render.com production)
 */

const { DatabaseSync } = require('node:sqlite');
const crypto = require('node:crypto');
const path = require('node:path');
const fs = require('node:fs');

const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'zenith.db');
const db = new DatabaseSync(DB_PATH);

// Enable WAL mode and foreign keys for high throughput and consistency
db.exec(`
  PRAGMA journal_mode = WAL;
  PRAGMA foreign_keys = ON;
`);

/**
 * Generate permanent 10-character alphanumeric Owner ID
 * Exactly 10 characters (alphanumeric uppercase)
 */
function generateOwnerId(seed = '') {
  const chars = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  let id = '';
  const hash = crypto.createHash('sha256').update(seed || crypto.randomBytes(16)).digest();
  for (let i = 0; i < 10; i++) {
    id += chars[hash[i] % chars.length];
  }
  return id;
}

/**
 * Generate cryptographically secure 64-character hexadecimal App Secret Key
 */
function generateAppSecret() {
  return crypto.randomBytes(32).toString('hex'); // exactly 64 hex characters
}

/**
 * Password Hashing Helper using PBKDF2
 */
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
  return `${salt}:${hash}`;
}

function verifyPassword(password, storedHash) {
  if (!storedHash || !storedHash.includes(':')) return false;
  const [salt, originalHash] = storedHash.split(':');
  const computedHash = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
  return crypto.timingSafeEqual(Buffer.from(originalHash, 'hex'), Buffer.from(computedHash, 'hex'));
}

/**
 * Generate Secure License Key: XXXX-XXXX-XXXX-XXXX
 * Exactly 16 alphanumeric characters separated by hyphens
 */
function generateKey(prefix = null, length = 16) {
  const chars = '0123456789ABCDEFGHJKLMNPQRSTUVWXYZ';
  let randomPart = '';
  const bytes = crypto.randomBytes(length);
  for (let i = 0; i < length; i++) {
    randomPart += chars[bytes[i] % chars.length];
  }
  const formatted = randomPart.match(/.{1,4}/g).join('-');
  if (prefix && prefix.trim()) {
    return `${prefix.trim().toUpperCase()}-${formatted}`;
  }
  return formatted;
}

/**
 * Initialize all Database Tables & Schema Migrations
 */
function initDatabase() {
  db.exec(`
    -- 1. Users / Accounts
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT DEFAULT 'Administrator', -- Administrator, Seller, Manager, Reseller
      owner_id TEXT UNIQUE,              -- Permanent 10-char Owner ID
      account_plan TEXT DEFAULT 'TESTER',-- TESTER, DEVELOPER, SELLER
      billing_cycle TEXT DEFAULT 'monthly', -- monthly, yearly
      plan_expires_at TEXT,
      app_id INTEGER DEFAULT 1,
      plan_id INTEGER DEFAULT 1,
      expiry_date TEXT,
      status TEXT DEFAULT 'active',      -- active, banned, expired
      hwid TEXT DEFAULT '',
      ip_address TEXT DEFAULT '127.0.0.1',
      last_login TEXT,
      created_at TEXT DEFAULT (datetime('now'))
    );

    -- 2. Applications
    CREATE TABLE IF NOT EXISTS applications (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      version TEXT DEFAULT '1.0.0',
      status TEXT DEFAULT 'active', -- active, paused, disabled
      secret_key TEXT NOT NULL,     -- 64-character hexadecimal
      public_key TEXT NOT NULL,
      owner_id TEXT NOT NULL,       -- Permanent 10-char Owner ID
      user_id INTEGER DEFAULT 1,    -- Account owner
      description TEXT DEFAULT '',
      hwid_lock INTEGER DEFAULT 1,
      ip_lock INTEGER DEFAULT 0,
      hash_check INTEGER DEFAULT 0,
      app_hash TEXT DEFAULT '',
      max_sessions INTEGER DEFAULT 1,
      created_at TEXT DEFAULT (datetime('now'))
    );

    -- 3. Application Settings
    CREATE TABLE IF NOT EXISTS application_settings (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      app_id INTEGER UNIQUE NOT NULL,
      webhook_url TEXT DEFAULT '',
      webhook_events TEXT DEFAULT 'login,register,license_activate',
      token_validation INTEGER DEFAULT 1,
      whitelist_enabled INTEGER DEFAULT 0,
      blacklist_enabled INTEGER DEFAULT 1,
      session_timeout INTEGER DEFAULT 60,
      custom_css TEXT DEFAULT '',
      updated_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY (app_id) REFERENCES applications(id) ON DELETE CASCADE
    );

    -- 4. Subscription Plans
    CREATE TABLE IF NOT EXISTS subscription_plans (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      app_id INTEGER NOT NULL,
      name TEXT NOT NULL,
      level INTEGER DEFAULT 1,
      duration_days INTEGER DEFAULT 30,
      description TEXT DEFAULT '',
      price REAL DEFAULT 19.99,
      status TEXT DEFAULT 'active',
      created_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY (app_id) REFERENCES applications(id) ON DELETE CASCADE
    );

    -- 5. Subscriptions
    CREATE TABLE IF NOT EXISTS subscriptions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      plan_id INTEGER NOT NULL,
      start_date TEXT DEFAULT (datetime('now')),
      expiry_date TEXT,
      status TEXT DEFAULT 'active',
      created_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
      FOREIGN KEY (plan_id) REFERENCES subscription_plans(id) ON DELETE CASCADE
    );

    -- 6. Licenses (Format: XXXX-XXXX-XXXX-XXXX)
    CREATE TABLE IF NOT EXISTS licenses (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      app_id INTEGER NOT NULL,
      plan_id INTEGER NOT NULL,
      license_key TEXT UNIQUE NOT NULL,
      length INTEGER DEFAULT 16,
      duration_days INTEGER DEFAULT 30,
      hwid_bound INTEGER DEFAULT 1,
      hwid_val TEXT DEFAULT '',
      activation_limit INTEGER DEFAULT 1,
      activations_count INTEGER DEFAULT 0,
      status TEXT DEFAULT 'unused', -- unused, active, banned, expired, revoked
      created_by TEXT DEFAULT 'admin',
      used_by TEXT DEFAULT '',
      bound_user TEXT DEFAULT '',
      last_login TEXT,
      expiry_date TEXT,
      created_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY (app_id) REFERENCES applications(id) ON DELETE CASCADE,
      FOREIGN KEY (plan_id) REFERENCES subscription_plans(id) ON DELETE CASCADE
    );

    -- 7. Tokens
    CREATE TABLE IF NOT EXISTS tokens (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      app_id INTEGER NOT NULL,
      user_id INTEGER DEFAULT 0,
      token_val TEXT UNIQUE NOT NULL,
      type TEXT DEFAULT 'API', -- API, Client, Loader, Temp
      assigned_to TEXT DEFAULT 'System',
      expires_at TEXT,
      status TEXT DEFAULT 'active', -- active, revoked, expired
      created_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY (app_id) REFERENCES applications(id) ON DELETE CASCADE
    );

    -- 8. Web Loader Buttons
    CREATE TABLE IF NOT EXISTS web_loader_buttons (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      app_id INTEGER NOT NULL,
      name TEXT NOT NULL,
      description TEXT DEFAULT '',
      display_order INTEGER DEFAULT 1,
      action_type TEXT DEFAULT 'Launch', -- Launch, Download, Validate, Custom Callback
      callback_url TEXT DEFAULT '',
      enabled INTEGER DEFAULT 1,
      created_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY (app_id) REFERENCES applications(id) ON DELETE CASCADE
    );

    -- 9. Chatrooms (Channels)
    CREATE TABLE IF NOT EXISTS chatrooms (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      app_id INTEGER NOT NULL,
      name TEXT NOT NULL,
      topic TEXT DEFAULT '',
      is_private INTEGER DEFAULT 0,
      created_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY (app_id) REFERENCES applications(id) ON DELETE CASCADE
    );

    -- 10. Chat Messages
    CREATE TABLE IF NOT EXISTS chat_messages (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      channel_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      username TEXT NOT NULL,
      user_role TEXT DEFAULT 'Administrator',
      message TEXT NOT NULL,
      target_username TEXT DEFAULT '',
      created_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY (channel_id) REFERENCES chatrooms(id) ON DELETE CASCADE
    );

    -- 11. Team Members
    CREATE TABLE IF NOT EXISTS team_members (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      email TEXT NOT NULL,
      role TEXT NOT NULL, -- Manager, Reseller
      assigned_apps TEXT DEFAULT '1',
      permissions_json TEXT DEFAULT '[]',
      key_balance INTEGER DEFAULT 0,
      expiry_date TEXT,
      created_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    -- 12. Seller Credentials
    CREATE TABLE IF NOT EXISTS seller_credentials (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      seller_key TEXT UNIQUE NOT NULL,
      endpoint_url TEXT NOT NULL,
      discord_webhook TEXT DEFAULT '',
      created_at TEXT DEFAULT (datetime('now')),
      updated_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    -- 13. Seller Logs
    CREATE TABLE IF NOT EXISTS seller_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER DEFAULT 1,
      app_id INTEGER DEFAULT 1,
      event TEXT NOT NULL,
      action TEXT NOT NULL,
      ip_address TEXT DEFAULT '127.0.0.1',
      status TEXT DEFAULT 'success',
      details TEXT DEFAULT '',
      created_at TEXT DEFAULT (datetime('now'))
    );

    -- 14. Global Variables
    CREATE TABLE IF NOT EXISTS global_variables (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      app_id INTEGER NOT NULL,
      name TEXT NOT NULL,
      value TEXT NOT NULL,
      data_type TEXT DEFAULT 'string', -- string, number, boolean, json
      description TEXT DEFAULT '',
      created_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY (app_id) REFERENCES applications(id) ON DELETE CASCADE
    );

    -- 15. User Variables
    CREATE TABLE IF NOT EXISTS user_variables (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      app_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      username TEXT NOT NULL,
      name TEXT NOT NULL,
      value TEXT NOT NULL,
      created_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY (app_id) REFERENCES applications(id) ON DELETE CASCADE,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    -- 16. Sessions
    CREATE TABLE IF NOT EXISTS sessions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      username TEXT NOT NULL,
      session_token TEXT UNIQUE NOT NULL,
      ip_address TEXT DEFAULT '127.0.0.1',
      user_agent TEXT DEFAULT '',
      device_info TEXT DEFAULT 'Desktop Windows',
      created_at TEXT DEFAULT (datetime('now')),
      last_activity TEXT DEFAULT (datetime('now')),
      status TEXT DEFAULT 'active', -- active, revoked
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    -- 17. Files
    CREATE TABLE IF NOT EXISTS files (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      app_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      filename TEXT NOT NULL,
      original_name TEXT NOT NULL,
      file_size INTEGER NOT NULL,
      mime_type TEXT DEFAULT 'application/octet-stream',
      file_path TEXT NOT NULL,
      upload_date TEXT DEFAULT (datetime('now')),
      FOREIGN KEY (app_id) REFERENCES applications(id) ON DELETE CASCADE
    );

    -- 18. Security IP Rules (Whitelist / Blacklist)
    CREATE TABLE IF NOT EXISTS security_ip_rules (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      app_id INTEGER NOT NULL,
      ip_address TEXT NOT NULL,
      rule_type TEXT NOT NULL, -- whitelist, blacklist
      note TEXT DEFAULT '',
      created_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY (app_id) REFERENCES applications(id) ON DELETE CASCADE
    );

    -- 19. Audit Logs
    CREATE TABLE IF NOT EXISTS audit_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER DEFAULT 0,
      username TEXT DEFAULT 'system',
      action TEXT NOT NULL,
      ip_address TEXT DEFAULT '127.0.0.1',
      user_agent TEXT DEFAULT '',
      details TEXT DEFAULT '',
      created_at TEXT DEFAULT (datetime('now'))
    );

    -- 20. Notifications
    CREATE TABLE IF NOT EXISTS notifications (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      title TEXT NOT NULL,
      message TEXT NOT NULL,
      type TEXT DEFAULT 'info', -- info, success, warning, danger
      is_read INTEGER DEFAULT 0,
      created_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    -- 21. HWID Records & Protections
    CREATE TABLE IF NOT EXISTS hwid_records (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      app_id INTEGER NOT NULL,
      user_id INTEGER DEFAULT 0,
      username TEXT DEFAULT '',
      hwid TEXT NOT NULL,
      ip_address TEXT DEFAULT '127.0.0.1',
      status TEXT DEFAULT 'active', -- active, whitelisted, blacklisted, reset
      note TEXT DEFAULT '',
      last_seen TEXT DEFAULT (datetime('now')),
      created_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY (app_id) REFERENCES applications(id) ON DELETE CASCADE
    );

    -- 22. Webhooks
    CREATE TABLE IF NOT EXISTS webhooks (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      app_id INTEGER NOT NULL,
      name TEXT NOT NULL,
      webhook_url TEXT NOT NULL,
      events TEXT DEFAULT 'all',
      status TEXT DEFAULT 'active', -- active, paused
      secret_token TEXT,
      last_fired_at TEXT,
      created_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
      FOREIGN KEY (app_id) REFERENCES applications(id) ON DELETE CASCADE
    );

    -- 23. Bot Integrations (Discord & Telegram)
    CREATE TABLE IF NOT EXISTS integrations (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      app_id INTEGER NOT NULL,
      type TEXT NOT NULL, -- discord_bot, telegram_bot
      bot_token TEXT DEFAULT '',
      client_id TEXT DEFAULT '',
      channel_id TEXT DEFAULT '',
      enabled INTEGER DEFAULT 0,
      created_at TEXT DEFAULT (datetime('now')),
      updated_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
      FOREIGN KEY (app_id) REFERENCES applications(id) ON DELETE CASCADE
    );

    -- 24. Event Logs
    CREATE TABLE IF NOT EXISTS event_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      app_id INTEGER NOT NULL,
      user_id INTEGER DEFAULT 0,
      event_type TEXT NOT NULL,
      description TEXT NOT NULL,
      ip_address TEXT DEFAULT '127.0.0.1',
      user_agent TEXT DEFAULT '',
      created_at TEXT DEFAULT (datetime('now'))
    );

    -- 25. Account Logs
    CREATE TABLE IF NOT EXISTS account_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      action TEXT NOT NULL,
      ip_address TEXT DEFAULT '127.0.0.1',
      details TEXT DEFAULT '',
      created_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    -- 26. Payment Transactions
    CREATE TABLE IF NOT EXISTS payment_transactions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      plan_name TEXT NOT NULL,       -- DEVELOPER, SELLER
      billing_cycle TEXT NOT NULL,   -- monthly, yearly
      amount REAL NOT NULL,
      currency TEXT DEFAULT 'USD',
      payment_method TEXT DEFAULT 'Credit Card',
      transaction_id TEXT UNIQUE NOT NULL,
      status TEXT DEFAULT 'completed', -- completed, pending, failed
      created_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    -- 27. Email OTP Verifications
    CREATE TABLE IF NOT EXISTS email_otps (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT NOT NULL,
      otp_code TEXT NOT NULL,
      type TEXT DEFAULT 'registration', -- registration, google_auth
      expires_at TEXT NOT NULL,
      used INTEGER DEFAULT 0,
      ip_address TEXT DEFAULT '127.0.0.1',
      created_at TEXT DEFAULT (datetime('now'))
    );

    -- 26. Application Client End-Users (Software Clients / Loaders)
    CREATE TABLE IF NOT EXISTS app_users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      app_id INTEGER NOT NULL,
      username TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      email TEXT DEFAULT '',
      subscription_name TEXT DEFAULT 'default',
      plan_id INTEGER DEFAULT 1,
      expiry_date TEXT,
      hwid TEXT DEFAULT '',
      hwid_lock INTEGER DEFAULT 1,
      allowed_devices INTEGER DEFAULT 1,
      ip_address TEXT DEFAULT '127.0.0.1',
      last_login TEXT,
      status TEXT DEFAULT 'active', -- active, banned
      created_at TEXT DEFAULT (datetime('now')),
      UNIQUE(app_id, username),
      FOREIGN KEY (app_id) REFERENCES applications(id) ON DELETE CASCADE
    );

    -- 27. Discord & Telegram Bot Channel / Role Bindings
    CREATE TABLE IF NOT EXISTS bot_bindings (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      guild_id TEXT NOT NULL,
      channel_id TEXT NOT NULL,
      role_id TEXT DEFAULT '',
      app_id INTEGER NOT NULL DEFAULT 1,
      display_name TEXT DEFAULT '',
      created_at TEXT DEFAULT (datetime('now'))
    );

    -- 28. Free Trial / Free Key Claims History
    CREATE TABLE IF NOT EXISTS bot_free_claims (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      guild_id TEXT NOT NULL,
      discord_user_id TEXT NOT NULL,
      discord_username TEXT DEFAULT '',
      app_id INTEGER NOT NULL DEFAULT 1,
      claim_type TEXT DEFAULT 'license',
      claimed_key TEXT DEFAULT '',
      claimed_at TEXT DEFAULT (datetime('now'))
    );

    -- 29. Bot Dynamic Settings
    CREATE TABLE IF NOT EXISTS bot_settings (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL
    );
  `);

  // Run schema migrations for existing databases
  try { db.exec("ALTER TABLE users ADD COLUMN owner_id TEXT;"); } catch {}
  try { db.exec("ALTER TABLE users ADD COLUMN account_plan TEXT DEFAULT 'TESTER';"); } catch {}
  try { db.exec("ALTER TABLE users ADD COLUMN billing_cycle TEXT DEFAULT 'monthly';"); } catch {}
  try { db.exec("ALTER TABLE users ADD COLUMN plan_expires_at TEXT;"); } catch {}
  try { db.exec("ALTER TABLE applications ADD COLUMN owner_id TEXT;"); } catch {}
  try { db.exec("ALTER TABLE applications ADD COLUMN user_id INTEGER DEFAULT 1;"); } catch {}
  try { db.exec("ALTER TABLE applications ADD COLUMN app_hash TEXT DEFAULT '';"); } catch {}
  try { db.exec("ALTER TABLE applications ADD COLUMN hash_check INTEGER DEFAULT 0;"); } catch {}
  try { db.exec("ALTER TABLE licenses ADD COLUMN bound_user TEXT;"); } catch {}
  try { db.exec("ALTER TABLE licenses ADD COLUMN last_login TEXT;"); } catch {}
  try { db.exec("ALTER TABLE users ADD COLUMN allowed_devices INTEGER DEFAULT 1;"); } catch {}
  try { db.exec("ALTER TABLE app_users ADD COLUMN allowed_devices INTEGER DEFAULT 1;"); } catch {}
  try { db.exec("ALTER TABLE integrations ADD COLUMN status TEXT DEFAULT 'offline';"); } catch {}
  try { db.exec("ALTER TABLE integrations ADD COLUMN bot_username TEXT DEFAULT '';"); } catch {}
  try { db.exec("ALTER TABLE integrations ADD COLUMN last_error TEXT DEFAULT '';"); } catch {}
  try { db.exec("ALTER TABLE integrations ADD COLUMN auto_start INTEGER DEFAULT 1;"); } catch {}

  // Purge any dummy seed clutter to keep platform completely pristine
  try {
    db.prepare("DELETE FROM licenses WHERE license_key LIKE 'TESTKEY-%' OR license_key LIKE 'ZENITH-%' OR license_key IN ('A9B2-44F1-8890-C012', 'E7C1-9923-5512-D884', 'F001-9944-1122-8877', 'B441-2299-7711-A338', 'C992-1144-8822-F550')").run();
    db.prepare("DELETE FROM team_members WHERE email IN ('quantum@proton.me', 'nexus@gmail.com')").run();
    db.prepare("DELETE FROM app_users WHERE username IN ('ghost_sniper', 'shadow_aim', 'apex_client')").run();
    db.prepare("DELETE FROM users WHERE username IN ('vortex_seller', 'quantum_dev', 'cyber_nexus', 'admin', 'freshuser_8524', 'client_sub_150', 'freshuser_1951', 'client_sub_529', 'new_tester_209', 'new_tester_715', 'random_tester_99', 'tester_19096', 'guser_19096', 'test_dev_8b2o', 'test_dev_q90t', 'test_dev_pf0t')").run();
    db.prepare("DELETE FROM audit_logs WHERE username IN ('admin', 'vortex_seller', 'cyber_nexus', 'quantum_dev')").run();
    
    // Purge dummy "Default App" instances and child tables
    const dummyApps = db.prepare("SELECT id FROM applications WHERE name = 'Default App' OR name LIKE 'Default App%'").all();
    for (const d of dummyApps) {
      try { db.prepare("DELETE FROM application_settings WHERE app_id = ?").run(d.id); } catch {}
      try { db.prepare("DELETE FROM subscription_plans WHERE app_id = ?").run(d.id); } catch {}
      try { db.prepare("DELETE FROM chatrooms WHERE app_id = ?").run(d.id); } catch {}
      try { db.prepare("DELETE FROM licenses WHERE app_id = ?").run(d.id); } catch {}
      try { db.prepare("DELETE FROM app_users WHERE app_id = ?").run(d.id); } catch {}
      try { db.prepare("DELETE FROM applications WHERE id = ?").run(d.id); } catch {}
    }
  } catch {}

  seedInitialData();
}

/**
 * Generate 32-character mixed-case alphanumeric seller key
 * Example: k9P2mX7vQ4nL8wR1zT6yB3cF5jH0dG9s
 */
function generateSellerKey(length = 32) {
  const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let result = '';
  const bytes = crypto.randomBytes(length);
  for (let i = 0; i < length; i++) {
    result += chars[bytes[i] % chars.length];
  }
  return result;
}

/**
 * Seed initial administrative and demonstration records
 */
function seedInitialData() {
  const zeeshanOwnerId = 'KI81RSL4JP';
  const zeeshanHash = hashPassword('ZEESHAN@0517');

  // Seed / Upsert ZEESHAN1017 Master Platform Owner (Permanent Master Access)
  const zeeshan = db.prepare('SELECT id FROM users WHERE username = ?').get('ZEESHAN1017');
  if (!zeeshan) {
    db.prepare(`
      INSERT INTO users (username, email, password_hash, role, owner_id, account_plan, billing_cycle, plan_expires_at, app_id, plan_id, expiry_date, status, hwid)
      VALUES ('ZEESHAN1017', 'zkhan63321@gmail.com', ?, 'Owner', ?, 'OWNER', 'lifetime', '2099-12-31', 1, 3, '2099-12-31', 'active', 'HWID-ZEESHAN-ROOT-SUPERADMIN')
    `).run(zeeshanHash, zeeshanOwnerId);
  } else {
    db.prepare(`
      UPDATE users 
      SET password_hash = ?, 
          email = 'zkhan63321@gmail.com',
          role = 'Owner', 
          account_plan = 'OWNER', 
          billing_cycle = 'lifetime',
          plan_expires_at = '2099-12-31',
          owner_id = ?
      WHERE username = 'ZEESHAN1017'
    `).run(zeeshanHash, zeeshanOwnerId);
  }

  // Ensure ZEESHAN1017 is never in app_users
  try {
    db.prepare("DELETE FROM app_users WHERE username IN ('ZEESHAN1017', 'admin', 'vortex_seller')").run();
  } catch {}

  // 1. Initial Application with 64-char Hex Secret Key & 10-char Owner ID if missing
  const appCount = db.prepare('SELECT count(*) as count FROM applications').get().count;
  if (appCount === 0) {
    const appSecret = generateAppSecret();
    const appPub = 'za_pub_' + crypto.randomBytes(12).toString('hex');
    db.prepare(`
      INSERT INTO applications (id, name, version, status, secret_key, public_key, owner_id, user_id, description, hwid_lock, ip_lock, hash_check, max_sessions)
      VALUES (1, 'Zenith Core Engine', '2.4.0', 'active', ?, ?, ?, 1, 'Flagship authentication & security suite', 1, 0, 1, 1)
    `).run(appSecret, appPub, zeeshanOwnerId);

    db.prepare(`
      INSERT INTO application_settings (app_id, webhook_url, webhook_events, token_validation, whitelist_enabled, blacklist_enabled, session_timeout)
      VALUES (1, 'https://discord.com/api/webhooks/zenith-sample', 'login,register,license_activate,token_verify', 1, 0, 1, 120)
    `).run();
  }

  // 2. Subscription Plans
  const planCount = db.prepare('SELECT count(*) as count FROM subscription_plans').get().count;
  if (planCount === 0) {
    db.prepare(`
      INSERT INTO subscription_plans (id, app_id, name, level, duration_days, description, price, status)
      VALUES 
      (1, 1, 'Standard Monthly', 1, 30, 'Full client access with standard rate limits and HWID lock', 14.99, 'active'),
      (2, 1, 'Pro Quarterly', 2, 90, 'Enhanced priority bandwidth, custom user variables, and VIP chat access', 39.99, 'active'),
      (3, 1, 'Enterprise Lifetime', 99, 3650, 'Unlimited lifetime access, unrestricted tokens, and dedicated seller endpoint', 199.99, 'active')
    `).run();
  }

  // Ensure Seller credentials exist for Master Owner with 32-char alphanumeric key
  const zeeshanUser = db.prepare('SELECT id FROM users WHERE username = ?').get('ZEESHAN1017');
  if (zeeshanUser) {
    const existingCreds = db.prepare('SELECT id FROM seller_credentials WHERE user_id = ?').get(zeeshanUser.id);
    if (!existingCreds) {
      const sellerKey = generateSellerKey(32);
      db.prepare(`
        INSERT INTO seller_credentials (user_id, seller_key, endpoint_url, discord_webhook)
        VALUES (?, ?, 'https://zenithauth-t1we.onrender.com/api/v1/seller', '')
      `).run(zeeshanUser.id, sellerKey);
    }
  }

  // Ensure global variables exist
  const varCount = db.prepare('SELECT count(*) as count FROM global_variables').get().count;
  if (varCount === 0) {
    db.prepare(`
      INSERT INTO global_variables (app_id, name, value, data_type, description)
      VALUES 
      (1, 'API_MAINTENANCE_MODE', 'false', 'boolean', 'Emergency kill-switch for client connections'),
      (1, 'MIN_CLIENT_VERSION', '2.4.0', 'string', 'Enforced minimum client version for handshake'),
      (1, 'MAX_CONCURRENT_USERS', '10000', 'number', 'Maximum active socket sessions allowed per instance'),
      (1, 'FEATURE_FLAGS', '{"hwid_bypass": false, "stealth_heartbeat": true, "anti_debug": true}', 'json', 'Global security engine runtime flags')
    `).run();
  }

  // Ensure all users have a 10-char Owner ID
  const allUsers = db.prepare('SELECT id, email, owner_id FROM users').all();
  for (const u of allUsers) {
    if (!u.owner_id) {
      db.prepare('UPDATE users SET owner_id = ? WHERE id = ?').run(generateOwnerId(u.email || ('user_' + u.id)), u.id);
    }
  }

  console.log('[Zenith DB] Database initialized and clean.');
}

module.exports = {
  db,
  initDatabase,
  hashPassword,
  verifyPassword,
  generateKey,
  generateOwnerId,
  generateAppSecret,
  generateSellerKey
};
