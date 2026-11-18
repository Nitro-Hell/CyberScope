PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT DEFAULT 'SOC Analyst',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS settings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL UNIQUE,
    ssrf_strict_mode INTEGER DEFAULT 1,
    rate_limit_rpm INTEGER DEFAULT 60,
    terminal_theme TEXT DEFAULT 'cyan-matrix',
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS scan_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    target TEXT NOT NULL,
    scan_type TEXT NOT NULL,
    score INTEGER NOT NULL,
    grade TEXT NOT NULL,
    findings_json TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS network_devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hostname TEXT NOT NULL,
    ip_address TEXT NOT NULL,
    mac_address TEXT NOT NULL,
    zone TEXT NOT NULL,
    status TEXT DEFAULT 'Authorized',
    latency_ms REAL DEFAULT 1.0,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS ctf_challenges (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    category TEXT NOT NULL,
    difficulty TEXT NOT NULL,
    points INTEGER NOT NULL,
    flag_hash TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ctf_progress (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    challenge_id TEXT NOT NULL,
    solved_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, challenge_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (challenge_id) REFERENCES ctf_challenges(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS crypto_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    operation TEXT NOT NULL,
    algorithm TEXT NOT NULL,
    digest_preview TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    title TEXT NOT NULL,
    module TEXT NOT NULL,
    severity TEXT NOT NULL,
    score INTEGER NOT NULL,
    summary TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS learning_progress (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    module_name TEXT NOT NULL,
    completed_exercises INTEGER DEFAULT 0,
    total_exercises INTEGER DEFAULT 5,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
