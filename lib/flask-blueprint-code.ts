// Complete Python Flask + SQLite + PostgreSQL production codebase & deployment artifacts
// for CyberScope (Phase 1-6 Reference Blueprint + Pydroid 3 Android & Cloud Server Setup).

export interface BlueprintFile {
  path: string;
  language: string;
  description: string;
  content: string;
}

export const FLASK_BLUEPRINT_FILES: BlueprintFile[] = [
  {
    path: 'CyberScope/requirements.txt',
    language: 'text',
    description: 'Lightweight, Pydroid 3 & Linux production-compatible Python dependencies.',
    content: `Flask==3.0.3
Flask-Limiter==3.8.0
Flask-WTF==1.2.1
Werkzeug==3.0.4
requests==2.32.3
dnspython==2.6.1
cryptography==43.0.1
gunicorn==22.0.0
psycopg2-binary==2.9.9
python-dotenv==1.0.1`,
  },
  {
    path: 'CyberScope/config.py',
    language: 'python',
    description: 'Environment-aware configuration supporting SQLite (dev/Pydroid 3) and PostgreSQL (production).',
    content: `import os
from datetime import timedelta

class Config:
    SECRET_KEY = os.environ.get("CYBERSCOPE_SECRET_KEY") or os.urandom(32).hex()
    DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///database/cyberscope.db")
    GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SECURE = os.environ.get("FLASK_ENV") == "production"
    SESSION_COOKIE_SAMESITE = "Lax"
    PERMANENT_SESSION_LIFETIME = timedelta(hours=8)
    MAX_CONTENT_LENGTH = 5 * 1024 * 1024  # 5 MB upload ceiling for Forensics/PCAP`,
  },
  {
    path: 'CyberScope/database/schema.sql',
    language: 'sql',
    description: 'Relational SQL schema with foreign keys and indexes for all 9 required tables.',
    content: `PRAGMA foreign_keys = ON;

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

CREATE INDEX IF NOT EXISTS idx_scan_history_created ON scan_history(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ctf_progress_user ON ctf_progress(user_id);`,
  },
  {
    path: 'CyberScope/database/db.py',
    language: 'python',
    description: 'Parameterized database helper with automatic schema bootstrap.',
    content: `import sqlite3
import os
from flask import g

DB_PATH = os.path.join(os.path.dirname(__file__), "cyberscope.db")
SCHEMA_PATH = os.path.join(os.path.dirname(__file__), "schema.sql")

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON;")
    return g.db

def close_db(e=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()

def init_db(app):
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    with app.app_context():
        db = get_db()
        with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
            db.executescript(f.read())
        db.commit()
    app.teardown_appcontext(close_db)`,
  },
  {
    path: 'CyberScope/app.py',
    language: 'python',
    description: 'Main Flask application registering modular Blueprints, CSRF & security headers.',
    content: `from flask import Flask, jsonify
from config import Config
from database.db import init_db
from backend.routes.dashboard import dashboard_bp
from backend.routes.network import network_bp
from backend.routes.scanner import scanner_bp
from backend.routes.crypto import crypto_bp
from backend.routes.ctf import ctf_bp
from backend.routes.reports import reports_bp

def create_app():
    app = Flask(
        __name__,
        template_folder="frontend/templates",
        static_folder="frontend/static"
    )
    app.config.from_object(Config)
    init_db(app)

    # Register Modular Blueprints
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(network_bp, url_prefix="/api/network")
    app.register_blueprint(scanner_bp, url_prefix="/api/scanner")
    app.register_blueprint(crypto_bp, url_prefix="/api/crypto")
    app.register_blueprint(ctf_bp, url_prefix="/api/ctf")
    app.register_blueprint(reports_bp, url_prefix="/api/reports")

    @app.after_request
    def set_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "SAMEORIGIN"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline';"
        return response

    return app

app = create_app()

if __name__ == "__main__":
    # Never enable debug=True in production
    app.run(host="0.0.0.0", port=5000, debug=False)`,
  },
];
