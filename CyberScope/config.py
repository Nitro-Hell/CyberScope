import os
from datetime import timedelta

class Config:
    SECRET_KEY = os.environ.get("CYBERSCOPE_SECRET_KEY") or os.urandom(32).hex()
    DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///database/cyberscope.db")
    GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SECURE = os.environ.get("FLASK_ENV") == "production"
    SESSION_COOKIE_SAMESITE = "Lax"
    PERMANENT_SESSION_LIFETIME = timedelta(hours=8)
    MAX_CONTENT_LENGTH = 5 * 1024 * 1024
