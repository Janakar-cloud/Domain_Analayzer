"""Database Storage System for Domain Intelligence using SQLite."""

import sqlite3
import json
import hashlib
import secrets
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, List, Dict, Any, Tuple
from contextlib import contextmanager
from dataclasses import dataclass

# Database file path
DB_PATH = Path(__file__).parent.parent.parent / "data" / "domain_intel.db"


@dataclass
class User:
    """User model."""
    id: int
    username: str
    password_hash: str
    salt: str
    email: Optional[str]
    role: str
    is_active: bool
    failed_login_attempts: int
    locked_until: Optional[datetime]
    created_at: datetime
    last_login: Optional[datetime]


@dataclass
class ScanRecord:
    """Scan record model."""
    id: int
    user_id: int
    domains: List[str]
    status: str
    total_findings: int
    severity_breakdown: Dict[str, int]
    scan_data: Dict[str, Any]
    created_at: datetime
    completed_at: Optional[datetime]
    duration_seconds: Optional[float]


@dataclass
class Session:
    """User session model."""
    id: str
    user_id: int
    created_at: datetime
    expires_at: datetime
    is_active: bool


class Database:
    """SQLite database manager."""
    
    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = db_path or DB_PATH
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_database()
    
    @contextmanager
    def get_connection(self):
        """Get database connection with context manager."""
        conn = sqlite3.connect(str(self.db_path), detect_types=sqlite3.PARSE_DECLTYPES)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()
    
    def _init_database(self):
        """Initialize database schema."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # Users table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    salt TEXT NOT NULL,
                    email TEXT,
                    role TEXT DEFAULT 'user',
                    is_active BOOLEAN DEFAULT 1,
                    failed_login_attempts INTEGER DEFAULT 0,
                    locked_until TIMESTAMP,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP
                )
            """)
            
            # Sessions table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS sessions (
                    id TEXT PRIMARY KEY,
                    user_id INTEGER NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP NOT NULL,
                    is_active BOOLEAN DEFAULT 1,
                    FOREIGN KEY (user_id) REFERENCES users(id)
                )
            """)
            
            # Scans table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    domains TEXT NOT NULL,
                    status TEXT DEFAULT 'pending',
                    total_findings INTEGER DEFAULT 0,
                    severity_breakdown TEXT,
                    scan_data TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    completed_at TIMESTAMP,
                    duration_seconds REAL,
                    FOREIGN KEY (user_id) REFERENCES users(id)
                )
            """)
            
            # Login attempts table (for rate limiting)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS login_attempts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL,
                    ip_address TEXT,
                    success BOOLEAN,
                    attempted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Webhooks table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS webhooks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    name TEXT NOT NULL,
                    url TEXT NOT NULL,
                    webhook_type TEXT DEFAULT 'generic',
                    is_active BOOLEAN DEFAULT 1,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(id)
                )
            """)
            
            # Audit log table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    action TEXT NOT NULL,
                    details TEXT,
                    ip_address TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(id)
                )
            """)
            
            # Create default admin user if not exists
            cursor.execute("SELECT id FROM users WHERE username = ?", ("admin",))
            if not cursor.fetchone():
                salt = secrets.token_hex(32)
                password_hash = self._hash_password("admin123", salt)
                cursor.execute("""
                    INSERT INTO users (username, password_hash, salt, email, role)
                    VALUES (?, ?, ?, ?, ?)
                """, ("admin", password_hash, salt, "admin@localhost", "admin"))
    
    @staticmethod
    def _hash_password(password: str, salt: str) -> str:
        """Hash password with salt using SHA-256."""
        return hashlib.sha256((password + salt).encode()).hexdigest()
    
    # ==================== USER METHODS ====================
    
    def create_user(self, username: str, password: str, email: Optional[str] = None, role: str = "user") -> Optional[int]:
        """Create a new user."""
        salt = secrets.token_hex(32)
        password_hash = self._hash_password(password, salt)
        
        with self.get_connection() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute("""
                    INSERT INTO users (username, password_hash, salt, email, role)
                    VALUES (?, ?, ?, ?, ?)
                """, (username, password_hash, salt, email, role))
                return cursor.lastrowid
            except sqlite3.IntegrityError:
                return None
    
    def verify_user(self, username: str, password: str) -> Optional[User]:
        """Verify user credentials and return user if valid."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
            row = cursor.fetchone()
            
            if not row:
                return None
            
            # Check if account is locked
            if row['locked_until']:
                locked_until = datetime.fromisoformat(row['locked_until']) if isinstance(row['locked_until'], str) else row['locked_until']
                if locked_until > datetime.utcnow():
                    return None
                else:
                    # Unlock the account
                    cursor.execute("UPDATE users SET locked_until = NULL, failed_login_attempts = 0 WHERE id = ?", (row['id'],))
            
            # Verify password
            password_hash = self._hash_password(password, row['salt'])
            if password_hash == row['password_hash']:
                # Reset failed attempts and update last login
                cursor.execute("""
                    UPDATE users SET failed_login_attempts = 0, last_login = ? WHERE id = ?
                """, (datetime.utcnow(), row['id']))
                
                return User(
                    id=row['id'],
                    username=row['username'],
                    password_hash=row['password_hash'],
                    salt=row['salt'],
                    email=row['email'],
                    role=row['role'],
                    is_active=row['is_active'],
                    failed_login_attempts=0,
                    locked_until=None,
                    created_at=row['created_at'],
                    last_login=datetime.utcnow()
                )
            else:
                # Increment failed attempts
                new_attempts = row['failed_login_attempts'] + 1
                locked_until = None
                if new_attempts >= 5:
                    locked_until = datetime.utcnow() + timedelta(minutes=15)
                
                cursor.execute("""
                    UPDATE users SET failed_login_attempts = ?, locked_until = ? WHERE id = ?
                """, (new_attempts, locked_until, row['id']))
                return None
    
    def get_user_by_id(self, user_id: int) -> Optional[User]:
        """Get user by ID."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
            row = cursor.fetchone()
            if row:
                return User(
                    id=row['id'],
                    username=row['username'],
                    password_hash=row['password_hash'],
                    salt=row['salt'],
                    email=row['email'],
                    role=row['role'],
                    is_active=row['is_active'],
                    failed_login_attempts=row['failed_login_attempts'],
                    locked_until=row['locked_until'],
                    created_at=row['created_at'],
                    last_login=row['last_login']
                )
            return None
    
    def get_user_by_username(self, username: str) -> Optional[User]:
        """Get user by username."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
            row = cursor.fetchone()
            if row:
                return User(
                    id=row['id'],
                    username=row['username'],
                    password_hash=row['password_hash'],
                    salt=row['salt'],
                    email=row['email'],
                    role=row['role'],
                    is_active=row['is_active'],
                    failed_login_attempts=row['failed_login_attempts'],
                    locked_until=row['locked_until'],
                    created_at=row['created_at'],
                    last_login=row['last_login']
                )
            return None
    
    def is_account_locked(self, username: str) -> Tuple[bool, Optional[datetime]]:
        """Check if account is locked."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT locked_until FROM users WHERE username = ?", (username,))
            row = cursor.fetchone()
            if row and row['locked_until']:
                locked_until = datetime.fromisoformat(row['locked_until']) if isinstance(row['locked_until'], str) else row['locked_until']
                if locked_until > datetime.utcnow():
                    return True, locked_until
            return False, None
    
    # ==================== SESSION METHODS ====================
    
    def create_session(self, user_id: int, duration_hours: int = 8) -> str:
        """Create a new session and return session ID."""
        session_id = secrets.token_urlsafe(32)
        expires_at = datetime.utcnow() + timedelta(hours=duration_hours)
        
        with self.get_connection() as conn:
            cursor = conn.cursor()
            # Deactivate old sessions for this user
            cursor.execute("UPDATE sessions SET is_active = 0 WHERE user_id = ?", (user_id,))
            # Create new session
            cursor.execute("""
                INSERT INTO sessions (id, user_id, expires_at)
                VALUES (?, ?, ?)
            """, (session_id, user_id, expires_at))
        
        return session_id
    
    def validate_session(self, session_id: str) -> Optional[User]:
        """Validate session and return user if valid."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT s.*, u.* FROM sessions s
                JOIN users u ON s.user_id = u.id
                WHERE s.id = ? AND s.is_active = 1
            """, (session_id,))
            row = cursor.fetchone()
            
            if not row:
                return None
            
            expires_at = datetime.fromisoformat(row['expires_at']) if isinstance(row['expires_at'], str) else row['expires_at']
            if expires_at < datetime.utcnow():
                # Session expired
                cursor.execute("UPDATE sessions SET is_active = 0 WHERE id = ?", (session_id,))
                return None
            
            return User(
                id=row['user_id'],
                username=row['username'],
                password_hash=row['password_hash'],
                salt=row['salt'],
                email=row['email'],
                role=row['role'],
                is_active=row['is_active'],
                failed_login_attempts=row['failed_login_attempts'],
                locked_until=row['locked_until'],
                created_at=row['created_at'],
                last_login=row['last_login']
            )
    
    def invalidate_session(self, session_id: str):
        """Invalidate a session."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE sessions SET is_active = 0 WHERE id = ?", (session_id,))
    
    def extend_session(self, session_id: str, duration_hours: int = 8) -> bool:
        """Extend session expiry time."""
        expires_at = datetime.utcnow() + timedelta(hours=duration_hours)
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE sessions SET expires_at = ? WHERE id = ? AND is_active = 1
            """, (expires_at, session_id))
            return cursor.rowcount > 0
    
    # ==================== LOGIN RATE LIMITING ====================
    
    def record_login_attempt(self, username: str, ip_address: Optional[str], success: bool):
        """Record a login attempt."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO login_attempts (username, ip_address, success)
                VALUES (?, ?, ?)
            """, (username, ip_address, success))
    
    def get_recent_login_attempts(self, username: str, minutes: int = 15) -> int:
        """Get count of recent failed login attempts."""
        since = datetime.utcnow() - timedelta(minutes=minutes)
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT COUNT(*) as count FROM login_attempts
                WHERE username = ? AND success = 0 AND attempted_at > ?
            """, (username, since))
            row = cursor.fetchone()
            return row['count'] if row else 0
    
    def is_rate_limited(self, username: str, max_attempts: int = 5, window_minutes: int = 15) -> bool:
        """Check if login is rate limited."""
        attempts = self.get_recent_login_attempts(username, window_minutes)
        return attempts >= max_attempts
    
    # ==================== SCAN METHODS ====================
    
    def create_scan(self, user_id: int, domains: List[str]) -> int:
        """Create a new scan record."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO scans (user_id, domains, status)
                VALUES (?, ?, 'running')
            """, (user_id, json.dumps(domains)))
            return cursor.lastrowid
    
    def update_scan(self, scan_id: int, status: str, total_findings: int = 0,
                    severity_breakdown: Optional[Dict] = None, scan_data: Optional[Dict] = None,
                    duration_seconds: Optional[float] = None):
        """Update scan record."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            completed_at = datetime.utcnow() if status in ('completed', 'failed') else None
            cursor.execute("""
                UPDATE scans SET status = ?, total_findings = ?, severity_breakdown = ?,
                scan_data = ?, completed_at = ?, duration_seconds = ?
                WHERE id = ?
            """, (status, total_findings, json.dumps(severity_breakdown) if severity_breakdown else None,
                  json.dumps(scan_data) if scan_data else None, completed_at, duration_seconds, scan_id))
    
    def get_scan(self, scan_id: int) -> Optional[ScanRecord]:
        """Get scan by ID."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
            row = cursor.fetchone()
            if row:
                return ScanRecord(
                    id=row['id'],
                    user_id=row['user_id'],
                    domains=json.loads(row['domains']),
                    status=row['status'],
                    total_findings=row['total_findings'],
                    severity_breakdown=json.loads(row['severity_breakdown']) if row['severity_breakdown'] else {},
                    scan_data=json.loads(row['scan_data']) if row['scan_data'] else {},
                    created_at=row['created_at'],
                    completed_at=row['completed_at'],
                    duration_seconds=row['duration_seconds']
                )
            return None
    
    def get_user_scans(self, user_id: int, limit: int = 50) -> List[ScanRecord]:
        """Get scans for a user."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM scans WHERE user_id = ?
                ORDER BY created_at DESC LIMIT ?
            """, (user_id, limit))
            rows = cursor.fetchall()
            return [
                ScanRecord(
                    id=row['id'],
                    user_id=row['user_id'],
                    domains=json.loads(row['domains']),
                    status=row['status'],
                    total_findings=row['total_findings'],
                    severity_breakdown=json.loads(row['severity_breakdown']) if row['severity_breakdown'] else {},
                    scan_data=json.loads(row['scan_data']) if row['scan_data'] else {},
                    created_at=row['created_at'],
                    completed_at=row['completed_at'],
                    duration_seconds=row['duration_seconds']
                )
                for row in rows
            ]
    
    def get_all_scans(self, limit: int = 100) -> List[ScanRecord]:
        """Get all scans (admin only)."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM scans ORDER BY created_at DESC LIMIT ?
            """, (limit,))
            rows = cursor.fetchall()
            return [
                ScanRecord(
                    id=row['id'],
                    user_id=row['user_id'],
                    domains=json.loads(row['domains']),
                    status=row['status'],
                    total_findings=row['total_findings'],
                    severity_breakdown=json.loads(row['severity_breakdown']) if row['severity_breakdown'] else {},
                    scan_data=json.loads(row['scan_data']) if row['scan_data'] else {},
                    created_at=row['created_at'],
                    completed_at=row['completed_at'],
                    duration_seconds=row['duration_seconds']
                )
                for row in rows
            ]
    
    def delete_scan(self, scan_id: int, user_id: int) -> bool:
        """Delete a scan (only if owned by user or user is admin)."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM scans WHERE id = ? AND user_id = ?", (scan_id, user_id))
            return cursor.rowcount > 0
    
    # ==================== WEBHOOK METHODS ====================
    
    def create_webhook(self, user_id: int, name: str, url: str, webhook_type: str = "generic") -> int:
        """Create a webhook."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO webhooks (user_id, name, url, webhook_type)
                VALUES (?, ?, ?, ?)
            """, (user_id, name, url, webhook_type))
            return cursor.lastrowid
    
    def get_user_webhooks(self, user_id: int) -> List[Dict]:
        """Get webhooks for a user."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM webhooks WHERE user_id = ? AND is_active = 1", (user_id,))
            return [dict(row) for row in cursor.fetchall()]
    
    def delete_webhook(self, webhook_id: int, user_id: int) -> bool:
        """Delete a webhook."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM webhooks WHERE id = ? AND user_id = ?", (webhook_id, user_id))
            return cursor.rowcount > 0
    
    def toggle_webhook(self, webhook_id: int, user_id: int, is_active: bool) -> bool:
        """Toggle webhook active status."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE webhooks SET is_active = ? WHERE id = ? AND user_id = ?
            """, (is_active, webhook_id, user_id))
            return cursor.rowcount > 0
    
    # ==================== AUDIT LOG ====================
    
    def log_audit(self, user_id: Optional[int], action: str, details: Optional[str] = None, ip_address: Optional[str] = None):
        """Log an audit event."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO audit_log (user_id, action, details, ip_address)
                VALUES (?, ?, ?, ?)
            """, (user_id, action, details, ip_address))
    
    def get_audit_log(self, limit: int = 100, user_id: Optional[int] = None) -> List[Dict]:
        """Get audit log entries."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            if user_id:
                cursor.execute("""
                    SELECT a.*, u.username FROM audit_log a
                    LEFT JOIN users u ON a.user_id = u.id
                    WHERE a.user_id = ?
                    ORDER BY a.created_at DESC LIMIT ?
                """, (user_id, limit))
            else:
                cursor.execute("""
                    SELECT a.*, u.username FROM audit_log a
                    LEFT JOIN users u ON a.user_id = u.id
                    ORDER BY a.created_at DESC LIMIT ?
                """, (limit,))
            return [dict(row) for row in cursor.fetchall()]


# Global database instance
db = Database()
