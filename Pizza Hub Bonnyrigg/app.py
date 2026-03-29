



from flask import (
    Flask, render_template, request, redirect,
    url_for, flash, session, g
)
# Imports Flask web framework and core security components for session management

from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps
# Implements bcrypt password hashing, file sanitization, and decorator utilities

from datetime import datetime, timedelta
import sqlite3
import os
import time
# Provides timestamp tracking for rate limiting, database operations, and timing attacks

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "pizza_blog.db")
UPLOAD_FOLDER = os.path.join(BASE_DIR, "static", "uploads")
# Defines absolute paths for database and uploads to prevent directory traversal attacks

ALLOWED_EXT = {"png", "jpg", "jpeg", "gif"}
app = Flask(__name__, static_folder="static", template_folder="templates")
app.secret_key = "dev_secret_change_me"
# Whitelists allowed image extensions, initializes Flask app with hardcoded secret key

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 4 * 1024 * 1024
# Configures upload folder path and enforces 4MB file size limit for DoS protection

MAX_LOGIN_ATTEMPTS = 5  # Max failed attempts before lockout
LOCKOUT_DURATION = 15 * 60  # 15 minutes in seconds
ATTEMPT_WINDOW = 60 * 60  # 1 hour window to count attempts
# Configures brute force protection: 5 attempts, 15-minute lockout, 1-hour tracking window

_failed_attempts = {}  # Format: {identifier: [(timestamp, count), ...]}
_locked_accounts = {}  # Format: {identifier: unlock_timestamp}
# In-memory storage for tracking failed attempts and locked accounts (lost on restart)


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXT
# Validates file extensions against whitelist to prevent malicious file uploads


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db
# Implements connection pooling per request with dictionary-like row access


@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()
# Automatically closes database connections after each request to prevent leaks


def init_db():
    db = sqlite3.connect(DB_PATH)
    cur = db.cursor()
# Connects to database and creates cursor for schema initialization

    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    """)
# Creates users table with UNIQUE email constraint to prevent duplicate accounts

    cur.execute("""
        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            author TEXT NOT NULL,
            content TEXT,
            ingredients TEXT,
            instructions TEXT,
            image_path TEXT
        )
    """)
# Creates posts table for storing pizza blog content without foreign key constraint

    cur.execute("""
        CREATE TABLE IF NOT EXISTS login_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            identifier TEXT NOT NULL,
            attempt_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            ip_address TEXT,
            success BOOLEAN DEFAULT 0
        )
    """)
# Creates audit table for persistent login attempt logging and forensic analysis

    db.commit()
    cur.execute("SELECT COUNT(*) FROM posts")
    if cur.fetchone()[0] == 0:
# Commits schema changes and checks if posts table is empty before seeding

        seed = [
            ("Margherita", "Admin", "Classic Margherita",
             "Tomatoes\nMozzarella\nBasil",
             "1. Prepare dough\n2. Add sauce\n3. Bake",
             "uploads/margherita.png"),
            ("Pepperoni", "Admin", "Pepperoni Pizza",
             "Pepperoni\nMozzarella\nSauce",
             "1. Prepare dough\n2. Add toppings\n3. Bake",
             "uploads/pepperoni.png"),
            ("BBQ Chicken", "Admin", "BBQ Chicken Pizza",
             "Chicken\nBBQ Sauce\nOnion",
             "1. Toss chicken\n2. Bake",
             "uploads/bbq_chicken.png"),
            ("Hawaiian", "Admin", "Hawaiian Pizza",
             "Pineapple\nHam\nMozzarella",
             "1. Add toppings\n2. Bake",
             "uploads/hawaiian.png"),
            ("Veggie Supreme", "Admin", "Veggie Pizza",
             "Peppers\nOlives\nMushrooms",
             "1. Prep veggies\n2. Bake",
             "uploads/veggie.png"),
            ("Meat Lovers", "Admin", "Meat Lovers Pizza",
             "Salami\nHam\nBacon\nSausage",
             "1. Add meats\n2. Bake",
             "uploads/meat_lovers.png")
        ]
# Defines 6 sample pizza recipes with hardcoded author "Admin" (security weakness)

        cur.executemany(
            """
            INSERT INTO posts
            (title, author, content, ingredients, instructions, image_path)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            seed
        )
        db.commit()
# Inserts seed data using parameterized queries to prevent SQL injection

    db.close()
init_db()
# Closes database connection after initialization and executes schema creation


def get_client_ip():
    """Get client IP address, handling proxies"""
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    return request.remote_addr
# Extracts real client IP from proxy headers for accurate rate limiting


def get_attempt_identifier(email=None):
    """
    Create unique identifier combining email and IP for targeted protection,
    while also tracking IP-only for broader protection
    """
    ip = get_client_ip()
    if email:
        return f"{email.lower()}:{ip}"
    return ip
# Creates composite identifier (email:IP) for per-user-per-location tracking


def is_locked_out(identifier):
    """Check if identifier is currently locked out"""
    if identifier in _locked_accounts:
        if datetime.now() < _locked_accounts[identifier]:
            remaining = (_locked_accounts[identifier] - datetime.now()).seconds // 60
            return True, remaining
        else:
            del _locked_accounts[identifier]
            if identifier in _failed_attempts:
                del _failed_attempts[identifier]
    return False, 0
# Checks lockout status, returns remaining minutes, and auto-cleans expired locks


def record_failed_attempt(identifier):
    """Record a failed login attempt"""
    now = datetime.now()
    
    if identifier not in _failed_attempts:
        _failed_attempts[identifier] = []
    
    _failed_attempts[identifier].append(now)
    
    cutoff = now - timedelta(seconds=ATTEMPT_WINDOW)
    _failed_attempts[identifier] = [
        t for t in _failed_attempts[identifier] if t > cutoff
    ]
# Records timestamp, initializes list, and removes attempts outside tracking window

    if len(_failed_attempts[identifier]) >= MAX_LOGIN_ATTEMPTS:
        _locked_accounts[identifier] = now + timedelta(seconds=LOCKOUT_DURATION)
        return True
    return False
# Locks account if attempts exceed threshold, returns True if newly locked


def record_successful_login(identifier):
    """Clear failed attempts on successful login"""
    if identifier in _failed_attempts:
        del _failed_attempts[identifier]
    if identifier in _locked_accounts:
        del _locked_accounts[identifier]
# Resets attempt counter and removes lockout on successful authentication


def get_remaining_attempts(identifier):
    """Get number of remaining attempts before lockout"""
    if identifier not in _failed_attempts:
        return MAX_LOGIN_ATTEMPTS
    return max(0, MAX_LOGIN_ATTEMPTS - len(_failed_attempts[identifier]))
# Calculates remaining allowed attempts, returns full attempts if no failures


def brute_force_protected(f):
    """Decorator to add brute force protection to login endpoints"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.method == "POST":
            email = request.form.get("email", "").strip().lower()
            identifier = get_attempt_identifier(email)
            
            locked, remaining = is_locked_out(identifier)
            if locked:
                flash(f"Account locked. Try again in {remaining} minutes.", "error")
                return redirect(url_for("login"))
            
            time.sleep(0.1 + (hash(identifier) % 200) / 1000)
            
        return f(*args, **kwargs)
    return decorated_function
# Intercepts POST requests, checks lockout status, adds random delay to prevent timing attacks


@app.route("/")
def index():
    db = get_db()
    cur = db.cursor()
    cur.execute("""
        SELECT id, title, author, content, image_path
        FROM posts
        ORDER BY id DESC
    """)
    posts = cur.fetchall()
# Fetches all posts with newest first using parameterized query (no user input)

    return render_template(
        "index.html",
        posts=posts,
        user_email=session.get("user_email")
    )
# Renders homepage with auto-escaping templates for XSS protection


@app.route("/post/<int:post_id>")
def post_view(post_id):
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT * FROM posts WHERE id = ?", (post_id,))
    post = cur.fetchone()
# Fetches single post using parameterized query to prevent SQL injection

    if not post:
        flash("Post not found", "error")
        return redirect(url_for("index"))
# Handles invalid post IDs with user feedback and redirect

    return render_template(
        "post_view.html",
        post=post,
        user_email=session.get("user_email")
    )
# Renders detailed post view with template auto-escaping


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
# Extracts and normalizes registration data (lowercases email for consistency)

        if not email or not password:
            flash("Email and password required", "error")
            return redirect(url_for("register"))
# Validates required fields before processing registration

        if len(password) < 8:
            flash("Password must be at least 8 characters long", "error")
            return redirect(url_for("register"))
# Enforces minimum password length of 8 characters

        if not any(c.isupper() for c in password) or not any(c.islower() for c in password):
            flash("Password must contain both uppercase and lowercase letters", "error")
            return redirect(url_for("register"))
# Requires both uppercase and lowercase letters for password complexity

        db = get_db()
        cur = db.cursor()

        try:
            cur.execute(
                "INSERT INTO users (email, password) VALUES (?, ?)",
                (email, generate_password_hash(password))
            )
            db.commit()
            flash("Registered. Please log in", "success")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("Email already registered", "error")
            return redirect(url_for("register"))
# Hashes password with bcrypt, handles duplicate email errors gracefully

    return render_template(
        "register.html",
        user_email=session.get("user_email")
    )
# Displays registration form (missing CSRF token protection)


@app.route("/login", methods=["GET", "POST"])
@brute_force_protected
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
# Protected by brute force decorator, extracts and normalizes credentials

        identifier = get_attempt_identifier(email)
        
        db = get_db()
        cur = db.cursor()
        cur.execute("SELECT * FROM users WHERE email = ?", (email,))
        row = cur.fetchone()
# Creates tracking identifier and fetches user with parameterized query

        if row and check_password_hash(row["password"], password):
            record_successful_login(identifier)
            
            session.clear()
            session["user_email"] = row["email"]
            flash("Logged in", "success")
            return redirect(url_for("dashboard"))
# Verifies password with constant-time comparison, clears attempts, creates session

        just_locked = record_failed_attempt(identifier)
        remaining = get_remaining_attempts(identifier)
        
        if just_locked:
            flash(f"Too many failed attempts. Account locked for {LOCKOUT_DURATION // 60} minutes.", "error")
        else:
            flash(f"Invalid credentials. {remaining} attempts remaining.", "error")
        
        return redirect(url_for("login"))
# Records failed attempt, displays remaining attempts or lockout message

    return render_template(
        "login.html",
        user_email=session.get("user_email")
    )
# Displays login form (missing CSRF token protection)


@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out", "success")
    return redirect(url_for("index"))
# Clears all session data on logout and redirects to homepage


@app.route("/dashboard")
def dashboard():
    if not session.get("user_email"):
        flash("Please log in", "error")
        return redirect(url_for("login"))
# Checks authentication before allowing access to user dashboard

    db = get_db()
    cur = db.cursor()
    cur.execute(
        "SELECT * FROM posts WHERE author = ?",
        (session.get("user_email"),)
    )
    my_posts = cur.fetchall()
# Filters posts by logged-in user's email using parameterized query

    return render_template(
        "dashboard.html",
        my_posts=my_posts,
        user_email=session.get("user_email")
    )
# Renders dashboard showing only user's own posts


@app.route("/post/new", methods=["GET", "POST"])
def post_new():
    if not session.get("user_email"):
        flash("Please log in to create a post", "error")
        return redirect(url_for("login"))
# Requires authentication before allowing post creation

    if request.method == "POST":
        title = request.form.get("title", "").strip()
        content = request.form.get("content", "").strip()
        ingredients = request.form.get("ingredients", "").strip()
        instructions = request.form.get("instructions", "").strip()
# Extracts form data without XSS sanitization (security vulnerability)

        if "image" not in request.files:
            flash("Image required", "error")
            return redirect(url_for("post_new"))
# Validates image file presence in request

        file = request.files["image"]
        if file.filename == "":
            flash("No image selected", "error")
            return redirect(url_for("post_new"))
# Checks that user actually selected a file

        if not allowed_file(file.filename):
            flash("Invalid image type", "error")
            return redirect(url_for("post_new"))
# Validates file extension against whitelist

        filename = secure_filename(file.filename)
        save_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
# Sanitizes filename to prevent path traversal attacks

        base, ext = os.path.splitext(filename)
        i = 1
        while os.path.exists(save_path):
            filename = f"{base}-{i}{ext}"
            save_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            i += 1
# Handles duplicate filenames by appending counter to prevent overwrites

        file.save(save_path)
        image_db_path = f"uploads/{filename}"
# Saves file to upload folder and creates database reference path

        db = get_db()
        cur = db.cursor()
        cur.execute(
            """
            INSERT INTO posts
            (title, author, content, ingredients, instructions, image_path)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                title,
                session.get("user_email"),
                content,
                ingredients,
                instructions,
                image_db_path
            )
        )
        db.commit()
# Inserts post with parameterized query but without XSS sanitization

        flash("Post created", "success")
        return redirect(url_for("post_view", post_id=cur.lastrowid))
# Redirects to view the newly created post

    return render_template(
        "post_new.html",
        user_email=session.get("user_email")
    )
# Displays post creation form (missing CSRF token protection)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
# Runs development server on localhost with debug mode (security risk for production)
