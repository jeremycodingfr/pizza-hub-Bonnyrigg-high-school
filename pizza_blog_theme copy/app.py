from flask import (
    Flask, render_template, request, redirect,
    url_for, flash, session, g
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import sqlite3
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "pizza_blog.db")
UPLOAD_FOLDER = os.path.join(BASE_DIR, "static", "uploads")
ALLOWED_EXT = {"png", "jpg", "jpeg", "gif"}

app = Flask(__name__, static_folder="static", template_folder="templates")
app.secret_key = "dev_secret_change_me"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 4 * 1024 * 1024


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXT


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DB_PATH)
    cur = db.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    """)

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

    db.commit()

    cur.execute("SELECT COUNT(*) FROM posts")
    if cur.fetchone()[0] == 0:
        seed = [
            (
                "Margherita", "Admin", "Classic Margherita",
                "Tomatoes\nMozzarella\nBasil",
                "1. Prepare dough\n2. Add sauce\n3. Bake",
                "uploads/margherita.png"
            ),
            (
                "Pepperoni", "Admin", "Pepperoni Pizza",
                "Pepperoni\nMozzarella\nSauce",
                "1. Prepare dough\n2. Add toppings\n3. Bake",
                "uploads/pepperoni.png"
            ),
            (
                "BBQ Chicken", "Admin", "BBQ Chicken Pizza",
                "Chicken\nBBQ Sauce\nOnion",
                "1. Toss chicken\n2. Bake",
                "uploads/bbq_chicken.png"
            ),
            (
                "Hawaiian", "Admin", "Hawaiian Pizza",
                "Pineapple\nHam\nMozzarella",
                "1. Add toppings\n2. Bake",
                "uploads/hawaiian.png"
            ),
            (
                "Veggie Supreme", "Admin", "Veggie Pizza",
                "Peppers\nOlives\nMushrooms",
                "1. Prep veggies\n2. Bake",
                "uploads/veggie.png"
            ),
            (
                "Meat Lovers", "Admin", "Meat Lovers Pizza",
                "Salami\nHam\nBacon\nSausage",
                "1. Add meats\n2. Bake",
                "uploads/meat_lovers.png"
            )
        ]

        cur.executemany(
            """
            INSERT INTO posts
            (title, author, content, ingredients, instructions, image_path)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            seed
        )
        db.commit()

    db.close()


init_db()


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
    return render_template(
        "index.html",
        posts=posts,
        user_email=session.get("user_email")
    )


@app.route("/post/<int:post_id>")
def post_view(post_id):
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT * FROM posts WHERE id = ?", (post_id,))
    post = cur.fetchone()

    if not post:
        flash("Post not found", "error")
        return redirect(url_for("index"))

    return render_template(
        "post_view.html",
        post=post,
        user_email=session.get("user_email")
    )


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not email or not password:
            flash("Email and password required", "error")
            return redirect(url_for("register"))

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

    return render_template(
        "register.html",
        user_email=session.get("user_email")
    )


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        db = get_db()
        cur = db.cursor()
        cur.execute("SELECT * FROM users WHERE email = ?", (email,))
        row = cur.fetchone()

        if row and check_password_hash(row["password"], password):
            session.clear()
            session["user_email"] = row["email"]
            flash("Logged in", "success")
            return redirect(url_for("dashboard"))

        flash("Invalid credentials", "error")
        return redirect(url_for("login"))

    return render_template(
        "login.html",
        user_email=session.get("user_email")
    )


@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out", "success")
    return redirect(url_for("index"))


@app.route("/dashboard")
def dashboard():
    if not session.get("user_email"):
        flash("Please log in", "error")
        return redirect(url_for("login"))

    db = get_db()
    cur = db.cursor()
    cur.execute(
        "SELECT * FROM posts WHERE author = ?",
        (session.get("user_email"),)
    )
    my_posts = cur.fetchall()

    return render_template(
        "dashboard.html",
        my_posts=my_posts,
        user_email=session.get("user_email")
    )


@app.route("/post/new", methods=["GET", "POST"])
def post_new():
    if not session.get("user_email"):
        flash("Please log in to create a post", "error")
        return redirect(url_for("login"))

    if request.method == "POST":
        title = request.form.get("title", "").strip()
        content = request.form.get("content", "").strip()
        ingredients = request.form.get("ingredients", "").strip()
        instructions = request.form.get("instructions", "").strip()

        if "image" not in request.files:
            flash("Image required", "error")
            return redirect(url_for("post_new"))

        file = request.files["image"]

        if file.filename == "":
            flash("No image selected", "error")
            return redirect(url_for("post_new"))

        if not allowed_file(file.filename):
            flash("Invalid image type", "error")
            return redirect(url_for("post_new"))

        filename = secure_filename(file.filename)
        save_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)

        base, ext = os.path.splitext(filename)
        i = 1
        while os.path.exists(save_path):
            filename = f"{base}-{i}{ext}"
            save_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            i += 1

        file.save(save_path)
        image_db_path = f"uploads/{filename}"

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

        flash("Post created", "success")
        return redirect(url_for("post_view", post_id=cur.lastrowid))

    return render_template(
        "post_new.html",
        user_email=session.get("user_email")
    )


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
