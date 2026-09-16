# =============================================================================
# CloudMart — app.py
# Intentionally Vulnerable Web Application for Cybersecurity Training Labs
# Topics: Threat Modeling, SAST/DAST, API Exploitation (BOLA/BFLA/SQLi), CI/CD Security
#
# FOR EDUCATIONAL USE ONLY. DO NOT DEPLOY IN PRODUCTION ENVIRONMENTS.
# =============================================================================

import os
import time
import sqlite3
import datetime
import threading
from collections import deque
from functools import wraps

import jwt
from flask import (
    Flask,
    request,
    jsonify,
    render_template,
    redirect,
    url_for,
    make_response,
    g,
)

app = Flask(__name__)

# =============================================================================
# CONFIGURATION & HARDCODED SECRETS
# =============================================================================

# VULN: Hardcoded JWT secret key directly in source code (CWE-798).
# Secrets should be securely injected via environment variables or a vault.
app.secret_key = "cloudmart-secret-jwt-key-2026-training-lab"

# VULN: Hardcoded database credentials in source code (CWE-798 / CWE-259).
DB_HOST = "internal-db.cloudmart.local"
DB_USER = "cloudmart_admin"
DB_PASSWORD = "SuperSecretDBPassword2026!"
DB_PATH = "lab.db"

# Thread-safe in-memory circular buffer for the live request log (last 20 requests)
REQUEST_LOG_LIMIT = 20
request_log = deque(maxlen=REQUEST_LOG_LIMIT)
request_log_lock = threading.Lock()


# =============================================================================
# DATABASE HELPERS
# =============================================================================

def get_db():
    """Return a connection to the SQLite database with Row factory."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


# =============================================================================
# REQUEST LOGGING HOOKS (Live Request Log Panel)
# =============================================================================

@app.before_request
def before_request_hook():
    """Track request start time for response latency measurement."""
    g.start_time = time.perf_counter()


@app.after_request
def after_request_hook(response):
    """
    Log incoming API and application requests to the in-memory log buffer.
    Excluded: Polling requests to /api/request-log and static assets to prevent flood.
    """
    # Exclude request-log polling and static assets from flooding the dashboard monitor
    if request.path == "/api/request-log" or request.path.startswith("/static"):
        return response

    duration_ms = round((time.perf_counter() - getattr(g, "start_time", time.perf_counter())) * 1000, 2)
    timestamp = datetime.datetime.now().strftime("%H:%M:%S")
    full_path = request.full_path.rstrip("?") if request.query_string else request.path

    entry = {
        "timestamp": timestamp,
        "method": request.method,
        "endpoint": full_path,
        "status_code": response.status_code,
        "duration_ms": duration_ms,
    }

    with request_log_lock:
        request_log.append(entry)

    return response


# =============================================================================
# AUTHENTICATION & JWT HELPERS
# =============================================================================

def get_current_user():
    """
    Extract and decode JWT token from Authorization header, cookie, or query param.
    Returns user payload dictionary or None if invalid/missing.
    """
    token = None

    # 1. Check Authorization Bearer header
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header.split(" ", 1)[1].strip()

    # 2. Check cookie (convenient for browser direct URL navigation like /orders/<id>)
    if not token:
        token = request.cookies.get("token")

    # 3. Check query param (convenient for quick lab testing)
    if not token:
        token = request.args.get("token")

    if not token:
        return None

    try:
        payload = jwt.decode(token, app.secret_key, algorithms=["HS256"])
        return payload
    except Exception:
        return None


def jwt_required(f):
    """Decorator requiring a valid JWT token to access the endpoint."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = get_current_user()
        if not user:
            # If the client expects JSON, return 401 JSON
            if request.is_json or request.path.startswith("/orders") or request.path.startswith("/admin"):
                return jsonify({"error": "Unauthorized: Valid JWT token required"}), 401
            return redirect(url_for("login_page"))
        g.current_user = user
        return f(*args, **kwargs)
    return decorated_function


# =============================================================================
# FRONTEND ROUTES (HTML)
# =============================================================================

@app.route("/")
def index():
    """Root route redirects to dashboard if authenticated, else login page."""
    user = get_current_user()
    if user:
        return redirect(url_for("dashboard_page"))
    return redirect(url_for("login_page"))


@app.route("/login", methods=["GET"])
def login_page():
    """Render the login page."""
    return render_template("login.html")


@app.route("/dashboard", methods=["GET"])
def dashboard_page():
    """Render the main CloudMart dashboard page."""
    return render_template("dashboard.html")


# =============================================================================
# API ENDPOINTS
# =============================================================================

# -----------------------------------------------------------------------------
# POST /login
# -----------------------------------------------------------------------------
@app.route("/login", methods=["POST"])
def login():
    """
    Authenticate a user by username and password.

    VULN: No rate limiting or brute-force throttling (CWE-307).
          An attacker can perform automated credential stuffing and brute-force attacks.

    VULN: Passwords stored and compared in plaintext (CWE-256 / CWE-312 / CWE-522).
          Passwords are never hashed or salted.
    """
    data = request.get_json(silent=True) or request.form.to_dict()
    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    conn = get_db()
    # VULN: Plaintext password comparison
    row = conn.execute(
        "SELECT id, username, email, password, role FROM users WHERE username = ? AND password = ?",
        (username, password),
    ).fetchone()
    conn.close()

    if not row:
        return jsonify({"status": "failure", "message": "Invalid username or password"}), 401

    # Issue JWT token valid for 24 hours
    token_payload = {
        "user_id": row["id"],
        "username": row["username"],
        "role": row["role"],
        "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=24),
    }
    token = jwt.encode(token_payload, app.secret_key, algorithm="HS256")

    response = make_response(
        jsonify({
            "status": "success",
            "message": f"Welcome back, {row['username']}!",
            "token": token,
            "user": {
                "id": row["id"],
                "username": row["username"],
                "email": row["email"],
                "role": row["role"],
            },
        })
    )
    # Set cookie for easy browser navigation across endpoints
    response.set_cookie("token", token, path="/", httponly=False)
    return response


# -----------------------------------------------------------------------------
# GET /products
# -----------------------------------------------------------------------------
@app.route("/products", methods=["GET"])
def get_products():
    """
    Public catalog endpoint returning all available cloud products.
    """
    conn = get_db()
    rows = conn.execute("SELECT id, name, price, description FROM products").fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


# -----------------------------------------------------------------------------
# GET /products/search?q=
# -----------------------------------------------------------------------------
@app.route("/products/search", methods=["GET"])
def search_products():
    """
    Search products by name.

    VULN: SQL Injection via unsanitized string formatting / f-string (CWE-89).
          The query is built with an f-string instead of parameterized query bindings.
          Exploit examples:
            /products/search?q=' OR '1'='1
            /products/search?q=' UNION SELECT id, username, password, role FROM users--

    VULN: Verbose Error Messages (CWE-209).
          Database exception messages are returned directly to the client, revealing
          table schemas and SQL dialect information to attackers.
    """
    q = request.args.get("q", "")

    conn = get_db()
    # VULN: Raw SQL query constructed with string concatenation / f-string
    query = f"SELECT id, name, price, description FROM products WHERE name LIKE '%{q}%'"

    try:
        rows = conn.execute(query).fetchall()
        products = [dict(r) for r in rows]
        return jsonify(products)
    except Exception as e:
        # VULN: Leaking database error trace to the client (CWE-209)
        return jsonify({
            "error": "Database Query Error",
            "details": str(e),
            "executed_query": query,
        }), 500
    finally:
        conn.close()


# -----------------------------------------------------------------------------
# GET /orders (List current logged-in user's orders)
# -----------------------------------------------------------------------------
@app.route("/orders", methods=["GET"])
@jwt_required
def list_my_orders():
    """
    Fetch the order history for the currently authenticated user.
    """
    current_user = g.current_user
    conn = get_db()
    query = """
        SELECT orders.id, orders.user_id, orders.product_id, products.name AS product_name,
               products.price, orders.quantity, orders.status
        FROM orders
        JOIN products ON orders.product_id = products.id
        WHERE orders.user_id = ?
        ORDER BY orders.id DESC
    """
    rows = conn.execute(query, (current_user["user_id"],)).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


# -----------------------------------------------------------------------------
# POST /orders (Create a new order for the logged-in user)
# -----------------------------------------------------------------------------
@app.route("/orders", methods=["POST"])
@jwt_required
def create_order():
    """
    Create a new order for the authenticated user. Requires valid JWT.
    """
    current_user = g.current_user
    data = request.get_json(silent=True) or request.form.to_dict()

    try:
        product_id = int(data.get("product_id"))
        quantity = int(data.get("quantity", 1))
    except (TypeError, ValueError):
        return jsonify({"error": "Invalid product_id or quantity"}), 400

    if quantity <= 0:
        return jsonify({"error": "Quantity must be greater than zero"}), 400

    conn = get_db()
    # Verify product exists
    product = conn.execute("SELECT id, name, price FROM products WHERE id = ?", (product_id,)).fetchone()
    if not product:
        conn.close()
        return jsonify({"error": "Product not found"}), 404

    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO orders (user_id, product_id, quantity, status) VALUES (?, ?, ?, 'Pending')",
        (current_user["user_id"], product_id, quantity),
    )
    order_id = cursor.lastrowid
    conn.commit()
    conn.close()

    return jsonify({
        "status": "success",
        "message": "Order created successfully",
        "order": {
            "id": order_id,
            "user_id": current_user["user_id"],
            "product_id": product_id,
            "product_name": product["name"],
            "quantity": quantity,
            "status": "Pending",
        }
    }), 201


# -----------------------------------------------------------------------------
# GET /orders/<id> (Order details — BOLA / IDOR)
# -----------------------------------------------------------------------------
@app.route("/orders/<int:order_id>", methods=["GET"])
@jwt_required
def get_order(order_id):
    """
    Fetch order details by order ID.

    VULN: Broken Object Level Authorization (BOLA / IDOR) (CWE-639).
          The endpoint requires a valid JWT, BUT it fails to verify whether the
          requested order belongs to the authenticated user!
          Any logged-in user can view any other user's order details simply by
          changing the ID in the URL.
    """
    conn = get_db()
    query = """
        SELECT orders.id, orders.user_id, users.username AS customer_username, users.email AS customer_email,
               orders.product_id, products.name AS product_name, products.price AS unit_price,
               orders.quantity, (products.price * orders.quantity) AS total_amount, orders.status
        FROM orders
        JOIN users ON orders.user_id = users.id
        JOIN products ON orders.product_id = products.id
        WHERE orders.id = ?
    """
    row = conn.execute(query, (order_id,)).fetchone()
    conn.close()

    if not row:
        return jsonify({"error": "Order not found"}), 404

    # Notice: No check like `if row["user_id"] != g.current_user["user_id"]:`
    # This exposes the order and customer information to any authenticated user.
    return jsonify(dict(row))


# -----------------------------------------------------------------------------
# GET /admin/users (Broken Function-Level Authorization)
# -----------------------------------------------------------------------------
@app.route("/admin/users", methods=["GET"])
@jwt_required
def admin_users():
    """
    Administrative endpoint meant to be restricted to admins only.

    VULN: Broken Function-Level Authorization (BFLA) / Missing Authorization Check (CWE-285 / CWE-862).
          The endpoint requires authentication (a valid JWT), but completely omits
          checking whether the user has the 'admin' role!
          Any regular logged-in user (e.g., 'alice', 'bob') can call this endpoint.

    VULN: Sensitive Data Exposure (CWE-200 / CWE-312).
          Returns the entire user database table including plaintext passwords.
    """
    # Notice: missing `if g.current_user.get("role") != "admin": return 403`
    conn = get_db()
    rows = conn.execute("SELECT id, username, email, password, role FROM users").fetchall()
    conn.close()

    return jsonify([dict(r) for r in rows])


# -----------------------------------------------------------------------------
# GET /api/request-log (Live Request Log Panel)
# -----------------------------------------------------------------------------
@app.route("/api/request-log", methods=["GET"])
def get_request_log():
    """
    Returns the last ~20 HTTP requests processed by the backend.
    Polled every 2 seconds by the live request log panel in the frontend.
    """
    with request_log_lock:
        logs = list(request_log)

    # Return reverse order so newest requests appear at top
    return jsonify(list(reversed(logs)))


# =============================================================================
# ENTRY POINT
# =============================================================================

if __name__ == "__main__":
    # VULN: Debug mode enabled in production-style entry point (CWE-215 / CWE-489).
    # debug=True enables Werkzeug's interactive web debugger which allows arbitrary
    # Python code execution when unhandled exceptions occur.
    print("[*] Starting CloudMart Vulnerable Application...")
    print("[*] Web Dashboard: http://127.0.0.1:5000")
    app.run(debug=False, host="0.0.0.0", port=5000)
