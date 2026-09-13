# CloudMart — Implementation & Architecture Documentation

This document provides a comprehensive technical overview of **CloudMart**, an intentionally vulnerable web application engineered for cybersecurity education. The application is tailored for hands-on 25–30 minute training labs covering threat modeling, SAST/DAST scanning, API/authorization exploitation, and CI/CD security pipelines.

---

## 1. Project Overview & Objectives

CloudMart simulates a modern cloud infrastructure service portal where authenticated users can browse compute/storage products, execute searches, provision resources (place orders), view order history, and monitor live API traffic.

The application serves three distinct cybersecurity training modules:

1. **Lab 1: Threat Modeling, SAST & DAST**
   - STRIDE threat modeling of cloud management portals and API boundaries.
   - Static Application Security Testing (SAST) using tools such as Bandit.
   - Dynamic Application Security Testing (DAST) using tools such as OWASP ZAP.
2. **Lab 2: API & Authorization Exploitation**
   - Exploiting SQL Injection (CWE-89) in search endpoints.
   - Exploiting Broken Object Level Authorization (BOLA / IDOR - CWE-639) by viewing cross-user orders.
   - Exploiting Broken Function-Level Authorization (BFLA - CWE-862) by accessing administrative user lists as an unprivileged user.
3. **Lab 3: CI/CD Security Pipeline**
   - Adding automated secret scanning (detect-secrets, TruffleHog, Gitleaks).
   - Establishing automated security quality gates in GitHub Actions or GitLab CI.

---

## 2. Technology Stack & Design Principles

- **Backend**: Python 3.10+ / Flask 3.0+
- **Authentication**: Stateless JSON Web Tokens (PyJWT) with HMAC-SHA256 signature algorithm.
- **Database**: SQLite3 (`lab.db`), seeded with users, catalog items, and multi-user orders via `init_db.py`.
- **Frontend**: Plain HTML5, modern CSS3 (custom dark-slate projector theme), and Vanilla JavaScript (ES6+). Zero build tools, zero npm/Webpack overhead.
- **Live Traffic Monitoring**: Thread-safe in-memory circular buffer tracking recent HTTP requests via Flask's `before_request` and `after_request` hooks.
- **Dual-Mode JWT Handling**: JWT is stored in both `localStorage` (for API fetch calls) and synchronized to an HTTP cookie (enabling seamless browser address bar URL editing for BOLA demonstrations).

---

## 3. Directory & File Structure

```
lab app/
├── app.py                  # Flask backend with all routes, hooks, and vulnerabilities
├── init_db.py              # SQLite database creation and seeding script
├── lab.db                  # SQLite database file (created on initialization)
├── requirements.txt        # Minimal Python dependencies (Flask, PyJWT)
├── test_app.py             # Automated unit and security exploitation test suite
├── README.md               # User quick-start guide and instructor answer key
├── app.md                  # Comprehensive technical implementation documentation
├── templates/
│   ├── login.html          # Authentication page with quick account switcher pills
│   └── dashboard.html      # Main portal: catalog, orders, admin modal, request monitor
└── static/
    ├── css/
    │   └── style.css       # Projector-friendly high-contrast dark theme
    └── js/
        └── app.js          # Client controller: auth, ordering, BOLA links, live polling
```

---

## 4. Database Schema & Seed Data (`init_db.py`)

### Tables

#### 1. `users` Table
```sql
CREATE TABLE users (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT    NOT NULL UNIQUE,
    email    TEXT    NOT NULL,
    password TEXT    NOT NULL,
    role     TEXT    NOT NULL DEFAULT 'user'
);
```
*Seeded records:*
- `alice` (`alice@cloudmart.local` / `password123` / role: `user`)
- `bob` (`bob@cloudmart.local` / `letmein` / role: `user`)
- `charlie` (`charlie@cloudmart.local` / `qwerty` / role: `user`)
- `admin` (`admin@cloudmart.local` / `admin1234` / role: `admin`)

#### 2. `products` Table
```sql
CREATE TABLE products (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT    NOT NULL,
    price       REAL    NOT NULL,
    description TEXT    NOT NULL
);
```
*Seeded records:*
1. Cloud Compute Instance - 4 vCPU ($49.99)
2. Object Storage Bucket - 1TB ($19.99)
3. Serverless Functions Pro ($29.99)
4. Managed Cloud SQL Database ($59.99)
5. Cloud Armor Web App Firewall ($89.99)
6. DevOps Continuous Delivery Pipeline ($39.99)

#### 3. `orders` Table
```sql
CREATE TABLE orders (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL,
    product_id INTEGER NOT NULL,
    quantity   INTEGER NOT NULL DEFAULT 1,
    status     TEXT    NOT NULL DEFAULT 'Pending',
    FOREIGN KEY (user_id) REFERENCES users (id),
    FOREIGN KEY (product_id) REFERENCES products (id)
);
```
*Seeded cross-user orders:*
- **Alice (User ID 1)**:
  - Order #1: Product 1 (2x Cloud Compute Instance) — `Delivered`
  - Order #2: Product 3 (1x Serverless Functions) — `Processing`
- **Bob (User ID 2)**:
  - Order #3: Product 2 (5x Object Storage Bucket) — `Delivered`
  - Order #4: Product 4 (1x Managed Cloud SQL) — `Shipped`
  - Order #5: Product 5 (1x Cloud Armor WAF) — `Pending`
- **Charlie (User ID 3)**:
  - Order #6: Product 6 (2x DevOps Pipeline) — `Delivered`
  - Order #7: Product 1 (1x Cloud Compute Instance) — `Shipped`
- **Admin (User ID 4)**:
  - Order #8: Product 5 (3x Cloud Armor WAF) — `Delivered`

---

## 5. Backend Endpoints Specification (`app.py`)

### 1. `POST /login`
- **Purpose**: Authenticates users and issues JWT.
- **Request Body**: `{"username": "alice", "password": "password123"}` (JSON or Form).
- **Vulnerabilities**:
  - `CWE-307`: No rate limiting or brute-force throttling.
  - `CWE-256 / CWE-312`: Cleartext password storage and direct string equality comparison.
- **Response**:
  ```json
  {
    "status": "success",
    "message": "Welcome back, alice!",
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "user": {
      "id": 1,
      "username": "alice",
      "email": "alice@cloudmart.local",
      "role": "user"
    }
  }
  ```
  *(Also sets `Set-Cookie: token=<jwt>; Path=/; Max-Age=86400`)*.

---

### 2. `GET /products`
- **Purpose**: Public catalog listing.
- **Authentication**: None.
- **Response**: Array of product objects (`id`, `name`, `price`, `description`).

---

### 3. `GET /products/search?q=`
- **Purpose**: Catalog search by product name.
- **Authentication**: None.
- **Implementation**:
  ```python
  query = f"SELECT id, name, price, description FROM products WHERE name LIKE '%{q}%'"
  ```
- **Vulnerabilities**:
  - `CWE-89`: SQL Injection via unescaped string formatting.
  - `CWE-209`: Verbose error exposure (returns `str(e)` and `executed_query` on SQLite syntax error).
- **Exploitation Examples**:
  - Bypass: `/products/search?q=' OR '1'='1`
  - UNION Injection: `/products/search?q=' UNION SELECT id, username, password, role FROM users--`

---

### 4. `GET /orders`
- **Purpose**: Lists all orders created by the authenticated user.
- **Authentication**: Valid JWT required.
- **Implementation**: Scoped by `WHERE orders.user_id = ?` using the decoded JWT user ID.
- **Response**: Array of user order objects with joined product titles and status values.

---

### 5. `POST /orders`
- **Purpose**: Provision a new cloud resource order for the authenticated user.
- **Authentication**: Valid JWT required.
- **Request Body**: `{"product_id": 1, "quantity": 2}`.
- **Response**: HTTP 201 with created order details.

---

### 6. `GET /orders/<id>` (BOLA / IDOR Target)
- **Purpose**: Retrieve full details of a specific order.
- **Authentication**: Valid JWT required.
- **Vulnerability**:
  - `CWE-639`: **Broken Object Level Authorization (BOLA)**.
  - While the route verifies that the requester has a valid JWT, it fails to verify whether the order belongs to the requester:
    ```python
    # VULN: Missing ownership check:
    # if row["user_id"] != g.current_user["user_id"]: return 403
    ```
- **Exploit**:
  1. User `alice` (User ID 1) logs in.
  2. Alice visits `/orders/1` in the browser or via curl.
  3. Alice changes the URL to `/orders/3` and immediately views Bob's private purchase order, total pricing, and contact email.

---

### 7. `GET /admin/users` (BFLA Target)
- **Purpose**: Administrative user management endpoint.
- **Authentication**: Valid JWT required.
- **Vulnerabilities**:
  - `CWE-862 / CWE-285`: **Broken Function-Level Authorization (BFLA)**. Lacks role enforcement (`role == 'admin'`). Any authenticated user (even role `user`) can call this endpoint.
  - `CWE-200 / CWE-312`: Sensitive data exposure — dumps all database columns including plaintext passwords.

---

### 8. `GET /api/request-log`
- **Purpose**: Live server traffic telemetry.
- **Authentication**: None.
- **Implementation**: Returns the last 20 requests stored in a thread-safe `collections.deque`.
- **Response**:
  ```json
  [
    {
      "timestamp": "22:31:05",
      "method": "GET",
      "endpoint": "/products/search?q=' OR '1'='1",
      "status_code": 200,
      "duration_ms": 1.45
    }
  ]
  ```

---

## 6. Complete Intentional Vulnerabilities Matrix

| # | Vulnerability Name | CWE ID | Code Location | Technical Description & Educational Significance |
|:--|:-------------------|:-------|:--------------|:-------------------------------------------------|
| **1** | **Hardcoded JWT Secret** | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) | `app.py:37` | Flask `secret_key` embedded in source code. Enables offline signature forgery of arbitrary JWT claims (`user_id`, `role`). |
| **2** | **Hardcoded DB Credentials** | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) / [CWE-259](https://cwe.mitre.org/data/definitions/259.html) | `app.py:40–42` | Embedded database username and password strings detectable by regex-based SAST and secret scanners. |
| **3** | **Debug Mode in Production** | [CWE-215](https://cwe.mitre.org/data/definitions/215.html) / [CWE-489](https://cwe.mitre.org/data/definitions/489.html) | `app.py:452` | `app.run(debug=True)` activates Werkzeug's interactive web debugger, allowing arbitrary Python evaluation on unhandled exceptions. |
| **4** | **Plaintext Passwords** | [CWE-256](https://cwe.mitre.org/data/definitions/256.html) / [CWE-312](https://cwe.mitre.org/data/definitions/312.html) | `init_db.py:42`, `app.py:201` | Passwords stored without one-way hashing (bcrypt/argon2) and compared using direct string equality. |
| **5** | **Absence of Rate Limiting** | [CWE-307](https://cwe.mitre.org/data/definitions/307.html) | `app.py:181` (`/login`) | Authentication endpoint lacks throttling, lockout policies, or proof-of-work, permitting high-velocity brute-force attacks. |
| **6** | **SQL Injection (SQLi)** | [CWE-89](https://cwe.mitre.org/data/definitions/89.html) | `app.py:273` (`/products/search`) | User query concatenated directly into SQL string using an f-string instead of parameterized query parameters (`?`). |
| **7** | **Verbose Error Leakage** | [CWE-209](https://cwe.mitre.org/data/definitions/209.html) | `app.py:280–285` (`/products/search`) | Database exceptions return raw error strings and the constructed SQL query to the HTTP client. |
| **8** | **Broken Object Level Auth (BOLA / IDOR)** | [CWE-639](https://cwe.mitre.org/data/definitions/639.html) | `app.py:368` (`/orders/<id>`) | Endpoint checks for authentication but omits authorization, allowing any user to view any other customer's order. |
| **9** | **Broken Function-Level Auth (BFLA)** | [CWE-862](https://cwe.mitre.org/data/definitions/862.html) / [CWE-285](https://cwe.mitre.org/data/definitions/285.html) | `app.py:404` (`/admin/users`) | Administrative functionality lacks role verification (`current_user.role == 'admin'`), exposing admin data to regular users. |
| **10** | **Sensitive Data Exposure** | [CWE-200](https://cwe.mitre.org/data/definitions/200.html) | `app.py:420` (`/admin/users`) | Query executes `SELECT *` / includes password column, leaking user credentials in API responses. |

---

## 7. Frontend Features & Visual Accent Scheme

1. **Aesthetic Accent Color Palette**:
   - **Background**: Very light gray canvas (`#f8fafc`) with clean white card surfaces (`#ffffff`).
   - **Primary Accent**: Soft blue (`#2563eb`, hover `#1d4ed8`) used for:
     - Header brand logo text (`CloudMart`)
     - Primary action buttons (`Search`, `Order`, `Sign In`)
     - Clickable links (`/orders/<id>`) and the `Admin Users (/admin/users)` action button
     - Section header left-border accents (`border-left: 3px solid #2563eb`)
   - **Text**: Dark slate / near-black for body text (`#1e293b`) and subtle gray for secondary notes (`#64748b`).
   - **Live Request Log Status Indicators**:
     - `2xx`: Green (`#16a34a`)
     - `3xx`: Amber / Orange (`#d97706`)
     - `4xx / 5xx`: Red (`#dc2626`)
2. **Simplified Badges & Header**:
   - Header title: **CloudMart** in soft blue with a compact pill badge: **`Training Lab`** (soft blue background, white text).
   - Removed all unnecessary decorative pills (`VULNERABLE LAB`, `BOLA DEMO TARGET`, `USER`/`ADMIN`).
3. **Accent-Bordered Section Headers**:
   - Headers for *Product Catalog*, *My Orders*, and *Live Request Log* feature a subtle 3px solid blue left-border accent for visual hierarchy.
4. **Button Hierarchy**:
   - Primary actions (*Search*, *Order*, *Sign In*): Solid blue background with white text.
   - Secondary actions (*Reset*, *Logout*): Outline gray buttons with gentle hover states.
   - Administrative test button: Soft blue tint background with blue text.
5. **Compact Testing Hints**:
   - Single clean box with one line per vulnerability:
     - **SQL Injection:** In the search box, try entering `' OR '1'='1` or `'`
     - **BOLA / IDOR:** Click an order link below, then change the ID in your browser address bar
     - **Broken Authz:** Click "Admin Users" above to test if regular users can read user records
6. **Live Request Log**:
   - Clean 4-column table (`Time`, `Method`, `Endpoint`, `Status`) with light row separators and 2xx/3xx/4xx status coloring.

---

## 8. Automated Test Suite (`test_app.py`)

An automated test suite validates both standard application flow and the exploitability of all intentional vulnerabilities:

```bash
python test_app.py
```

### Verified Test Cases:
1. `test_01_public_products`: Verifies catalog retrieval without authentication.
2. `test_02_login_plaintext_and_jwt`: Verifies plaintext authentication and JWT token issuance.
3. `test_03_sqli_search`: Verifies SQL injection query `' OR '1'='1` and error disclosure on `'`.
4. `test_04_my_orders_and_creation`: Verifies order listing and new order creation for logged-in user.
5. `test_05_bola_idor_exploitation`: Verifies that user `alice` can retrieve `bob`'s order #3 via `GET /orders/3`.
6. `test_06_broken_function_level_authorization`: Verifies that standard user `alice` can access `GET /admin/users` and read plaintext passwords.
7. `test_07_request_log`: Verifies telemetry logging, response latency tracking, and circular buffer FIFO mechanics.

---

## 9. Quick-Start Guide for Instructors & Students

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Seed database
python init_db.py

# 3. Start web application
python app.py
```

Open your browser to: **http://127.0.0.1:5000**
