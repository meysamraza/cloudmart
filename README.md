# CloudMart — Vulnerable Cloud Infrastructure App

> **⚠️ CAUTION: EDUCATIONAL USE ONLY.** This application is intentionally vulnerable. It is designed for cybersecurity training courses covering threat modeling, SAST/DAST scanning, API/authorization exploitation, and CI/CD security pipelines. **Do not deploy this application to production or expose it to untrusted networks.**

---

## 📖 Course & Lab Context

CloudMart is a lightweight cloud management web application designed to be explored across **3 hands-on 25–30 minute training labs**:

1. **Lab 1: Threat Modeling & SAST/DAST**
   - Identify trust boundaries, data flows, and assets using STRIDE.
   - Run static analysis (SAST) tools like Bandit to detect hardcoded secrets and dangerous functions.
   - Run dynamic analysis (DAST) tools like OWASP ZAP to fuzz endpoints.
2. **Lab 2: API & Authorization Exploitation**
   - Exploit **SQL Injection (CWE-89)** via `/products/search?q=`.
   - Exploit **Broken Object Level Authorization (BOLA / IDOR - CWE-639)** via `/orders/<id>`.
   - Exploit **Broken Function-Level Authorization (BFLA - CWE-862)** via `/admin/users`.
3. **Lab 3: CI/CD Security Pipeline**
   - Integrate automated secret scanning (detect-secrets, Gitleaks, or TruffleHog).
   - Integrate SAST gates (`bandit -r . -ll`) that fail the pipeline on High/Medium severity findings.

---

## 🛠️ Stack & Architecture

- **Backend**: Python 3 + Flask (REST API & template rendering)
- **Authentication**: JSON Web Tokens (PyJWT, HMAC-SHA256)
- **Database**: SQLite (`lab.db`), seeded via `init_db.py`
- **Frontend**: Plain HTML5, CSS3, and modern Vanilla JavaScript (no npm, no Webpack, no external frameworks)
- **Request Inspector**: In-memory circular buffer exposed at `GET /api/request-log`, polled dynamically every 2 seconds by the UI.

---

## 🚀 Setup & Run

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Initialize and Seed the Database
```bash
python init_db.py
```
This sets up `lab.db` with sample users, catalog products, and cross-user orders.

### 3. Start the Application
```bash
python app.py
```
Open your browser and navigate to:
**[http://127.0.0.1:5000](http://127.0.0.1:5000)**

---

## 👥 Seeded Lab Accounts

All passwords are intentionally stored and validated in plaintext:

| Username | Password | Role | Description |
|:---------|:---------|:-----|:------------|
| `alice` | `password123` | `user` | Standard customer (owns Orders #1, #2) |
| `bob` | `letmein` | `user` | Standard customer (owns Orders #3, #4, #5) |
| `charlie` | `qwerty` | `user` | Standard customer (owns Orders #6, #7) |
| `admin` | `admin1234` | `admin` | Portal administrator (owns Order #8) |

*(Quick autofill buttons for each account are built directly into the login page.)*

---

## 🌐 Endpoints & API Reference

| Method | Endpoint | Auth Required | Description |
|:-------|:---------|:-------------:|:------------|
| `GET` | `/` | No | Redirects to `/dashboard` or `/login` |
| `GET` | `/login` | No | HTML login interface |
| `POST` | `/login` | No | Authenticates user; returns JWT token & sets session cookie |
| `GET` | `/dashboard` | Yes | Main web portal (catalog, orders, live inspector) |
| `GET` | `/products` | No | Returns all public products (JSON) |
| `GET` | `/products/search?q=` | No | Searches products (vulnerable to SQLi) |
| `GET` | `/orders` | Yes (JWT) | Lists orders belonging to currently logged-in user |
| `POST` | `/orders` | Yes (JWT) | Creates a new order for logged-in user (`{"product_id": 1, "quantity": 1}`) |
| `GET` | `/orders/<id>` | Yes (JWT) | Fetches order by ID (vulnerable to BOLA / IDOR) |
| `GET` | `/admin/users` | Yes (JWT) | Dumps all users and credentials (vulnerable to BFLA) |
| `GET` | `/api/request-log` | No | Returns the last 20 API requests with latency in ms |

---

## 🧪 Interactive Lab Exploitation Walkthroughs

### 1. SQL Injection (CWE-89)
The search endpoint builds SQL queries via raw string interpolation without parameter binding.
- **Browser Demo**: In the dashboard search bar, enter:
  ```text
  ' OR '1'='1
  ```
  All products will be returned regardless of query term.
- **Error-Based Leakage (CWE-209)**: Enter a single quote `'` in the search bar. The backend catches the exception and reflects the raw database error message along with the executed SQL statement.
- **Data Exfiltration (UNION-based)**:
  ```bash
  curl -s "http://127.0.0.1:5000/products/search?q=%27%20UNION%20SELECT%20id,%20username,%20password,%20role%20FROM%20users--"
  ```

### 2. Broken Object Level Authorization (BOLA / IDOR - CWE-639)
1. Log in as `alice` (`password123`).
2. Notice Alice's orders in the **"My Cloud Orders"** table (e.g. Order #1, Order #2).
3. Click on the order link `/orders/1` — it will open in a browser tab displaying the order JSON.
4. In the browser address bar, change the URL to:
   ```text
   http://127.0.0.1:5000/orders/3
   ```
5. Observe that you can view Bob's order, contact email, purchased resources, and price, even though Alice does not own Order #3.

### 3. Broken Function-Level Authorization (BFLA - CWE-862)
1. Log in as standard user `alice` (role: `user`).
2. Click the **"🛡️ Admin Users (/admin/users)"** button in the top navigation bar.
3. Observe that the endpoint returns HTTP 200 and reveals all user accounts and plaintext passwords.
4. Using curl with Alice's JWT:
   ```bash
   curl -s http://127.0.0.1:5000/admin/users \
        -H "Authorization: Bearer <ALICE_JWT>"
   ```

### 4. Live Request Inspector
Watch the bottom panel on the dashboard while performing attacks. It polls `GET /api/request-log` every 2 seconds, displaying each request method, endpoint, HTTP status code, and execution time in milliseconds.

---

## 🔑 INSTRUCTOR-ONLY REFERENCE — Planted Vulnerabilities

*(Do not distribute this section to students prior to the training sessions.)*

| # | Vulnerability Name | CWE ID | Location | Technical Description & Risk |
|:--|:-------------------|:-------|:---------|:-----------------------------|
| **1** | **Hardcoded JWT Secret Key** | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) | `app.py:37` | Flask `secret_key` is hardcoded as `"cloudmart-secret-jwt-key-2026-training-lab"`. An attacker can forge arbitrary JWT tokens with any `user_id` or `role`. |
| **2** | **Hardcoded Database Credentials** | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) / [CWE-259](https://cwe.mitre.org/data/definitions/259.html) | `app.py:40–42` | `DB_USER = "cloudmart_admin"` and `DB_PASSWORD = "SuperSecretDBPassword2026!"` are hardcoded in the codebase and detectable by secret scanners. |
| **3** | **Debug Mode Enabled in Entry Point** | [CWE-215](https://cwe.mitre.org/data/definitions/215.html) / [CWE-489](https://cwe.mitre.org/data/definitions/489.html) | `app.py:452` | `app.run(debug=True)` activates Werkzeug's interactive debugger, which can allow remote code execution (RCE) via pin bypass or console execution upon exceptions. |
| **4** | **Plaintext Passwords** | [CWE-256](https://cwe.mitre.org/data/definitions/256.html) / [CWE-312](https://cwe.mitre.org/data/definitions/312.html) / [CWE-522](https://cwe.mitre.org/data/definitions/522.html) | `init_db.py:42`, `app.py:201` | Passwords are stored in SQLite and compared during login in cleartext without bcrypt, argon2, or cryptographic salting. |
| **5** | **Lack of Rate Limiting (Brute-Force)** | [CWE-307](https://cwe.mitre.org/data/definitions/307.html) | `app.py:181` (`/login`) | The `/login` endpoint has no throttling, lockouts, or proof-of-work, allowing high-speed credential stuffing and dictionary attacks. |
| **6** | **SQL Injection (SQLi)** | [CWE-89](https://cwe.mitre.org/data/definitions/89.html) | `app.py:273` (`/products/search`) | Query string `q` is directly interpolated into the SQL string via `f"SELECT ... WHERE name LIKE '%{q}%'"`. Allows authentication bypass, union extraction, and database dumping. |
| **7** | **Verbose Error Information Exposure** | [CWE-209](https://cwe.mitre.org/data/definitions/209.html) | `app.py:280–285` (`/products/search`) | When an invalid SQL query is supplied, the `try...except` block returns `str(e)` and the raw SQL query to the client in the 500 JSON response. |
| **8** | **Broken Object Level Authorization (BOLA / IDOR)** | [CWE-639](https://cwe.mitre.org/data/definitions/639.html) | `app.py:368` (`/orders/<id>`) | Endpoint verifies that a JWT exists, but fails to check if `order['user_id'] == current_user['user_id']`. Any authenticated user can view any customer's order. |
| **9** | **Broken Function-Level Authorization (BFLA)** | [CWE-862](https://cwe.mitre.org/data/definitions/862.html) / [CWE-285](https://cwe.mitre.org/data/definitions/285.html) | `app.py:404` (`/admin/users`) | Endpoint requires a valid JWT, but does not enforce the `admin` role (`if current_user.get("role") != "admin"`). Normal users can access administrative functionality. |
| **10** | **Sensitive Data Exposure** | [CWE-200](https://cwe.mitre.org/data/definitions/200.html) | `app.py:420` (`/admin/users`) | The administrative users query does `SELECT *` / includes passwords, returning cleartext credentials in API responses. |

---

## 🛡️ Suggested Tooling for Labs

```bash
# SAST Scanning with Bandit
pip install bandit
bandit -r app.py init_db.py

# Secret Scanning with Detect-Secrets or TruffleHog
pip install detect-secrets
detect-secrets scan .

# Run Automated Test Suite
python test_app.py
```
