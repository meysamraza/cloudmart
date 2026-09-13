# =============================================================================
# CloudMart — init_db.py
# Database Initialization & Seeding Script for Cybersecurity Training Labs
# =============================================================================

import sqlite3

DB_PATH = "lab.db"

SCHEMA = """
DROP TABLE IF EXISTS orders;
DROP TABLE IF EXISTS products;
DROP TABLE IF EXISTS users;

CREATE TABLE users (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT    NOT NULL UNIQUE,
    email    TEXT    NOT NULL,
    password TEXT    NOT NULL,
    role     TEXT    NOT NULL DEFAULT 'user'
);

CREATE TABLE products (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT    NOT NULL,
    price       REAL    NOT NULL,
    description TEXT    NOT NULL
);

CREATE TABLE orders (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL,
    product_id INTEGER NOT NULL,
    quantity   INTEGER NOT NULL DEFAULT 1,
    status     TEXT    NOT NULL DEFAULT 'Pending',
    FOREIGN KEY (user_id) REFERENCES users (id),
    FOREIGN KEY (product_id) REFERENCES products (id)
);
"""

# VULN: Passwords stored in plaintext without hashing or salting (CWE-256 / CWE-312 / CWE-522)
USERS_SEED = [
    ("alice",   "alice@cloudmart.local",   "password123", "user"),
    ("bob",     "bob@cloudmart.local",     "letmein",     "user"),
    ("charlie", "charlie@cloudmart.local", "qwerty",      "user"),
    ("admin",   "admin@cloudmart.local",   "admin1234",   "admin"),
]

PRODUCTS_SEED = [
    ("Cloud Compute Instance - 4 vCPU", 49.99, "Scalable cloud virtual machine with 4 vCPUs and 16GB RAM."),
    ("Object Storage Bucket - 1TB", 19.99, "Secure, durable object storage with 99.999999999% data durability."),
    ("Serverless Functions Pro", 29.99, "Event-driven serverless compute platform with auto-scaling."),
    ("Managed Cloud SQL Database", 59.99, "High-availability relational database cluster with automatic backups."),
    ("Cloud Armor Web App Firewall", 89.99, "L3-L7 DDoS defense and enterprise web application firewall inspection."),
    ("DevOps Continuous Delivery Pipeline", 39.99, "Automated build, test, and container deployment pipeline."),
]

# Seeded orders across users to demonstrate BOLA (CWE-639)
ORDERS_SEED = [
    # Alice's orders (user_id: 1)
    (1, 1, 2, "Delivered"),
    (1, 3, 1, "Processing"),
    # Bob's orders (user_id: 2)
    (2, 2, 5, "Delivered"),
    (2, 4, 1, "Shipped"),
    (2, 5, 1, "Pending"),
    # Charlie's orders (user_id: 3)
    (3, 6, 2, "Delivered"),
    (3, 1, 1, "Shipped"),
    # Admin's orders (user_id: 4)
    (4, 5, 3, "Delivered"),
]


def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Execute schema creation
    cursor.executescript(SCHEMA)

    # Insert Users
    cursor.executemany(
        "INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)",
        USERS_SEED,
    )

    # Insert Products
    cursor.executemany(
        "INSERT INTO products (name, price, description) VALUES (?, ?, ?)",
        PRODUCTS_SEED,
    )

    # Insert Orders
    cursor.executemany(
        "INSERT INTO orders (user_id, product_id, quantity, status) VALUES (?, ?, ?, ?)",
        ORDERS_SEED,
    )

    conn.commit()
    conn.close()
    print(f"[+] CloudMart database '{DB_PATH}' seeded successfully:")
    print(f"    - {len(USERS_SEED)} users")
    print(f"    - {len(PRODUCTS_SEED)} products")
    print(f"    - {len(ORDERS_SEED)} orders")


if __name__ == "__main__":
    init_db()
