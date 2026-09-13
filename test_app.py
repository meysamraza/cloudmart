# test_app.py — Automated verification test for CloudMart
import json
import unittest
from app import app, DB_PATH
import init_db as db_module

class TestCloudMart(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        db_module.init_db()
        app.config['TESTING'] = True
        cls.client = app.test_client()

    def test_01_public_products(self):
        res = self.client.get('/products')
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIsInstance(data, list)
        self.assertGreaterEqual(len(data), 6)
        print("[PASS] GET /products returns catalog")

    def test_02_login_plaintext_and_jwt(self):
        # Successful login
        res = self.client.post('/login', json={'username': 'alice', 'password': 'password123'})
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIn('token', data)
        self.assertEqual(data['user']['username'], 'alice')
        self.__class__.alice_token = data['token']
        print("[PASS] POST /login succeeds with plaintext password and issues JWT")

        # Failed login
        res = self.client.post('/login', json={'username': 'alice', 'password': 'wrongpassword'})
        self.assertEqual(res.status_code, 401)
        print("[PASS] POST /login rejects invalid credentials")

    def test_03_sqli_search(self):
        # Normal search
        res = self.client.get('/products/search?q=Compute')
        self.assertEqual(res.status_code, 200)
        self.assertGreaterEqual(len(res.get_json()), 1)

        # SQL Injection search: ' OR '1'='1
        res_sqli = self.client.get("/products/search?q=' OR '1'='1")
        self.assertEqual(res_sqli.status_code, 200)
        self.assertEqual(len(res_sqli.get_json()), 6)
        print("[PASS] GET /products/search vulnerable to SQLi (' OR '1'='1)")

        # SQL syntax error leak (CWE-209)
        res_err = self.client.get("/products/search?q='")
        self.assertEqual(res_err.status_code, 500)
        err_data = res_err.get_json()
        self.assertIn("error", err_data)
        self.assertIn("executed_query", err_data)
        print("[PASS] GET /products/search leaks database error details (CWE-209)")

    def test_04_my_orders_and_creation(self):
        headers = {'Authorization': f'Bearer {self.alice_token}'}
        # List orders
        res = self.client.get('/orders', headers=headers)
        self.assertEqual(res.status_code, 200)
        orders = res.get_json()
        self.assertGreaterEqual(len(orders), 2)
        print("[PASS] GET /orders returns user orders")

        # Create new order
        res_create = self.client.post('/orders', headers=headers, json={'product_id': 2, 'quantity': 3})
        self.assertEqual(res_create.status_code, 201)
        new_order = res_create.get_json()
        self.assertEqual(new_order['order']['quantity'], 3)
        print("[PASS] POST /orders creates new order")

    def test_05_bola_idor_exploitation(self):
        # Alice (user_id 1) requests Bob's order (order_id 3, belonging to user_id 2)
        headers = {'Authorization': f'Bearer {self.alice_token}'}
        res = self.client.get('/orders/3', headers=headers)
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data['id'], 3)
        self.assertEqual(data['user_id'], 2)
        self.assertEqual(data['customer_username'], 'bob')
        print(f"[PASS] BOLA: Alice viewed Bob's order #{data['id']} (CWE-639)")

    def test_06_broken_function_level_authorization(self):
        # Alice (role: 'user') accesses /admin/users
        headers = {'Authorization': f'Bearer {self.alice_token}'}
        res = self.client.get('/admin/users', headers=headers)
        self.assertEqual(res.status_code, 200)
        users = res.get_json()
        self.assertGreaterEqual(len(users), 4)
        # Check plaintext passwords are leaked
        admin_row = next((u for u in users if u['username'] == 'admin'), None)
        self.assertIsNotNone(admin_row)
        self.assertEqual(admin_row['password'], 'admin1234')
        print("[PASS] BFLA: Regular user Alice accessed /admin/users and leaked passwords (CWE-862 / CWE-312)")

    def test_07_request_log(self):
        res = self.client.get('/api/request-log')
        self.assertEqual(res.status_code, 200)
        logs = res.get_json()
        self.assertIsInstance(logs, list)
        self.assertGreater(len(logs), 0)
        first = logs[0]
        self.assertIn('method', first)
        self.assertIn('endpoint', first)
        self.assertIn('status_code', first)
        self.assertIn('duration_ms', first)
        self.assertIn('timestamp', first)
        print(f"[PASS] GET /api/request-log working. Recent log count: {len(logs)}")

if __name__ == '__main__':
    unittest.main()
