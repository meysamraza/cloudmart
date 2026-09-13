# CloudMart — Quick Start

## Requirements
- Python 3.x
- pip

## Setup Steps

1. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

2. **Initialize the database**
   ```bash
   python init_db.py
   ```
   This creates and seeds `lab.db` with sample users, products, and orders.

3. **Run the app**
   ```bash
   python app.py
   ```

4. **Open in browser**
   ```
   http://127.0.0.1:5000
   ```

## Demo Login
Use any seeded user from `init_db.py`, for example:
- Username: `alice`
- Password: `password123`

## Notes
- This app is intentionally vulnerable — for training use only.
- Do not deploy publicly or use real credentials/data.
