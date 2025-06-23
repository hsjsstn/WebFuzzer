import sqlite3

conn = sqlite3.connect("webfuzzer.db")
cur = conn.cursor()

cur.execute("""
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
            
CREATE TABLE results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    target_url TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    vuln_count INTEGER,
    report_path TEXT,
    log_path TEXT,
    visibility TEXT DEFAULT 'private',
    FOREIGN KEY(user_id) REFERENCES users(id)
);
""")

conn.commit()
conn.close()
print("✅ DB 초기화 완료")