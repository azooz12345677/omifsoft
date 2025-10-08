import sqlite3
from werkzeug.security import generate_password_hash

DB = 'nm.db'

def is_hashed(pw: str) -> bool:
    if not pw:
        return False
    return pw.startswith('pbkdf2:') or pw.startswith('argon2:') or pw.startswith('$2b$')

def migrate():
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    cur.execute('SELECT id, username, password FROM users')
    rows = cur.fetchall()
    updated = 0
    for r in rows:
        id, username, pw = r
        if not is_hashed(pw):
            new_pw = generate_password_hash(pw)
            cur.execute('UPDATE users SET password = ? WHERE id = ?', (new_pw, id))
            updated += 1
            print(f"Updated user {username} (id={id})")
    conn.commit()
    conn.close()
    print(f"Migration complete. Updated {updated} users.")

if __name__ == '__main__':
    migrate()
