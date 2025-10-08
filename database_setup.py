import sqlite3

def initialize_database():
    connection = sqlite3.connect('nm.db')
    cursor = connection.cursor()

    # Create users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE
        )
    ''')

    connection.commit()
    connection.close()

if __name__ == "__main__":
    initialize_database()
    print("Database initialized successfully.")