import sqlite3
import os

# SQLite 数据库文件路径
DATABASE = os.getenv('DATABASE', 'example.db')

def create_table():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS confessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nickname TEXT NOT NULL,
            target TEXT NOT NULL,
            message TEXT NOT NULL,
            user_gender TEXT NOT NULL,
            target_gender TEXT NOT NULL,
            anonymous BOOLEAN NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

if __name__ == '__main__':
    create_table()
