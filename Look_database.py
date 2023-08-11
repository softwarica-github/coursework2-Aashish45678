import sqlite3

def view_table():
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users")
    rows = cursor.fetchall()
    conn.close()

    if rows:
        print("Users in the database:")
        for row in rows:
            print(f"ID: {row[0]}, Username: {row[1]}, Password: {row[2]}")
    else:
        print("No users found in the database.")

# Call this function to view the table
view_table()