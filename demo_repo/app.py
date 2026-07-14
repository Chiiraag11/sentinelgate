import sqlite3
import subprocess
import pickle

AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"


def get_user(user_id):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    # Vulnerable: string-concatenated SQL query
    query = "SELECT * FROM users WHERE id = " + user_id
    cursor.execute(query)
    return cursor.fetchone()


def run_backup(filename):
    # Vulnerable: shell command built from unsanitized input
    subprocess.call("tar -czf backup.tar.gz " + filename, shell=True)


def load_session(data):
    # Vulnerable: insecure deserialization
    return pickle.loads(data)


def render_greeting(name):
    # Vulnerable: unescaped output (would be XSS in a web context)
    return "<div>Hello, " + name + "</div>"
