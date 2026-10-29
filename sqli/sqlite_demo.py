"""
sqlite3 demo: what each query ACTUALLY does to a database, with and without
the grammar scanner standing in front of it. Uses a throw-away in-memory DB.
"""
import sqlite3

from .detector import scan

DEMO_QUERIES = [
    ("Normal lookup", "SELECT username, email FROM users WHERE id = 1"),
    ("Tautology  (dump all rows)", "SELECT username, email FROM users WHERE id = 1 OR 1=1"),
    ("Auth bypass via comment", "SELECT * FROM users WHERE username = 'admin'--' AND password = 'wrong'"),
    ("UNION data theft", "SELECT username, email FROM users WHERE id = 1 UNION SELECT username, password FROM admin"),
    ("Stacked query (DROP)", "SELECT * FROM users WHERE id = 1; DROP TABLE users"),
]


def make_db():
    conn = sqlite3.connect(":memory:")
    conn.executescript(
        """
        CREATE TABLE users (id INTEGER, username TEXT, email TEXT, password TEXT);
        CREATE TABLE admin (username TEXT, password TEXT);
        INSERT INTO users VALUES (1, 'alice', 'alice@example.com', 'alice123');
        INSERT INTO users VALUES (2, 'bob',   'bob@example.com',   'bobpass');
        INSERT INTO users VALUES (3, 'admin', 'admin@example.com', 'S3cr3t!');
        INSERT INTO admin VALUES ('root', 'r00t-p@ss');
        """
    )
    return conn


def _run(conn, query):
    try:
        return conn.execute(query).fetchall(), None
    except Exception as e:  # sqlite3.Error / ProgrammingError
        return None, f"{type(e).__name__}: {e}"


def run_demo(print_fn=print):
    conn = make_db()
    for title, query in DEMO_QUERIES:
        print_fn("=" * 78)
        print_fn(f"{title}\n  {query}")
        res = scan(query)
        print_fn(f"  Scanner verdict : {res.verdict}")
        rows, err = _run(conn, query)
        if err:
            print_fn(f"  WITHOUT scanner : error -> {err}")
        else:
            print_fn(f"  WITHOUT scanner : {len(rows)} row(s) returned -> {rows}")
        if res.injection:
            print_fn("  WITH scanner    : BLOCKED - query never reaches the database")
        else:
            print_fn(f"  WITH scanner    : allowed -> {len(rows)} row(s)")
    conn.close()
