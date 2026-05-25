import os
import sqlite3
from flask import g


DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "database.db")


def get_db_connection():
    if "db_conn" not in g:
        conn = sqlite3.connect(DB_PATH, timeout=5, detect_types=sqlite3.PARSE_DECLTYPES)
        conn.row_factory = sqlite3.Row
        g.db_conn = conn
    return g.db_conn


def close_db_connection(exc=None):
    conn = g.pop("db_conn", None)
    if conn is not None:
        conn.close()
