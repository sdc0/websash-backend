import sqlite3 as sql
import os

path = os.path.dirname(__file__)

db = sql.connect(path + "/badges.db")
cur = db.cursor()

cur.execute("""
CREATE TABLE IF NOT EXISTS student (
    id INTEGER PRIMARY KEY,
    name VARCHAR(128),
    email VARCHAR(128) UNIQUE,
    password VARCHAR(128),
    salt VARCHAR(32)
)""")

cur.execute("""
CREATE TABLE IF NOT EXISTS issuer (
    id INTEGER PRIMARY KEY,
    name VARCHAR(128),
    department VARCHAR(256),
    email VARCHAR(128) UNIQUE,
    password VARCHAR(128),
    salt VARCHAR(32)
)""")

cur.execute("""
CREATE TABLE IF NOT EXISTS badge (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name VARCHAR(256),
    abbr VARCHAR(8) UNIQUE,
    desc VARCHAR(1024),
    short VARCHAR(512),
    req VARCHAR(1024),
    image VARCHAR(256),
    type VARCHAR(256),
    creator INTEGER,
    FOREIGN KEY (creator) REFERENCES issuer(id)
)""")

cur.execute("""
CREATE TABLE IF NOT EXISTS issuance (
    badge INTEGER,
    student INTEGER,
    issuer INTEGER,
    date DATETIME,
    PRIMARY KEY (badge, student),
    FOREIGN KEY (badge) REFERENCES badge(id),
    FOREIGN KEY (student) REFERENCES student(id),
    FOREIGN KEY (issuer) REFERENCES issuer(id)
)""")

db.commit()
db.close()

# setup filesystem for image storage
os.makedirs(path + "/images", exist_ok=True)

print("Setup database")
