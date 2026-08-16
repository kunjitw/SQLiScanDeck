#!/usr/bin/env python3
"""
========================================================================
 SQLiScanDeck — portable MariaDB control for the MySQL test lab
========================================================================
Stands up the bundled, self-contained MariaDB (testlab/mariadb) with a
private data dir (testlab/mysql-data) bound to 127.0.0.1 — NO install,
NO service, NO admin rights, nothing touched outside testlab/.

  ⚠️  Loopback-only throwaway lab. The app user is intentionally a DBA
      (so is_dba / --passwords are demonstrable). Never expose it.

Usage:
    python testlab/mysql_lab.py up        # init (first run) + start + seed  [idempotent]
    python testlab/mysql_lab.py down       # shut the server down
    python testlab/mysql_lab.py status     # is it up? show identity
    python testlab/mysql_lab.py reseed      # wipe & re-seed the demo schema
    python testlab/mysql_lab.py destroy     # down + delete the data dir

Env overrides: LAB_DB_PORT (default 3307).
========================================================================
"""
import os
import shutil
import socket
import subprocess
import sys
import time
import urllib.request
import zipfile

import pymysql

HERE = os.path.dirname(os.path.abspath(__file__))
BASEDIR = os.path.join(HERE, "mariadb")
BIN = os.path.join(BASEDIR, "bin")
MARIADB_VER = "11.4.4"
MARIADB_URL = ("https://archive.mariadb.org/mariadb-%s/winx64-packages/"
               "mariadb-%s-winx64.zip" % (MARIADB_VER, MARIADB_VER))
DATADIR = os.path.join(HERE, "mysql-data")
LOGFILE = os.path.join(HERE, "mysql-data", "mariadbd.log")
HOST = "127.0.0.1"
PORT = int(os.environ.get("LAB_DB_PORT", "3307"))

APP_USER, APP_PASS = "vulnapp", "vulnpass"
DBS = ("shop", "blog")


def _exe(name):
    p = os.path.join(BIN, name + ".exe")
    if not os.path.exists(p):
        sys.exit("!! missing binary: %s (did the MariaDB unpack fail?)" % p)
    return p


def _port_open(host, port, timeout=1.0):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _root_conn(db=None, timeout=5):
    return pymysql.connect(host=HOST, port=PORT, user="root", password="",
                           database=db, autocommit=True, connect_timeout=timeout)


def _wait_ready(secs=40):
    """Wait until root can actually authenticate (port-open is not enough)."""
    deadline = time.time() + secs
    last = None
    while time.time() < deadline:
        if _port_open(HOST, PORT):
            try:
                _root_conn(timeout=3).close()
                return True
            except Exception as e:
                last = e
        time.sleep(0.7)
    sys.exit("!! MariaDB did not become ready in %ds (last: %s)\n   see %s" % (secs, last, LOGFILE))


# ---- lifecycle ----------------------------------------------------------
def ensure_binaries():
    """Download + unpack the portable MariaDB (~90MB, one-time) if it's not here yet.
    Pure stdlib so it works before any pip step. Windows-only (winx64 build)."""
    if os.path.exists(os.path.join(BIN, "mariadbd.exe")):
        return
    if os.name != "nt":
        sys.exit("!! the bundled MariaDB is a Windows build; on other OSes install "
                 "MariaDB yourself and point vuln_mysql_server.py at it via VULN_DB_*.")
    print("· MariaDB not found — downloading portable build (~90MB, one-time)…")
    tmpzip = os.path.join(HERE, "_mariadb.zip")
    urllib.request.urlretrieve(MARIADB_URL, tmpzip)
    print("· extracting…")
    exdir = os.path.join(HERE, "_mariadb_tmp")
    shutil.rmtree(exdir, ignore_errors=True)
    with zipfile.ZipFile(tmpzip) as z:
        z.extractall(exdir)
    inner = os.path.join(exdir, "mariadb-%s-winx64" % MARIADB_VER)
    shutil.rmtree(BASEDIR, ignore_errors=True)
    shutil.move(inner, BASEDIR)
    shutil.rmtree(exdir, ignore_errors=True)
    os.remove(tmpzip)
    print("· MariaDB ready at", BASEDIR)


def init_datadir():
    if os.path.exists(os.path.join(DATADIR, "mysql")):
        return  # already initialised
    print("· initialising data dir:", DATADIR)
    os.makedirs(DATADIR, exist_ok=True)
    # On Windows there is no unix_socket auth: mariadb-install-db creates root@localhost
    # with an EMPTY password, reachable over TCP — exactly what we need to seed via pymysql.
    r = subprocess.run([_exe("mariadb-install-db"), "--datadir=" + DATADIR],
                       cwd=BASEDIR, capture_output=True, text=True)
    if r.returncode != 0:
        print(r.stdout[-2000:]); print(r.stderr[-2000:])
        sys.exit("!! mariadb-install-db failed (rc=%d)" % r.returncode)


def start_server():
    if _port_open(HOST, PORT):
        print("· server already listening on %s:%d" % (HOST, PORT))
        return
    print("· starting mariadbd on %s:%d" % (HOST, PORT))
    logf = open(LOGFILE, "ab")
    flags = 0
    if os.name == "nt":
        flags = subprocess.CREATE_NEW_PROCESS_GROUP | 0x00000008  # DETACHED_PROCESS
    subprocess.Popen([_exe("mariadbd"), "--no-defaults",
                      "--datadir=" + DATADIR, "--basedir=" + BASEDIR,
                      "--bind-address=" + HOST, "--port=%d" % PORT,
                      "--skip-name-resolve", "--console"],
                     cwd=BASEDIR, stdout=logf, stderr=logf,
                     creationflags=flags, close_fds=True)
    _wait_ready()
    print("· server ready")


SCHEMA = """
DROP TABLE IF EXISTS users; DROP TABLE IF EXISTS products; DROP TABLE IF EXISTS articles;
DROP TABLE IF EXISTS comments; DROP TABLE IF EXISTS orders; DROP TABLE IF EXISTS categories;
CREATE TABLE users(id INT PRIMARY KEY, username VARCHAR(64), password VARCHAR(64), role VARCHAR(32), email VARCHAR(128));
CREATE TABLE products(id INT PRIMARY KEY, name VARCHAR(64), category VARCHAR(64), price DOUBLE);
CREATE TABLE articles(id INT PRIMARY KEY, title VARCHAR(128), slug VARCHAR(128), tag VARCHAR(64), body TEXT);
CREATE TABLE comments(id INT PRIMARY KEY, post_id INT, author VARCHAR(64), body TEXT);
CREATE TABLE orders(id INT PRIMARY KEY, user_id INT, status VARCHAR(32), total DOUBLE);
CREATE TABLE categories(id INT PRIMARY KEY, name VARCHAR(64), parent VARCHAR(64));
INSERT INTO users VALUES
  (1,'admin','s3cr3t!','admin','admin@lab.local'),
  (2,'alice','alicepw','user','alice@lab.local'),
  (3,'bob','bobpw','user','bob@lab.local');
INSERT INTO products VALUES
  (1,'Laptop','electronics',999.0),(2,'Phone','electronics',599.0),(3,'Desk','furniture',149.0);
INSERT INTO articles VALUES
  (1,'Hello World','hello-world','news','first post'),(2,'On SQLi','on-sqli','security','be careful');
INSERT INTO comments VALUES (1,1,'alice','nice!'),(2,1,'bob','+1'),(3,2,'admin','indeed');
INSERT INTO orders VALUES (1,2,'shipped',999.0),(2,3,'pending',149.0);
INSERT INTO categories VALUES (1,'electronics',NULL),(2,'furniture',NULL),(3,'phones','electronics');
"""

# a SECOND database so --dbs / multi-schema enumeration has >1 real target
BLOG_SCHEMA = """
DROP TABLE IF EXISTS posts; DROP TABLE IF EXISTS authors;
CREATE TABLE authors(id INT PRIMARY KEY, name VARCHAR(64), email VARCHAR(128));
CREATE TABLE posts(id INT PRIMARY KEY, title VARCHAR(128), author VARCHAR(64), body TEXT);
INSERT INTO authors VALUES (1,'Editor','editor@blog.local'),(2,'Guest','guest@blog.local');
INSERT INTO posts VALUES (1,'Welcome','Editor','hello'),(2,'Second','Guest','more');
"""


def _exec_script(cur, script):
    for stmt in [s.strip() for s in script.split(";") if s.strip()]:
        cur.execute(stmt)


def seed():
    print("· seeding schema (databases: %s)" % ", ".join(DBS))
    conn = _root_conn()
    cur = conn.cursor()
    cur.execute("CREATE DATABASE IF NOT EXISTS shop CHARACTER SET utf8mb4")
    cur.execute("CREATE DATABASE IF NOT EXISTS blog CHARACTER SET utf8mb4")
    cur.execute("USE shop"); _exec_script(cur, SCHEMA)
    cur.execute("USE blog"); _exec_script(cur, BLOG_SCHEMA)
    # app user: over-privileged on purpose -> is_dba True, can read mysql.user (--passwords),
    # sees every schema (--dbs). Loopback lab only.
    cur.execute("CREATE USER IF NOT EXISTS '%s'@'%%' IDENTIFIED BY '%s'" % (APP_USER, APP_PASS))
    cur.execute("SET PASSWORD FOR '%s'@'%%' = PASSWORD('%s')" % (APP_USER, APP_PASS))
    cur.execute("GRANT ALL PRIVILEGES ON *.* TO '%s'@'%%' WITH GRANT OPTION" % APP_USER)
    cur.execute("FLUSH PRIVILEGES")
    conn.close()
    print("· seeded. app login: %s/%s (DBA), default db 'shop'" % (APP_USER, APP_PASS))


def stop_server():
    if not _port_open(HOST, PORT):
        print("· not running"); return
    print("· shutting down…")
    subprocess.run([_exe("mysqladmin"), "--no-defaults", "-h", HOST, "-P", str(PORT),
                    "-u", "root", "shutdown"], capture_output=True, text=True)
    for _ in range(20):
        if not _port_open(HOST, PORT):
            print("· stopped"); return
        time.sleep(0.5)
    print("!! still up after shutdown request — check", LOGFILE)


def status():
    up = _port_open(HOST, PORT)
    print("MariaDB lab @ %s:%d — %s" % (HOST, PORT, "UP" if up else "down"))
    if up:
        try:
            conn = pymysql.connect(host=HOST, port=PORT, user=APP_USER, password=APP_PASS,
                                   database="shop", autocommit=True, connect_timeout=5)
            cur = conn.cursor()
            for q, lbl in [("SELECT VERSION()", "banner"), ("SELECT CURRENT_USER()", "current user"),
                           ("SELECT DATABASE()", "current db"), ("SELECT @@hostname", "hostname"),
                           ("SELECT COUNT(*) FROM information_schema.schemata", "schema count")]:
                cur.execute(q)
                print("   %-13s %s" % (lbl + ":", cur.fetchone()[0]))
            conn.close()
        except Exception as e:
            print("   (app login failed: %s)" % e)


def up():
    ensure_binaries()
    init_datadir()
    start_server()
    seed()
    status()
    print("\nnext:  python testlab/vuln_mysql_server.py 127.0.0.1 5001")


def destroy():
    stop_server()
    if os.path.isdir(DATADIR):
        shutil.rmtree(DATADIR, ignore_errors=True)
        print("· deleted", DATADIR)


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "up"
    ({"up": up, "down": stop_server, "status": status, "fetch": ensure_binaries,
      "reseed": seed, "destroy": destroy}.get(cmd)
     or (lambda: sys.exit("usage: mysql_lab.py [up|down|status|reseed|destroy|fetch]")))()


if __name__ == "__main__":
    main()
