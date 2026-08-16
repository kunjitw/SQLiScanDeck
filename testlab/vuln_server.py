#!/usr/bin/env python3
"""
========================================================================
 SQLiScanDeck — LOCAL TEST LAB (intentionally vulnerable)  ⚠️
========================================================================
A deliberately INSECURE toy web app used ONLY to exercise SQLiScanDeck
against a safe local target you own. It binds to 127.0.0.1 by default.

  ⚠️  DO NOT expose this to a network. DO NOT deploy it. It contains
      real SQL injection on purpose (string-concatenated queries).

It serves many nested paths so the test-record TREE fills out nicely.
Backend: stdlib http.server + sqlite3 (no dependencies, no setup).

Run:  python testlab/vuln_server.py            (defaults 127.0.0.1:5000)
      python testlab/vuln_server.py 127.0.0.1 5001
========================================================================
"""
import html
import re
import sqlite3
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs


def _delay_from_payload(raw):
    """Simulated time-based backend: if the injected value carries a delay
    function, ACTUALLY sleep that many seconds (capped 15) so sqlmap/ghauri/gosqli
    time-based payloads visibly delay the response. Covers MySQL SLEEP(),
    PostgreSQL pg_sleep() and MSSQL WAITFOR DELAY."""
    for pat in (r"sleep\s*\(\s*(\d+)", r"pg_sleep\s*\(\s*(\d+)",
                r"waitfor\s+delay\s+'0*:0*:0*(\d+)"):
        m = re.search(pat, raw, re.I)
        if m:
            return min(int(m.group(1)), 15)
    return 0

DB = ":memory:"
_conn = None
_lock = threading.Lock()


def _init_db():
    """One shared in-memory DB, seeded with a little data for each table."""
    global _conn
    _conn = sqlite3.connect(DB, check_same_thread=False)
    c = _conn.cursor()
    c.executescript(
        """
        CREATE TABLE users(id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT, email TEXT);
        CREATE TABLE products(id INTEGER PRIMARY KEY, name TEXT, category TEXT, price REAL);
        CREATE TABLE articles(id INTEGER PRIMARY KEY, title TEXT, slug TEXT, tag TEXT, body TEXT);
        CREATE TABLE comments(id INTEGER PRIMARY KEY, post_id INTEGER, author TEXT, body TEXT);
        CREATE TABLE orders(id INTEGER PRIMARY KEY, user_id INTEGER, status TEXT, total REAL);
        CREATE TABLE categories(id INTEGER PRIMARY KEY, name TEXT, parent TEXT);
        INSERT INTO users VALUES
          (1,'admin','s3cr3t!','admin','admin@lab.local'),
          (2,'alice','alicepw','user','alice@lab.local'),
          (3,'bob','bobpw','user','bob@lab.local');
        INSERT INTO products VALUES
          (1,'Laptop','electronics',999.0),
          (2,'Phone','electronics',599.0),
          (3,'Desk','furniture',149.0);
        INSERT INTO articles VALUES
          (1,'Hello World','hello-world','news','first post'),
          (2,'On SQLi','on-sqli','security','be careful');
        INSERT INTO comments VALUES (1,1,'alice','nice!'),(2,1,'bob','+1'),(3,2,'admin','indeed');
        INSERT INTO orders VALUES (1,2,'shipped',999.0),(2,3,'pending',149.0);
        INSERT INTO categories VALUES (1,'electronics',NULL),(2,'furniture',NULL),(3,'phones','electronics');
        """
    )
    _conn.commit()


def _run_sql(sql):
    """Execute and return rows as text. Errors are RETURNED (error-based SQLi)."""
    with _lock:
        try:
            cur = _conn.cursor()
            cur.execute(sql)
            rows = cur.fetchall()
            return True, rows
        except Exception as e:                       # surfaces SQL errors on purpose
            return False, str(e)


# path -> (sql_template, [param names], is_quoted_string_context)
# {V} is replaced by the RAW (unsanitised) first value of the first param.
# The template is built with raw string concat inside the handler.
def _q_num(table, col, param):   # numeric context:  ... WHERE col = <V>
    return (table, col, param, False)


def _q_str(table, col, param):   # string context:   ... WHERE col = '<V>'
    return (table, col, param, True)


# Every entry is a vulnerable endpoint. Nested paths on purpose -> deep tree.
ROUTES = {
    "/login":               _q_str("users", "username", "username"),   # also uses POST body
    "/search":              _q_str("products", "name", "q"),
    "/product":             _q_num("products", "id", "id"),
    "/products":            _q_str("products", "category", "category"),
    "/category":            _q_str("categories", "name", "name"),
    "/user":                _q_num("users", "id", "id"),
    "/profile":             _q_str("users", "username", "user"),
    "/article":             _q_num("articles", "id", "id"),
    "/articles":            _q_str("articles", "tag", "tag"),
    "/blog/post":           _q_str("articles", "slug", "slug"),
    "/blog/comments":       _q_num("comments", "post_id", "post_id"),
    "/shop/cart":           _q_num("products", "id", "item"),
    "/shop/checkout":       _q_num("orders", "id", "order"),
    "/api/products":        _q_num("products", "id", "id"),
    "/api/v1/users":        _q_num("users", "id", "id"),
    "/api/v1/orders":       _q_str("orders", "status", "status"),
    "/admin/report":        _q_num("orders", "id", "year"),
    "/admin/users":         _q_str("users", "role", "role"),
}
# sample value per param name, so the homepage can build clickable ?param=value links
SAMPLE = {
    "q": "phone", "id": "1", "category": "electronics", "name": "electronics",
    "user": "admin", "tag": "news", "slug": "hello-world", "post_id": "1",
    "item": "1", "order": "1", "status": "shipped", "year": "1", "role": "admin",
    "username": "admin",
}
# Non-vulnerable static pages (no params) — give the tree some plain nodes too.
STATIC = {"/", "/about", "/contact", "/help/faq"}


class Handler(BaseHTTPRequestHandler):
    server_version = "VulnLab/1.0"

    def log_message(self, *a):        # keep the console quiet
        pass

    def _send(self, body, code=200):
        data = body.encode("utf-8", "replace")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _page(self, title, inner):
        return ("<!doctype html><meta charset=utf-8><title>{t}</title>"
                "<h2>{t}</h2>{b}<hr><small>VulnLab — local test target</small>"
                ).format(t=html.escape(title), b=inner)

    def _handle(self, path, params):
        # ---- TIME-BASED blind: constant content, no error; only timing leaks ----
        if path == "/blind/time":
            raw = (params.get("id") or ["1"])[0]
            d = _delay_from_payload(raw)
            if d:
                time.sleep(d)
            sql = "SELECT * FROM products WHERE id = %s" % raw
            return self._send(self._page("時間盲注 (time-based blind)",
                "<p>狀態:OK</p><p>此端點<b>永遠回相同內容、也不報錯</b> —— 只有<b>回應時間</b>會洩漏是否可注入。<br>"
                "試 <code>/blind/time?id=1</code>(秒回) vs <code>/blind/time?id=1 AND SLEEP(5)</code>(慢 5 秒)。</p>"
                "<p>模擬執行的 SQL:<br><code>%s</code></p>" % html.escape(sql)))
        # ---- BOOLEAN blind: no error, no data; only 存在/不存在 differs ----
        if path == "/blind/bool":
            raw = (params.get("id") or ["1"])[0]
            good, res = _run_sql("SELECT id FROM users WHERE id = %s" % raw)
            exists = bool(good and res)     # error -> treated as false, nothing leaked
            # true/false pages are DELIBERATELY very different (length + content) so
            # boolean-blind detection (sqlmap/ghauri) catches the difference cleanly.
            if exists:
                inner = ("<h3>✓ 使用者存在</h3><p>Welcome back, valued customer. Your account "
                         "is active and in good standing, with full access to every feature "
                         "of the portal. We are glad to see you again today.</p>")
            else:
                inner = "<h3>✗ 查無使用者</h3>"
            return self._send(self._page("布林盲注 (boolean-based blind)", inner))
        if path in STATIC:
            rows = ""
            for p in sorted(ROUTES):
                _t, _c, pname, quoted = ROUTES[p]
                href = "%s?%s=%s" % (p, pname, SAMPLE.get(pname, "1"))
                rows += ('<li><a href="%s"><code>%s</code></a> &nbsp; 注入點: <b>%s</b> (%s型)</li>'
                         % (href, href, pname, "字串" if quoted else "數字"))
            guide = (
                "<h3>怎麼手動測(以 <code>/product?id=1</code> 為例)</h3><ol>"
                "<li>正常:<code>/product?id=1</code> → 回 1 筆</li>"
                "<li><b>錯誤型</b>:<code>/product?id=1'</code> → 頁面出現 <b>DB error</b>(注入成功的鐵證)</li>"
                "<li><b>布林真</b>:<code>/product?id=1 AND 1=1</code> → 有資料</li>"
                "<li><b>布林假</b>:<code>/product?id=1 AND 1=2</code> → <b>0 筆</b>(真假有差 = 可注入)</li>"
                "<li><b>UNION</b>:<code>/product?id=-1 UNION SELECT 1,2,3,4</code> → products 有 4 欄,注出你控制的值</li>"
                "<li><b>字串型</b>(<code>/search?q=</code>):<code>/search?q=x' OR '1'='1</code> → 回全部</li>"
                "<li><b>撈資料</b>:<code>/user?id=-1 UNION SELECT 1,username,password,role,email FROM users</code> → 拉出帳密</li>"
                "</ol><p>每頁最下方都會印出<b>實際執行的 SQL</b>,你可以看到 payload 是怎麼拼進去的。"
                " URL 裡的空格瀏覽器會自動編碼,直接打即可。</p>")
            types = (
                "<h3>🎯 注入類型示範(各一個代表端點)</h3><ul>"
                "<li><b>錯誤型 error-based</b>:<a href='/user?id=1%27'><code>/user?id=1'</code></a> → 頁面直接跳 DB 錯誤</li>"
                "<li><b>UNION 撈資料</b>:<code>/user?id=-1 UNION SELECT 1,username,password,role,email FROM users</code> → 拉出帳密</li>"
                "<li><b>布林盲注 boolean-blind</b>:<a href='/blind/bool?id=1'><code>/blind/bool?id=1</code></a> → 不報錯不回資料,只有存在/不存在</li>"
                "<li><b>時間盲注 time-based</b>:<a href='/blind/time?id=1'><code>/blind/time?id=1</code></a> → 內容永遠一樣,靠回應時間;試 <code>?id=1 AND SLEEP(5)</code></li>"
                "</ul>")
            body = ("<p><b>⚠ 這是故意留 SQL 注入的本地測試靶場</b>(只綁 127.0.0.1)。</p>"
                    "%s<h3>所有可注入端點</h3><ul>%s</ul>%s"
                    "<p>POST 端點:<code>/login</code>(參數 username / password;例 username 填 <code>admin' OR '1'='1</code>)。</p>"
                    % (types, rows, guide))
            return self._send(self._page("VulnLab 測試靶場", body))
        route = ROUTES.get(path)
        if not route:
            return self._send(self._page("404", "<p>No such path.</p>"), 404)
        table, col, pname, quoted = route
        vals = params.get(pname)
        raw = vals[0] if vals else ("1" if not quoted else "admin")   # default so the tree node still works
        # *** THE VULNERABILITY: raw value concatenated straight into SQL ***
        if quoted:
            sql = "SELECT * FROM %s WHERE %s = '%s'" % (table, col, raw)
        else:
            sql = "SELECT * FROM %s WHERE %s = %s" % (table, col, raw)
        ok, result = _run_sql(sql)
        if ok:
            body = "<p>query ok, %d row(s)</p><pre>%s</pre>" % (
                len(result), html.escape("\n".join(map(str, result))))
        else:
            body = "<p>DB error</p><pre>%s</pre>" % html.escape(str(result))   # error-based leak
        body += "<p>實際執行的 SQL:<br><code>%s</code></p><p><a href='/'>← 回首頁</a></p>" % html.escape(sql)
        return self._send(self._page(path, body))

    def do_GET(self):
        u = urlparse(self.path)
        self._handle(u.path, parse_qs(u.query, keep_blank_values=True))

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length).decode("utf-8", "replace") if length else ""
        u = urlparse(self.path)
        params = parse_qs(raw, keep_blank_values=True)
        params.update(parse_qs(u.query, keep_blank_values=True))
        self._handle(u.path, params)


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 5000
    _init_db()
    srv = ThreadingHTTPServer((host, port), Handler)
    print("VulnLab (INTENTIONALLY VULNERABLE) listening on http://%s:%d" % (host, port))
    print("Endpoints:", ", ".join(sorted(ROUTES)))
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
