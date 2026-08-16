#!/usr/bin/env python3
"""
========================================================================
 SQLiScanDeck — LOCAL TEST LAB · MySQL/MariaDB edition (vulnerable)  ⚠️
========================================================================
A deliberately INSECURE toy web app, identical in shape to
`vuln_server.py` but backed by a REAL MySQL/MariaDB server instead of
in-memory SQLite. It binds to 127.0.0.1 by default.

Why a MySQL edition exists
--------------------------
SQLite has no server-side identity, so several very common checks are
genuinely N/A there and can't be verified:
    · current user      (CURRENT_USER())
    · current database  (DATABASE())
    · hostname          (@@hostname)
    · multiple schemas  (--dbs shows >1 database)
    · password hashes   (--passwords reads mysql.user)
Against a real MariaDB these all return real values, so we can confirm
the parser CAPTURES them (no 少抓) and never invents them (no 誤判).

  ⚠️  DO NOT expose this to a network. DO NOT deploy it. It contains
      real SQL injection on purpose (string-concatenated queries) and
      the DB user is intentionally over-privileged for the demo.

Prereq: a MariaDB is already running & seeded. The one-liner:
    python testlab/mysql_lab.py up      (downloads-free; uses testlab/mariadb)
then:
    python testlab/vuln_mysql_server.py               (127.0.0.1:5001)
    python testlab/vuln_mysql_server.py 127.0.0.1 5002
========================================================================
"""
import html
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

import pymysql

# ---- connection to the portable MariaDB stood up by mysql_lab.py ----------
# Over-privileged on purpose (is_dba should read True, --passwords should work):
# this is a throwaway loopback lab, never a real deployment.
DB_CFG = dict(
    host=os.environ.get("VULN_DB_HOST", "127.0.0.1"),
    port=int(os.environ.get("VULN_DB_PORT", "3307")),
    user=os.environ.get("VULN_DB_USER", "vulnapp"),
    password=os.environ.get("VULN_DB_PASS", "vulnpass"),
    database=os.environ.get("VULN_DB_NAME", "shop"),   # -> DATABASE() = 'shop'
    # cap a runaway time-based SLEEP() payload so it can't pin a backend connection forever
    # (each request opens its own connection; a burst could otherwise exhaust max_connections)
    read_timeout=30,
)


def _run_sql(sql):
    """Execute and return rows as text. Errors are RETURNED verbatim (error-based
    SQLi) — pymysql surfaces MariaDB's own '(1064, ...SQL syntax...)' message, which
    is exactly what fingerprinting keys on. A fresh connection per call keeps this
    thread-safe under ThreadingHTTPServer with zero shared state.

    NOTE: multi-statements are intentionally NOT enabled (pymysql default), so a
    stacked-query payload cannot run a second destructive statement. The injection
    is still fully real for in-query techniques (error / UNION / boolean / time)."""
    conn = None
    try:
        conn = pymysql.connect(**DB_CFG, autocommit=True, connect_timeout=5)
        cur = conn.cursor()
        cur.execute(sql)
        rows = cur.fetchall()
        return True, rows
    except Exception as e:                    # surfaces SQL errors on purpose
        return False, str(e)
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass


# path -> (table, col, param, is_quoted_string_context)   [identical to vuln_server.py]
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
SAMPLE = {
    "q": "phone", "id": "1", "category": "electronics", "name": "electronics",
    "user": "admin", "tag": "news", "slug": "hello-world", "post_id": "1",
    "item": "1", "order": "1", "status": "shipped", "year": "1", "role": "admin",
    "username": "admin",
}
STATIC = {"/", "/about", "/contact", "/help/faq"}


class Handler(BaseHTTPRequestHandler):
    server_version = "VulnLab-MySQL/1.0"

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
                "<h2>{t}</h2>{b}<hr><small>VulnLab (MySQL/MariaDB) — local test target</small>"
                ).format(t=html.escape(title), b=inner)

    def _handle(self, path, params):
        # ---- TIME-BASED blind: constant content, no error; only timing leaks ----
        #      backed by a REAL DB, so `id=1 AND SLEEP(5)` genuinely sleeps 5s. ----
        if path == "/blind/time":
            raw = (params.get("id") or ["1"])[0]
            sql = "SELECT * FROM products WHERE id = %s" % raw
            _run_sql(sql)   # actually runs -> a SLEEP() payload really delays here
            return self._send(self._page("時間盲注 (time-based blind)",
                "<p>狀態:OK</p><p>此端點<b>永遠回相同內容、也不報錯</b> —— 只有<b>回應時間</b>會洩漏是否可注入。<br>"
                "試 <code>/blind/time?id=1</code>(秒回) vs <code>/blind/time?id=1 AND SLEEP(5)</code>(慢 5 秒)。</p>"
                "<p>實際執行的 SQL:<br><code>%s</code></p>" % html.escape(sql)))
        # ---- BOOLEAN blind: no error, no data; only 存在/不存在 differs ----
        if path == "/blind/bool":
            raw = (params.get("id") or ["1"])[0]
            good, res = _run_sql("SELECT id FROM users WHERE id = %s" % raw)
            exists = bool(good and res)     # error -> treated as false, nothing leaked
            if exists:
                inner = ("<h3>✓ 使用者存在</h3><p>Welcome back, valued customer. Your account "
                         "is active and in good standing, with full access to every feature "
                         "of the portal. We are glad to see you again today.</p>")
            else:
                inner = "<h3>✗ 查無使用者</h3>"
            return self._send(self._page("布林盲注 (boolean-based blind)", inner))
        # ---- SAFE reference endpoint: bound parameter -> NOT injectable. ----
        if path == "/safe/product":
            raw = (params.get("id") or ["1"])[0]
            try:
                pid = int(raw)
            except ValueError:
                pid = 0     # coerce -> stable 200 so tools reach a positive "clean" verdict
            ok, rows = True, []
            conn = None
            try:
                conn = pymysql.connect(**DB_CFG, autocommit=True, connect_timeout=5)
                cur = conn.cursor()
                cur.execute("SELECT * FROM products WHERE id = %s", (pid,))   # bound -> safe
                rows = cur.fetchall()
            except Exception as e:
                ok, rows = False, [(str(e),)]
            finally:
                if conn is not None:
                    try:
                        conn.close()
                    except Exception:
                        pass
            return self._send(self._page("安全端點 (parameterised, NOT injectable)",
                "<p>query ok, %d row(s)</p><pre>%s</pre><p>此端點用 <b>bound parameter</b>,無法注入 —— "
                "掃描應判為<b>無洞</b>。</p>" % (len(rows), html.escape("\n".join(map(str, rows))))))
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
                "<li><b>錯誤型</b>:<code>/product?id=1'</code> → 頁面出現 <b>MySQL error</b>(注入成功的鐵證)</li>"
                "<li><b>布林真</b>:<code>/product?id=1 AND 1=1</code> → 有資料</li>"
                "<li><b>布林假</b>:<code>/product?id=1 AND 1=2</code> → <b>0 筆</b>(真假有差 = 可注入)</li>"
                "<li><b>UNION</b>:<code>/product?id=-1 UNION SELECT 1,2,3,4</code> → products 有 4 欄,注出你控制的值</li>"
                "<li><b>字串型</b>(<code>/search?q=</code>):<code>/search?q=x' OR '1'='1</code> → 回全部</li>"
                "<li><b>撈資料</b>:<code>/user?id=-1 UNION SELECT 1,username,password,role,email FROM users</code> → 拉出帳密</li>"
                "<li><b>撈全部 DB</b>:<code>/product?id=-1 UNION SELECT schema_name,2,3,4 FROM information_schema.schemata</code></li>"
                "</ol><p>每頁最下方都會印出<b>實際執行的 SQL</b>。此靶場是<b>真 MariaDB</b>,"
                "current_user / current_db / hostname / 多個資料庫 / 密碼雜湊 都能真正列舉。</p>")
            types = (
                "<h3>🎯 注入類型示範(各一個代表端點)</h3><ul>"
                "<li><b>錯誤型 error-based</b>:<a href='/user?id=1%27'><code>/user?id=1'</code></a> → 頁面直接跳 MySQL 錯誤</li>"
                "<li><b>UNION 撈資料</b>:<code>/user?id=-1 UNION SELECT 1,username,password,role,email FROM users</code></li>"
                "<li><b>布林盲注 boolean-blind</b>:<a href='/blind/bool?id=1'><code>/blind/bool?id=1</code></a></li>"
                "<li><b>時間盲注 time-based</b>:<a href='/blind/time?id=1'><code>/blind/time?id=1</code></a>;試 <code>?id=1 AND SLEEP(5)</code></li>"
                "</ul>")
            body = ("<p><b>⚠ 這是故意留 SQL 注入的本地測試靶場</b>(只綁 127.0.0.1;後端為真 MariaDB)。</p>"
                    "%s<h3>所有可注入端點</h3><ul>%s</ul>%s"
                    "<p>POST 端點:<code>/login</code>(參數 username / password;例 username 填 <code>admin' OR '1'='1</code>)。</p>"
                    % (types, rows, guide))
            return self._send(self._page("VulnLab 測試靶場 (MySQL/MariaDB)", body))
        route = ROUTES.get(path)
        if not route:
            return self._send(self._page("404", "<p>No such path.</p>"), 404)
        table, col, pname, quoted = route
        vals = params.get(pname)
        raw = vals[0] if vals else ("1" if not quoted else "admin")
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
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 5001
    # fail fast with a friendly hint if the DB isn't up yet
    try:
        c = pymysql.connect(**DB_CFG, connect_timeout=5)
        c.close()
    except Exception as e:
        print("!! cannot reach MariaDB at %s:%d (%s)" % (DB_CFG["host"], DB_CFG["port"], e))
        print("   start it first:  python testlab/mysql_lab.py up")
        sys.exit(2)
    srv = ThreadingHTTPServer((host, port), Handler)
    print("VulnLab-MySQL (INTENTIONALLY VULNERABLE) listening on http://%s:%d" % (host, port))
    print("Backend: MariaDB %s@%s:%d  db=%s" % (
        DB_CFG["user"], DB_CFG["host"], DB_CFG["port"], DB_CFG["database"]))
    print("Endpoints:", ", ".join(sorted(ROUTES)))
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
