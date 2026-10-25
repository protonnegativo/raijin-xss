"""Local lab for the raijin-xss benchmark: small, intentionally vulnerable HTTP servers on 127.0.0.1.

Each argument is port=site. Every page reflects its query parameters in a known context, so dalfox has
something to find, and one parameter is always escaped, so it has something to reject.

  shop      a catalog: 10 item pages (/item/1 ... /item/10) that all reflect "q" in the page body the
            same way, plus a "sort" parameter that is escaped: the same param and context on many URLs.
            And a note form (/note?msg=) whose textarea strips its own closing tag, so every payload
            reflects but stays text: dalfox reports each one it tried as reflected.
  app       one page per context: HTML body (/search?q=), attribute value (/profile?name=), a JS string
            (/widget?cb=), an escaped parameter (/safe?q=), a JSON API that echoes its input
            (/api/echo?msg=), and a parameter that answers a quote with a SQL error (/report?id=), which
            dalfox greps.

usage: python3 lab.py 19300=shop 19301=app
"""
import html
import json
import re
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

PAGE = "<!DOCTYPE html><html><head><title>{title}</title></head><body>\n{body}\n</body></html>\n"


def shop(path, q):
    if path.startswith("/item/"):
        n = path[len("/item/"):]
        body = (
            f"<h1>Item {html.escape(n)}</h1>\n"
            f"<p>Results for: {q.get('q', '')}</p>\n"
            f"<p>Sorted by {html.escape(q.get('sort', 'price'))}</p>"
        )
        return 200, PAGE.format(title="Item", body=body)
    if path == "/note":
        # a textarea that strips its own closing tag: payloads reflect, but stay text
        msg = re.sub(r"(?i)</\s*textarea", "", q.get("msg", ""))
        return 200, PAGE.format(title="Note", body=f"<form><textarea name=\"msg\">{msg}</textarea></form>")
    if path == "/":
        links = "\n".join(f'<a href="/item/{i}?q=shoes&sort=price">item {i}</a>' for i in range(1, 11))
        return 200, PAGE.format(title="Shop", body=links)
    return 404, PAGE.format(title="Not found", body="<p>not found</p>")


def app(path, q):
    if path == "/search":
        return 200, PAGE.format(title="Search", body=f"<p>You searched for {q.get('q', '')}</p>")
    if path == "/profile":
        body = f'<form><input type="text" name="name" value="{q.get("name", "")}"></form>'
        return 200, PAGE.format(title="Profile", body=body)
    if path == "/widget":
        body = f"<script>var callback = '{q.get('cb', '')}'; console.log(callback);</script>"
        return 200, PAGE.format(title="Widget", body=body)
    if path == "/safe":
        return 200, PAGE.format(title="Safe", body=f"<p>{html.escape(q.get('q', ''))}</p>")
    if path == "/report":
        rid = q.get("id", "")
        if "'" in rid or '"' in rid:
            err = ("You have an error in your SQL syntax; check the manual that corresponds to your MySQL "
                   "server version for the right syntax to use near '" + html.escape(rid) + "' at line 1")
            return 500, PAGE.format(title="Error", body=f"<pre>{err}</pre>")
        return 200, PAGE.format(title="Report", body=f"<p>Report {html.escape(rid)}</p>")
    if path == "/api/echo":
        # a JSON API that echoes its input unescaped
        return 200, json.dumps({"echo": q.get("msg", "")}, ensure_ascii=False), "application/json"
    if path == "/":
        links = ('<a href="/search?q=a">search</a> <a href="/profile?name=a">profile</a> '
                 '<a href="/widget?cb=a">widget</a> <a href="/safe?q=a">safe</a> <a href="/report?id=1">report</a> '
                 '<a href="/api/echo?msg=a">echo</a>')
        return 200, PAGE.format(title="App", body=links)
    return 404, PAGE.format(title="Not found", body="<p>not found</p>")


SITES = {"shop": shop, "app": app}


def handler(site):
    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            u = urlsplit(self.path)
            q = {k: v[0] for k, v in parse_qs(u.query, keep_blank_values=True).items()}
            status, body, *ctype = SITES[site](u.path, q)
            data = body.encode()
            self.send_response(status)
            self.send_header("Content-Type", (ctype or ["text/html"])[0] + "; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        do_POST = do_GET

        def log_message(self, *a):
            pass

    return H


def main():
    servers = []
    for arg in sys.argv[1:]:
        port, site = arg.split("=", 1)
        s = ThreadingHTTPServer(("127.0.0.1", int(port)), handler(site))
        servers.append(s)
        threading.Thread(target=s.serve_forever, daemon=True).start()
    threading.Event().wait()


if __name__ == "__main__":
    main()
