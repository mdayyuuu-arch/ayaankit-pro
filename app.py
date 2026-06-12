from flask import Flask, render_template_string, request, redirect, session
import socket, requests as req, datetime, hashlib
from concurrent.futures import ThreadPoolExecutor
import dns.resolver, ssl as ssl_lib

app = Flask(__name__)
app.secret_key = "ayaankit2026"

USERS = {"ayaan": hashlib.md5(b"admin123").hexdigest()}
HISTORY = []

def base(content, result=""):
    return f"""<!DOCTYPE html>
<html><head><title>AyaanKit SaaS</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
body{{background:#0a0c0f;color:#00ff41;font-family:monospace;padding:16px}}
h1{{text-align:center;text-shadow:0 0 10px #00ff41}}
nav{{display:flex;flex-wrap:wrap;gap:6px;margin:12px 0}}
nav a{{background:#0f1318;color:#00ff41;border:1px solid #1a2a1a;padding:6px 12px;text-decoration:none;font-size:0.75rem}}
.card{{border:1px solid #1a2a1a;padding:12px;margin:10px 0;background:#0f1318}}
input{{background:#111;color:#00ff41;border:1px solid #00ff41;padding:8px;width:100%;margin:6px 0;font-family:monospace}}
button{{background:#00ff41;color:#000;padding:8px;border:none;width:100%;font-weight:bold;cursor:pointer;margin-top:6px}}
.result{{background:#060809;border:1px solid #00ff41;padding:12px;margin-top:12px;white-space:pre-wrap;font-size:0.78rem}}
</style></head><body>
<h1>AyaanKit SaaS</h1>
<p style="text-align:center;color:#4a7a55;font-size:0.75rem">by Mohammed Ayaan</p>
<nav><a href="/scan">Port Scan</a><a href="/vuln">Vuln</a><a href="/dns">DNS</a><a href="/ssl">SSL</a><a href="/sub">Subdomains</a><a href="/report">Report</a><a href="/history">History</a><a href="/logout" style="color:#ff3c3c">Logout</a></nav>
{content}
{"<div class='result'>"+result+"</div>" if result else ""}
</body></html>"""

def tool_page(title, action, btn, result=""):
    content = f"<div class='card'><h3>{title}</h3><form method='POST' action='{action}'><input name='target' placeholder='example.com' required><button type='submit'>{btn}</button></form></div>"
    return base(content, result)

def check_port(args):
    target, port = args
    try:
        s = socket.socket()
        s.settimeout(0.5)
        s.connect((target, port))
        s.close()
        return port, True
    except:
        return port, False

def add_history(tool, target):
    HISTORY.append({"time": datetime.datetime.now().strftime("%H:%M"), "tool": tool, "target": target})

def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user" not in session:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated

@app.route("/")
def home():
    return redirect("/login" if "user" not in session else "/scan")

@app.route("/login", methods=["GET","POST"])
def login():
    error = ""
    if request.method == "POST":
        u = request.form.get("username","")
        p = hashlib.md5(request.form.get("password","").encode()).hexdigest()
        if u in USERS and USERS[u] == p:
            session["user"] = u
            return redirect("/scan")
        error = "<p style='color:#ff3c3c'>Wrong credentials!</p>"
    content = f"<div class='card'><h3>Login</h3><form method='POST'><input name='username' placeholder='Username'><input name='password' type='password' placeholder='Password'><button type='submit'>Login</button></form>{error}</div>"
    return f"""<!DOCTYPE html><html><head><title>AyaanKit Login</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>body{{background:#0a0c0f;color:#00ff41;font-family:monospace;padding:16px}}
h1{{text-align:center;text-shadow:0 0 10px #00ff41}}
.card{{border:1px solid #1a2a1a;padding:12px;margin:10px 0;background:#0f1318}}
input{{background:#111;color:#00ff41;border:1px solid #00ff41;padding:8px;width:100%;margin:6px 0;font-family:monospace}}
button{{background:#00ff41;color:#000;padding:8px;border:none;width:100%;font-weight:bold;cursor:pointer;margin-top:6px}}
</style></head><body><h1>AyaanKit SaaS</h1>{content}</body></html>"""

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")

@app.route("/scan", methods=["GET","POST"])
@login_required
def scan():
    result = ""
    if request.method == "POST":
        target = request.form.get("target","").strip()
        result = f"[PORT SCAN] {target}\n{'='*30}\n"
        with ThreadPoolExecutor(max_workers=10) as ex:
            results = list(ex.map(check_port, [(target,p) for p in [21,22,80,443,3306,8080,8443]]))
        for port, open_ in sorted(results):
            result += f"{'OPEN' if open_ else 'CLOSED'}: Port {port}\n"
        add_history("Port Scan", target)
    return tool_page("Port Scanner", "/scan", "Scan", result)

@app.route("/vuln", methods=["GET","POST"])
@login_required
def vuln():
    result = ""
    if request.method == "POST":
        target = request.form.get("target","").strip()
        result = f"[VULN CHECK] {target}\n{'='*30}\n"
        try:
            r = req.get(f"https://{target}", timeout=5)
            for h,name in {"X-Frame-Options":"Clickjacking","Strict-Transport-Security":"HSTS","Content-Security-Policy":"CSP","X-XSS-Protection":"XSS"}.items():
                result += f"{'SAFE' if h in r.headers else 'VULN'}: {name}\n"
        except Exception as e:
            result += f"Error: {e}"
        add_history("Vuln Check", target)
    return tool_page("Vuln Checker", "/vuln", "Check", result)

@app.route("/dns", methods=["GET","POST"])
@login_required
def dns_lookup():
    result = ""
    if request.method == "POST":
        target = request.form.get("target","").strip()
        result = f"[DNS] {target}\n{'='*30}\n"
        for rtype in ["A","MX","NS"]:
            try:
                for r in dns.resolver.resolve(target, rtype):
                    result += f"{rtype}: {r}\n"
            except:
                result += f"{rtype}: Not found\n"
        add_history("DNS", target)
    return tool_page("DNS Lookup", "/dns", "Lookup", result)

@app.route("/ssl", methods=["GET","POST"])
@login_required
def ssl_check():
    result = ""
    if request.method == "POST":
        target = request.form.get("target","").strip()
        result = f"[SSL] {target}\n{'='*30}\n"
        try:
            ctx = ssl_lib.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=target) as s:
                s.settimeout(5)
                s.connect((target, 443))
                cert = s.getpeercert()
                result += f"Expires: {cert['notAfter']}\nSSL: VALID\n"
        except Exception as e:
            result += f"Error: {e}"
        add_history("SSL", target)
    return tool_page("SSL Checker", "/ssl", "Check SSL", result)

@app.route("/sub", methods=["GET","POST"])
@login_required
def sub():
    result = ""
    if request.method == "POST":
        target = request.form.get("target","").strip()
        result = f"[SUBDOMAINS] {target}\n{'='*30}\n"
        for s in ["www","mail","api","admin","dev","blog"]:
            try:
                ip = socket.gethostbyname(f"{s}.{target}")
                result += f"FOUND: {s}.{target} -> {ip}\n"
            except:
                result += f"NOT FOUND: {s}.{target}\n"
        add_history("Subdomain", target)
    return tool_page("Subdomain Finder", "/sub", "Find", result)

@app.route("/report", methods=["GET","POST"])
@login_required
def report():
    result = ""
    if request.method == "POST":
        target = request.form.get("target","").strip()
        result = f"[REPORT] {target}\nDate: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}\nBy: Mohammed Ayaan\n{'='*30}\n"
        with ThreadPoolExecutor(max_workers=5) as ex:
            for port, open_ in list(ex.map(check_port, [(target,p) for p in [80,443,8080]])):
                result += f"{'OPEN' if open_ else 'CLOSED'}: {port}\n"
        try:
            r = req.get(f"https://{target}", timeout=5)
            for h in ["X-Frame-Options","Strict-Transport-Security","Content-Security-Policy"]:
                result += f"{'SAFE' if h in r.headers else 'VULN'}: {h}\n"
        except Exception as e:
            result += f"Error: {e}"
        add_history("Report", target)
    return tool_page("Full Report", "/report", "Generate", result)

@app.route("/history")
@login_required
def history():
    rows = "".join(f"<div style='border-bottom:1px solid #1a2a1a;padding:4px;font-size:0.72rem;color:#4a7a55'>{h['time']} | {h['tool']} | {h['target']}</div>" for h in HISTORY)
    content = f"<div class='card'><h3>Scan History</h3>{rows or 'No scans yet'}</div>"
    return base(content)

if __name__ == "__main__":
    print("[*] AyaanKit SaaS: http://0.0.0.0:5000")
    print("[*] Login: ayaan / admin123")
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)
