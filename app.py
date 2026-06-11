from flask import Flask, render_template_string, request
import socket, requests as req, dns.resolver
from concurrent.futures import ThreadPoolExecutor
import json, datetime

app = Flask(__name__)

HTML = """<!DOCTYPE html>
<html>
<head>
<title>AyaanKit Pro</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#0a0c0f;color:#00ff41;font-family:monospace;padding:16px}
h1{text-align:center;font-size:1.5rem;margin:10px 0;text-shadow:0 0 10px #00ff41}
nav{display:flex;flex-wrap:wrap;gap:6px;margin:12px 0}
nav button{background:#0f1318;color:#00ff41;border:1px solid #1a2a1a;padding:6px 12px;cursor:pointer;font-family:monospace;font-size:0.75rem}
nav button.active{background:#004d14;border-color:#00ff41}
.tool{display:none}.tool.active{display:block}
.card{border:1px solid #1a2a1a;padding:12px;margin:10px 0;background:#0f1318}
h3{color:#00ff41;margin-bottom:8px}
input{background:#111;color:#00ff41;border:1px solid #00ff41;padding:8px;width:100%;margin:6px 0;font-family:monospace}
button.btn{background:#00ff41;color:#000;padding:8px 16px;border:none;width:100%;font-weight:bold;cursor:pointer;margin-top:6px}
.result{background:#060809;border:1px solid #00ff41;padding:12px;margin-top:12px;white-space:pre-wrap;font-size:0.78rem;line-height:1.6}
.safe{color:#00ff41}.vuln{color:#ff3c3c}.warn{color:#ffd600}
</style>
</head>
<body>
<h1>⚡ AyaanKit Pro</h1>
<p style="text-align:center;color:#4a7a55;font-size:0.75rem">by Mohammed Ayaan | Ethical Security Toolkit</p>

<nav>
<button class="active" onclick="show('ports',this)">Port Scan</button>
<button onclick="show('vuln',this)">Vuln Check</button>
<button onclick="show('dns',this)">DNS Lookup</button>
<button onclick="show('ssl',this)">SSL Check</button>
<button onclick="show('sub',this)">Subdomains</button>
<button onclick="show('report',this)">Report</button>
</nav>

<div id="ports" class="tool active">
<div class="card">
<h3>🔍 Port Scanner</h3>
<form method="POST" action="/scan">
<input name="target" placeholder="example.com" required>
<button class="btn" type="submit">Scan Ports</button>
</form></div></div>

<div id="vuln" class="tool">
<div class="card">
<h3>🛡 Vulnerability Checker</h3>
<form method="POST" action="/vuln">
<input name="target" placeholder="example.com" required>
<button class="btn" type="submit">Check Vulns</button>
</form></div></div>

<div id="dns" class="tool">
<div class="card">
<h3>🌐 DNS Lookup</h3>
<form method="POST" action="/dns">
<input name="target" placeholder="example.com" required>
<button class="btn" type="submit">DNS Lookup</button>
</form></div></div>

<div id="ssl" class="tool">
<div class="card">
<h3>🔒 SSL Checker</h3>
<form method="POST" action="/ssl">
<input name="target" placeholder="example.com" required>
<button class="btn" type="submit">Check SSL</button>
</form></div></div>

<div id="sub" class="tool">
<div class="card">
<h3>🕵 Subdomain Finder</h3>
<form method="POST" action="/sub">
<input name="target" placeholder="example.com" required>
<button class="btn" type="submit">Find Subdomains</button>
</form></div></div>

<div id="report" class="tool">
<div class="card">
<h3>📄 Generate Report</h3>
<form method="POST" action="/report">
<input name="target" placeholder="example.com" required>
<button class="btn" type="submit">Full Scan + Report</button>
</form></div></div>

{% if result %}<div class="result">{{ result }}</div>{% endif %}

<script>
function show(id, btn){
  document.querySelectorAll('.tool').forEach(t=>t.classList.remove('active'));
  document.querySelectorAll('nav button').forEach(b=>b.classList.remove('active'));
  document.getElementById(id).classList.add('active');
  btn.classList.add('active');
}
</script>
</body></html>"""

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

@app.route("/")
def home():
    return render_template_string(HTML)

@app.route("/scan", methods=["POST"])
def scan():
    target = request.form.get("target","").strip()
    result = f"[PORT SCAN] {target}\n{'='*30}\n"
    ports = [21,22,23,25,53,80,443,3306,8080,8443]
    with ThreadPoolExecutor(max_workers=10) as ex:
        results = list(ex.map(check_port, [(target,p) for p in ports]))
    for port, open_ in sorted(results):
        result += f"{'OPEN' if open_ else 'CLOSED'}: Port {port}\n"
    return render_template_string(HTML, result=result)

@app.route("/vuln", methods=["POST"])
def vuln():
    target = request.form.get("target","").strip()
    result = f"[VULN CHECK] {target}\n{'='*30}\n"
    try:
        r = req.get(f"https://{target}", timeout=5)
        checks = {
            "X-Frame-Options":"Clickjacking Protection",
            "X-XSS-Protection":"XSS Protection",
            "Strict-Transport-Security":"HSTS",
            "Content-Security-Policy":"CSP",
            "X-Content-Type-Options":"MIME Sniffing"
        }
        for h,name in checks.items():
            result += f"{'SAFE' if h in r.headers else 'VULN'}: {name}\n"
        result += f"\nStatus: {r.status_code}"
    except Exception as e:
        result += f"Error: {e}"
    return render_template_string(HTML, result=result)

@app.route("/dns", methods=["POST"])
def dns():
    target = request.form.get("target","").strip()
    result = f"[DNS LOOKUP] {target}\n{'='*30}\n"
    try:
        for rtype in ["A","MX","NS","TXT"]:
            try:
                answers = dns.resolver.resolve(target, rtype)
                for r in answers:
                    result += f"{rtype}: {r}\n"
            except:
                result += f"{rtype}: Not found\n"
    except Exception as e:
        result += f"Error: {e}"
    return render_template_string(HTML, result=result)

@app.route("/ssl", methods=["POST"])
def ssl():
    target = request.form.get("target","").strip()
    result = f"[SSL CHECK] {target}\n{'='*30}\n"
    try:
        import ssl, socket
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=target) as s:
            s.settimeout(5)
            s.connect((target, 443))
            cert = s.getpeercert()
            result += f"Subject: {cert['subject'][0][0][1]}\n"
            result += f"Issuer: {cert['issuer'][1][0][1]}\n"
            result += f"Expires: {cert['notAfter']}\n"
            result += "SSL: VALID ✅\n"
    except Exception as e:
        result += f"SSL Error: {e}\n"
    return render_template_string(HTML, result=result)

@app.route("/sub", methods=["POST"])
def sub():
    target = request.form.get("target","").strip()
    result = f"[SUBDOMAINS] {target}\n{'='*30}\n"
    subs = ["www","mail","ftp","admin","api","dev","test","blog","shop","portal"]
    for s in subs:
        try:
            ip = socket.gethostbyname(f"{s}.{target}")
            result += f"FOUND: {s}.{target} -> {ip}\n"
        except:
            result += f"NOT FOUND: {s}.{target}\n"
    return render_template_string(HTML, result=result)

@app.route("/report", methods=["POST"])
def report():
    target = request.form.get("target","").strip()
    result = f"[FULL REPORT] {target}\n"
    result += f"Date: {datetime.datetime.now()}\n"
    result += f"By: Mohammed Ayaan\n{'='*30}\n"
    ports = [80,443,8080]
    with ThreadPoolExecutor(max_workers=5) as ex:
        presults = list(ex.map(check_port, [(target,p) for p in ports]))
    result += "\n[PORTS]\n"
    for port, open_ in presults:
        result += f"{'OPEN' if open_ else 'CLOSED'}: {port}\n"
    try:
        r = req.get(f"https://{target}", timeout=5)
        result += "\n[HEADERS]\n"
        for h in ["X-Frame-Options","Strict-Transport-Security","Content-Security-Policy"]:
            result += f"{'SAFE' if h in r.headers else 'VULN'}: {h}\n"
    except Exception as e:
        result += f"\nError: {e}"
    return render_template_string(HTML, result=result)

if __name__ == "__main__":
    print("[*] AyaanKit Pro on http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, debug=False, threaded=True)
