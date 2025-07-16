from flask import Flask, request, render_template
import requests
from bs4 import BeautifulSoup

app = Flask(__name__)

# SQL Injection Scanner
def scan_sql_injection(url):
    payload = "' OR '1'='1"
    try:
        response = requests.get(url + payload)
        if any(err in response.text.lower() for err in ['sql', 'syntax', 'query']):
            return "[HIGH] SQL Injection Detected"
        return "[OK] No SQL Injection Found"
    except Exception as e:
        return f"[ERROR] {e}"

# XSS Scanner
def scan_xss(url):
    payload = "<script>alert('XSS')</script>"
    try:
        response = requests.get(url + payload)
        if payload in response.text:
            return "[HIGH] XSS Detected"
        return "[OK] No XSS Found"
    except Exception as e:
        return f"[ERROR] {e}"

# CSRF Scanner
def scan_csrf(url):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        for form in forms:
            if not form.find('input', {'name': 'csrf'}) and not form.find('input', {'name': 'csrf_token'}):
                return "[MEDIUM] CSRF Token Missing in Forms"
        return "[OK] CSRF Token Found"
    except Exception as e:
        return f"[ERROR] {e}"

# Header Scanner
def scan_headers(url):
    try:
        response = requests.get(url)
        issues = []
        if 'X-Frame-Options' not in response.headers:
            issues.append("X-Frame-Options Missing")
        if 'Content-Security-Policy' not in response.headers:
            issues.append("CSP Header Missing")
        if 'Strict-Transport-Security' not in response.headers:
            issues.append("HSTS Header Missing")
        if issues:
            return f"[MEDIUM] Headers Issues: {', '.join(issues)}"
        return "[OK] Security Headers Found"
    except Exception as e:
        return f"[ERROR] {e}"

# HTTPS Scanner
def scan_https(url):
    if not url.startswith("https"):
        return "[HIGH] HTTPS Not Used"
    return "[OK] HTTPS Enabled"

# Directory Fuzzing
def scan_dir_fuzz(url, wordlist=None):
    if wordlist is None:
        common_paths = ["/admin", "/login", "/dashboard", "/backup", "/test", "/.git"]
    else:
        common_paths = [line.strip() for line in wordlist if line.strip()]

    found = []
    for path in common_paths:
        try:
            full_url = url.rstrip('/') + path
            response = requests.get(full_url)
            if response.status_code == 200:
                found.append(path)
        except:
            continue

    if found:
        return f"[INFO] Directories Found: {', '.join(found)}"
    return "[OK] No Sensitive Directories Found"

@app.route('/', methods=['GET', 'POST'])
def index():
    report = {}
    if request.method == 'POST':
        url = request.form['url']
        wordlist_text = request.form.get('wordlist', '')
        wordlist = wordlist_text.splitlines() if wordlist_text else None

        report["SQL Injection"] = scan_sql_injection(url)
        report["XSS"] = scan_xss(url)
        report["CSRF"] = scan_csrf(url)
        report["Headers"] = scan_headers(url)
        report["HTTPS"] = scan_https(url)
        report["Directory Fuzzing"] = scan_dir_fuzz(url, wordlist)

        return render_template('report.html', url=url, report=report)
    return render_template('index.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
