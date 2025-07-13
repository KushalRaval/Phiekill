import re, tldextract, requests, json, time
from urllib.parse import urlparse

# Banner
def show_banner():
    print(r"""
██████╗ ██╗  ██╗██╗███████╗██╗  ██╗██╗██╗     ██╗     
██╔══██╗██║  ██║██║██╔════╝██║ ██╔╝██║██║     ██║     
██████╔╝███████║██║█████╗  █████╔╝ ██║██║     ██║     
██╔═══╝ ██╔══██║██║██╔══╝  ██╔═██╗ ██║██║     ██║     
██║     ██║  ██║██║███████╗██║  ██╗██║███████╗███████╗
╚═╝     ╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝

        Advanced URL Threat Detection System
              Created by: Kushal Raval
""")

# Local rule-based detection
def is_suspicious(url):
    score, reasons = 0, []
    if not url.startswith("http"):
        url = "http://" + url
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    suffix = tldextract.extract(url).suffix

    if re.match(r'https?://(\d{1,3}\.){3}\d{1,3}', url):
        score += 3
        reasons.append("Uses IP address")
    if "@" in url:
        score += 2
        reasons.append("Contains '@'")
    if not url.startswith("https://"):
        score += 1
        reasons.append("Not HTTPS")
    for s in ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly']:
        if s in url:
            score += 3
            reasons.append("Shortener used")
            break
    keywords = ['login', 'secure', 'account', 'update', 'bank', 'verify', 'signin', 'submit', 'confirm', 'security', 'ebay', 'paypal']
    if any(w in url.lower() for w in keywords):
        score += 2
        reasons.append("Phishing keywords")
    if suffix in ['xyz', 'top', 'club', 'online', 'tk', 'ml', 'ga', 'cf', 'gq']:
        score += 2
        reasons.append(f"Suspicious TLD .{suffix}")
    if hostname.count('.') > 3:
        score += 2
        reasons.append("Too many subdomains")
    if len(url) > 75:
        score += 1
        reasons.append("Very long URL")
    if url.count('-') > 3:
        score += 1
        reasons.append("Too many hyphens")
    if re.search(r"[;%*<>`]", url):
        score += 1
        reasons.append("Special chars")
    return {"url": url, "score": score, "reasons": reasons}

# Hidden VirusTotal
def external_url_scan(url):
    api_key = "002c617d4cb5d4c10eccae9c7899947073d931c37081ae9e5b27b3f56fa78277"
    h = {"x-apikey": api_key}
    r = requests.post("https://www.virustotal.com/api/v3/urls", headers=h, data={"url": url})
    r.raise_for_status()
    url_id = r.json()["data"]["id"]
    resp = requests.get(f"https://www.virustotal.com/api/v3/analyses/{url_id}", headers=h)
    resp.raise_for_status()
    data = resp.json()
    while data["data"]["attributes"]["status"] == "queued":
        print("⏳ Scanning externally...")
        time.sleep(2)
        data = requests.get(f"https://www.virustotal.com/api/v3/analyses/{url_id}", headers=h).json()
    st = data["data"]["attributes"]["stats"]
    return {"mal": st.get("malicious", 0), "sus": st.get("suspicious", 0), "har": st.get("harmless", 0), "und": st.get("undetected", 0)}

# Google Safe Browsing
def check_google_safebrowse(url, api_key="AIzaSyCrwpED7klLZD-RbL683jXeetLNXM0B-3o"):
    body = {
        "client": {"clientId": "scanner", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    r = requests.post(f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}", json=body)
    if r.status_code == 200 and r.json().get("matches"):
        return True
    return False

# PhishTank check
def check_phishtank(url, app_key=""):
    data = {"url": url, "format": "json"}
    if app_key:
        data["app_key"] = app_key
    r = requests.post("http://checkurl.phishtank.com/checkurl/", data=data)
    if r.status_code == 200:
        j = r.json()
        return j.get("results", {}).get("in_database", False) and j.get("results", {}).get("valid", False)
    return None

# URLScan.io check
def check_urlscan(url, api_key="01980247-ce96-71cd-a778-845957340fc1"):
    h = {"API-Key": api_key, "Content-Type": "application/json"}
    j = requests.post("https://urlscan.io/api/v1/scan/", json={"url": url, "visibility": "public"}, headers=h).json()
    uuid = j.get("uuid")
    time.sleep(2)
    res = requests.get(f"https://urlscan.io/api/v1/result/{uuid}/", headers=h).json()
    return res.get("verdicts", {}).get("overall", {})

# Main
if __name__ == "__main__":
    show_banner()
    u = input("🔍 Enter URL to scan: ").strip()
    local = is_suspicious(u)
    vt = external_url_scan(u)
    sb = check_google_safebrowse(u)
    pt = check_phishtank(u)
    us = check_urlscan(u, "01980247-ce96-71cd-a778-845957340fc1")

    print("\n==============================")
    print(f"🧠 URL: {local['url']}")
    print(f"📊 Score: {local['score']}")
    print("📌 Reasons:")
    for r in local["reasons"]:
        print(f"   - {r}")

    print("\n🔎 External Verdicts:")
    print(f" - External malicious hits: mal={vt['mal']}, sus={vt['sus']}")
    print(f" - Google Safe Browsing flagged? {sb}")
    print(f" - In PhishTank DB? {pt}")
    print(f" - URLScan verdict: {us}")

    print("\n==============================")
    verdict = "PHISHING URL 🔥" if local["score"] > 2 else "NOT a phishing URL ✅"
    print(f"⚠️ Final Verdict: {verdict}")
    print("==============================")
