# fake-website-detection



from flask import Flask, render_template, request
import whois
import requests
import socket
import ssl
import datetime
from bs4 import BeautifulSoup

app = Flask(__name__)

# Google Safe Browsing API Key (Replace with your actual key)
GOOGLE_API_KEY = "AIzaSyB7yvEgaftZFG6KgngHRuPUfvEBfycDg6A"

# VirusTotal API Key (Replace with your actual key)
VIRUSTOTAL_API_KEY = "80305c9b6fdde681bd97caa45494e34010dfb4f1e2141adf7abcd0e83a36f2cf"

# Function to check WHOIS domain age
def get_domain_info(domain):
    try:
        domain_info = whois.whois(domain)
        creation_date = domain_info.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        age = (datetime.datetime.now() - creation_date).days
        registrar = domain_info.registrar
        return age, registrar
    except Exception as e:
        return None, f"WHOIS Lookup Failed: {e}"

# Function to check SSL Certificate
def check_ssl_certificate(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                certificate = ssock.getpeercert()
                return "Valid SSL Certificate"
    except Exception:
        return "No SSL Certificate Found"

# Function to check Google Safe Browsing
def check_google_safety(domain):
    url = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
    payload = {
        "client": {"clientId": "website-checker", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": f"http://{domain}"}],
        },
    }
    headers = {"Content-Type": "application/json"}
    response = requests.post(f"{url}?key={GOOGLE_API_KEY}", json=payload, headers=headers)
    return "Threat Found!" if response.json() else "Safe"

# Function to analyze website content
def analyze_website_content(domain):
    try:
        response = requests.get(f"http://{domain}")
        soup = BeautifulSoup(response.text, "html.parser")
        text = soup.get_text().lower()
        suspicious_words = ["free money", "limited offer", "congratulations", "click here", "password reset"]
        for word in suspicious_words:
            if word in text:
                return "Suspicious content detected!"
        return "Content looks normal"
    except Exception:
        return "Could not analyze website content"

# Function to check VirusTotal blacklist
def check_virustotal(domain):
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY
    }
    try:
        response = requests.get(url, headers=headers)
        data = response.json()
        if "data" in data and "attributes" in data["data"]:
            malicious_votes = data["data"]["attributes"]["last_analysis_stats"]["malicious"]
            if malicious_votes > 0:
                return f"⚠️ Blacklisted by {malicious_votes} sources!"
            else:
                return "✅ Not Blacklisted"
        return "Could not retrieve VirusTotal data"
    except Exception as e:
        return f"VirusTotal Check Failed: {e}"

# Flask route for homepage
@app.route("/", methods=["GET", "POST"])
def home():
    result = None
    if request.method == "POST":
        domain = request.form["domain"]
        age, registrar = get_domain_info(domain)
        ssl_status = check_ssl_certificate(domain)
        google_status = check_google_safety(domain)
        content_analysis = analyze_website_content(domain)
        virustotal_status = check_virustotal(domain)

        result = {
            "domain": domain,
            "age": f"{age} days" if age else registrar,
            "ssl": ssl_status,
            "google_safety": google_status,
            "content_analysis": content_analysis,
            "virustotal_status": virustotal_status
        }
    
    return render_template("index.html", result=result)

if __name__ == "__main__":
    app.run(debug=True)
