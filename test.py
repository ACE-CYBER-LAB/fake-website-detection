from flask import Flask, render_template, request
import whois as python_whois  # Correcting the whois module
import requests
import socket
import ssl
import datetime
from bs4 import BeautifulSoup
import json

app = Flask(__name__)

# Google Safe Browsing API Key (Replace with your actual key)
GOOGLE_API_KEY = "AIzaSyB7yvEgaftZFG6KgngHRuPUfvEBfycDg6A"
VIRUSTOTAL_API_KEY = "80305c9b6fdde681bd97caa45494e34010dfb4f1e2141adf7abcd0e83a36f2cf"

# Function to check WHOIS domain age
def get_domain_info(domain):
    try:
        domain_info = python_whois.whois(domain)  # Corrected whois usage
        creation_date = domain_info.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        age = (datetime.datetime.now() - creation_date).days if creation_date else "Unknown"
        registrar = domain_info.registrar or "Unknown Registrar"
        return age, registrar
    except Exception as e:
        return None, f"WHOIS Lookup Failed: {e}"

# Function to check SSL Certificate
def check_ssl_certificate(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                return "Valid SSL Certificate"
    except Exception:
        return "No SSL Certificate Found"

# Function to check Google Safe Browsing
def check_google_safety(domain):
    try:
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
    except Exception:
        return "Google Safety Check Failed"

# Function to check VirusTotal blacklist
def check_virustotal(domain):
    try:
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            detections = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            if detections.get("malicious", 0) > 0:
                return "Blacklisted on VirusTotal!"
            return "Not Blacklisted on VirusTotal"
        return "VirusTotal Lookup Failed"
    except Exception:
        return "VirusTotal Check Failed"

# Function to analyze website content
def analyze_website_content(domain):
    try:
        response = requests.get(f"http://{domain}", timeout=5)
        soup = BeautifulSoup(response.text, "html.parser")
        text = soup.get_text().lower()
        suspicious_words = ["free money", "limited offer", "congratulations", "click here", "password reset"]
        for word in suspicious_words:
            if word in text:
                return "Suspicious content detected!"
        return "Content looks normal"
    except Exception:
        return "Could not analyze website content"

# Function to check ScamAdviser
def check_scamadviser(domain):
    try:
        scamadviser_url = f"https://www.scamadviser.com/check-website/{domain}"
        return f"Check reputation manually: {scamadviser_url}"
    except Exception:
        return "ScamAdviser check failed"

# Function to get IP & Hosting Provider
def get_ip_hosting(domain):
    try:
        ip = socket.gethostbyname(domain)
        return f"IP: {ip}"
    except Exception:
        return "Could not fetch IP address"

# Flask route for homepage
@app.route("/", methods=["GET", "POST"])
def home():
    result = None
    if request.method == "POST":
        domain = request.form["domain"]
        age, registrar = get_domain_info(domain)
        ssl_status = check_ssl_certificate(domain)
        google_status = check_google_safety(domain)
        virustotal_status = check_virustotal(domain)
        content_analysis = analyze_website_content(domain)
        scamadviser_status = check_scamadviser(domain)
        ip_hosting = get_ip_hosting(domain)

        result = {
            "domain": domain,
            "age": f"{age} days" if age else registrar,
            "ssl": ssl_status,
            "google_safety": google_status,
            "virustotal": virustotal_status,
            "content_analysis": content_analysis,
            "scamadviser": scamadviser_status,
            "ip_hosting": ip_hosting,
        }
    
    return render_template("index.html", result=result)

if __name__ == "__main__":
    app.run(debug=True)
