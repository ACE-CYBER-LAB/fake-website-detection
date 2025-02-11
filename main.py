import whois
import requests
import socket
import ssl
import datetime
import json
from bs4 import BeautifulSoup

# Google Safe Browsing API Key (Replace with your actual key)
GOOGLE_API_KEY = "YOUR_GOOGLE_SAFE_BROWSING_API_KEY"

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

# Function to get IP Address & Hosting Provider
def get_ip_and_hosting(domain):
    try:
        ip_address = socket.gethostbyname(domain)
        response = requests.get(f"http://ip-api.com/json/{ip_address}")
        data = response.json()
        hosting_provider = data.get("isp", "Unknown ISP")
        return ip_address, hosting_provider
    except Exception:
        return "Unknown IP", "Unknown Hosting Provider"

# Function to check ScamAdviser for reputation
def check_scamadviser(domain):
    try:
        response = requests.get(f"https://www.scamadviser.com/check-website/{domain}")
        if "scamadviser" in response.url:
            return "Check ScamAdviser manually: " + response.url
        return "ScamAdviser lookup failed"
    except Exception:
        return "ScamAdviser check failed"

# Function to check VirusTotal blacklist (Requires API Key)
def check_virustotal(domain):
    VT_API_KEY = "YOUR_VIRUSTOTAL_API_KEY"
    headers = {"x-apikey": VT_API_KEY}
    response = requests.get(f"https://www.virustotal.com/api/v3/domains/{domain}", headers=headers)
    if response.status_code == 200:
        data = response.json()
        if data["data"]["attributes"]["last_analysis_stats"]["malicious"] > 0:
            return "Listed as malicious on VirusTotal!"
        return "Not flagged by VirusTotal"
    return "VirusTotal check failed"

# Main function
def check_website(domain):
    print(f"\n🔍 Checking Website: {domain}\n")
    
    # WHOIS Domain Age & Registrar
    age, registrar = get_domain_info(domain)
    print(f"📅 Domain Age: {age} days" if age else registrar)
    
    # SSL Certificate Check
    print(f"🔒 SSL Certificate: {check_ssl_certificate(domain)}")
    
    # Google Safe Browsing Check
    print(f"⚠️ Google Safety Check: {check_google_safety(domain)}")
    
    # Website Content Analysis
    print(f"📄 Content Analysis: {analyze_website_content(domain)}")
    
    # IP & Hosting Provider Check
    ip, hosting = get_ip_and_hosting(domain)
    print(f"🌍 IP Address: {ip}")
    print(f"🏢 Hosting Provider: {hosting}")
    
    # ScamAdviser Check
    print(f"🔎 ScamAdviser Reputation: {check_scamadviser(domain)}")
    
    # VirusTotal Blacklist Check
    print(f"🚨 VirusTotal Check: {check_virustotal(domain)}\n")

# Example Usage
domain = input("Enter website domain (without http/https): ")
check_website(domain)
