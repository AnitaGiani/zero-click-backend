from flask import Flask, request, jsonify
from flask_cors import CORS
import re
import os
import csv
from datetime import datetime


app = Flask(__name__)
CORS(app)

# List of common risky keywords and domains
RISKY_KEYWORDS = ["login", "verify", "free", "bank", "update", "security", "confirm"]
SUSPICIOUS_DOMAINS = ["bit.ly", "tinyurl.com", "shorte.st", "adf.ly", "zip", "rar", "exe"]
MAX_DOT_COUNT = 5
MAX_HYPHEN_COUNT = 4

def check_url_threat(url):
    url_lower = url.lower()

    # Check for suspicious domains
    if any(domain in url_lower for domain in SUSPICIOUS_DOMAINS):
        return "Malicious"

    # Check for risky keywords
    if any(keyword in url_lower for keyword in RISKY_KEYWORDS):
        return "Suspicious"

    # Check for excessive dots or hyphens (phishing tactic)
    if url.count('.') > MAX_DOT_COUNT or url.count('-') > MAX_HYPHEN_COUNT:
        return "Suspicious"

    # Check for IP address in URL
    if re.match(r"https?://\d+\.\d+\.\d+\.\d+", url):
        return "Suspicious"

    return "Safe"
def log_url_check(url, result):
    log_file = "scan_log.csv"
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    with open(log_file, mode='a', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        writer.writerow([timestamp, url, result])


@app.route('/check_url', methods=['POST'])
def check_url():
    data = request.get_json()
    url = data.get('url')
    print("Received URL:", url)

    result = check_url_threat(url)

    # Log to CSV
    log_url_check(url, result)

    return jsonify({"status": result})

@app.route("/")
def home():
    return {"message": "Zero Click Detector API is live"}


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)

