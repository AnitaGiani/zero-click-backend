from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import re
import os
import csv
from datetime import datetime
import joblib

# Load trained model and vectorizer
model = joblib.load("url_model.pkl")
vectorizer = joblib.load("vectorizer.pkl")


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

def predict_with_model(url):
    X = vectorizer.transform([url])
    prediction = model.predict(X)[0]
    return "Malicious" if prediction == 1 else "Safe"


def log_url_check(url, result):
    log_file = "scan_log.csv"
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S") 

    # Unpack values safely
    rule_based = result.get("rule_based", "Unknown")
    ml_based = result.get("ml_based", "Unknown")

    with open(log_file, mode='a', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        writer.writerow([timestamp, url, rule_based, ml_based])







@app.route('/check_url', methods=['GET', 'POST'])
def check_url():
    if request.method == 'GET':
        return jsonify({"error": "Please use POST with JSON body containing 'url'."}), 405

    data = request.get_json()
    url = data.get('url')

    rule_based_result = check_url_threat(url)
    ml_result = predict_with_model(url)

    result = {
        "rule_based": rule_based_result,
        "ml_based": ml_result
    }

    log_url_check(url, result)
    print("Logging result:", result)

    return jsonify(result)




@app.route('/scan_logs', methods=['GET'])
def get_scan_logs():
    from_date = request.args.get('from')
    to_date = request.args.get('to')

    logs = []
    try:
        with open("scan_log.csv", "r") as f:
            reader = csv.reader(f)
            for row in reader:
                if len(row) != 4:
                    continue
                timestamp, url, rule_based, ml_based = row
                log_date = timestamp.split(" ")[0]

                if from_date and log_date < from_date:
                    continue
                if to_date and log_date > to_date:
                    continue

                logs.append({
                    "timestamp": timestamp,
                    "url": url,
                    "rule_based": rule_based,
                    "ml_based": ml_based
                })
    except FileNotFoundError:
        return jsonify({"logs": []})

    return jsonify({"logs": logs})


@app.route('/report')
def scan_report():
    logs = []
    try:
        with open("scan_log.csv", "r") as f:
            reader = csv.reader(f)
            for row in reader:
                if len(row) == 3:
                    logs.append({"timestamp": row[0], "url": row[1], "result": row[2]})
    except FileNotFoundError:
        logs = []

    return render_template("scan_report.html", logs=logs)


@app.route("/")
def home():
    return {"message": "Zero Click Detector API is live"}


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)

