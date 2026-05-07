from flask import Flask, render_template, request

app = Flask(__name__)

# ----------------------------
# CYBER RISK SCORING ENGINE
# ----------------------------

def analyze_url(url):
    score = 0
    reasons = []

    url_lower = url.lower()

    # 1. HTTPS check
    if "https://" not in url_lower:
        score += 20
        reasons.append("No HTTPS encryption detected (unsafe connection)")

    # 2. Suspicious keywords
    suspicious_keywords = ["login", "bank", "verify", "password", "update", "secure"]

    for word in suspicious_keywords:
        if word in url_lower:
            score += 15
            reasons.append(f"Suspicious keyword found: '{word}'")

    # 3. URL length check
    if len(url) > 75:
        score += 10
        reasons.append("URL is unusually long (possible phishing indicator)")

    # 4. Special character check
    if "@" in url:
        score += 15
        reasons.append("Contains '@' symbol (possible redirect attack)")

    if "-" in url:
        score += 5
        reasons.append("Contains hyphen (-), sometimes used in fake domains")

    # 5. IP address instead of domain (basic check)
    if any(char.isdigit() for char in url.split("//")[-1].split("/")[0]):
        if "." in url:
            score += 20
            reasons.append("URL uses IP address instead of domain name")

    # ----------------------------
    # FINAL RISK LEVEL
    # ----------------------------

    if score <= 30:
        level = "LOW"
        color = "green"
    elif score <= 70:
        level = "MEDIUM"
        color = "orange"
    else:
        level = "HIGH"
        color = "red"

    return score, level, color, reasons


# ----------------------------
# ROUTES
# ----------------------------

@app.route('/')
def home():
    return render_template("index.html")


@app.route('/check', methods=['POST'])
def check():
    url = request.form['url']

    score, level, color, reasons = analyze_url(url)

    return render_template(
        "result.html",
        url=url,
        score=score,
        level=level,
        color=color,
        reasons=reasons
    )


# ----------------------------
# RUN APP
# ----------------------------

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)