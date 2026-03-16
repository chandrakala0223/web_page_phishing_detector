import os
import pickle
import webbrowser
import numpy as np
import re
from urllib.parse import urlparse
from flask import Flask, render_template, request

app = Flask(__name__)

# -----------------------------------
# Feature extraction (same as training)
# -----------------------------------
def extract_url_features(url):

    url = str(url).strip()

    features = [
        len(url),
        url.count("."),
        url.count("/"),
        url.count("@"),
        int(url.startswith("https")),
        int("%" in url),
        int("-" in url)
    ]

    return np.array(features).reshape(1, -1)


# -----------------------------------
# URL validation
# -----------------------------------
def is_valid_url(url):

    pattern = re.compile(
        r'^(https?:\/\/)?'
        r'([a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,}'
    )

    return pattern.match(url)


# -----------------------------------
# Load ML model
# -----------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "phishing_model.pkl")

with open(MODEL_PATH, "rb") as f:
    model = pickle.load(f)


# -----------------------------------
# Home page
# -----------------------------------
@app.route("/")
def home():
    return render_template("index.html")


# -----------------------------------
# Scan URL
# -----------------------------------
@app.route("/scan", methods=["POST"])
def scan():

    url = request.form.get("url")

    if not url:
        return render_template("index.html")

    # -----------------------
    # Step 1: URL format check
    # -----------------------
    if not is_valid_url(url):

        return render_template(
            "phishing.html",
            url=url,
            score="Invalid URL"
        )

    # -----------------------
    # Step 2: Trusted domains
    # -----------------------
    trusted_sites = [
        "google.com",
        "youtube.com",
        "github.com",
        "amazon.com",
        "wikipedia.org"
    ]

    for site in trusted_sites:
        if site in url:

            return render_template(
                "safe.html",
                url=url,
                score="99%"
            )

    # -----------------------
    # Step 3: ML prediction
    # -----------------------
    features = extract_url_features(url)

    prediction = model.predict(features)[0]

    confidence = ""

    if hasattr(model, "predict_proba"):
        prob = model.predict_proba(features)[0]
        confidence = f"{max(prob)*100:.1f}%"

    # dataset assumption
    # 1 = phishing
    # 0 = safe

    if int(prediction) == 1:

        return render_template(
            "phishing.html",
            url=url,
            score=confidence
        )

    else:

        return render_template(
            "safe.html",
            url=url,
            score=confidence
        )


# -----------------------------------
# Run server
# -----------------------------------
if __name__ == "__main__":

    webbrowser.open("http://127.0.0.1:5000")

    app.run(debug=True)