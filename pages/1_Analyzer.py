import streamlit as st
import joblib
import os
import pandas as pd
from datetime import datetime
import numpy as np
import tldextract
import plotly.express as px
from feature_extractor import extract_url_features

# -------------------------------------------------------
# LOAD MODEL & VECTORIZER
# -------------------------------------------------------
@st.cache_resource
def load_model_and_vectorizer():
    model_path = "model/phishing_model.pkl"
    vectorizer_path = "model/vectorizer.pkl"
    if os.path.exists(model_path) and os.path.exists(vectorizer_path):
        return joblib.load(model_path), joblib.load(vectorizer_path)
    return None, None

model, vec = load_model_and_vectorizer()

st.title("🔍 Threat Analyzer (Fast Mode)")

if model is None:
    st.error("⚠️ Model files missing. Train locally & upload model/ folder.")
    st.stop()

# -------------------------------------------------------
# QUICK, NON-BLOCKING CHECKS (NO NETWORK TIMEOUTS)
# -------------------------------------------------------

def get_domain(url):
    ext = tldextract.extract(url)
    return f"{ext.domain}.{ext.suffix}"

def string_pattern_risk(url):
    keywords = [
        "login", "verify", "secure", "update", "confirm", "reset",
        "refund", "support", "auth", "billing", "unlock",
        "mpesa", "ecitizen", "kra", "ntsa", "helb"
    ]
    score = 0
    hits = []
    for k in keywords:
        if k in url.lower():
            score += 0.05
            hits.append(k)
    return score, hits

def domain_suspicion(domain):
    # Fast static checks, works offline
    risk = 0
    reasons = []

    # Suspicious TLDs
    bad_tlds = ["xyz", "top", "site", "online", "info", "click"]
    if domain.split(".")[-1] in bad_tlds:
        risk += 0.15
        reasons.append("Uncommon or high-risk TLD")

    # Multi-hyphen phishing style
    if domain.count("-") >= 2:
        risk += 0.10
        reasons.append("Multiple hyphens (common in phishing)")

    # Very long domains
    if len(domain) > 22:
        risk += 0.10
        reasons.append("Long domain name")

    return risk, reasons


# -------------------------------------------------------
# USER INPUT
# -------------------------------------------------------
url_input = st.text_input("Enter URL", placeholder="https://example.com")

if st.button("Analyze URL"):
    if not url_input.strip():
        st.error("Enter a valid URL.")
        st.stop()

    domain = get_domain(url_input)
    
    # ML prediction
    feats = extract_url_features(url_input)
    X = vec.transform([feats])
    pred = int(model.predict(X)[0])
    prob = float(model.predict_proba(X)[0][pred])

    # Fast scoring system
    string_score, pattern_hits = string_pattern_risk(url_input)
    domain_score, domain_flags = domain_suspicion(domain)

    final_score = min(prob + string_score + domain_score, 1)

    # -------------------------------------------------------
    # DISPLAY RESULTS
    # -------------------------------------------------------
    st.subheader("🔎 Final Risk Score")
    if final_score >= 0.6:
        st.error(f"⚠️ HIGH RISK — Likely Malicious (Score: {final_score:.2f})")
    elif final_score >= 0.35:
        st.warning(f"⚠️ Medium Risk — Suspicious (Score: {final_score:.2f})")
    else:
        st.success(f"✅ Safe (Score: {final_score:.2f})")

    st.subheader("🧠 Machine Learning Result")
    st.write(f"Prediction: **{'Malicious' if pred == 1 else 'Safe'}**")
    st.write(f"Model Confidence: **{prob:.2f}**")

    st.subheader("📌 Pattern Indicators")
    st.write(pattern_hits if pattern_hits else "None")

    st.subheader("📌 Domain Flags")
    st.write(domain_flags if domain_flags else "None")

    # PIE CHART
    fig = px.pie(
        names=["Threat Score", "Safety"],
        values=[final_score, 1 - final_score],
        hole=0.65,
        color_discrete_sequence=px.colors.sequential.Reds
    )
    st.plotly_chart(fig, use_container_width=True)

    # LOGGING
    os.makedirs("logs", exist_ok=True)
    df_log = pd.DataFrame([{
        "timestamp": datetime.utcnow().isoformat(),
        "url": url_input,
        "domain": domain,
        "prediction": pred,
        "probability": prob,
        "final_score": final_score
    }])

    log_path = "logs/scans.csv"
    df_log.to_csv(log_path, mode='a', header=not os.path.exists(log_path), index=False)

    # ML Explainability
    try:
        importances = model.feature_importances_
        vocab = np.array(vec.get_feature_names_out())
        top_idx = importances.argsort()[-15:][::-1]
        st.subheader("🔍 Top Contributing Features")
        st.dataframe(pd.DataFrame({
            "feature": vocab[top_idx],
            "importance": importances[top_idx]
        }))
    except:
        st.info("Explainability unavailable for this model type.")
