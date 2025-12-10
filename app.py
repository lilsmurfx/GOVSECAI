import streamlit as st

st.set_page_config(
    page_title="GovSec AI – Cybersecurity Intelligence",
    page_icon="🇰🇪",
    layout="wide"
)

# --- HERO SECTION ---
st.markdown(
    """
    <div style="padding:60px 20px; text-align:center;">
        <h1 style="font-size:3rem; font-weight:700; margin-bottom:10px;">
            🇰🇪 GovSec AI
        </h1>
        <p style="font-size:1.3rem; color:#555; max-width:750px; margin:auto;">
            AI-powered cyber threat detection and intelligence built to protect
            Kenya’s digital public services from phishing, impersonation attacks,
            and online fraud.
        </p>
    </div>
    """,
    unsafe_allow_html=True
)

# Divider
st.markdown("---")

# --- FEATURES SECTION ---
st.subheader("🔐 What GovSec AI Does")
st.markdown(
    """
    <div style="font-size:1.1rem;">
        <ul>
            <li><b>Real-time phishing detection</b> using machine learning models trained on Kenyan threat patterns.</li>
            <li><b>Impersonation monitoring</b> for fake eCitizen, KRA, NTSA, NHIF, and county websites.</li>
            <li><b>WHOIS & domain intelligence</b> to detect newly created malicious domains.</li>
            <li><b>Threat feed integration</b> powered by OpenPhish & community signals.</li>
            <li><b>Explainability engine</b> showing why a URL is marked suspicious.</li>
        </ul>
    </div>
    """,
    unsafe_allow_html=True
)

# --- VISUAL CALLOUT ----
st.markdown(
    """
    <div style="padding:40px; margin-top:20px; border-radius:12px; 
                background:linear-gradient(135deg, #e8f5e9, #e3f2fd);">
        <h3 style="text-align:center; font-size:1.8rem;">
            “Securing Kenya’s digital future using Artificial Intelligence.”
        </h3>
    </div>
    """,
    unsafe_allow_html=True
)

st.markdown(" ")

# --- CTA BUTTON ---
st.markdown("### 🚀 Get Started")
start = st.button("Open Threat Analyzer")
if start:
    st.switch_page("pages/1_Analyzer.py")

# --- FOOTER ---
st.markdown("---")
st.caption("GovSec AI • Developed for the AI for National Prosperity Challenge • © 2025")
