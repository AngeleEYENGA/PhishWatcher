# main.py

import re
import requests
import csv
import streamlit as st
import pandas as pd
import tempfile

# === CONFIGURATION ===
VIRUSTOTAL_API_KEY = 'b77fd74596e93a2a6bfc8e5ecc72bcc1f1856fe916068f5af22da95f51fec106'
VT_URL = 'https://www.virustotal.com/api/v3/urls'

# === ANALYSE DE L'URL ===
def check_suspicious_patterns(url):
    score = 0
    reasons = []

    if '@' in url:
        score += 1
        reasons.append("Présence de '@' (tentative de redirection)")
    if re.search(r"(login|secure|account|update|verify)", url, re.I):
        score += 1
        reasons.append("Mots-clés sensibles dans l’URL")
    if re.search(r"(micros0ft|paypa1|g00gle)", url, re.I):
        score += 2
        reasons.append("Faux domaine connu (typosquatting)")
    if url.count('.') > 3:
        score += 1
        reasons.append("Nom de domaine très long")

    return score, reasons

def scan_virustotal(url):
    headers = { "x-apikey": VIRUSTOTAL_API_KEY }
    data = { "url": url }

    try:
        response = requests.post(VT_URL, headers=headers, data=data)
        if response.status_code != 200:
            return 0
        analysis_id = response.json()['data']['id']
        get_url = f"{VT_URL}/{analysis_id}"
        result = requests.get(get_url, headers=headers)
        stats = result.json()['data']['attributes']['last_analysis_stats']
        return stats['malicious'] + stats['suspicious']
    except:
        return 0

def analyser_url(url):
    local_score, reasons = check_suspicious_patterns(url)
    vt_score = scan_virustotal(url)
    total_score = local_score + vt_score

    if total_score < 3:
        niveau = "🟢 Risque faible"
    elif total_score < 5:
        niveau = "🟠 Risque modéré"
    else:
        niveau = "🔴 Risque élevé"

    return {
        "URL": url,
        "Score local": local_score,
        "Détections VirusTotal": vt_score,
        "Score total": total_score,
        "Niveau de risque": niveau,
        "Motifs détectés": " | ".join(reasons)
    }

# === INTERFACE STREAMLIT ===
st.set_page_config(page_title="PhishWatcher", layout="centered")
st.title("🛡️ PhishWatcher – Détection de phishing")
st.write("Analyse de liens suspects – URL unique ou liste depuis un fichier")

mode = st.radio("Choisir le mode :", ["URL unique", "Fichier d’URLs"])

resultats = []

if mode == "URL unique":
    url = st.text_input("🔗 Entre l’URL à analyser")
    if st.button("Analyser"):
        if url:
            with st.spinner("Analyse en cours..."):
                res = analyser_url(url)
                df = pd.DataFrame([res])
                st.success("Analyse terminée")
                st.dataframe(df)
                resultats.append(res)
        else:
            st.warning("Merci de saisir une URL.")

elif mode == "Fichier d’URLs":
    fichier = st.file_uploader("📄 Upload un fichier .txt", type="txt")
    if fichier:
        lignes = fichier.read().decode().splitlines()
        lignes = [l.strip() for l in lignes if l.strip()]
        if st.button("Analyser le fichier"):
            with st.spinner("Analyse en cours..."):
                for url in lignes:
                    res = analyser_url(url)
                    resultats.append(res)
                df = pd.DataFrame(resultats)
                st.success("Analyse terminée")
                st.dataframe(df)

# === EXPORT CSV ===
if resultats:
    df = pd.DataFrame(resultats)
    csv_file = df.to_csv(index=False).encode('utf-8')
    st.download_button("⬇️ Télécharger le rapport CSV", data=csv_file, file_name="rapport_phishing.csv", mime="text/csv")
