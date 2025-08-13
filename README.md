# 🛡️ PhishWatcher – Détection et Analyse de Phishing

PhishWatcher est un outil développé en **Python** pour détecter, analyser et classifier les tentatives de phishing, qu’il s’agisse d’**URLs frauduleuses** ou d’**emails suspects**.  
Ce projet combine des techniques de **cybersécurité** et d’**apprentissage automatique** pour aider les particuliers, entreprises et institutions financières à protéger leurs utilisateurs.

## 🚀 Fonctionnalités principales
- **Analyse d’URL** : détection de liens potentiellement frauduleux (phishing, scam…).
- **Analyse d’email** : inspection du contenu textuel pour repérer des indicateurs de phishing.
- **Machine Learning** : modèle pré-entraîné pour la classification des menaces.
- **Interface utilisateur simple** via Streamlit (version web possible).
- **Export des résultats** au format CSV pour archivage ou intégration dans un SIEM.

## 🛠️ Technologies utilisées
- **Python 3.x**
- **Pandas** & **NumPy** – manipulation et traitement des données
- **Scikit-learn** – classification et entraînement du modèle
- **NLTK / regex** – nettoyage et analyse du texte
- **Streamlit** – interface utilisateur
- **VirusTotal API** *(optionnel)* – analyse des URLs via une base externe

## 📂 Structure du projet
