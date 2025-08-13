#!/bin/bash

echo "🔧 [1/5] Mise à jour des paquets..."
sudo apt update

echo "📦 [2/5] Installation de python3.12-venv si nécessaire..."
sudo apt install -y python3.12-venv

echo "🐍 [3/5] Création de l'environnement virtuel..."
python3 -m venv venv

echo "✅ [4/5] Activation de l'environnement virtuel et installation des dépendances..."
source venv/bin/activate
pip install --upgrade pip
pip install streamlit requests pandas

echo "🚀 [5/5] Lancement de l'application Streamlit..."
streamlit run main.py
