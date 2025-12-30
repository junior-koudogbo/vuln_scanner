#!/bin/bash

# Script pour démarrer le backend

echo "🛡️  Démarrage du backend Vulnerability Scanner"
echo ""

# Vérifier si Python est installé
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 n'est pas installé"
    exit 1
fi

# Activer l'environnement virtuel s'il existe
if [ -d "venv" ]; then
    echo "🔧 Activation de l'environnement virtuel..."
    source venv/bin/activate
else
    echo "📦 Création de l'environnement virtuel..."
    python3 -m venv venv
    source venv/bin/activate
    echo "📥 Installation des dépendances..."
    pip install -r requirements.txt
fi

# Vérifier si la base de données existe
if [ ! -f "vuln_scanner.db" ]; then
    echo "🗄️  Initialisation de la base de données..."
    python3 init_db.py
fi

echo ""
echo "✅ Démarrage de l'API sur http://localhost:8000"
echo "📖 Documentation: http://localhost:8000/docs"
echo ""
echo "Appuyez sur Ctrl+C pour arrêter le serveur"
echo ""

# Démarrer l'API
uvicorn api.main:app --host 0.0.0.0 --port 8000 --reload

