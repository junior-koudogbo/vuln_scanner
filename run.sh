#!/bin/bash

# Script de démarrage de l'application

echo "🛡️  Démarrage de la plateforme de scan de vulnérabilités"
echo ""

# Vérifier si Python est installé
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 n'est pas installé"
    exit 1
fi

# Vérifier si les dépendances sont installées
if [ ! -d "venv" ]; then
    echo "📦 Création de l'environnement virtuel..."
    python3 -m venv venv
fi

echo "🔧 Activation de l'environnement virtuel..."
source venv/bin/activate

echo "📥 Installation des dépendances Python..."
pip install -r requirements.txt

echo "🗄️  Initialisation de la base de données..."
python3 init_db.py

echo ""
echo "✅ Configuration terminée!"
echo ""
echo "Pour démarrer l'API:"
echo "  uvicorn api.main:app --reload"
echo ""
echo "Pour démarrer le frontend (dans un autre terminal):"
echo "  cd frontend && npm install && npm start"
echo ""

