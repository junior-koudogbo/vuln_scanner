# 🚀 Guide de démarrage rapide

## Installation rapide

### Option 1 : Avec Docker (Recommandé)

```bash
# Construire et lancer
docker-compose up --build

# L'application sera accessible sur:
# - Frontend: http://localhost:3000
# - API: http://localhost:8000
# - Docs API: http://localhost:8000/docs
```

### Option 2 : Installation manuelle

1. **Backend**
```bash
# Créer l'environnement virtuel
python3 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Installer les dépendances
pip install -r requirements.txt

# Initialiser la base de données
python3 init_db.py

# Lancer l'API
uvicorn api.main:app --reload
```

2. **Frontend** (dans un nouveau terminal)
```bash
cd frontend
npm install
npm start
```

## Prérequis système

- **Nmap** : `sudo apt-get install nmap` (Ubuntu/Debian) ou `brew install nmap` (macOS)
- **Nikto** (optionnel) : `sudo apt-get install nikto` ou `brew install nikto`

## Première utilisation

1. Ouvrir http://localhost:3000 dans votre navigateur
2. Entrer une URL cible (ex: `https://example.com`)
3. Choisir le type de scan (Rapide ou Complet)
4. Cliquer sur "Lancer le scan"
5. Attendre la fin du scan (peut prendre quelques minutes)
6. Consulter les résultats et générer le rapport HTML

## URLs de test recommandées

Pour tester l'application en toute sécurité :
- http://testphp.vulnweb.com
- http://testfire.net
- Votre propre application de test

⚠️ **Important** : N'utilisez cette application que sur des systèmes pour lesquels vous avez l'autorisation explicite.

## Dépannage

### Erreur "Nmap not found"
Installez Nmap : `sudo apt-get install nmap` ou `brew install nmap`

### Erreur de permissions Nmap
Certains scans Nmap nécessitent des privilèges root. Le scanner utilisera une méthode alternative si nécessaire.

### Le frontend ne se connecte pas à l'API
Vérifiez que l'API est bien lancée sur le port 8000 et que le proxy dans `package.json` est correctement configuré.

### Erreur de base de données
Exécutez `python3 init_db.py` pour réinitialiser la base de données.

