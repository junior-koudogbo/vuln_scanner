# 🛡️ Plateforme de Scan & Analyse de Vulnérabilités

Vuln_scanner est une application web complète pour le scan et l'analyse automatique de vulnérabilités web, conçue pour développer mes compétences en cybersécurité offensive et défensive, ainsi qu'en DevSecOps.

## 🎯 Fonctionnalités

- **Scan automatique de vulnérabilités** : Détection de multiples types de vulnérabilités
- **Rapports détaillés** : Génération de rapports HTML avec scores CVSS
- **Interface moderne** : Frontend React avec une UX soignée
- **API RESTful** : Backend FastAPI pour l'intégration facile
- **Base de données** : Stockage des scans et vulnérabilités dans SQLite

## 🔎 Vulnérabilités détectées

- **Ports ouverts** : Détection des ports ouverts via Nmap
- **Headers de sécurité manquants** : Vérification des headers HTTP de sécurité
- **XSS (Cross-Site Scripting)** : Détection de vulnérabilités XSS
- **SQL Injection** : Détection de vulnérabilités SQLi
- **Versions logicielles vulnérables** : Identification des versions obsolètes

## 🧱 Stack technique

### Backend
- **Python 3.11+**
- **FastAPI** : Framework web moderne et performant
- **SQLAlchemy** : ORM pour la gestion de base de données
- **SQLite** : Base de données légère

### Outils de scan
- **Nmap** : Scan de ports et services
- **Nikto** : Scanner de vulnérabilités web
- **Scanners personnalisés** : XSS, SQLi, Headers, Versions

### Frontend
- **React 18** : Framework JavaScript moderne
- **Axios** : Client HTTP pour les appels API
- **CSS moderne** : Interface responsive et élégante

### Infrastructure
- **Docker** : Containerisation de l'application
- **Docker Compose** : Orchestration multi-conteneurs

## 📁 Structure du projet

```
vuln_scanner/
├── api/                    # Backend FastAPI
│   ├── __init__.py
│   ├── main.py            # Point d'entrée de l'API
│   └── database.py        # Modèles et configuration DB
├── scanners/               # Modules de scan
│   ├── __init__.py
│   ├── scanner_manager.py # Gestionnaire principal
│   ├── nmap_scanner.py    # Scanner Nmap
│   ├── nikto_scanner.py   # Scanner Nikto
│   ├── headers_scanner.py # Scanner des headers
│   ├── xss_scanner.py     # Scanner XSS
│   ├── sqli_scanner.py    # Scanner SQLi
│   └── version_scanner.py # Scanner de versions
├── reports/                # Génération de rapports
│   ├── __init__.py
│   └── report_generator.py # Générateur de rapports HTML
├── frontend/               # Application React
│   ├── public/
│   ├── src/
│   │   ├── components/    # Composants React
│   │   ├── App.js
│   │   └── index.js
│   ├── package.json
│   └── Dockerfile
├── Dockerfile              # Dockerfile pour l'API
├── docker-compose.yml     # Configuration Docker Compose
├── requirements.txt       # Dépendances Python
└── README.md
```

## 🚀 Installation et utilisation

### Prérequis

- Python 3.11+
- Node.js 18+
- Docker et Docker Compose (optionnel)
- Nmap installé sur le système
- Nikto installé (optionnel, le scan fonctionnera sans)

### Installation manuelle

1. **Cloner le repository**
```bash
git clone <repository-url>
cd vuln_scanner
```

2. **Installer les dépendances Python**
```bash
python -m venv venv
source venv/bin/activate  # Sur Windows: venv\Scripts\activate
pip install -r requirements.txt
```

3. **Installer les dépendances frontend**
```bash
cd frontend
npm install
cd ..
```

4. **Installer les outils système**
```bash
# Sur Ubuntu/Debian
sudo apt-get update
sudo apt-get install nmap nikto

# Sur macOS
brew install nmap nikto
```

### Lancement

1. **Démarrer l'API backend**
```bash
# Depuis la racine du projet
uvicorn api.main:app --reload
```

L'API sera accessible sur `http://localhost:8000`

2. **Démarrer le frontend**
```bash
cd frontend
npm start
```

Le frontend sera accessible sur `http://localhost:3000`

### Utilisation avec Docker

1. **Construire et lancer les conteneurs**
```bash
docker-compose up --build
```

2. **Accéder à l'application**
- Frontend : http://localhost:3000
- API : http://localhost:8000
- Documentation API : http://localhost:8000/docs

## 📖 Utilisation

1. **Créer un scan**
   - Entrer l'URL cible dans le formulaire
   - Choisir le type de scan (Rapide ou Complet)
   - Cliquer sur "Lancer le scan"

2. **Consulter les résultats**
   - La liste des scans s'affiche automatiquement
   - Cliquer sur un scan pour voir les détails
   - Les vulnérabilités sont classées par sévérité

3. **Générer un rapport HTML**
   - Dans les détails d'un scan, cliquer sur "Voir le rapport HTML"
   - Le rapport contient toutes les vulnérabilités avec recommandations

## 🔌 API Endpoints

### `GET /`
Informations sur l'API

### `POST /api/scans`
Créer un nouveau scan
```json
{
  "target_url": "https://example.com",
  "scan_type": "full"
}
```

### `GET /api/scans`
Liste tous les scans

### `GET /api/scans/{scan_id}`
Détails d'un scan avec ses vulnérabilités

### `GET /api/scans/{scan_id}/report`
Rapport HTML d'un scan

## 📊 Types de scan

- **Rapide (quick)** : Scan des headers de sécurité et ports ouverts
- **Complet (full)** : Tous les scanners (XSS, SQLi, Headers, Ports, Versions, Nikto)

## 🛡️ Sécurité

⚠️ **Important** : Cette application est conçue pour des tests de sécurité autorisés uniquement. Ne l'utilisez que sur des systèmes pour lesquels vous avez l'autorisation explicite.

## 🧪 Tests

Pour tester l'application, vous pouvez utiliser des cibles de test comme :
- http://testphp.vulnweb.com
- http://testfire.net
- Votre propre application de test

## 📝 Notes

- Les scans peuvent prendre plusieurs minutes selon le type choisi
- Nmap nécessite des privilèges élevés pour certains scans (utiliser `sudo` si nécessaire)
- Nikto est optionnel mais recommandé pour des scans plus complets

## 🔧 Configuration

Les paramètres peuvent être modifiés dans :
- `api/database.py` : Configuration de la base de données
- `scanners/*.py` : Paramètres des scanners individuels
- `api/main.py` : Configuration de l'API

## 📄 Licence

Ce projet est un projet personnel.

## 👤 Auteur

Junior Koudogbo.

## 🚀 Améliorations futures

- Intégration OWASP ZAP API
- Support de l'authentification
- Export PDF des rapports
- Planification de scans récurrents
- Dashboard avec statistiques
- Intégration CI/CD

