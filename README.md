#  Plateforme de Scan & Analyse de Vulnérabilités

Vuln_scanner est une application web complète pour le scan et l'analyse automatique de vulnérabilités web, conçue pour développer mes compétences en cybersécurité offensive et défensive, ainsi qu'en DevSecOps.

##  Fonctionnalités

- **Scan automatique de vulnérabilités** : Détection de multiples types de vulnérabilités
- **Rapports détaillés** : Génération de rapports HTML avec scores CVSS et statistiques
- **Interface moderne** : Frontend React avec une UX soignée
- **API RESTful** : Backend FastAPI pour l'intégration facile
- **Base de données** : Stockage des scans et vulnérabilités dans SQLite
- **Intégration OWASP ZAP** : Scans actifs avancés (Spider + Active Scan)

##  Vulnérabilités détectées

- **Ports ouverts** : Détection des ports ouverts via Nmap (avec contextualisation des risques)
- **Headers de sécurité manquants** : Vérification des headers HTTP de sécurité (CSP, HSTS, X-Frame-Options, etc.)
- **XSS (Cross-Site Scripting)** : Détection de vulnérabilités XSS dans les formulaires et champs de recherche
- **SQL Injection** : Détection de vulnérabilités SQLi dans les formulaires
- **Versions logicielles vulnérables** : Identification des versions obsolètes via Nikto
- **Vulnérabilités ZAP** : Détection avancée via OWASP ZAP (Spider + Active Scan)

##  Stack technique

### Backend
- **Python 3.11+**
- **FastAPI** : Framework web moderne et performant
- **SQLAlchemy** : ORM pour la gestion de base de données
- **SQLite** : Base de données légère

### Outils de scan
- **Nmap** : Scan de ports et services
- **Nikto** : Scanner de vulnérabilités web
- **OWASP ZAP** : Scanner de sécurité web avancé (optionnel)
- **Scanners personnalisés** : XSS, SQLi, Headers, Versions

### Frontend
- **React 18** : Framework JavaScript moderne
- **Axios** : Client HTTP pour les appels API
- **CSS moderne** : Interface responsive et élégante

### Infrastructure
- **Docker** : Containerisation de l'application
- **Docker Compose** : Orchestration multi-conteneurs (API + Frontend + ZAP)

##  Structure du projet

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
│   ├── zap_scanner.py     # Scanner OWASP ZAP
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
├── init_db.py            # Script d'initialisation de la DB
└── README.md
```

##  Installation et démarrage

### Prérequis

- Python 3.11+
- Node.js 18+
- Docker et Docker Compose (optionnel mais recommandé)
- Nmap installé sur le système
- Nikto installé (optionnel, le scan fonctionnera sans)
- OWASP ZAP (optionnel, intégré dans Docker Compose)

### Option 1 : Avec Docker (Recommandé)

```bash
# Cloner le repository
git clone <https://github.com/junior-koudogbo/vuln_scanner.git>
cd vuln_scanner

# Construire et lancer tous les services (API + Frontend + ZAP)
docker-compose up --build

# L'application sera accessible sur:
# - Frontend: http://localhost:3000
# - API: http://localhost:8000
# - Docs API: http://localhost:8000/docs
# - ZAP: http://localhost:8080
```

### Option 2 : Installation manuelle

1. **Cloner le repository**
```bash
git clone <https://github.com/junior-koudogbo/vuln_scanner.git>
cd vuln_scanner
```

2. **Installer les dépendances Python**
```bash
python3 -m venv venv
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
sudo apt-get install nmap git perl libwww-perl libnet-ssleay-perl

# Installer Nikto depuis GitHub (optionnel)
git clone --depth 1 https://github.com/sullo/nikto.git /opt/nikto
chmod +x /opt/nikto/program/nikto.pl
ln -sf /opt/nikto/program/nikto.pl /usr/local/bin/nikto

# Sur macOS
brew install nmap
```

5. **Initialiser la base de données**
```bash
python3 init_db.py
```

6. **Démarrer l'API backend** (Terminal 1)
```bash
uvicorn api.main:app --reload
```

L'API sera accessible sur `http://localhost:8000`

7. **Démarrer le frontend** (Terminal 2)
```bash
cd frontend
npm start
```

Le frontend sera accessible sur `http://localhost:3000`

**Important** : Le backend doit être démarré AVANT le frontend pour éviter les erreurs de connexion.

### Configuration OWASP ZAP (Optionnel)

ZAP est automatiquement démarré avec Docker Compose. Pour une installation manuelle :

```bash
# Avec Docker
docker run -d -p 8080:8080 ghcr.io/zaproxy/zaproxy:stable \
  zap.sh -daemon -host 0.0.0.0 -port 8080 -config api.disablekey=true

# Vérifier que ZAP est accessible
curl http://localhost:8080/JSON/core/view/version
```

Pour utiliser une URL différente, définissez la variable d'environnement :
```bash
export ZAP_PROXY_URL=http://localhost:8080
export ZAP_API_KEY=votre_cle_api  # Optionnel si api.disablekey=true
```

##  Utilisation

1. **Créer un scan**
   - Ouvrir http://localhost:3000 dans votre navigateur
   - Entrer l'URL cible dans le formulaire
   - Choisir le type de scan (Rapide ou Complet)
   - Cliquer sur "Lancer le scan"

2. **Consulter les résultats**
   - La liste des scans s'affiche automatiquement
   - Cliquer sur un scan pour voir les détails
   - Les vulnérabilités sont classées par sévérité (Critique, Élevé, Moyen, Faible, Information)

3. **Générer un rapport HTML**
   - Dans les détails d'un scan, cliquer sur "Voir le rapport HTML"
   - Le rapport contient toutes les vulnérabilités avec recommandations et scores CVSS

##  Types de scan

- **Rapide (quick)** : Scan des headers de sécurité et ports ouverts
- **Complet (full)** : Tous les scanners (XSS, SQLi, Headers, Ports, Versions, Nikto, ZAP)

##  API Endpoints

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

## 🧪 Tests

Pour tester l'application, vous pouvez utiliser des cibles de test comme :
- http://testphp.vulnweb.com
- http://testfire.net
- Votre propre application de test

 **Important** : Cette application est conçue pour des tests de sécurité autorisés uniquement. Ne l'utilisez que sur des systèmes pour lesquels vous avez l'autorisation explicite.

##  Dépannage

### Erreur : ERR_CONNECTION_REFUSED / ERR_SOCKET_NOT_CONNECTED

Le frontend ne peut pas se connecter au backend. Solutions :

1. **Vérifier que le backend est démarré**
   - Avec Docker : `docker-compose up`
   - Installation manuelle : `uvicorn api.main:app --reload`

2. **Vérifier que l'API répond**
   - http://localhost:8000/ (informations de l'API)
   - http://localhost:8000/docs (documentation Swagger)
   - http://localhost:8000/api/scans (devrait retourner `[]`)

3. **Vérifier les ports**
   - Backend : port **8000**
   - Frontend : port **3000**
   - ZAP : port **8080**

4. **Vérifier les logs**
   ```bash
   # Avec Docker
   docker-compose logs api
   
   # Installation manuelle
   # Les logs s'affichent dans le terminal où uvicorn tourne
   ```

### Erreur : ModuleNotFoundError

```bash
pip install -r requirements.txt
```

### Erreur : Database locked

```bash
# Supprimer la base de données et la recréer
rm vuln_scanner.db
python3 init_db.py
```

### Erreur : Nmap not found

```bash
# Ubuntu/Debian
sudo apt-get install nmap

# macOS
brew install nmap
```

### Erreur : Port déjà utilisé

Changez le port dans `api/main.py` ou utilisez une variable d'environnement :
```bash
REACT_APP_API_URL=http://localhost:8001 npm start
```

### Le frontend affiche "API non disponible"

1. Vérifiez que le backend est bien démarré
2. Vérifiez que vous pouvez accéder à http://localhost:8000 dans votre navigateur
3. Vérifiez la console du navigateur pour les erreurs détaillées
4. Le frontend devrait automatiquement détecter quand l'API redevient disponible

##  Notes importantes

- Les scans peuvent prendre plusieurs minutes selon le type choisi
- Nmap nécessite des privilèges élevés pour certains scans (utiliser `sudo` si nécessaire)
- Nikto est optionnel mais recommandé pour des scans plus complets
- ZAP est optionnel : l'application fonctionne sans lui, mais les scans seront moins complets
- Les scans ZAP peuvent prendre plusieurs minutes selon la taille du site
- Les ports 80/443 sont classés en "Information" car ils sont normaux pour un serveur web
- Les vulnérabilités sont classées par sévérité avec scores CVSS

##  Configuration

Les paramètres peuvent être modifiés dans :
- `api/database.py` : Configuration de la base de données
- `scanners/*.py` : Paramètres des scanners individuels
- `api/main.py` : Configuration de l'API
- `docker-compose.yml` : Configuration Docker (ports, variables d'environnement)

##  Améliorations futures

- Intégration OWASP ZAP API (Déjà implémentée)
- Support de l'authentification
- Export PDF des rapports
- Planification de scans récurrents
- Dashboard avec statistiques
- Intégration CI/CD
- Support PostgreSQL en production

##  Licence

Ce projet est réalisé à titre personnel par Junior Koudogbo. Vous êtes libre de l'utiliser, le modifier et le distribuer selon vos besoins.

##  Auteur

Junior Koudogbo

Projet réalisé dans le cadre d'un apprentissage personnel de la cybersécurité offensive et défensive, ainsi que du DevSecOps.

##  Remerciements

- **OWASP** pour les outils et ressources de sécurité (ZAP, Top 10)
- **Nmap Project** pour l'outil de scan de ports
- **Nikto** pour le scanner de vulnérabilités web
- **FastAPI** et **React** pour les frameworks utilisés
- La communauté open source pour les ressources et documentations

##  Contact

Pour toute question ou suggestion concernant ce projet, n'hésitez pas à ouvrir une issue sur le [dépôt GitHub](https://github.com/junior-koudogbo/vuln_scanner).

**Note** : Ce projet est à des fins éducatives et de démonstration. Assurez-vous d'avoir l'autorisation appropriée avant d'effectuer des scans de sécurité sur des systèmes qui ne vous appartiennent pas.
