# 🔧 Guide de dépannage

## Erreur : ERR_CONNECTION_REFUSED / ERR_SOCKET_NOT_CONNECTED

Cette erreur signifie que le frontend ne peut pas se connecter au backend. Voici comment résoudre le problème :

### 1. Vérifier que le backend est démarré

**Option A : Avec Docker**
```bash
docker-compose up
```

**Option B : Installation manuelle**
```bash
# Dans le répertoire racine du projet
python3 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
python3 init_db.py
uvicorn api.main:app --reload
```

### 2. Vérifier que l'API répond

Ouvrez votre navigateur et allez sur :
- http://localhost:8000/ (devrait afficher les informations de l'API)
- http://localhost:8000/docs (documentation Swagger de l'API)
- http://localhost:8000/api/scans (devrait retourner une liste vide `[]`)

### 3. Vérifier les ports

- **Backend** : doit être sur le port **8000**
- **Frontend** : doit être sur le port **3000**

Si un port est déjà utilisé :
```bash
# Vérifier quel processus utilise le port 8000
lsof -i :8000  # Linux/Mac
netstat -ano | findstr :8000  # Windows

# Tuer le processus si nécessaire
kill -9 <PID>  # Linux/Mac
```

### 4. Vérifier les logs du backend

Si le backend est démarré mais ne répond pas, vérifiez les logs pour voir les erreurs :
```bash
# Avec Docker
docker-compose logs api

# Installation manuelle
# Les logs s'affichent dans le terminal où vous avez lancé uvicorn
```

### 5. Problèmes courants

#### Base de données non initialisée
```bash
python3 init_db.py
```

#### Port déjà utilisé
Changez le port dans `api/main.py` :
```python
uvicorn.run(app, host="0.0.0.0", port=8001)  # Utiliser 8001 au lieu de 8000
```

Et mettez à jour `API_URL` dans le frontend ou utilisez une variable d'environnement :
```bash
REACT_APP_API_URL=http://localhost:8001 npm start
```

#### CORS errors
Le backend a déjà CORS configuré pour accepter toutes les origines. Si vous avez encore des problèmes, vérifiez `api/main.py`.

### 6. Tester la connexion manuellement

```bash
# Test avec curl
curl http://localhost:8000/api/scans

# Devrait retourner : []
```

### 7. Redémarrer proprement

```bash
# Arrêter tous les processus
# Ctrl+C dans les terminaux où tournent les serveurs

# Avec Docker
docker-compose down

# Relancer
docker-compose up --build
```

## Erreur : ModuleNotFoundError

Si vous obtenez des erreurs de modules Python manquants :
```bash
pip install -r requirements.txt
```

## Erreur : Database locked

Si vous obtenez une erreur de base de données verrouillée :
```bash
# Supprimer la base de données et la recréer
rm vuln_scanner.db
python3 init_db.py
```

## Le frontend affiche "API non disponible"

1. Vérifiez que le backend est bien démarré (voir étape 1)
2. Vérifiez que vous pouvez accéder à http://localhost:8000 dans votre navigateur
3. Vérifiez la console du navigateur pour les erreurs détaillées
4. Le frontend devrait automatiquement détecter quand l'API redevient disponible

