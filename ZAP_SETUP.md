# 🕷️ Configuration OWASP ZAP

## Installation et démarrage de ZAP

OWASP ZAP peut être utilisé pour des scans actifs plus poussés (Spider + Active Scan).

### Option 1 : Avec Docker (Recommandé)

Ajoutez ce service à votre `docker-compose.yml` :

```yaml
  zap:
    image: owasp/zap2docker-stable:latest
    ports:
      - "8080:8080"
    command: zap.sh -daemon -host 0.0.0.0 -port 8080 -config api.disablekey=true
```

Puis démarrez :
```bash
docker-compose up -d zap
```

### Option 2 : Installation locale

**Sur Linux :**
```bash
# Télécharger ZAP
wget https://github.com/zaproxy/zaproxy/releases/latest/download/ZAP_2.14.0_Linux.tar.gz
tar -xzf ZAP_2.14.0_Linux.tar.gz
cd ZAP_2.14.0

# Démarrer ZAP en mode daemon
./zap.sh -daemon -host 0.0.0.0 -port 8080 -config api.disablekey=true
```

**Sur macOS :**
```bash
brew install --cask owasp-zap
# Puis démarrer ZAP et configurer l'API
```

**Sur Windows :**
Téléchargez depuis https://www.zaproxy.org/download/

### Vérification

Vérifiez que ZAP est accessible :
```bash
curl http://localhost:8080/JSON/core/view/version
```

Vous devriez voir une réponse JSON avec la version de ZAP.

## Configuration

Le scanner détecte automatiquement ZAP sur `http://localhost:8080`.

Pour utiliser une URL différente, définissez la variable d'environnement :
```bash
export ZAP_PROXY_URL=http://localhost:8080
export ZAP_API_KEY=votre_cle_api  # Optionnel si api.disablekey=true
```

## Utilisation

Une fois ZAP démarré, les scans complets incluront automatiquement :
- **Spider** : Crawl du site pour découvrir toutes les pages
- **Active Scan** : Tests de sécurité actifs (XSS, SQLi, etc.)

Les résultats ZAP seront fusionnés avec les résultats des autres scanners dans le rapport.

## Notes

- Les scans ZAP peuvent prendre plusieurs minutes selon la taille du site
- ZAP est optionnel : l'application fonctionne sans lui, mais les scans seront moins complets
- Pour testfire.net, ZAP devrait détecter les vulnérabilités XSS et SQLi dans les formulaires

