FROM python:3.11-slim

# Installer les dépendances système nécessaires
RUN apt-get update && apt-get install -y \
    nmap \
    curl \
    git \
    perl \
    libwww-perl \
    libnet-ssleay-perl \
    && rm -rf /var/lib/apt/lists/*

# Installer Nikto depuis GitHub (optionnel - le scanner fonctionne sans)
# Si l'installation échoue, l'application continuera de fonctionner
RUN (git clone --depth 1 https://github.com/sullo/nikto.git /opt/nikto && \
    chmod +x /opt/nikto/program/nikto.pl && \
    ln -sf /opt/nikto/program/nikto.pl /usr/local/bin/nikto) || echo "Nikto installation failed, continuing without it..."

WORKDIR /app

# Copier les fichiers de dépendances
COPY requirements.txt .

# Installer les dépendances Python
RUN pip install --no-cache-dir -r requirements.txt

# Copier le code de l'application
COPY . .

# Exposer le port
EXPOSE 8000

# Commande pour démarrer l'API
CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]

