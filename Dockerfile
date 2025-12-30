FROM python:3.11-slim

# Installer les dépendances système nécessaires
RUN apt-get update && apt-get install -y \
    nmap \
    curl \
    wget \
    unzip \
    perl \
    libwww-perl \
    libnet-ssleay-perl \
    && rm -rf /var/lib/apt/lists/*

# Installer Nikto depuis GitHub (optionnel - le scanner fonctionne sans)
RUN mkdir -p /opt/nikto && \
    wget -q https://github.com/sullo/nikto/archive/master.zip -O /tmp/nikto.zip && \
    unzip -q /tmp/nikto.zip -d /opt/ && \
    mv /opt/nikto-master /opt/nikto && \
    rm /tmp/nikto.zip && \
    chmod +x /opt/nikto/program/nikto.pl && \
    (ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto 2>/dev/null || true)

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

