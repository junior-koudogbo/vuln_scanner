#!/usr/bin/env python3
"""
Script d'initialisation de la base de données
"""
from api.database import init_db

if __name__ == "__main__":
    print("Initialisation de la base de données...")
    init_db()
    print("Base de données initialisée avec succès!")

