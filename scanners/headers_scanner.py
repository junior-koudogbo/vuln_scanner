import requests
from urllib.parse import urlparse


class HeadersScanner:
    def __init__(self):
        self.security_headers = {
            'X-Content-Type-Options': {
                'required': True,
                'expected': 'nosniff',
                'description': 'Le header X-Content-Type-Options manque ou est mal configuré',
                'severity': 'low',
                'cvss_score': 3.0,
                'recommendation': 'Ajouter le header: X-Content-Type-Options: nosniff pour prévenir le MIME-sniffing'
            },
            'X-Frame-Options': {
                'required': True,
                'expected': ['DENY', 'SAMEORIGIN'],
                'description': 'Le header X-Frame-Options manque, permettant potentiellement le clickjacking',
                'severity': 'low',
                'cvss_score': 3.5,
                'recommendation': 'Ajouter le header: X-Frame-Options: DENY ou SAMEORIGIN pour prévenir le clickjacking'
            },
            'X-XSS-Protection': {
                'required': False,
                'expected': '1; mode=block',
                'description': 'Le header X-XSS-Protection manque (obsolète mais encore utilisé)',
                'severity': 'low',
                'cvss_score': 3.1,
                'recommendation': 'Ajouter le header: X-XSS-Protection: 1; mode=block (ou utiliser CSP)'
            },
            'Strict-Transport-Security': {
                'required': True,
                'expected': 'max-age=',
                'description': 'Le header HSTS (Strict-Transport-Security) manque',
                'severity': 'medium',
                'cvss_score': 5.0,
                'recommendation': 'Ajouter le header: Strict-Transport-Security: max-age=31536000; includeSubDomains. Important pour forcer HTTPS et prévenir les attaques man-in-the-middle.'
            },
            'Content-Security-Policy': {
                'required': True,
                'expected': None,
                'description': 'Le header Content-Security-Policy manque',
                'severity': 'medium',
                'cvss_score': 4.5,
                'recommendation': 'Ajouter un Content-Security-Policy approprié pour votre application. C\'est une best practice de sécurité qui aide à prévenir les attaques XSS.'
            },
            'Referrer-Policy': {
                'required': False,
                'expected': None,
                'description': 'Le header Referrer-Policy manque',
                'severity': 'low',
                'cvss_score': 2.5,
                'recommendation': 'Ajouter le header: Referrer-Policy: strict-origin-when-cross-origin'
            },
            'Permissions-Policy': {
                'required': False,
                'expected': None,
                'description': 'Le header Permissions-Policy manque',
                'severity': 'low',
                'cvss_score': 3.0,
                'recommendation': 'Ajouter un Permissions-Policy pour restreindre les fonctionnalités du navigateur'
            }
        }

    def scan(self, target_url: str):
        """Scanner les headers de sécurité"""
        try:
            print(f"[*] Scan des headers de sécurité pour {target_url}...")
            
            # Faire une requête HEAD ou GET
            response = requests.get(target_url, timeout=10, allow_redirects=True, verify=False)
            headers = response.headers
            
            missing_headers = []
            
            for header_name, header_config in self.security_headers.items():
                header_value = headers.get(header_name)
                
                if header_config['required'] and not header_value:
                    # Header requis manquant
                    missing_headers.append({
                        'header': header_name,
                        'description': header_config['description'],
                        'severity': header_config['severity'],
                        'cvss_score': header_config['cvss_score'],
                        'recommendation': header_config['recommendation'],
                        'found': False
                    })
                elif header_value and header_config['expected']:
                    # Vérifier si la valeur est correcte
                    if isinstance(header_config['expected'], list):
                        if header_value not in header_config['expected']:
                            missing_headers.append({
                                'header': header_name,
                                'description': f"{header_config['description']} (valeur actuelle: {header_value})",
                                'severity': header_config['severity'],
                                'cvss_score': header_config['cvss_score'],
                                'recommendation': header_config['recommendation'],
                                'found': True,
                                'current_value': header_value
                            })
                    elif isinstance(header_config['expected'], str):
                        if header_config['expected'] not in header_value:
                            missing_headers.append({
                                'header': header_name,
                                'description': f"{header_config['description']} (valeur actuelle: {header_value})",
                                'severity': header_config['severity'],
                                'cvss_score': header_config['cvss_score'],
                                'recommendation': header_config['recommendation'],
                                'found': True,
                                'current_value': header_value
                            })
            
            return missing_headers
        except requests.exceptions.RequestException as e:
            print(f"Erreur lors du scan des headers: {e}")
            return []
        except Exception as e:
            print(f"Erreur inattendue: {e}")
            return []

