import requests
from bs4 import BeautifulSoup
import re


class VersionScanner:
    def __init__(self):
        self.version_patterns = {
            'apache': [
                r'Apache/([\d.]+)',
                r'Server:\s*Apache/([\d.]+)',
            ],
            'nginx': [
                r'nginx/([\d.]+)',
                r'Server:\s*nginx/([\d.]+)',
            ],
            'php': [
                r'PHP/([\d.]+)',
                r'X-Powered-By:\s*PHP/([\d.]+)',
            ],
            'iis': [
                r'Microsoft-IIS/([\d.]+)',
                r'Server:\s*Microsoft-IIS/([\d.]+)',
            ],
            'wordpress': [
                r'wp-content/themes',
                r'WordPress ([\d.]+)',
            ],
        }
        
        self.vulnerable_versions = {
            'apache': {
                '2.4.49': {'severity': 'critical', 'cvss': 9.8, 'description': 'Apache 2.4.49 - Path Traversal (CVE-2021-41773)'},
                '2.4.50': {'severity': 'critical', 'cvss': 9.8, 'description': 'Apache 2.4.50 - Path Traversal (CVE-2021-42013)'},
            },
            'nginx': {
                '1.18.0': {'severity': 'high', 'cvss': 7.5, 'description': 'Nginx versions < 1.20.0 peuvent avoir des vulnérabilités'},
            },
            'php': {
                '7.4.0': {'severity': 'medium', 'cvss': 6.0, 'description': 'PHP < 7.4.33 peut avoir des vulnérabilités'},
                '8.0.0': {'severity': 'medium', 'cvss': 6.0, 'description': 'PHP < 8.0.30 peut avoir des vulnérabilités'},
            },
        }

    def scan(self, target_url: str):
        """Scanner les versions logicielles vulnérables"""
        try:
            print(f"[*] Scan des versions pour {target_url}...")
            
            response = requests.get(target_url, timeout=10, allow_redirects=True)
            headers = response.headers
            html_content = response.text
            
            detected_versions = []
            
            # Scanner les headers HTTP
            for software, patterns in self.version_patterns.items():
                for pattern in patterns:
                    # Chercher dans les headers
                    for header_name, header_value in headers.items():
                        match = re.search(pattern, header_value, re.IGNORECASE)
                        if match:
                            version = match.group(1) if match.groups() else 'detected'
                            detected_versions.append({
                                'software': software,
                                'version': version,
                                'source': f'header: {header_name}',
                                'raw_value': header_value
                            })
                            break
                    
                    # Chercher dans le HTML
                    match = re.search(pattern, html_content, re.IGNORECASE)
                    if match:
                        version = match.group(1) if match.groups() else 'detected'
                        detected_versions.append({
                            'software': software,
                            'version': version,
                            'source': 'html',
                            'raw_value': match.group(0)
                        })
            
            # Vérifier si les versions détectées sont vulnérables
            vulnerabilities = []
            for detected in detected_versions:
                software = detected['software']
                version = detected['version']
                
                if software in self.vulnerable_versions:
                    for vuln_version, vuln_info in self.vulnerable_versions[software].items():
                        if self._is_version_vulnerable(version, vuln_version):
                            vulnerabilities.append({
                                'software': software,
                                'version': version,
                                'description': f"{vuln_info['description']} (Version détectée: {version})",
                                'severity': vuln_info['severity'],
                                'cvss_score': vuln_info['cvss'],
                                'source': detected['source']
                            })
                            break
                
                # Vérifier aussi les versions très anciennes
                if self._is_old_version(software, version):
                    vulnerabilities.append({
                        'software': software,
                        'version': version,
                        'description': f"Version ancienne de {software} détectée ({version}). Il est recommandé de mettre à jour vers la dernière version sécurisée.",
                        'severity': 'medium',
                        'cvss_score': 5.0,
                        'source': detected['source']
                    })
            
            return vulnerabilities
        except Exception as e:
            print(f"Erreur lors du scan de versions: {e}")
            return []

    def _is_version_vulnerable(self, detected_version: str, vulnerable_version: str) -> bool:
        """Vérifier si la version détectée correspond à une version vulnérable"""
        try:
            # Comparaison simple de versions
            detected_parts = [int(x) for x in detected_version.split('.')]
            vuln_parts = [int(x) for x in vulnerable_version.split('.')]
            
            # Vérifier si la version détectée est <= à la version vulnérable
            for i in range(min(len(detected_parts), len(vuln_parts))):
                if detected_parts[i] < vuln_parts[i]:
                    return True
                elif detected_parts[i] > vuln_parts[i]:
                    return False
            
            # Si les versions sont identiques jusqu'à la longueur la plus courte
            if len(detected_parts) <= len(vuln_parts):
                return True
            
            return False
        except:
            # Si la comparaison échoue, considérer comme potentiellement vulnérable
            return detected_version == vulnerable_version

    def _is_old_version(self, software: str, version: str) -> bool:
        """Vérifier si la version est ancienne"""
        try:
            version_parts = [int(x) for x in version.split('.')]
            
            # Versions minimales recommandées
            min_versions = {
                'apache': [2, 4, 50],
                'nginx': [1, 20, 0],
                'php': [8, 1, 0],
            }
            
            if software in min_versions:
                min_version = min_versions[software]
                for i in range(min(len(version_parts), len(min_version))):
                    if version_parts[i] < min_version[i]:
                        return True
                    elif version_parts[i] > min_version[i]:
                        return False
            
            return False
        except:
            return False

