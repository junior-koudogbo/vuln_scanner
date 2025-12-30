import requests
from urllib.parse import urlparse, urlencode, parse_qs
from bs4 import BeautifulSoup
import re


class XSSScanner:
    def __init__(self):
        self.xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<body onload=alert('XSS')>",
            "'\"><script>alert('XSS')</script>",
            "<iframe src=javascript:alert('XSS')>",
        ]

    def scan(self, target_url: str):
        """Scanner les vulnérabilités XSS"""
        try:
            print(f"[*] Scan XSS pour {target_url}...")
            
            parsed = urlparse(target_url)
            vulnerabilities = []
            
            # Extraire les paramètres de l'URL
            params = parse_qs(parsed.query)
            
            if not params:
                # Si pas de paramètres, tester les formulaires sur la page
                return self._scan_forms(target_url)
            
            # Tester chaque paramètre avec des payloads XSS
            for param_name, param_values in params.items():
                for payload in self.xss_payloads[:3]:  # Limiter pour éviter trop de requêtes
                    test_url = self._build_test_url(target_url, param_name, payload)
                    
                    try:
                        response = requests.get(test_url, timeout=5, allow_redirects=False)
                        
                        # Vérifier si le payload est reflété dans la réponse
                        if self._check_xss_reflection(response.text, payload):
                            vulnerabilities.append({
                                'description': f"Vulnérabilité XSS potentielle dans le paramètre '{param_name}'. Le payload est reflété dans la réponse.",
                                'severity': 'high',
                                'cvss_score': 7.5,
                                'parameter': param_name,
                                'payload': payload,
                                'url': test_url
                            })
                            break  # Une vulnérabilité trouvée pour ce paramètre
                    except:
                        continue
            
            return vulnerabilities
        except Exception as e:
            print(f"Erreur lors du scan XSS: {e}")
            return []

    def _scan_forms(self, target_url: str):
        """Scanner les formulaires sur la page pour XSS"""
        try:
            response = requests.get(target_url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            forms = soup.find_all('form')
            vulnerabilities = []
            
            for form in forms:
                action = form.get('action', '')
                method = form.get('method', 'get').lower()
                inputs = form.find_all(['input', 'textarea'])
                
                if not inputs:
                    continue
                
                # Tester le premier input trouvé
                for input_field in inputs[:1]:
                    input_name = input_field.get('name', '')
                    if not input_name:
                        continue
                    
                    payload = self.xss_payloads[0]
                    
                    # Construire l'URL de test
                    form_url = urlparse(action) if action else urlparse(target_url)
                    if not form_url.netloc:
                        form_url = urlparse(target_url)
                    
                    test_data = {input_name: payload}
                    
                    try:
                        if method == 'post':
                            test_response = requests.post(
                                f"{form_url.scheme}://{form_url.netloc}{form_url.path or '/'}",
                                data=test_data,
                                timeout=5
                            )
                        else:
                            test_response = requests.get(
                                f"{form_url.scheme}://{form_url.netloc}{form_url.path or '/'}",
                                params=test_data,
                                timeout=5
                            )
                        
                        if self._check_xss_reflection(test_response.text, payload):
                            vulnerabilities.append({
                                'description': f"Vulnérabilité XSS potentielle dans le formulaire (champ '{input_name}').",
                                'severity': 'high',
                                'cvss_score': 7.5,
                                'form_field': input_name,
                                'payload': payload
                            })
                    except:
                        continue
            
            return vulnerabilities
        except Exception as e:
            print(f"Erreur lors du scan des formulaires: {e}")
            return []

    def _build_test_url(self, base_url: str, param_name: str, payload: str) -> str:
        """Construire une URL de test avec un payload"""
        parsed = urlparse(base_url)
        params = parse_qs(parsed.query)
        params[param_name] = [payload]
        
        new_query = urlencode(params, doseq=True)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"

    def _check_xss_reflection(self, html_content: str, payload: str) -> bool:
        """Vérifier si le payload est reflété dans le HTML"""
        # Nettoyer le payload pour la recherche
        clean_payload = payload.replace("'", "['\"]")
        clean_payload = re.escape(clean_payload)
        
        # Vérifier si le payload (ou une partie) apparaît non échappé
        if payload in html_content:
            # Vérifier qu'il n'est pas dans un commentaire ou échappé
            if '<script' in payload.lower():
                # Chercher des balises script non échappées
                if re.search(r'<script[^>]*>', html_content, re.IGNORECASE):
                    return True
            elif 'onerror' in payload.lower() or 'onload' in payload.lower():
                # Chercher des attributs d'événement
                if re.search(r'on\w+\s*=', html_content, re.IGNORECASE):
                    return True
        
        return False

