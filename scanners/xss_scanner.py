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
            
            # Aussi chercher les champs de recherche et autres inputs dans la page
            search_inputs = soup.find_all('input', {'type': ['text', 'search']})
            
            for form in forms:
                action = form.get('action', '')
                method = form.get('method', 'get').lower()
                inputs = form.find_all(['input', 'textarea'])
                
                if not inputs:
                    continue
                
                # Tester TOUS les champs de texte, pas seulement le premier
                for input_field in inputs:
                    input_name = input_field.get('name', '')
                    input_type = input_field.get('type', 'text').lower()
                    
                    if not input_name or input_type in ['hidden', 'submit', 'button', 'password']:
                        continue
                    
                    # Tester plusieurs payloads pour chaque champ
                    for payload in self.xss_payloads[:3]:
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
                                    timeout=5,
                                    allow_redirects=True
                                )
                            else:
                                test_response = requests.get(
                                    f"{form_url.scheme}://{form_url.netloc}{form_url.path or '/'}",
                                    params=test_data,
                                    timeout=5,
                                    allow_redirects=True
                                )
                            
                            if self._check_xss_reflection(test_response.text, payload):
                                vulnerabilities.append({
                                    'description': f"Vulnérabilité XSS potentielle dans le formulaire (champ '{input_name}'). Le payload est reflété dans la réponse.",
                                    'severity': 'high',
                                    'cvss_score': 7.5,
                                    'form_field': input_name,
                                    'payload': payload,
                                    'form_action': action or target_url
                                })
                                break  # Une vulnérabilité trouvée pour ce champ
                        except:
                            continue
            
            # Tester aussi les champs de recherche dans la page (hors formulaires)
            for search_input in search_inputs[:3]:  # Limiter à 3 pour éviter trop de requêtes
                input_name = search_input.get('name', '')
                if not input_name:
                    continue
                
                # Construire une URL de recherche
                parsed = urlparse(target_url)
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{input_name}={self.xss_payloads[0]}"
                
                try:
                    test_response = requests.get(test_url, timeout=5, allow_redirects=True)
                    if self._check_xss_reflection(test_response.text, self.xss_payloads[0]):
                        vulnerabilities.append({
                            'description': f"Vulnérabilité XSS potentielle dans le champ de recherche '{input_name}'. Le payload est reflété dans la réponse.",
                            'severity': 'high',
                            'cvss_score': 7.5,
                            'form_field': input_name,
                            'payload': self.xss_payloads[0],
                            'url': test_url
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
        # Vérifier si le payload est présent dans le HTML (même partiellement)
        payload_lower = payload.lower()
        html_lower = html_content.lower()
        
        # Vérifier la présence du payload (échappé ou non)
        if payload in html_content or payload_lower in html_lower:
            # Vérifier qu'il n'est pas dans un commentaire HTML
            if f"<!--{payload}" in html_content or f"<!--{payload_lower}" in html_lower:
                return False
            
            # Vérifier qu'il n'est pas complètement échappé (HTML entities)
            escaped_payload = payload.replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;')
            if escaped_payload in html_content and payload not in html_content:
                # Le payload est échappé, donc probablement sécurisé
                return False
            
            # Si le payload contient des balises script
            if '<script' in payload_lower:
                # Chercher des balises script non échappées dans le HTML
                if re.search(r'<script[^>]*>.*?' + re.escape(payload), html_content, re.IGNORECASE | re.DOTALL):
                    return True
                # Ou si le payload script apparaît tel quel
                if payload in html_content:
                    return True
            
            # Si le payload contient des attributs d'événement
            if 'onerror' in payload_lower or 'onload' in payload_lower or 'onclick' in payload_lower:
                # Chercher des attributs d'événement dans le HTML
                if re.search(r'on\w+\s*=\s*["\']?[^"\'>]*' + re.escape(payload), html_content, re.IGNORECASE):
                    return True
                # Ou si le payload apparaît dans un attribut
                if re.search(r'<[^>]+\s+' + re.escape(payload) + r'[^>]*>', html_content, re.IGNORECASE):
                    return True
            
            # Si le payload contient des balises HTML simples
            if payload.startswith('<') and payload.endswith('>'):
                # Vérifier si la balise apparaît non échappée
                if payload in html_content:
                    # Vérifier qu'elle n'est pas dans un contexte sécurisé
                    if not re.search(r'&lt;' + re.escape(payload[1:-1]) + r'&gt;', html_content):
                        return True
        
        return False

