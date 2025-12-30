import requests
from urllib.parse import urlparse, urlencode, parse_qs
from bs4 import BeautifulSoup
import re


class SQLiScanner:
    def __init__(self):
        self.sqli_payloads = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' /*",
            "admin'--",
            "admin'/*",
            "' UNION SELECT NULL--",
            "1' AND '1'='1",
            "1' AND '1'='2",
            "' OR 1=1#",
            "' OR 1=1--",
        ]
        
        self.error_patterns = [
            r"SQL syntax.*MySQL",
            r"Warning.*\Wmysql_",
            r"MySQLSyntaxErrorException",
            r"valid MySQL result",
            r"PostgreSQL.*ERROR",
            r"Warning.*\Wpg_",
            r"valid PostgreSQL result",
            r"Npgsql\.NpgsqlException",
            r"SQLite.*error",
            r"SQLiteException",
            r"SQLite.*SQL syntax",
            r"Microsoft.*ODBC.*SQL Server",
            r"ODBC SQL Server Driver",
            r"SQLServer JDBC Driver",
            r"Warning.*\Wmssql_",
            r"Warning.*\Wsqlsrv_",
            r"SQLException",
            r"Unclosed quotation mark",
            r"quoted string not properly terminated",
        ]

    def scan(self, target_url: str):
        """Scanner les vulnérabilités SQL Injection"""
        try:
            print(f"[*] Scan SQLi pour {target_url}...")
            
            parsed = urlparse(target_url)
            vulnerabilities = []
            
            # Extraire les paramètres de l'URL
            params = parse_qs(parsed.query)
            
            if not params:
                # Si pas de paramètres, tester les formulaires
                return self._scan_forms(target_url)
            
            # Tester chaque paramètre avec des payloads SQLi
            for param_name, param_values in params.items():
                for payload in self.sqli_payloads[:5]:  # Limiter pour éviter trop de requêtes
                    test_url = self._build_test_url(target_url, param_name, payload)
                    
                    try:
                        response = requests.get(test_url, timeout=5, allow_redirects=False)
                        
                        # Vérifier les erreurs SQL dans la réponse
                        if self._check_sqli_errors(response.text):
                            vulnerabilities.append({
                                'description': f"Vulnérabilité SQL Injection potentielle dans le paramètre '{param_name}'. Erreurs SQL détectées dans la réponse.",
                                'severity': 'critical',
                                'cvss_score': 9.0,
                                'parameter': param_name,
                                'payload': payload,
                                'url': test_url
                            })
                            break
                        
                        # Vérifier les différences de réponse (time-based serait mieux mais plus complexe)
                        baseline_response = requests.get(target_url, timeout=5)
                        if self._check_response_difference(response.text, baseline_response.text):
                            vulnerabilities.append({
                                'description': f"Vulnérabilité SQL Injection potentielle dans le paramètre '{param_name}'. Réponse anormale détectée.",
                                'severity': 'high',
                                'cvss_score': 8.0,
                                'parameter': param_name,
                                'payload': payload,
                                'url': test_url
                            })
                            break
                    except:
                        continue
            
            return vulnerabilities
        except Exception as e:
            print(f"Erreur lors du scan SQLi: {e}")
            return []

    def _scan_forms(self, target_url: str):
        """Scanner les formulaires pour SQLi"""
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
                
                # Obtenir une réponse baseline pour comparaison
                try:
                    baseline_data = {}
                    for input_field in inputs:
                        input_name = input_field.get('name', '')
                        if input_name:
                            baseline_data[input_name] = 'test'
                    
                    form_url = urlparse(action) if action else urlparse(target_url)
                    if not form_url.netloc:
                        form_url = urlparse(target_url)
                    
                    if method == 'post':
                        baseline_response = requests.post(
                            f"{form_url.scheme}://{form_url.netloc}{form_url.path or '/'}",
                            data=baseline_data,
                            timeout=5,
                            allow_redirects=True
                        )
                    else:
                        baseline_response = requests.get(
                            f"{form_url.scheme}://{form_url.netloc}{form_url.path or '/'}",
                            params=baseline_data,
                            timeout=5,
                            allow_redirects=True
                        )
                except:
                    baseline_response = None
                
                # Tester TOUS les champs de type text avec plusieurs payloads
                for input_field in inputs:
                    input_name = input_field.get('name', '')
                    input_type = input_field.get('type', 'text').lower()
                    
                    if not input_name or input_type in ['hidden', 'submit', 'button', 'password']:
                        continue
                    
                    # Tester plusieurs payloads SQLi
                    for payload in self.sqli_payloads[:5]:
                        # Construire l'URL de test
                        form_url = urlparse(action) if action else urlparse(target_url)
                        if not form_url.netloc:
                            form_url = urlparse(target_url)
                        
                        test_data = baseline_data.copy() if baseline_data else {}
                        test_data[input_name] = payload
                        
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
                            
                            # Vérifier les erreurs SQL
                            if self._check_sqli_errors(test_response.text):
                                vulnerabilities.append({
                                    'description': f"Vulnérabilité SQL Injection potentielle dans le formulaire (champ '{input_name}'). Erreurs SQL détectées dans la réponse.",
                                    'severity': 'critical',
                                    'cvss_score': 9.0,
                                    'form_field': input_name,
                                    'payload': payload,
                                    'form_action': action or target_url
                                })
                                break  # Une vulnérabilité trouvée pour ce champ
                            
                            # Vérifier les différences de réponse
                            if baseline_response and self._check_response_difference(test_response.text, baseline_response.text):
                                vulnerabilities.append({
                                    'description': f"Vulnérabilité SQL Injection potentielle dans le formulaire (champ '{input_name}'). Réponse anormale détectée.",
                                    'severity': 'high',
                                    'cvss_score': 8.0,
                                    'form_field': input_name,
                                    'payload': payload,
                                    'form_action': action or target_url
                                })
                                break
                        except:
                            continue
            
            return vulnerabilities
        except Exception as e:
            print(f"Erreur lors du scan des formulaires: {e}")
            return []

    def _build_test_url(self, base_url: str, param_name: str, payload: str) -> str:
        """Construire une URL de test avec un payload SQLi"""
        parsed = urlparse(base_url)
        params = parse_qs(parsed.query)
        params[param_name] = [payload]
        
        new_query = urlencode(params, doseq=True)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"

    def _check_sqli_errors(self, html_content: str) -> bool:
        """Vérifier si des erreurs SQL sont présentes dans la réponse"""
        html_lower = html_content.lower()
        
        for pattern in self.error_patterns:
            if re.search(pattern, html_content, re.IGNORECASE):
                return True
        
        return False

    def _check_response_difference(self, test_response: str, baseline_response: str) -> bool:
        """Vérifier si la réponse est significativement différente"""
        # Comparaison simple de longueur et contenu
        if abs(len(test_response) - len(baseline_response)) > len(baseline_response) * 0.2:
            return True
        
        # Vérifier des mots-clés suspects
        suspicious_keywords = ['error', 'exception', 'warning', 'database', 'sql']
        test_lower = test_response.lower()
        baseline_lower = baseline_response.lower()
        
        for keyword in suspicious_keywords:
            if keyword in test_lower and keyword not in baseline_lower:
                return True
        
        return False

