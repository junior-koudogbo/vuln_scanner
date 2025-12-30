import requests
import time
from urllib.parse import urlparse


class ZAPScanner:
    def __init__(self, zap_proxy_url="http://localhost:8080", zap_api_key=None):
        """
        Initialiser le scanner ZAP
        
        Args:
            zap_proxy_url: URL du proxy ZAP (par défaut http://localhost:8080)
            zap_api_key: Clé API ZAP (optionnelle si ZAP est en mode non-sécurisé)
        """
        self.zap_proxy_url = zap_proxy_url.rstrip('/')
        self.zap_api_key = zap_api_key
    
    def _make_request(self, endpoint, params=None, method='GET'):
        """Faire une requête à l'API ZAP"""
        try:
            url = f"{self.zap_proxy_url}/JSON/{endpoint}"
            if params is None:
                params = {}
            if self.zap_api_key:
                params['apikey'] = self.zap_api_key
            
            if method == 'GET':
                response = requests.get(url, params=params, timeout=30)
            else:
                response = requests.post(url, params=params, timeout=30)
            
            if response.status_code == 200:
                return response.json()
            return None
        except Exception as e:
            print(f"Erreur lors de la requête ZAP API: {e}")
            return None
    
    def is_available(self):
        """Vérifier si ZAP est disponible"""
        try:
            result = self._make_request("core/view/version")
            if result and 'version' in result:
                print(f"[*] ZAP détecté - Version: {result.get('version', 'unknown')}")
                return True
            return False
        except:
            return False
    
    def scan(self, target_url: str):
        """
        Effectuer un scan complet avec ZAP (Spider + Active Scan)
        
        Args:
            target_url: URL cible à scanner
            
        Returns:
            Liste de vulnérabilités détectées
        """
        if not self.is_available():
            print("[!] ZAP n'est pas disponible. Assurez-vous que ZAP est démarré sur", self.zap_proxy_url)
            return []
        
        try:
            print(f"[*] Démarrage du scan ZAP pour {target_url}...")
            
            # Étape 1: Spider (crawl) du site
            print("[*] Phase 1/2: Spider (crawl) du site...")
            spider_scan_id = self._start_spider(target_url)
            if spider_scan_id:
                self._wait_for_spider(spider_scan_id)
            
            # Étape 2: Active Scan
            print("[*] Phase 2/2: Active Scan (tests de sécurité)...")
            active_scan_id = self._start_active_scan(target_url)
            if active_scan_id:
                self._wait_for_active_scan(active_scan_id)
            
            # Récupérer les alertes
            print("[*] Récupération des alertes ZAP...")
            alerts = self._get_alerts(target_url)
            
            return self._parse_alerts(alerts, target_url)
            
        except Exception as e:
            print(f"Erreur lors du scan ZAP: {e}")
            return []
    
    def _start_spider(self, target_url: str):
        """Démarrer un scan Spider"""
        try:
            params = {'url': target_url}
            if self.zap_api_key:
                params['apikey'] = self.zap_api_key
            
            url = f"{self.zap_proxy_url}/JSON/spider/action/scan"
            response = requests.get(url, params=params, timeout=30)
            
            if response.status_code == 200:
                result = response.json()
                if 'scan' in result:
                    return result['scan']
            return None
        except Exception as e:
            print(f"Erreur lors du démarrage du Spider: {e}")
            return None
    
    def _wait_for_spider(self, scan_id, timeout=300):
        """Attendre la fin du scan Spider"""
        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                params = {'scanId': scan_id}
                if self.zap_api_key:
                    params['apikey'] = self.zap_api_key
                
                url = f"{self.zap_proxy_url}/JSON/spider/view/status"
                response = requests.get(url, params=params, timeout=30)
                
                if response.status_code == 200:
                    result = response.json()
                    status = int(result.get('status', 100))
                    if status >= 100:  # 100 = terminé
                        print(f"[*] Spider terminé: {status}%")
                        return True
                    print(f"[*] Spider en cours: {status}%")
                time.sleep(2)
            except:
                time.sleep(2)
        return False
    
    def _start_active_scan(self, target_url: str):
        """Démarrer un scan actif"""
        try:
            params = {'url': target_url}
            if self.zap_api_key:
                params['apikey'] = self.zap_api_key
            
            url = f"{self.zap_proxy_url}/JSON/ascan/action/scan"
            response = requests.get(url, params=params, timeout=30)
            
            if response.status_code == 200:
                result = response.json()
                if 'scan' in result:
                    return result['scan']
            return None
        except Exception as e:
            print(f"Erreur lors du démarrage de l'Active Scan: {e}")
            return None
    
    def _wait_for_active_scan(self, scan_id, timeout=600):
        """Attendre la fin du scan actif"""
        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                params = {'scanId': scan_id}
                if self.zap_api_key:
                    params['apikey'] = self.zap_api_key
                
                url = f"{self.zap_proxy_url}/JSON/ascan/view/status"
                response = requests.get(url, params=params, timeout=30)
                
                if response.status_code == 200:
                    result = response.json()
                    status = int(result.get('status', 100))
                    if status >= 100:  # 100 = terminé
                        print(f"[*] Active Scan terminé: {status}%")
                        return True
                    print(f"[*] Active Scan en cours: {status}%")
                time.sleep(3)
            except:
                time.sleep(3)
        return False
    
    def _get_alerts(self, target_url: str):
        """Récupérer les alertes ZAP"""
        try:
            parsed = urlparse(target_url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"
            
            params = {'baseurl': base_url}
            if self.zap_api_key:
                params['apikey'] = self.zap_api_key
            
            url = f"{self.zap_proxy_url}/JSON/core/view/alerts"
            response = requests.get(url, params=params, timeout=30)
            
            if response.status_code == 200:
                result = response.json()
                if 'alerts' in result:
                    return result['alerts']
            return []
        except Exception as e:
            print(f"Erreur lors de la récupération des alertes: {e}")
            return []
    
    def _parse_alerts(self, alerts, target_url):
        """Parser les alertes ZAP en vulnérabilités"""
        vulnerabilities = []
        
        # Mapping des risques ZAP vers nos niveaux de sévérité
        risk_mapping = {
            'Informational': 'info',
            'Low': 'low',
            'Medium': 'medium',
            'High': 'high',
            'Critical': 'critical'
        }
        
        # Mapping des risques vers CVSS
        cvss_mapping = {
            'Informational': 0.0,
            'Low': 3.0,
            'Medium': 5.5,
            'High': 7.5,
            'Critical': 9.0
        }
        
        for alert in alerts:
            risk = alert.get('risk', 'Medium')
            severity = risk_mapping.get(risk, 'medium')
            cvss = cvss_mapping.get(risk, 5.5)
            
            # Filtrer les alertes informatives sauf si importantes
            if severity == 'info' and 'SQL' not in alert.get('name', '') and 'XSS' not in alert.get('name', ''):
                continue
            
            vulnerability = {
                'title': alert.get('name', 'Vulnérabilité détectée par ZAP'),
                'description': alert.get('description', ''),
                'severity': severity,
                'cvss_score': cvss,
                'url': alert.get('url', target_url),
                'parameter': alert.get('param', ''),
                'evidence': alert.get('evidence', ''),
                'solution': alert.get('solution', ''),
                'reference': alert.get('reference', ''),
                'cweid': alert.get('cweid', ''),
                'wascid': alert.get('wascid', '')
            }
            
            vulnerabilities.append(vulnerability)
        
        return vulnerabilities

