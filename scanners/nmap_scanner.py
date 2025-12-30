import nmap
import re
from urllib.parse import urlparse


class NmapScanner:
    def __init__(self):
        self.nm = nmap.PortScanner()

    def scan(self, target_url: str):
        """Scanner les ports ouverts d'une cible"""
        try:
            # Extraire l'hostname ou l'IP de l'URL
            parsed = urlparse(target_url)
            host = parsed.hostname or parsed.netloc.split(':')[0]
            
            if not host:
                return []

            # Scanner les ports communs
            print(f"[*] Scan Nmap de {host}...")
            self.nm.scan(host, '22-443,8080,8443', arguments='-sV --version-intensity 2')
            
            results = []
            for hostname in self.nm.all_hosts():
                for proto in self.nm[hostname].all_protocols():
                    ports = self.nm[hostname][proto].keys()
                    for port in ports:
                        port_info = self.nm[hostname][proto][port]
                        results.append({
                            'port': port,
                            'protocol': proto,
                            'state': port_info.get('state', 'unknown'),
                            'service': port_info.get('name', 'unknown'),
                            'version': port_info.get('version', 'unknown'),
                            'product': port_info.get('product', 'unknown')
                        })
            
            return results
        except Exception as e:
            print(f"Erreur Nmap: {e}")
            # Fallback: détecter les ports communs via des requêtes HTTP/HTTPS
            return self._fallback_port_detection(target_url)

    def _fallback_port_detection(self, target_url: str):
        """Détection basique des ports si Nmap n'est pas disponible"""
        import requests
        results = []
        
        parsed = urlparse(target_url)
        scheme = parsed.scheme or 'http'
        host = parsed.hostname or parsed.netloc.split(':')[0]
        
        # Tester les ports communs
        common_ports = {
            'http': 80,
            'https': 443,
            'http-alt': 8080,
            'https-alt': 8443
        }
        
        for service, port in common_ports.items():
            try:
                test_url = f"{scheme}://{host}:{port}"
                response = requests.get(test_url, timeout=2, allow_redirects=False)
                if response.status_code:
                    results.append({
                        'port': port,
                        'protocol': 'tcp',
                        'state': 'open',
                        'service': service,
                        'version': 'unknown',
                        'product': 'unknown'
                    })
            except:
                pass
        
        return results

