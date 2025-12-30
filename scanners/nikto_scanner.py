import subprocess
import re
from urllib.parse import urlparse


class NiktoScanner:
    def __init__(self):
        self.nikto_path = self._find_nikto()

    def _find_nikto(self):
        """Trouver le chemin vers Nikto"""
        try:
            result = subprocess.run(['which', 'nikto'], capture_output=True, text=True)
            if result.returncode == 0:
                return result.stdout.strip()
        except:
            pass
        return None

    def scan(self, target_url: str):
        """Scanner avec Nikto"""
        if not self.nikto_path:
            print("[!] Nikto non trouvé, scan ignoré")
            return []

        try:
            parsed = urlparse(target_url)
            host = parsed.hostname or parsed.netloc.split(':')[0]
            port = parsed.port or (443 if parsed.scheme == 'https' else 80)
            
            print(f"[*] Scan Nikto de {target_url}...")
            
            # Exécuter Nikto
            cmd = [
                self.nikto_path,
                '-h', host,
                '-p', str(port),
                '-Format', 'txt'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.returncode != 0:
                return []

            # Parser les résultats
            vulnerabilities = []
            lines = result.stdout.split('\n')
            
            for line in lines:
                if '+ ' in line and 'OSVDB' in line:
                    # Format Nikto: + /path: description (OSVDB-xxxxx)
                    match = re.search(r'\+ (.+?): (.+?) \(OSVDB-(\d+)\)', line)
                    if match:
                        path = match.group(1)
                        description = match.group(2)
                        osvdb_id = match.group(3)
                        
                        vulnerabilities.append({
                            'title': f"Vulnérabilité Nikto: {path}",
                            'description': description,
                            'severity': self._determine_severity(description),
                            'cvss_score': 5.0,
                            'recommendation': 'Vérifier la configuration du serveur et appliquer les correctifs recommandés.',
                            'path': path,
                            'osvdb_id': osvdb_id
                        })
            
            return vulnerabilities
        except subprocess.TimeoutExpired:
            print("[!] Scan Nikto timeout")
            return []
        except Exception as e:
            print(f"Erreur Nikto: {e}")
            return []

    def _determine_severity(self, description: str) -> str:
        """Déterminer la sévérité basée sur la description"""
        description_lower = description.lower()
        
        if any(word in description_lower for word in ['xss', 'sql injection', 'rce', 'remote code']):
            return 'high'
        elif any(word in description_lower for word in ['directory', 'file', 'information disclosure']):
            return 'medium'
        else:
            return 'low'

