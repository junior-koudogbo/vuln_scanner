from sqlalchemy.orm import Session
from scanners.nmap_scanner import NmapScanner
from scanners.nikto_scanner import NiktoScanner
from scanners.headers_scanner import HeadersScanner
from scanners.xss_scanner import XSSScanner
from scanners.sqli_scanner import SQLiScanner
from scanners.version_scanner import VersionScanner
from api.database import Vulnerability
import requests


class ScannerManager:
    def __init__(self, db: Session, scan_id: int):
        self.db = db
        self.scan_id = scan_id
        self.nmap_scanner = NmapScanner()
        self.nikto_scanner = NiktoScanner()
        self.headers_scanner = HeadersScanner()
        self.xss_scanner = XSSScanner()
        self.sqli_scanner = SQLiScanner()
        self.version_scanner = VersionScanner()

    def run_quick_scan(self, target_url: str):
        """Scan rapide - headers et ports uniquement"""
        print(f"[*] Démarrage du scan rapide pour {target_url}")
        
        # Scan des headers de sécurité
        self._scan_headers(target_url)
        
        # Scan des ports ouverts (version simplifiée)
        self._scan_ports(target_url)

    def run_full_scan(self, target_url: str):
        """Scan complet - tous les scanners"""
        print(f"[*] Démarrage du scan complet pour {target_url}")
        
        # Scan des ports
        self._scan_ports(target_url)
        
        # Scan des headers de sécurité
        self._scan_headers(target_url)
        
        # Scan XSS
        self._scan_xss(target_url)
        
        # Scan SQLi
        self._scan_sqli(target_url)
        
        # Scan des versions logicielles
        self._scan_versions(target_url)
        
        # Scan Nikto (si disponible)
        self._scan_nikto(target_url)

    def _scan_ports(self, target_url: str):
        """Scanner les ports ouverts"""
        try:
            results = self.nmap_scanner.scan(target_url)
            if results:
                for result in results:
                    port = result.get('port')
                    severity, cvss, recommendation = self._analyze_port_for_web_server(port, result, target_url)
                    
                    # Ne pas signaler les ports web standards comme des vulnérabilités
                    if severity == "info":
                        self._save_vulnerability(
                            title=f"Port web standard détecté: {port}/{result.get('protocol')}",
                            description=f"Le port {port} ({result.get('protocol')}) est ouvert. C'est normal pour un serveur web.",
                            severity=severity,
                            cvss_score=cvss,
                            vuln_type="ports",
                            recommendation=recommendation,
                            evidence=result
                        )
                    else:
                        self._save_vulnerability(
                            title=f"Port inhabituel détecté: {port}/{result.get('protocol')}",
                            description=f"Le port {port} ({result.get('protocol')}) est ouvert sur {target_url}. Vérifiez si ce port est nécessaire pour un serveur web public.",
                            severity=severity,
                            cvss_score=cvss,
                            vuln_type="ports",
                            recommendation=recommendation,
                            evidence=result
                        )
        except Exception as e:
            print(f"Erreur lors du scan de ports: {e}")

    def _scan_headers(self, target_url: str):
        """Scanner les headers de sécurité"""
        try:
            results = self.headers_scanner.scan(target_url)
            if results:
                for result in results:
                    self._save_vulnerability(
                        title=f"Header de sécurité manquant: {result.get('header')}",
                        description=result.get('description'),
                        severity=result.get('severity', 'medium'),
                        cvss_score=result.get('cvss_score', 5.0),
                        vuln_type="headers",
                        recommendation=result.get('recommendation'),
                        evidence=result
                    )
        except Exception as e:
            print(f"Erreur lors du scan des headers: {e}")

    def _scan_xss(self, target_url: str):
        """Scanner les vulnérabilités XSS"""
        try:
            results = self.xss_scanner.scan(target_url)
            if results:
                for result in results:
                    self._save_vulnerability(
                        title="Vulnérabilité XSS potentielle",
                        description=result.get('description'),
                        severity=result.get('severity', 'high'),
                        cvss_score=result.get('cvss_score', 7.5),
                        vuln_type="xss",
                        recommendation="Valider et échapper toutes les entrées utilisateur. Utiliser Content Security Policy (CSP).",
                        evidence=result
                    )
        except Exception as e:
            print(f"Erreur lors du scan XSS: {e}")

    def _scan_sqli(self, target_url: str):
        """Scanner les vulnérabilités SQLi"""
        try:
            results = self.sqli_scanner.scan(target_url)
            if results:
                for result in results:
                    self._save_vulnerability(
                        title="Vulnérabilité SQL Injection potentielle",
                        description=result.get('description'),
                        severity=result.get('severity', 'critical'),
                        cvss_score=result.get('cvss_score', 9.0),
                        vuln_type="sqli",
                        recommendation="Utiliser des requêtes préparées (prepared statements). Valider et échapper toutes les entrées.",
                        evidence=result
                    )
        except Exception as e:
            print(f"Erreur lors du scan SQLi: {e}")

    def _scan_versions(self, target_url: str):
        """Scanner les versions logicielles vulnérables"""
        try:
            results = self.version_scanner.scan(target_url)
            if results:
                for result in results:
                    self._save_vulnerability(
                        title=f"Version logicielle potentiellement vulnérable: {result.get('software')}",
                        description=result.get('description'),
                        severity=result.get('severity', 'medium'),
                        cvss_score=result.get('cvss_score', 6.0),
                        vuln_type="version",
                        recommendation="Mettre à jour le logiciel vers la dernière version sécurisée.",
                        evidence=result
                    )
        except Exception as e:
            print(f"Erreur lors du scan de versions: {e}")

    def _scan_nikto(self, target_url: str):
        """Scanner avec Nikto (si disponible)"""
        try:
            results = self.nikto_scanner.scan(target_url)
            if results:
                for result in results:
                    self._save_vulnerability(
                        title=result.get('title', 'Vulnérabilité détectée par Nikto'),
                        description=result.get('description'),
                        severity=result.get('severity', 'medium'),
                        cvss_score=result.get('cvss_score', 5.0),
                        vuln_type="nikto",
                        recommendation=result.get('recommendation', 'Vérifier la configuration du serveur.'),
                        evidence=result
                    )
        except Exception as e:
            print(f"Erreur lors du scan Nikto: {e}")

    def _save_vulnerability(self, title: str, description: str, severity: str,
                           cvss_score: float, vuln_type: str, recommendation: str, evidence: dict = None):
        """Sauvegarder une vulnérabilité dans la base de données"""
        vuln = Vulnerability(
            scan_id=self.scan_id,
            title=title,
            description=description,
            severity=severity,
            cvss_score=cvss_score,
            vulnerability_type=vuln_type,
            recommendation=recommendation,
            evidence=evidence
        )
        self.db.add(vuln)
        self.db.commit()

    def _analyze_port_for_web_server(self, port: int, port_info: dict, target_url: str):
        """
        Analyser un port dans le contexte d'un serveur web.
        Retourne (severity, cvss_score, recommendation)
        """
        # Ports web standards - normaux pour un serveur web
        WEB_STANDARD_PORTS = [80, 443]
        
        # Ports web alternatifs - souvent utilisés pour le développement ou reverse proxy
        WEB_ALTERNATIVE_PORTS = [8080, 8443, 8000, 8888]
        
        # Ports critiques qui ne devraient PAS être exposés publiquement sur un serveur web
        CRITICAL_EXPOSED_PORTS = {
            21: ("FTP", "high", 7.5),
            22: ("SSH", "high", 7.0),  # SSH devrait être sur un port non-standard ou via VPN
            23: ("Telnet", "critical", 9.0),  # Telnet non chiffré
            135: ("RPC", "high", 7.5),
            139: ("NetBIOS", "high", 7.0),
            445: ("SMB", "high", 8.0),
            1433: ("MSSQL", "critical", 9.0),
            3306: ("MySQL", "critical", 9.0),
            5432: ("PostgreSQL", "critical", 9.0),
            3389: ("RDP", "critical", 9.0),
            27017: ("MongoDB", "critical", 9.0),
            6379: ("Redis", "critical", 9.0),
        }
        
        # Ports suspects mais moins critiques
        SUSPICIOUS_PORTS = {
            25: ("SMTP", "medium", 5.0),
            110: ("POP3", "medium", 5.0),
            143: ("IMAP", "medium", 5.0),
        }
        
        # Ports web standards - juste informatif
        if port in WEB_STANDARD_PORTS:
            service = port_info.get('service', 'http' if port == 80 else 'https')
            return (
                "info",
                0.0,
                f"Port web standard {port} ({service}) détecté. C'est normal pour un serveur web public."
            )
        
        # Ports web alternatifs - faible risque, souvent utilisé pour reverse proxy
        if port in WEB_ALTERNATIVE_PORTS:
            service = port_info.get('service', 'http-alt')
            return (
                "low",
                2.0,
                f"Port web alternatif {port} ({service}) détecté. Vérifiez si ce port est intentionnellement exposé."
            )
        
        # Ports critiques - ne devraient pas être exposés
        if port in CRITICAL_EXPOSED_PORTS:
            service_name, severity, cvss = CRITICAL_EXPOSED_PORTS[port]
            return (
                severity,
                cvss,
                f"Port {service_name} ({port}) est exposé publiquement ! Ce port ne devrait PAS être accessible depuis Internet. Restreignez l'accès via firewall ou VPN."
            )
        
        # Ports suspects
        if port in SUSPICIOUS_PORTS:
            service_name, severity, cvss = SUSPICIOUS_PORTS[port]
            return (
                severity,
                cvss,
                f"Port {service_name} ({port}) détecté. Vérifiez si ce service doit être accessible publiquement."
            )
        
        # Autres ports - risque moyen par défaut
        service = port_info.get('service', 'unknown')
        return (
            "medium",
            4.0,
            f"Port {port} ({service}) détecté. Vérifiez si ce port est nécessaire pour votre application web."
        )

