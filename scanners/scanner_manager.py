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
                    self._save_vulnerability(
                        title=f"Port ouvert détecté: {result.get('port')}/{result.get('protocol')}",
                        description=f"Le port {result.get('port')} ({result.get('protocol')}) est ouvert sur {target_url}",
                        severity=self._get_severity_for_port(result.get('port')),
                        cvss_score=self._calculate_cvss_for_port(result.get('port')),
                        vuln_type="ports",
                        recommendation="Fermer les ports non nécessaires. Utiliser un firewall pour restreindre l'accès.",
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

    def _get_severity_for_port(self, port: int) -> str:
        """Déterminer la sévérité selon le port"""
        critical_ports = [21, 23, 135, 139, 445, 1433, 3306, 5432, 3389]
        high_ports = [80, 443, 8080, 8443]
        
        if port in critical_ports:
            return "high"
        elif port in high_ports:
            return "medium"
        else:
            return "low"

    def _calculate_cvss_for_port(self, port: int) -> float:
        """Calculer un score CVSS simplifié pour un port"""
        critical_ports = [21, 23, 135, 139, 445, 1433, 3306, 5432, 3389]
        high_ports = [80, 443, 8080, 8443]
        
        if port in critical_ports:
            return 7.5
        elif port in high_ports:
            return 5.0
        else:
            return 3.0

