from jinja2 import Template
from datetime import datetime
from api.database import Scan, Vulnerability


def generate_html_report(scan: Scan, vulnerabilities: list) -> str:
    """Générer un rapport HTML pour un scan"""
    
    # Compter les vulnérabilités par sévérité
    severity_counts = {
        'critical': 0,
        'high': 0,
        'medium': 0,
        'low': 0,
        'info': 0
    }
    
    for vuln in vulnerabilities:
        severity = vuln.severity.lower() if hasattr(vuln, 'severity') else 'info'
        if severity in severity_counts:
            severity_counts[severity] += 1
    
    # Calculer le score de risque global
    risk_score = (
        severity_counts['critical'] * 10 +
        severity_counts['high'] * 7 +
        severity_counts['medium'] * 4 +
        severity_counts['low'] * 1
    )
    
    if risk_score >= 50:
        risk_level = "Critique"
        risk_color = "#dc3545"
    elif risk_score >= 30:
        risk_level = "Élevé"
        risk_color = "#fd7e14"
    elif risk_score >= 15:
        risk_level = "Moyen"
        risk_color = "#ffc107"
    elif risk_score > 0:
        risk_level = "Faible"
        risk_color = "#0dcaf0"
    else:
        risk_level = "Aucun"
        risk_color = "#198754"
    
    # Template HTML
    html_template = """
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Rapport de Scan - {{ scan.target_url }}</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #f5f5f5;
            color: #333;
            line-height: 1.6;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        .header p {
            font-size: 1.1em;
            opacity: 0.9;
        }
        .risk-badge {
            display: inline-block;
            padding: 10px 20px;
            border-radius: 25px;
            font-weight: bold;
            font-size: 1.2em;
            margin-top: 20px;
            background: {{ risk_color }};
            color: white;
        }
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .stat-card {
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            text-align: center;
        }
        .stat-card h3 {
            font-size: 2.5em;
            color: #667eea;
            margin-bottom: 10px;
        }
        .stat-card p {
            color: #666;
            font-weight: 500;
        }
        .severity-critical { color: #dc3545; }
        .severity-high { color: #fd7e14; }
        .severity-medium { color: #ffc107; }
        .severity-low { color: #0dcaf0; }
        .severity-info { color: #6c757d; }
        .vulnerabilities {
            margin-top: 30px;
        }
        .vuln-card {
            background: white;
            padding: 25px;
            border-radius: 10px;
            margin-bottom: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            border-left: 5px solid;
        }
        .vuln-card.critical { border-left-color: #dc3545; }
        .vuln-card.high { border-left-color: #fd7e14; }
        .vuln-card.medium { border-left-color: #ffc107; }
        .vuln-card.low { border-left-color: #0dcaf0; }
        .vuln-card.info { border-left-color: #6c757d; }
        .vuln-header {
            display: flex;
            justify-content: space-between;
            align-items: start;
            margin-bottom: 15px;
        }
        .vuln-title {
            font-size: 1.3em;
            font-weight: bold;
            color: #333;
        }
        .vuln-badge {
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 0.9em;
            font-weight: bold;
            text-transform: uppercase;
        }
        .vuln-badge.critical { background: #dc3545; color: white; }
        .vuln-badge.high { background: #fd7e14; color: white; }
        .vuln-badge.medium { background: #ffc107; color: #333; }
        .vuln-badge.low { background: #0dcaf0; color: white; }
        .vuln-badge.info { background: #6c757d; color: white; }
        .vuln-section {
            margin-bottom: 15px;
        }
        .vuln-section h4 {
            color: #667eea;
            margin-bottom: 8px;
            font-size: 1.1em;
        }
        .vuln-section p {
            color: #666;
            line-height: 1.8;
        }
        .cvss-score {
            display: inline-block;
            background: #f8f9fa;
            padding: 5px 10px;
            border-radius: 5px;
            font-weight: bold;
            color: #667eea;
        }
        .footer {
            text-align: center;
            padding: 30px;
            color: #666;
            margin-top: 50px;
        }
        .no-vuln {
            text-align: center;
            padding: 60px;
            background: white;
            border-radius: 10px;
            color: #198754;
        }
        .no-vuln h2 {
            font-size: 2em;
            margin-bottom: 10px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Rapport de Scan de Vulnérabilités</h1>
            <p><strong>Cible:</strong> {{ scan.target_url }}</p>
            <p><strong>Date:</strong> {{ scan.created_at.strftime('%d/%m/%Y %H:%M:%S') if scan.created_at else 'N/A' }}</p>
            <p><strong>Type de scan:</strong> {{ scan.scan_type }}</p>
            <div class="risk-badge">Niveau de risque: {{ risk_level }}</div>
        </div>
        
        <div class="stats">
            <div class="stat-card">
                <h3 class="severity-critical">{{ severity_counts['critical'] }}</h3>
                <p>Critique</p>
            </div>
            <div class="stat-card">
                <h3 class="severity-high">{{ severity_counts['high'] }}</h3>
                <p>Élevé</p>
            </div>
            <div class="stat-card">
                <h3 class="severity-medium">{{ severity_counts['medium'] }}</h3>
                <p>Moyen</p>
            </div>
            <div class="stat-card">
                <h3 class="severity-low">{{ severity_counts['low'] }}</h3>
                <p>Faible</p>
            </div>
            <div class="stat-card">
                <h3 class="severity-info">{{ severity_counts['info'] }}</h3>
                <p>Information</p>
            </div>
            <div class="stat-card">
                <h3>{{ len(vulnerabilities) }}</h3>
                <p>Total</p>
            </div>
        </div>
        
        <div class="vulnerabilities">
            {% if vulnerabilities %}
                {% for vuln in vulnerabilities %}
                <div class="vuln-card {{ vuln.severity.lower() }}">
                    <div class="vuln-header">
                        <div class="vuln-title">{{ vuln.title }}</div>
                        <div class="vuln-badge {{ vuln.severity.lower() }}">{{ vuln.severity }}</div>
                    </div>
                    
                    <div class="vuln-section">
                        <h4>📋 Description</h4>
                        <p>{{ vuln.description }}</p>
                    </div>
                    
                    <div class="vuln-section">
                        <h4>📊 Score CVSS</h4>
                        <p><span class="cvss-score">{{ "%.1f"|format(vuln.cvss_score) }}</span></p>
                    </div>
                    
                    <div class="vuln-section">
                        <h4>🔧 Recommandation</h4>
                        <p>{{ vuln.recommendation }}</p>
                    </div>
                    
                    {% if vuln.evidence %}
                    <div class="vuln-section">
                        <h4>🔍 Preuve</h4>
                        <p><code>{{ vuln.evidence }}</code></p>
                    </div>
                    {% endif %}
                </div>
                {% endfor %}
            {% else %}
                <div class="no-vuln">
                    <h2>✅ Aucune vulnérabilité détectée</h2>
                    <p>Le scan n'a révélé aucune vulnérabilité pour cette cible.</p>
                </div>
            {% endif %}
        </div>
        
        <div class="footer">
            <p>Rapport généré le {{ datetime.now().strftime('%d/%m/%Y à %H:%M:%S') }}</p>
            <p>Plateforme de Scan & Analyse de Vulnérabilités v1.0</p>
        </div>
    </div>
</body>
</html>
    """
    
    template = Template(html_template)
    return template.render(
        scan=scan,
        vulnerabilities=vulnerabilities,
        risk_level=risk_level,
        risk_color=risk_color,
        severity_counts=severity_counts,
        datetime=datetime
    )

