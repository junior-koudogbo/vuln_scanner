import React, { useState, useEffect } from 'react';
import './ScanDetail.css';
import axios from 'axios';

// URL de l'API
const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000';

function ScanDetail({ scan, onBack }) {
  const [scanDetails, setScanDetails] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    fetchScanDetails();
    
    // Si le scan est en cours, rafraîchir toutes les 3 secondes
    if (scan.status === 'running' || scan.status === 'pending') {
      const interval = setInterval(() => {
        fetchScanDetails();
      }, 3000);
      
      return () => clearInterval(interval);
    }
  }, [scan.id]);

  const fetchScanDetails = async () => {
    try {
      const response = await axios.get(`${API_URL}/api/scans/${scan.id}`, {
        timeout: 10000,
      });
      setScanDetails(response.data);
      setLoading(false);
      setError('');
    } catch (err) {
      if (err.code === 'ECONNREFUSED' || err.message.includes('Failed to fetch')) {
        setError('Impossible de se connecter au serveur. Vérifiez que l\'API est démarrée.');
      } else {
        setError('Erreur lors de la récupération des détails du scan');
      }
      setLoading(false);
    }
  };

  const handleViewReport = () => {
    window.open(`${API_URL}/api/scans/${scan.id}/report`, '_blank');
  };

  if (loading) {
    return (
      <div className="scan-detail-container">
        <div className="loading">Chargement...</div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="scan-detail-container">
        <div className="error">{error}</div>
        <button onClick={onBack} className="back-button">Retour</button>
      </div>
    );
  }

  const vulnerabilities = scanDetails?.vulnerabilities || [];
  
  // Compter par sévérité
  const severityCounts = {
    critical: vulnerabilities.filter(v => v.severity === 'critical').length,
    high: vulnerabilities.filter(v => v.severity === 'high').length,
    medium: vulnerabilities.filter(v => v.severity === 'medium').length,
    low: vulnerabilities.filter(v => v.severity === 'low').length,
    info: vulnerabilities.filter(v => v.severity === 'info').length,
  };

  const getSeverityClass = (severity) => {
    return `severity-${severity.toLowerCase()}`;
  };

  return (
    <div className="scan-detail-container">
      <button onClick={onBack} className="back-button">← Retour à la liste</button>

      <div className="scan-detail-header">
        <h2>{scanDetails.target_url}</h2>
        <div className="scan-actions">
          <button onClick={handleViewReport} className="report-button">
            📄 Voir le rapport HTML
          </button>
        </div>
      </div>

      <div className="scan-info">
        <p><strong>Statut:</strong> {scanDetails.status}</p>
        <p><strong>Type:</strong> {scanDetails.scan_type === 'full' ? 'Complet' : 'Rapide'}</p>
        <p><strong>Créé le:</strong> {new Date(scanDetails.created_at).toLocaleString('fr-FR')}</p>
        {scanDetails.completed_at && (
          <p><strong>Terminé le:</strong> {new Date(scanDetails.completed_at).toLocaleString('fr-FR')}</p>
        )}
      </div>

      <div className="severity-stats">
        <div className="stat-item critical">
          <div className="stat-number">{severityCounts.critical}</div>
          <div className="stat-label">Critique</div>
        </div>
        <div className="stat-item high">
          <div className="stat-number">{severityCounts.high}</div>
          <div className="stat-label">Élevé</div>
        </div>
        <div className="stat-item medium">
          <div className="stat-number">{severityCounts.medium}</div>
          <div className="stat-label">Moyen</div>
        </div>
        <div className="stat-item low">
          <div className="stat-number">{severityCounts.low}</div>
          <div className="stat-label">Faible</div>
        </div>
        <div className="stat-item total">
          <div className="stat-number">{vulnerabilities.length}</div>
          <div className="stat-label">Total</div>
        </div>
      </div>

      {scanDetails.status === 'running' && (
        <div className="scan-progress">
          <p>⏳ Scan en cours... Veuillez patienter.</p>
        </div>
      )}

      {vulnerabilities.length === 0 && scanDetails.status === 'completed' ? (
        <div className="no-vulnerabilities">
          <h3>✅ Aucune vulnérabilité détectée</h3>
          <p>Le scan n'a révélé aucune vulnérabilité pour cette cible.</p>
        </div>
      ) : (
        <div className="vulnerabilities-list">
          <h3>Vulnérabilités détectées</h3>
          {vulnerabilities.map((vuln) => (
            <div key={vuln.id} className={`vuln-item ${getSeverityClass(vuln.severity)}`}>
              <div className="vuln-header">
                <h4>{vuln.title}</h4>
                <span className={`severity-badge ${getSeverityClass(vuln.severity)}`}>
                  {vuln.severity}
                </span>
              </div>
              <div className="vuln-body">
                <p className="vuln-description">{vuln.description}</p>
                <div className="vuln-meta">
                  <span className="cvss-score">CVSS: {vuln.cvss_score.toFixed(1)}</span>
                  <span className="vuln-type">Type: {vuln.vulnerability_type}</span>
                </div>
                <div className="vuln-recommendation">
                  <strong>Recommandation:</strong> {vuln.recommendation}
                </div>
                {vuln.evidence && (
                  <div className="vuln-evidence">
                    <strong>Preuve:</strong>
                    <pre>{JSON.stringify(vuln.evidence, null, 2)}</pre>
                  </div>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export default ScanDetail;

