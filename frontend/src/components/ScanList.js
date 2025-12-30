import React, { useState, useEffect } from 'react';
import './ScanList.css';
import axios from 'axios';

function ScanList({ scans, onScanSelect, onRefresh, apiAvailable }) {
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    // Rafraîchir automatiquement toutes les 5 secondes seulement si l'API est disponible
    if (!apiAvailable) {
      return;
    }
    
    const interval = setInterval(() => {
      onRefresh();
    }, 5000);

    return () => clearInterval(interval);
  }, [onRefresh, apiAvailable]);

  const getStatusBadgeClass = (status) => {
    switch (status) {
      case 'completed':
        return 'status-completed';
      case 'running':
        return 'status-running';
      case 'failed':
        return 'status-failed';
      default:
        return 'status-pending';
    }
  };

  const getStatusLabel = (status) => {
    switch (status) {
      case 'completed':
        return 'Terminé';
      case 'running':
        return 'En cours';
      case 'failed':
        return 'Échoué';
      default:
        return 'En attente';
    }
  };

  return (
    <div className="scan-list-container">
      <div className="scan-list-header">
        <h2>Historique des Scans</h2>
        <button onClick={onRefresh} className="refresh-button">
          🔄 Actualiser
        </button>
      </div>

      {scans.length === 0 ? (
        <div className="no-scans">
          <p>Aucun scan pour le moment. Créez votre premier scan ci-dessus.</p>
        </div>
      ) : (
        <div className="scan-list">
          {scans.map((scan) => (
            <div
              key={scan.id}
              className="scan-card"
              onClick={() => onScanSelect(scan)}
            >
              <div className="scan-card-header">
                <h3>{scan.target_url}</h3>
                <span className={`status-badge ${getStatusBadgeClass(scan.status)}`}>
                  {getStatusLabel(scan.status)}
                </span>
              </div>
              <div className="scan-card-info">
                <p>
                  <strong>Type:</strong> {scan.scan_type === 'full' ? 'Complet' : 'Rapide'}
                </p>
                <p>
                  <strong>Créé le:</strong>{' '}
                  {new Date(scan.created_at).toLocaleString('fr-FR')}
                </p>
                {scan.completed_at && (
                  <p>
                    <strong>Terminé le:</strong>{' '}
                    {new Date(scan.completed_at).toLocaleString('fr-FR')}
                  </p>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export default ScanList;

