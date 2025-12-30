import React, { useState } from 'react';
import './ScanForm.css';
import axios from 'axios';

function ScanForm({ onScanCreated }) {
  const [targetUrl, setTargetUrl] = useState('');
  const [scanType, setScanType] = useState('full');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      const response = await axios.post('http://localhost:8000/api/scans', {
        target_url: targetUrl,
        scan_type: scanType
      });

      onScanCreated(response.data);
      setTargetUrl('');
    } catch (err) {
      setError(err.response?.data?.detail || 'Erreur lors de la création du scan');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="scan-form-container">
      <div className="scan-form-card">
        <h2>Nouveau Scan</h2>
        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label htmlFor="targetUrl">URL cible</label>
            <input
              type="url"
              id="targetUrl"
              value={targetUrl}
              onChange={(e) => setTargetUrl(e.target.value)}
              placeholder="https://example.com"
              required
            />
          </div>

          <div className="form-group">
            <label htmlFor="scanType">Type de scan</label>
            <select
              id="scanType"
              value={scanType}
              onChange={(e) => setScanType(e.target.value)}
            >
              <option value="quick">Rapide (Headers & Ports)</option>
              <option value="full">Complet (Tous les scanners)</option>
            </select>
          </div>

          {error && <div className="error-message">{error}</div>}

          <button type="submit" disabled={loading} className="submit-button">
            {loading ? 'Création du scan...' : 'Lancer le scan'}
          </button>
        </form>
      </div>
    </div>
  );
}

export default ScanForm;

