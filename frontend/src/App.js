import React, { useState, useEffect } from 'react';
import './App.css';
import ScanForm from './components/ScanForm';
import ScanList from './components/ScanList';
import ScanDetail from './components/ScanDetail';

// URL de l'API - utilise le proxy en développement ou l'URL complète
const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000';

function App() {
  const [scans, setScans] = useState([]);
  const [selectedScan, setSelectedScan] = useState(null);
  const [loading, setLoading] = useState(false);
  const [apiAvailable, setApiAvailable] = useState(true);

  useEffect(() => {
    fetchScans();
  }, []);

  const fetchScans = async () => {
    try {
      const response = await fetch(`${API_URL}/api/scans`, {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
        },
      });
      
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      
      const data = await response.json();
      setScans(data);
      setApiAvailable(true);
    } catch (error) {
      // Ne logger l'erreur qu'une seule fois pour éviter le spam dans la console
      if (apiAvailable) {
        console.warn('Backend non disponible. Assurez-vous que l\'API est démarrée sur', API_URL);
      }
      setApiAvailable(false);
      // Ne pas mettre à jour scans pour garder les données précédentes
    }
  };

  const handleScanCreated = (newScan) => {
    setScans([newScan, ...scans]);
    setSelectedScan(newScan);
  };

  const handleScanSelect = (scan) => {
    setSelectedScan(scan);
  };

  const handleBackToList = () => {
    setSelectedScan(null);
    fetchScans();
  };

  return (
    <div className="App">
      <header className="App-header">
        <h1>🛡️ Plateforme de Scan & Analyse de Vulnérabilités</h1>
        <p>Détection automatique de vulnérabilités web</p>
      </header>

      <main className="App-main">
        {!apiAvailable && (
          <div className="api-error-banner">
            <p>⚠️ Impossible de se connecter au serveur backend. Assurez-vous que l'API est démarrée sur {API_URL}</p>
          </div>
        )}
        {selectedScan ? (
          <ScanDetail scan={selectedScan} onBack={handleBackToList} />
        ) : (
          <>
            <ScanForm onScanCreated={handleScanCreated} apiAvailable={apiAvailable} />
            <ScanList 
              scans={scans} 
              onScanSelect={handleScanSelect} 
              onRefresh={fetchScans}
              apiAvailable={apiAvailable}
            />
          </>
        )}
      </main>
    </div>
  );
}

export default App;

