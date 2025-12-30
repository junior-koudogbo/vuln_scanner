import React, { useState, useEffect } from 'react';
import './App.css';
import ScanForm from './components/ScanForm';
import ScanList from './components/ScanList';
import ScanDetail from './components/ScanDetail';

function App() {
  const [scans, setScans] = useState([]);
  const [selectedScan, setSelectedScan] = useState(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    fetchScans();
  }, []);

  const fetchScans = async () => {
    try {
      const response = await fetch('http://localhost:8000/api/scans');
      const data = await response.json();
      setScans(data);
    } catch (error) {
      console.error('Erreur lors de la récupération des scans:', error);
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
        {selectedScan ? (
          <ScanDetail scan={selectedScan} onBack={handleBackToList} />
        ) : (
          <>
            <ScanForm onScanCreated={handleScanCreated} />
            <ScanList scans={scans} onScanSelect={handleScanSelect} onRefresh={fetchScans} />
          </>
        )}
      </main>
    </div>
  );
}

export default App;

