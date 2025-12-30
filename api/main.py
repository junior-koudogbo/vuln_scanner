from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, HTMLResponse
from sqlalchemy.orm import Session
from pydantic import BaseModel, HttpUrl
from typing import List, Optional
from datetime import datetime
import uvicorn

from api.database import get_db, init_db, Scan, Vulnerability
from scanners.scanner_manager import ScannerManager

app = FastAPI(
    title="Vulnerability Scanner API",
    description="API pour le scan et l'analyse de vulnérabilités",
    version="1.0.0"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Modèles Pydantic
class ScanRequest(BaseModel):
    target_url: str
    scan_type: str = "full"  # full, quick, custom


class ScanResponse(BaseModel):
    id: int
    target_url: str
    status: str
    created_at: datetime
    scan_type: str

    class Config:
        from_attributes = True


class VulnerabilityResponse(BaseModel):
    id: int
    scan_id: int
    title: str
    description: str
    severity: str
    cvss_score: float
    vulnerability_type: str
    recommendation: str
    evidence: Optional[dict] = None

    class Config:
        from_attributes = True


class ScanDetailResponse(ScanResponse):
    vulnerabilities: List[VulnerabilityResponse] = []


# Initialisation de la base de données
@app.on_event("startup")
async def startup_event():
    init_db()


@app.get("/")
async def root():
    return {
        "message": "Vulnerability Scanner API",
        "version": "1.0.0",
        "endpoints": {
            "POST /api/scans": "Créer un nouveau scan",
            "GET /api/scans": "Liste tous les scans",
            "GET /api/scans/{scan_id}": "Détails d'un scan",
            "GET /api/scans/{scan_id}/report": "Rapport HTML d'un scan"
        }
    }


@app.post("/api/scans", response_model=ScanResponse)
async def create_scan(
    scan_request: ScanRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """Créer un nouveau scan de vulnérabilité"""
    # Créer l'enregistrement du scan
    scan = Scan(
        target_url=scan_request.target_url,
        scan_type=scan_request.scan_type,
        status="pending"
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    # Lancer le scan en arrière-plan
    background_tasks.add_task(run_scan, scan.id, scan_request.target_url, scan_request.scan_type)

    return scan


@app.get("/api/scans", response_model=List[ScanResponse])
async def list_scans(db: Session = Depends(get_db)):
    """Liste tous les scans"""
    scans = db.query(Scan).order_by(Scan.created_at.desc()).all()
    return scans


@app.get("/api/scans/{scan_id}", response_model=ScanDetailResponse)
async def get_scan(scan_id: int, db: Session = Depends(get_db)):
    """Récupérer les détails d'un scan avec ses vulnérabilités"""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan non trouvé")

    vulnerabilities = db.query(Vulnerability).filter(
        Vulnerability.scan_id == scan_id
    ).all()

    return {
        **scan.__dict__,
        "vulnerabilities": vulnerabilities
    }


@app.get("/api/scans/{scan_id}/report")
async def get_scan_report(scan_id: int, db: Session = Depends(get_db)):
    """Générer un rapport HTML pour un scan"""
    from reports.report_generator import generate_html_report

    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan non trouvé")

    vulnerabilities = db.query(Vulnerability).filter(
        Vulnerability.scan_id == scan_id
    ).all()

    html_report = generate_html_report(scan, vulnerabilities)
    return HTMLResponse(content=html_report, media_type="text/html")


def run_scan(scan_id: int, target_url: str, scan_type: str):
    """Exécuter le scan en arrière-plan"""
    from api.database import SessionLocal
    
    db = SessionLocal()
    try:
        # Mettre à jour le statut
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return

        scan.status = "running"
        db.commit()

        # Initialiser le gestionnaire de scanners
        scanner_manager = ScannerManager(db, scan_id)

        # Exécuter les scans selon le type
        if scan_type == "quick":
            scanner_manager.run_quick_scan(target_url)
        elif scan_type == "full":
            scanner_manager.run_full_scan(target_url)
        else:
            scanner_manager.run_full_scan(target_url)

        # Mettre à jour le statut
        scan.status = "completed"
        scan.completed_at = datetime.utcnow()
        db.commit()

    except Exception as e:
        # En cas d'erreur
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if scan:
            scan.status = "failed"
            db.commit()
        print(f"Erreur lors du scan {scan_id}: {str(e)}")
    finally:
        db.close()


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)

