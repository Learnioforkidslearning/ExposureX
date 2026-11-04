# ExposureX (core build)
Email exposure scanner + explainable risk score + URL pattern checker. FastAPI backend serves the frontend.

## Run on Windows 11 (PowerShell, inside the ExposureX folder)
```
py -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r backend\requirements.txt
cd backend
uvicorn main:app --reload
```
Open http://127.0.0.1:8000. If activation is blocked: `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`.
Tests: `pytest tests` (from the ExposureX folder, venv active).

## Hosted demo
The `docs/` folder is a static version (demo data only) for GitHub Pages. Settings > Pages > branch main, folder /docs.

## Status
Implemented: scanner, demo mode, risk engine, recommendations, URL checker, 3D hero, 5 unit tests.
NOT yet built: SQLite/history, login, PDF report, charts, timeline page, quiz, separate pages, GSAP.
The XposedOrNot response fields in `parse_analytics` were written from memory and must be checked against https://xposedornot.com/api_doc.
