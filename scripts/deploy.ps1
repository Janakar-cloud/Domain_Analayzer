<#
Deploy Domain Intelligence on Windows VM.
Creates venv, installs dependencies, and can start backend/frontend.

Usage examples:
  .\scripts\deploy.ps1 -Setup
  .\scripts\deploy.ps1 -StartBackend
  .\scripts\deploy.ps1 -StartFrontend
  .\scripts\deploy.ps1 -StartBackend -StartFrontend
#>

param(
  [switch]$Setup,
  [switch]$StartBackend,
  [switch]$StartFrontend
)

$ErrorActionPreference = 'Stop'
Push-Location (Split-Path -Parent $MyInvocation.MyCommand.Path)
Push-Location ..

function Ensure-Venv {
  if (-not (Test-Path ".venv")) {
    Write-Host "[+] Creating virtual environment..." -ForegroundColor Green
    py -3 -m venv .venv
  }
}

function Install-Dependencies {
  Write-Host "[+] Installing dependencies..." -ForegroundColor Green
  & .\.venv\Scripts\pip.exe install --upgrade pip
  & .\.venv\Scripts\pip.exe install -r requirements.txt
}

function Start-Backend {
  Write-Host "[+] Starting FastAPI backend (http://127.0.0.1:8000)..." -ForegroundColor Green
  Start-Process -FilePath ".\.venv\Scripts\python.exe" -ArgumentList "-m","uvicorn","src.server:app","--host","0.0.0.0","--port","8000" -WindowStyle Hidden
}

function Start-Frontend {
  Write-Host "[+] Starting Streamlit frontend (http://127.0.0.1:8501)..." -ForegroundColor Green
  $env:DOMAIN_INTEL_API = "http://127.0.0.1:8000"
  Start-Process -FilePath ".\.venv\Scripts\streamlit.exe" -ArgumentList "run","src\webui\app.py","--server.port","8501"
}

if ($Setup) {
  Ensure-Venv
  Install-Dependencies
}

if ($StartBackend) { Start-Backend }
if ($StartFrontend) { Start-Frontend }

Pop-Location
Pop-Location