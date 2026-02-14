# Clean repository-generated artifacts safely (no source code removed)

$ErrorActionPreference = 'Continue'

$paths = @(
  "output",
  "evidence",
  "logs",
  "**\__pycache__",
  ".pytest_cache",
  "htmlcov"
)

foreach ($p in $paths) {
  Write-Host "[~] Removing: $p" -ForegroundColor Yellow
  Get-ChildItem -Path $p -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host "[OK] Cleanup complete" -ForegroundColor Green