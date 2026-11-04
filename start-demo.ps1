$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) { throw 'Docker is required. Install/start Docker Desktop or Docker Engine.' }
& docker info *> $null
if ($LASTEXITCODE -ne 0) { throw 'Docker daemon is unavailable. Start Docker and check permissions.' }
& docker compose version
if ($LASTEXITCODE -ne 0) { throw 'Docker Compose is required.' }
if (-not (Get-Command python -ErrorAction SilentlyContinue)) { throw 'Python 3.10+ must be installed and available as python.' }
& python -c "import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)"
if ($LASTEXITCODE -ne 0) { throw 'Python 3.10+ is required.' }
& python '.\demo.py'
exit $LASTEXITCODE
