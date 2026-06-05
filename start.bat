@echo off
docker info >nul 2>&1
if errorlevel 1 (
    echo Docker is not running. Please start Docker Desktop and try again.
    pause
    exit /b 1
)
echo Starting Surfshark VPN Proxy...
docker compose up -d --build
echo.
echo Dashboard: http://localhost:8000
echo SOCKS5 Proxy: localhost:1080
pause
