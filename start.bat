@echo off
rem Arranque da plataforma SecurePass
set "PATH=C:\Program Files\nodejs;%PATH%"
cd /d "%~dp0"
if not exist node_modules (
  echo A instalar dependencias...
  call npm install --no-audit --no-fund
)
node src\seed.js
start "" http://localhost:3000
node server.js
