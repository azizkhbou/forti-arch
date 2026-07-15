@echo off
echo ===================================================
echo     FortiGate Network Mapper Launcher (Windows)
echo ===================================================
echo.

:: Check Python installation
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERREUR] Python n'est pas installe ou n'est pas ajoute au PATH systeme.
    echo Veuillez installer Python 3 pour continuer.
    pause
    exit /b 1
)

:: Install dependencies
echo [1/2] Installation des dependances requises...
pip install -r requirements.txt
if %errorlevel% neq 0 (
    echo [ERREUR] Impossible d'installer les dependances.
    pause
    exit /b 1
)

:: Run application
echo.
echo [2/2] Lancement du serveur local sur http://127.0.0.1:5000/
echo Pour arreter le serveur, fermez cette fenetre ou appuyez sur Ctrl+C.
echo.
python -m backend.app
pause
