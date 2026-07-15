#!/bin/bash
# ===================================================
#     FortiGate Network Mapper Launcher (Linux)
# ===================================================

echo "==================================================="
echo "    FortiGate Network Mapper Launcher (Linux)"
echo "==================================================="
echo ""

# Check Python 3
if ! command -v python3 &> /dev/null; then
    echo "[ERREUR] Python 3 n'est pas installé sur ce système."
    echo "Veuillez installer python3 et retenter le lancement."
    exit 1
fi

# Install dependencies
echo "[1/2] Installation des dépendances requises..."
python3 -m pip install -r requirements.txt
if [ $? -ne 0 ]; then
    echo "[ERREUR] Impossible d'installer les dépendances."
    exit 1
fi

# Start local server
echo ""
echo "[2/2] Lancement du serveur local sur http://127.0.0.1:5000/"
echo "Pour arrêter le serveur, appuyez sur Ctrl+C."
echo ""
python3 -m backend.app
