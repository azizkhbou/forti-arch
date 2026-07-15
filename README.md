# FortiGate Network Mapper

FortiGate Network Mapper est une application professionnelle de haut niveau permettant de **générer automatiquement une architecture réseau et des diagrammes de topologie interactifs** à partir de fichiers de configuration FortiGate.

L'outil analyse et extrait les configurations globales ainsi que les VDOMs Fortinet, identifie les zones, interfaces, VLANs, sous-réseaux, VIP, VPNs, politiques de firewalling, et relations inter-VDOM, puis produit un diagramme visuel interactif, entièrement modifiable et exportable vers **Draw.io**.

---

## 1. Fonctionnalités Clés

- **Modes d'Importation Flexibles** :
  - **Mode A (Fichier complet)** : Import d'un fichier FortiGate unique englobant la configuration globale et les VDOMs.
  - **Mode B (Fichiers séparés)** : Importation du fichier global de base et association de jusqu'à 3 fichiers de configuration VDOM distincts.
- **Style Visuel Proche de Draw.io** :
  - Grille d'alignement avec connecteurs orthogonaux intelligents.
  - Déplacement libre des équipements par glisser-déposer.
  - Sélection multiple, zoom, centrage et disposition automatique hiérarchique.
- **Filtres Avancés & Gestion des Couches** :
  - Filtrage par VDOM, par zone, par type de règle (actives, d'interdiction, avec NAT).
  - Couches activables/désactivables : Topologie physique, topologie logique, VPN, VIP, Politiques firewall (flux).
- **Contrôles de Cohérence & Détection d'Anomalies** :
  - Détection automatique des interfaces sans IP, des zones vides, des règles "Any-Any", des routes ou règles pointant vers des éléments inexistants, des VIP non utilisés, des doublons de règles, etc.
- **Sécurité et Confidentialité Absolue** :
  - Fonctionne **entièrement en local** sans aucune transmission réseau vers des tiers.
  - Masquage automatique des secrets (mots de passe, clés prépartagées VPN).
  - Option d'anonymisation dynamique des adresses IP lors de l'importation.
- **Exports Multi-formats** :
  - Fichier Draw.io (`.drawio`) éditable, conservant la hiérarchie des conteneurs, positions et styles.
  - Fichier HTML autonome et interactif (pour affichage autonome hors-ligne).
  - Fichier JSON brut et rapports d'inventaire CSV filtrables et triables.

---

## 2. Architecture Technique et Répertoire

L'application est structurée de manière modulaire selon les meilleures pratiques d'ingénierie logicielle :

```
fortigate-network-mapper/
├── backend/
│   ├── app.py                     # Serveur Web Flask API local
│   ├── parsers/
│   │   ├── fortigate_parser.py    # Moteur d'analyse lexicale FortiGate
│   │   ├── global_parser.py       # Extracteur de configuration globale
│   │   └── vdom_parser.py         # Extracteur de configuration VDOM
│   ├── models/
│   │   └── models.py              # Modèle de données objet unifié
│   ├── services/
│   │   ├── topology_builder.py    # Orchestrateur de topologie
│   │   ├── relationship_engine.py # Moteur de relations réseau et déductions IP
│   │   ├── validation_engine.py   # Analyseur de cohérence et anomalies
│   │   ├── drawio_exporter.py     # Générateur XML compatible Draw.io / Diagrams.net
│   │   └── report_exporter.py     # Générateur d'inventaires CSV
│   └── tests/
│       └── test_mapper.py         # Suite complète de tests unitaires
├── frontend/
│   ├── index.html                 # Interface utilisateur principale
│   ├── css/
│   │   └── style.css              # Charte graphique (Fortinet Dark/Light)
│   ├── js/
│   │   ├── app.js                 # Logique frontend (interactivité, Cytoscape, filtres)
│   │   └── cytoscape.min.js       # Librairie de rendu graphique (locale/hors-ligne)
│   └── components/
│   └── assets/
├── samples/                       # Exemples fictifs de fichiers de configuration
├── exports/                       # Dossier de sauvegarde pour les exports
├── requirements.txt               # Dépendances Python
├── README.md                      # Documentation
├── run.bat                        # Script de lancement Windows
└── run.sh                         # Script de lancement Linux
```

---

## 3. Guide de Démarrage Rapide

### Configuration requise
- **Python 3.8+** installé sur votre machine.

### Lancement sous Windows
Double-cliquez sur le fichier `run.bat` à la racine du projet ou exécutez dans un terminal :
```cmd
run.bat
```

### Lancement sous Linux / macOS
Ouvrez votre terminal, assurez-vous que le script a les droits d'exécution et lancez-le :
```bash
chmod +x run.sh
./run.sh
```

Une fois lancé, accédez simplement à l'adresse suivante dans votre navigateur web :
👉 **`http://127.0.0.1:5000/`**

---

## 4. Exécution des Tests Unitaires

Une suite de tests unitaires automatisés valide l'intégralité du traitement de parsing, la correspondance d'IP (longest prefix match), la qualité, les anomalies et les exports XML/CSV.

Pour exécuter les tests :
```bash
python3 -m unittest discover -s backend/tests -p "test_*.py"
```

---

## 5. Spécifications du Modèle de Données

Les données extraites des fichiers FortiGate sont unifiées au sein de la classe `FortiGateModel` dans `backend/models/models.py`. Les objets clés incluent :
- **FortiGateDevice** : Hôte, modèle, version de l'OS, numéro de série et rapport de qualité.
- **VDOM** : Nom du VDOM, mode de fonctionnement (NAT/Transparent).
- **Interface** : Nom, alias, IP, masque, type (physique, VLAN, vdom-link, tunnel), VLAN ID, accès admin, statut, zone associée.
- **Zone** : Nom, interfaces membres, intrazone (allow/deny), rôle présumé (LAN, WAN, DMZ).
- **StaticRoute** : Destination CIDR, gateway, interface de sortie, distance administrative et priorité.
- **FirewallPolicy** : ID, nom, interfaces/zones source/destination, adresses source/destination, services, action (accept/deny), NAT (enable/disable), profils de sécurité.
- **VIP** : Nom, IP externe, IP interne mappée, redirection de ports, interface externe.
- **VPN** : Nom du tunnel, type (IPsec/SSL), passerelle distante, sous-réseaux locaux/distants.
- **Finding** : Écart de cohérence détecté (sévérité, catégorie, description).

---

## 6. Instructions de Packaging en Application Autonome

Si vous souhaitez distribuer cette application sous forme d'**exécutable autonome (.exe ou binaire Linux)** utilisable sans installer de dépendances ou de serveur Python tiers, vous pouvez utiliser **PyInstaller** :

1. Installez PyInstaller dans votre environnement :
   ```bash
   pip install pyinstaller
   ```
2. Générez le binaire autonome en incluant le dossier statique `frontend` :
   - **Sous Windows** :
     ```cmd
     pyinstaller --onefile --add-data "frontend;frontend" backend/app.py
     ```
   - **Sous Linux / macOS** :
     ```bash
     pyinstaller --onefile --add-data "frontend:frontend" backend/app.py
     ```
3. L'exécutable généré sera disponible dans le dossier `dist/` sous le nom `app` (ou `app.exe`). Lancez-le pour démarrer automatiquement l'application sur le port local.
