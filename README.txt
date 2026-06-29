================================================================================
  TABLEAU DE BORD D'AUDIT ET DE DETECTION - README
================================================================================

OBJET : Mini-projet 10 - Tableau de bord d'audit et de détection
COURS  : Python/PowerShell pour la Sécurité
AUTEUR : Dr. Salah Gontara

--------------------------------------------------------------------------------
STRUCTURE DU PROJET
--------------------------------------------------------------------------------

Sujet-10-Dashboard/
├── README.txt              (ce fichier)
├── collect-dashboard.ps1   (script PowerShell de collecte)
├── analyze-dashboard.py    (script Python d'analyse)
├── data/                   (données collectées)
│   ├── users.json
│   ├── administrators.json
│   ├── processes.json
│   ├── services.json
│   ├── ports.json
│   ├── events.json
│   ├── defender.json
│   └── firewall.json
├── results/                (résultats générés)
│   ├── dashboard.html
│   ├── summary.json
│   └── alerts.csv
└── Rapport.pdf             (rapport final à générer)

--------------------------------------------------------------------------------
PRÉREQUIS
--------------------------------------------------------------------------------

- Windows 10/11 ou Windows Server
- PowerShell 5.1 ou supérieur
- Python 3.8 ou supérieur
- Modules Python requis :
    pip install pandas matplotlib numpy

--------------------------------------------------------------------------------
EXECUTION
--------------------------------------------------------------------------------

ÉTAPE 1 - COLLECTE (PowerShell)
--------------------------------
1. Ouvrir PowerShell en tant qu'Administrateur
2. Exécuter la politique d'exécution si nécessaire :
   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
3. Lancer le script de collecte :
   .\collect-dashboard.ps1
4. Les fichiers seront générés dans le dossier 'data/'

ÉTAPE 2 - ANALYSE (Python)
--------------------------
1. S'assurer que les fichiers JSON sont dans 'data/'
2. Lancer le script d'analyse :
   python analyze-dashboard.py
3. Les résultats seront générés dans le dossier 'results/'

--------------------------------------------------------------------------------
DESCRIPTION DES SCRIPTS
--------------------------------------------------------------------------------

COLLECT-DASHBOARD.PS1
----------------------
Ce script collecte les informations suivantes :
- Utilisateurs locaux
- Membres du groupe Administrators
- Processus en cours
- Services Windows
- Ports ouverts (TCP)
- Événements Windows (sélectionnés)
- État de Microsoft Defender
- État du Pare-feu Windows

ANALYZE-DASHBOARD.PY
---------------------
Ce script analyse les données collectées et :
- Calcule des statistiques générales
- Génère un tableau de bord HTML interactif
- Identifie les alertes de sécurité
- Produit des recommandations

--------------------------------------------------------------------------------
LIVRABLES
--------------------------------------------------------------------------------

- dashboard.html : Tableau de bord visuel avec graphiques
- summary.json   : Résumé structuré des statistiques
- alerts.csv     : Liste des alertes détectées

--------------------------------------------------------------------------------
NOTES DE SÉCURITÉ
--------------------------------------------------------------------------------

- Ce projet est conçu pour un environnement de laboratoire ou une machine
  autorisée.
- Les scripts ne collectent pas de mots de passe ou d'informations sensibles.
- Les résultats doivent être analysés dans leur contexte.
- Ce n'est pas un outil de production.

--------------------------------------------------------------------------------
