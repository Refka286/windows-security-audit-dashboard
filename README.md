# Tableau de Bord d'Audit et de Détection de Sécurité Windows

> Mini-Projet 10 — Cours **Python/PowerShell pour la Sécurité**  
> Dr. Salah Gontara

Dashboard interactif de sécurité Windows combinant PowerShell (collecte de données) et Python (analyse + génération HTML).

---

## Aperçu

Le projet génère un **tableau de bord HTML interactif** (auto-contenu, ~180 KB) qui analyse l'état de sécurité d'une machine Windows :

- Score de risque global **0–100** avec jauge visuelle
- **8 onglets** de navigation : Vue d'ensemble, Système, Identités, Processus, Services, Réseau, Sécurité, Alertes
- **6 graphiques** (Chart.js) : distribution des alertes, top processus RAM, état des services, événements Windows, etc.
- **68+ alertes** classées par sévérité (Critique / Haute / Moyenne / Basse) avec **remédiation** et **tactique MITRE ATT&CK**
- Recherche en temps réel, tri de colonnes, pagination, export CSV, mode clair/sombre

---

## Structure du projet

```
Sujet-10-Dashboard/
├── collect-dashboard.ps1   # Collecte PowerShell (admin requis)
├── analyze-dashboard.py    # Analyse Python + génération HTML
├── run-dashboard.ps1       # Orchestrateur (mode continu)
├── data/                   # Données collectées (JSON)
│   ├── system.json
│   ├── users.json
│   ├── administrators.json
│   ├── processes.json
│   ├── services.json
│   ├── ports.json
│   ├── events.json
│   ├── defender.json
│   └── firewall.json
└── results/                # Résultats générés
    ├── dashboard.html      ← Ouvrir dans un navigateur
    ├── summary.json
    └── alerts.csv
```

---

## Prérequis

| Outil | Version minimale |
|-------|-----------------|
| Windows | 10 / 11 ou Windows Server |
| PowerShell | 5.1+ |
| Python | 3.8+ |

Aucune dépendance Python supplémentaire requise (bibliothèques standard uniquement).  
Chart.js est chargé via CDN — une connexion internet est nécessaire pour afficher les graphiques.

---

## Exécution rapide

### Option 1 — Script tout-en-un (recommandé)

```powershell
# PowerShell en tant qu'Administrateur
.\run-dashboard.ps1
```

### Option 2 — Étape par étape

**Étape 1 — Collecte des données**

```powershell
# PowerShell en tant qu'Administrateur
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
.\collect-dashboard.ps1
```

**Étape 2 — Analyse et génération du dashboard**

```bash
python analyze-dashboard.py
```

**Étape 3 — Consulter le dashboard**

Ouvrir `results/dashboard.html` dans un navigateur.

### Mode continu (actualisation automatique)

```powershell
.\run-dashboard.ps1 -Continuous -RefreshInterval 30
```

---

## Données collectées

| Catégorie | Ce qui est analysé |
|-----------|-------------------|
| Système | OS, build, RAM, modèle, dernier démarrage |
| Utilisateurs | Comptes locaux, statut, dernière connexion |
| Administrateurs | Membres du groupe Administrators |
| Processus | 300+ processus — CPU, mémoire, chemins |
| Services | 300 services — état, type de démarrage |
| Réseau | Ports TCP, connexions établies, adresses distantes |
| Événements | 7 derniers jours — Security/System/Application logs |
| Defender | Antivirus, protection temps réel, âge des signatures |
| Pare-feu | Profils Domain/Private/Public |

---

## Fonctionnalités du dashboard

### Analyse de sécurité
- **Détection LOLBAS** — binaires légitimes souvent détournés (certutil, mshta, rundll32, etc.)
- **Brute force** — détection de multiples échecs de connexion (Event 4625)
- **Services critiques** — alerte si Windows Update, Defender ou Event Log sont arrêtés
- **Ports sensibles** — FTP (21), Telnet (23), SMB (445), RDP (3389), VNC (5900)
- **Tactiques MITRE ATT&CK** — chaque alerte référence la tactique associée

### Interface interactive
- Recherche en temps réel sur toutes les tables
- Tri par colonne (clic sur l'en-tête)
- Pagination 25 lignes/page
- Filtre par sévérité (alertes) et par état (services)
- Export CSV des alertes
- Panneau de remédiation (slide-in)
- Mode sombre / mode clair

---

## Niveaux d'alerte

| Niveau | Couleur | Exemples |
|--------|---------|----------|
| **Critique** | Rouge | Antivirus désactivé, protection temps réel inactive |
| **Haute** | Orange | Services installés (7045), échecs de connexion, pare-feu désactivé |
| **Moyenne** | Bleu | Ports sensibles ouverts, services critiques arrêtés, comptes jamais connectés |
| **Basse** | Vert | Processus sans chemin, connexions externes établies |

---

## Score de risque

```
Score = min(100,
    min(40, critiques × 20) +
    min(30, hautes × 5)     +
    min(20, moyennes × 3)   +
    min(10, basses × 1)
)
```

| Score | Niveau |
|-------|--------|
| 0–19 | Faible |
| 20–39 | Modéré |
| 40–69 | Élevé |
| 70–100 | Critique |

---

## Notes de sécurité

- Ce projet est destiné à un **environnement de laboratoire ou une machine autorisée**.
- Les scripts ne collectent **aucun mot de passe** ni identifiant sensible.
- Le dashboard HTML généré peut contenir des informations système sensibles — **ne pas le partager publiquement**.
- Ce n'est pas un outil de production.

---

*Cours Python/PowerShell pour la Sécurité — Dr. Salah Gontara*
