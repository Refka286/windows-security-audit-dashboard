# =============================================================================
# SCRIPT PYTHON D'ANALYSE - TABLEAU DE BORD D'AUDIT ET DE DETECTION
# =============================================================================
# Auteur : Dr. Salah Gontara
# Cours  : Python/PowerShell pour la Sécurité
# Version améliorée : Dashboard interactif complet
# =============================================================================

import json
import os
import csv
import re
from datetime import datetime
from pathlib import Path
from collections import Counter

# =============================================================================
# CONFIGURATION
# =============================================================================

DATA_DIR = Path("data")
RESULTS_DIR = Path("results")

ALERT_SEVERITY = {
    "critical": [],
    "high": [],
    "medium": [],
    "low": []
}

STATS = {
    "system": {},
    "users": {},
    "administrators": {},
    "processes": {},
    "services": {},
    "ports": {},
    "defender": {},
    "firewall": {},
    "events": {}
}

RISK_SCORE = {
    "total": 0,
    "level": "Faible",
    "level_class": "faible",
    "breakdown": {}
}

# LOLBAS (Living Off the Land Binaries) - binaires légitimes souvent détournés
LOLBAS_BINARIES = {
    "certutil.exe": "Téléchargement/encodage de fichiers",
    "mshta.exe": "Exécution de scripts HTA",
    "wscript.exe": "Exécution de scripts VBS/JS",
    "cscript.exe": "Exécution de scripts VBS/JS",
    "regsvr32.exe": "Exécution de DLL/scripts COM",
    "rundll32.exe": "Exécution de DLL arbitraire",
    "msiexec.exe": "Installation/exécution MSI distante",
    "installutil.exe": "Exécution de code .NET non signé",
    "msbuild.exe": "Compilation et exécution C# inline",
    "cmstp.exe": "Contournement UAC / exécution INF",
    "bitsadmin.exe": "Téléchargement de fichiers via BITS",
    "wmic.exe": "Reconnaissance / mouvement latéral",
    "ntdsutil.exe": "Extraction base Active Directory",
    "vssadmin.exe": "Manipulation clichés VSS / accès NTDS",
    "diskshadow.exe": "Extraction NTDS.dit via shadow copy",
    "esentutl.exe": "Copie de fichiers verrouillés",
    "mavinject.exe": "Injection de DLL dans un processus",
    "nc.exe": "Netcat — shell inversé / transfert",
    "ncat.exe": "Netcat — shell inversé / transfert",
    "netcat": "Netcat — shell inversé / transfert",
    "mimikatz": "Extraction de credentials Windows",
    "psexec.exe": "Exécution distante (SysInternals)",
    "wce.exe": "Windows Credentials Editor",
    "pwdump": "Dump de hachages de mots de passe",
    "fgdump": "Dump de credentials SAM",
    "hashcat": "Cassage de mots de passe hors ligne",
    "rainbow": "Tables arc-en-ciel — cassage hash",
}

# Tactiques MITRE ATT&CK
MITRE_TACTICS = {
    "TA0001": "Accès initial",
    "TA0002": "Exécution",
    "TA0003": "Persistance",
    "TA0004": "Escalade de privilèges",
    "TA0005": "Évasion de défense",
    "TA0006": "Accès aux identifiants",
    "TA0007": "Découverte",
    "TA0008": "Mouvement latéral",
    "TA0010": "Exfiltration",
    "TA0011": "Commande et contrôle",
}

# =============================================================================
# UTILITAIRES
# =============================================================================

def load_json(filename):
    """Charge un fichier JSON depuis le dossier data/"""
    filepath = DATA_DIR / filename
    if filepath.exists():
        with open(filepath, 'r', encoding='utf-8-sig') as f:
            return json.load(f)
    return None

def save_json(data, filename):
    """Sauvegarde un fichier JSON dans results/"""
    filepath = RESULTS_DIR / filename
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    print(f"  [OK] {filename}")

def save_csv(data, filename):
    """Sauvegarde un fichier CSV dans results/"""
    filepath = RESULTS_DIR / filename
    if not data:
        with open(filepath, 'w', newline='', encoding='utf-8-sig') as f:
            f.write("")
        print(f"  [OK] {filename} (vide)")
        return

    headers = list(data[0].keys()) if isinstance(data, list) and data else []
    if not headers:
        with open(filepath, 'w', newline='', encoding='utf-8-sig') as f:
            f.write("")
        print(f"  [OK] {filename} (vide)")
        return

    with open(filepath, 'w', newline='', encoding='utf-8-sig') as f:
        writer = csv.DictWriter(f, fieldnames=headers, extrasaction='ignore')
        writer.writeheader()
        writer.writerows(data)
    print(f"  [OK] {filename}")

def add_alert(severity, message, category, details=None, remediation=None, mitre_tactic=None):
    """Ajoute une alerte à la liste avec remédiation et tactique MITRE optionnelles"""
    alert = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "severity": severity,
        "category": category,
        "message": message,
    }
    if details:
        alert["details"] = details
    if remediation:
        alert["remediation"] = remediation
    if mitre_tactic:
        alert["mitre_tactic"] = mitre_tactic
        alert["mitre_tactic_name"] = MITRE_TACTICS.get(mitre_tactic, "")
    ALERT_SEVERITY[severity].append(alert)

# =============================================================================
# ANALYSE DES DONNÉES
# =============================================================================

def analyze_system():
    """Analyse les informations système"""
    print("\n2.1 Analyse système...")

    data = load_json("system.json")
    if not data:
        print("    [ERREUR] system.json non trouvé")
        return

    STATS["system"] = {
        "hostname": data.get("hostname", "N/A"),
        "domain": data.get("domain", "N/A"),
        "os_name": data.get("os_name", "N/A"),
        "os_version": data.get("os_version", "N/A"),
        "os_build": data.get("os_build", "N/A"),
        "manufacturer": data.get("manufacturer", "N/A"),
        "model": data.get("model", "N/A"),
        "total_ram_gb": data.get("total_physical_ram", "N/A"),
        "current_user": data.get("current_user", "N/A"),
        "collection_time": data.get("collection_time", "N/A"),
        "last_boot": data.get("last_boot", "N/A"),
    }

    build = data.get("os_build", "")
    if build:
        try:
            if int(build) < 19041:
                add_alert("medium", "Version Windows potentiellement obsolète",
                          "Système", f"Build {build} — Mise à jour fortement recommandée",
                          "Exécuter Windows Update: Settings > Windows Update > Check for updates",
                          "TA0005")
        except ValueError:
            pass

    print(f"    [OK] {data.get('hostname')} — {data.get('os_name')}")

def analyze_users():
    """Analyse les utilisateurs locaux"""
    print("2.2 Analyse utilisateurs...")

    data = load_json("users.json")
    if not data:
        print("    [ERREUR] users.json non trouvé")
        return

    users = data if isinstance(data, list) else []
    enabled_users = [u for u in users if u.get("enabled") is True]
    disabled_users = [u for u in users if u.get("enabled") is False]
    never_logged = [u for u in users if u.get("last_logon") == "Jamais"]

    STATS["users"] = {
        "total": len(users),
        "enabled": len(enabled_users),
        "disabled": len(disabled_users),
        "never_logged": len(never_logged),
        "users_list": users
    }

    if len(users) > 5:
        add_alert("low", f"{len(users)} utilisateurs locaux trouvés",
                  "Utilisateurs", "Vérifier la nécessité de chaque compte",
                  "Supprimer ou désactiver les comptes inutiles: Computer Management > Local Users and Groups",
                  "TA0007")

    for user in never_logged:
        add_alert("medium", f"Compte jamais connecté: {user.get('name')}",
                  "Utilisateurs", "Compte potentiellement obsolète ou backdoor",
                  f"Désactiver le compte via: net user \"{user.get('name')}\" /active:no",
                  "TA0003")

    print(f"    [OK] {len(users)} utilisateurs ({len(enabled_users)} actifs)")

def analyze_administrators():
    """Analyse les administrateurs locaux"""
    print("2.3 Analyse administrateurs...")

    data = load_json("administrators.json")
    if not data:
        print("    [ERREUR] administrators.json non trouvé")
        return

    admins = data if isinstance(data, list) else []
    local_admins = [a for a in admins if a.get("source") == "Local"]
    domain_admins = [a for a in admins if a.get("source") == "Domain"]
    group_admins = [a for a in admins if a.get("object_class") == "Group"]

    STATS["administrators"] = {
        "total": len(admins),
        "local": len(local_admins),
        "domain": len(domain_admins),
        "groups": len(group_admins),
        "list": admins
    }

    if len(admins) > 3:
        add_alert("high", f"{len(admins)} comptes dans le groupe Administrateurs",
                  "Privilèges", "Nombre élevé de comptes administrateurs — surface d'attaque augmentée",
                  "Restreindre le groupe Administrators aux comptes strictement nécessaires via: lusrmgr.msc",
                  "TA0004")

    for admin in admins:
        name = admin.get("name", "")
        if "Guest" in name:
            add_alert("high", f"Compte Invité dans les administrateurs: {name}",
                      "Privilèges", f"Source: {admin.get('source')} — risque critique",
                      f"Retirer immédiatement du groupe: net localgroup Administrators \"{name}\" /delete",
                      "TA0004")

    print(f"    [OK] {len(admins)} administrateurs")

def analyze_processes():
    """Analyse les processus"""
    print("2.4 Analyse processus...")

    data = load_json("processes.json")
    if not data:
        print("    [ERREUR] processes.json non trouvé")
        return

    processes = data if isinstance(data, list) else []
    top_memory = sorted(processes, key=lambda x: x.get("memory_mb", 0), reverse=True)[:15]

    STATS["processes"] = {
        "total": len(processes),
        "top_memory": top_memory,
        "all": processes,
        "total_memory_mb": sum(p.get("memory_mb", 0) for p in processes)
    }

    # Détection de processus suspects (noms connus)
    for proc in processes:
        name = proc.get("name", "").lower()
        for lolbas, desc in LOLBAS_BINARIES.items():
            if lolbas.lower().replace(".exe", "") == name.replace(".exe", ""):
                path = proc.get("path", "") or ""
                safe_paths = ["c:\\windows\\system32", "c:\\windows\\syswow64", "c:\\windows\\"]
                is_safe_path = any(path.lower().startswith(sp) for sp in safe_paths) if path else False
                if not is_safe_path:
                    add_alert("high", f"Processus LOLBAS suspect: {proc.get('name')} (PID {proc.get('pid')})",
                              "Processus", f"Chemin: {path or 'Inconnu'} — {desc}",
                              f"Terminer le processus: Stop-Process -Id {proc.get('pid')} -Force puis analyser le fichier avec Defender",
                              "TA0005")

    # Processus sans chemin
    no_path = [p for p in processes if not p.get("path")]
    if no_path:
        add_alert("low", f"{len(no_path)} processus sans chemin défini",
                  "Processus", "Peut indiquer des processus temporaires, injectés, ou masqués",
                  "Inspecter avec Process Explorer (SysInternals): https://docs.microsoft.com/sysinternals",
                  "TA0005")

    top_name = top_memory[0]['name'] if top_memory else 'N/A'
    print(f"    [OK] {len(processes)} processus (Top mémoire: {top_name})")

def analyze_services():
    """Analyse les services Windows"""
    print("2.5 Analyse services...")

    data = load_json("services.json")
    if not data:
        print("    [ERREUR] services.json non trouvé")
        return

    services = data if isinstance(data, list) else []
    running = [s for s in services if s.get("status") == "Running"]
    stopped = [s for s in services if s.get("status") == "Stopped"]

    critical_services = {
        "wuauserv": "Windows Update",
        "WinDefend": "Microsoft Defender Antivirus",
        "MpsSvc": "Windows Firewall",
        "EventLog": "Windows Event Log",
        "RpcSs": "Remote Procedure Call (RPC)",
        "DHCP": "DHCP Client",
        "Dnscache": "DNS Client",
        "WdNisSvc": "Microsoft Defender Network Inspection"
    }

    STATS["services"] = {
        "total": len(services),
        "running": len(running),
        "stopped": len(stopped),
        "list": services
    }

    for svc in services:
        name = svc.get("name", "")
        if name in critical_services and svc.get("status") == "Stopped":
            add_alert("medium", f"Service critique arrêté: {svc.get('display_name', name)}",
                      "Services", f"Service: {name} — {critical_services[name]}",
                      f"Démarrer le service: Start-Service -Name \"{name}\" ou via services.msc",
                      "TA0005")

    print(f"    [OK] {len(services)} services ({len(running)} actifs)")

def analyze_ports():
    """Analyse les ports ouverts"""
    print("2.6 Analyse ports...")

    data = load_json("ports.json")
    if not data:
        print("    [ERREUR] ports.json non trouvé")
        return

    ports = data if isinstance(data, list) else []
    listening = [p for p in ports if p.get("state") == "Listen"]
    established = [p for p in ports if p.get("state") == "Established"]

    sensitive_ports = {
        21: "FTP (non chiffré — credentials en clair)",
        23: "Telnet (non chiffré — remplacer par SSH)",
        25: "SMTP (relai email — risque de spam/exfiltration)",
        135: "RPC DCOM (surface d'attaque importante)",
        139: "NetBIOS (protocole obsolète et non sécurisé)",
        445: "SMB (risque EternalBlue/ransomware)",
        3389: "RDP (cible principale des attaques par force brute)",
        5900: "VNC (accès bureau à distance non sécurisé)",
        4444: "Port Metasploit/shells inversés classique",
        1433: "MSSQL (base de données exposée)",
        3306: "MySQL (base de données exposée)",
    }

    STATS["ports"] = {
        "total": len(ports),
        "listening": len(listening),
        "established": len(established),
        "list": ports
    }

    for port_info in ports:
        port = port_info.get("local_port")
        if port in sensitive_ports:
            add_alert("medium", f"Port sensible ouvert: {port} ({sensitive_ports[port].split(' (')[0]})",
                      "Réseau", f"Processus: {port_info.get('process_name', 'N/A')} — {sensitive_ports[port]}",
                      f"Bloquer le port {port} si non nécessaire: New-NetFirewallRule -Action Block -Direction Inbound -LocalPort {port} -Protocol TCP",
                      "TA0001")

    external = [p for p in established
                if not str(p.get("remote_address", "")).startswith(("127.", "::1", "0.", "::"))]
    if external:
        add_alert("low", f"{len(external)} connexions externes établies",
                  "Réseau", f"Connexions actives vers des adresses distantes: {len(external)} trouvées",
                  "Analyser avec TCPView (SysInternals) ou: netstat -an | findstr ESTABLISHED",
                  "TA0011")

    print(f"    [OK] {len(ports)} connexions ({len(listening)} en écoute)")

def analyze_defender():
    """Analyse l'état de Microsoft Defender"""
    print("2.7 Analyse Defender...")

    data = load_json("defender.json")
    if not data:
        print("    [ERREUR] defender.json non trouvé")
        return

    STATS["defender"] = data

    if data.get("antivirus_enabled") is False:
        add_alert("critical", "Antivirus Windows Désactivé",
                  "Sécurité", "La protection antivirus est inactive — système vulnérable",
                  "Réactiver via PowerShell: Set-MpPreference -DisableRealtimeMonitoring $false ou via Windows Security",
                  "TA0005")

    if data.get("realtime_protection") is False:
        add_alert("critical", "Protection Temps Réel Désactivée",
                  "Sécurité", "Les menaces actives ne sont pas bloquées en temps réel",
                  "Réactiver: Set-MpPreference -DisableRealtimeMonitoring $false",
                  "TA0005")

    age = data.get("antivirus_signature_age")
    if age is not None:
        try:
            if int(age) > 7:
                add_alert("high", f"Signatures antivirus obsolètes ({age} jours sans mise à jour)",
                          "Sécurité", "Nouvelles menaces potentiellement non détectées",
                          "Mettre à jour les signatures: Update-MpSignature ou Windows Security > Virus protection > Update",
                          "TA0005")
        except (ValueError, TypeError):
            pass

    enabled = data.get("antivirus_enabled", False)
    realtime = data.get("realtime_protection", False)
    print(f"    [OK] Antivirus: {'Actif' if enabled else 'INACTIF'}, Temps Réel: {'Actif' if realtime else 'INACTIF'}")

def analyze_firewall():
    """Analyse l'état du pare-feu"""
    print("2.8 Analyse pare-feu...")

    data = load_json("firewall.json")
    if not data:
        print("    [ERREUR] firewall.json non trouvé")
        return

    profiles = data.get("profiles", []) if isinstance(data, dict) else []
    enabled_profiles = [p for p in profiles if p.get("enabled")]
    disabled_profiles = [p for p in profiles if not p.get("enabled")]

    STATS["firewall"] = {
        "profiles_total": len(profiles),
        "profiles_enabled": len(enabled_profiles),
        "profiles_disabled": len(disabled_profiles),
        "profiles": profiles,
        "status": data.get("status", "")
    }

    for profile in disabled_profiles:
        add_alert("high", f"Pare-feu désactivé: profil {profile.get('name', 'N/A')}",
                  "Réseau", f"Le profil {profile.get('name')} du pare-feu est inactif",
                  f"Réactiver: Set-NetFirewallProfile -Profile {profile.get('name', 'All')} -Enabled True",
                  "TA0005")

    print(f"    [OK] {len(enabled_profiles)}/{len(profiles)} profils pare-feu actifs")

def analyze_events():
    """Analyse les événements Windows"""
    print("2.9 Analyse événements...")

    data = load_json("events.json")
    if not data:
        print("    [ERREUR] events.json non trouvé")
        return

    events = data.get("events", []) if isinstance(data, dict) else []
    security_events = [e for e in events if e.get("log_name") == "Security"]
    system_events   = [e for e in events if e.get("log_name") == "System"]
    app_events      = [e for e in events if e.get("log_name") == "Application"]

    # Compter les événements par ID
    event_ids = Counter(e.get("event_id") for e in events)

    # Détection brute force: regrouper les 4625 par compte ciblé
    failed_logins = [e for e in events if e.get("event_id") == 4625]
    account_failures = Counter()
    for ev in failed_logins:
        msg = ev.get("message", "")
        m = re.search(r'Nom du compte\s*:\s*([^\r\n\t]+)', msg)
        if not m:
            m = re.search(r'Account Name\s*:\s*([^\r\n\t]+)', msg)
        if m:
            acc = m.group(1).strip()
            if acc and acc not in ("-", ""):
                account_failures[acc] += 1

    brute_force_targets = []
    for acc, count in account_failures.items():
        if count >= 3:
            brute_force_targets.append({"account": acc, "failures": count})
            severity = "critical" if count >= 20 else "high"
            add_alert(severity, f"Force brute possible: {count} échecs pour '{acc}'",
                      "Événements", f"Compte ciblé: {acc}, Échecs sur 7 jours: {count}",
                      "Activer le verrouillage de compte (Account Lockout Policy) via: secpol.msc > Account Policies",
                      "TA0006")

    STATS["events"] = {
        "total": data.get("total_events", 0),
        "security": len(security_events),
        "system": len(system_events),
        "application": len(app_events),
        "date_range": data.get("date_range", "N/A"),
        "event_id_counts": dict(event_ids.most_common(20)),
        "brute_force_targets": brute_force_targets,
        "failed_logins": len(failed_logins),
    }

    # Alertes événements
    event_alerts = {
        4625: ("Échec de connexion détecté", "high",
               "Investiguer la source — activer Account Lockout Policy via secpol.msc", "TA0006"),
        4720: ("Nouveau compte utilisateur créé", "medium",
               "Vérifier si la création est autorisée: Get-LocalUser pour lister tous les comptes", "TA0003"),
        4726: ("Compte utilisateur supprimé", "medium",
               "Vérifier dans les logs qui a supprimé ce compte et pourquoi", "TA0003"),
        7045: ("Nouveau service installé", "high",
               "Vérifier le service: Get-Service | Where StartType -eq Automatic | sort Name", "TA0003"),
    }

    processed_ids = set()
    for event in events:
        eid = event.get("event_id")
        if eid in event_alerts and eid not in processed_ids:
            msg, severity, rem, mitre = event_alerts[eid]
            count = event_ids.get(eid, 1)
            add_alert(severity, f"Événement {eid}: {msg} ({count} occurrence(s))",
                      "Événements", event.get("message", "")[:120],
                      rem, mitre)
            processed_ids.add(eid)

    print(f"    [OK] {data.get('total_events', 0)} événements ({len(failed_logins)} échecs connexion)")

# =============================================================================
# SCORE DE RISQUE GLOBAL
# =============================================================================

def compute_risk_score():
    """Calcule le score de risque global (0-100) à partir des alertes"""
    n_crit = len(ALERT_SEVERITY["critical"])
    n_high = len(ALERT_SEVERITY["high"])
    n_med  = len(ALERT_SEVERITY["medium"])
    n_low  = len(ALERT_SEVERITY["low"])

    score = min(100,
        min(40, n_crit * 20) +
        min(30, n_high * 5) +
        min(20, n_med * 3) +
        min(10, n_low * 1)
    )

    if score >= 70:
        level = "Critique"
        level_class = "critique"
    elif score >= 40:
        level = "Élevé"
        level_class = "eleve"
    elif score >= 20:
        level = "Modéré"
        level_class = "modere"
    else:
        level = "Faible"
        level_class = "faible"

    RISK_SCORE["total"] = score
    RISK_SCORE["level"] = level
    RISK_SCORE["level_class"] = level_class
    RISK_SCORE["breakdown"] = {
        "critiques": n_crit,
        "hautes": n_high,
        "moyennes": n_med,
        "basses": n_low,
    }
    print(f"    [OK] Score de risque: {score}/100 ({level})")
    return score

# =============================================================================
# GÉNÉRATION DU TABLEAU DE BORD HTML INTERACTIF
# =============================================================================

def generate_html_dashboard():
    """Génère le tableau de bord HTML interactif complet"""
    print("\n3. Génération du tableau de bord HTML interactif...")

    # Préparer les alertes avec IDs uniques
    all_alerts = []
    for sev in ["critical", "high", "medium", "low"]:
        for alert in ALERT_SEVERITY[sev]:
            a = dict(alert)
            a["id"] = f"ALT-{len(all_alerts)+1:04d}"
            all_alerts.append(a)

    # Données embarquées dans le JS
    embedded = {
        "system": STATS.get("system", {}),
        "users": STATS.get("users", {}),
        "administrators": STATS.get("administrators", {}),
        "processes": STATS.get("processes", {}),
        "services": STATS.get("services", {}),
        "ports": STATS.get("ports", {}),
        "defender": STATS.get("defender", {}),
        "firewall": STATS.get("firewall", {}),
        "events": STATS.get("events", {}),
        "alerts": all_alerts,
        "risk_score": RISK_SCORE,
        "alert_counts": {
            "critical": len(ALERT_SEVERITY["critical"]),
            "high": len(ALERT_SEVERITY["high"]),
            "medium": len(ALERT_SEVERITY["medium"]),
            "low": len(ALERT_SEVERITY["low"]),
            "total": len(all_alerts),
        },
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }

    data_json = json.dumps(embedded, ensure_ascii=False, default=str)
    data_json_safe = data_json.replace("</script>", "<\\/script>")

    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    risk_total = RISK_SCORE["total"]
    risk_level = RISK_SCORE["level"]
    risk_class = RISK_SCORE["level_class"]

    # --- CSS ---
    css = """
:root {
    --bg: #f4f5f7; --bg2: #ffffff; --bg3: #ebecf0;
    --text: #172b4d; --text-muted: #6b778c;
    --accent: #0052cc; --accent-hover: #0747a6;
    --border: #dfe1e6; --card-bg: #ffffff;
    --card-shadow: 0 1px 3px rgba(9,30,66,.12),0 0 1px rgba(9,30,66,.08);
    --success: #36b37e; --warning: #ff8b00; --danger: #de350b; --info: #0052cc;
    --nav-bg: #0b1d35; --footer-bg: #091928;
}
body.dark-mode {
    --bg: #0d1117; --bg2: #161b22; --bg3: #21262d;
    --text: #c9d1d9; --text-muted: #8b949e;
    --accent: #58a6ff; --accent-hover: #79b8ff;
    --border: #30363d; --card-bg: #161b22;
    --card-shadow: 0 1px 3px rgba(0,0,0,.4),0 0 1px rgba(0,0,0,.3);
    --success: #3fb950; --warning: #d29922; --danger: #f85149; --info: #58a6ff;
    --nav-bg: #010409; --footer-bg: #010409;
}
* { margin:0; padding:0; box-sizing:border-box; }
body { font-family:'Segoe UI',Arial,sans-serif; background:var(--bg); color:var(--text); min-height:100vh; transition:background 0.3s,color 0.3s; }
a { color:var(--accent); }
/* ── HEADER ── */
.header { background:var(--nav-bg); padding:16px 28px; display:flex; align-items:center; justify-content:space-between; gap:12px; flex-wrap:wrap; border-bottom:3px solid var(--accent); }
.header-info h1 { font-size:1.3em; color:#ffffff; font-weight:700; letter-spacing:.2px; }
.header-info p { color:rgba(255,255,255,.60); font-size:.8em; margin-top:3px; }
.header-right { display:flex; align-items:center; gap:10px; flex-wrap:wrap; }
.theme-btn { background:transparent; border:1px solid rgba(255,255,255,.3); color:rgba(255,255,255,.85); padding:6px 14px; border-radius:3px; cursor:pointer; font-size:.78em; letter-spacing:.3px; }
.theme-btn:hover { background:rgba(255,255,255,.1); border-color:rgba(255,255,255,.6); }
.risk-pill { padding:5px 13px; border-radius:3px; font-weight:700; font-size:.78em; color:#fff; letter-spacing:.5px; }
.rp-faible  { background:#36b37e; }
.rp-modere  { background:#ff8b00; }
.rp-eleve   { background:#ff5630; }
.rp-critique{ background:#de350b; }
/* ── TABS ── */
.tab-bar { background:var(--bg2); border-bottom:1px solid var(--border); display:flex; overflow-x:auto; padding:0 20px; scrollbar-width:thin; box-shadow:0 1px 0 var(--border); }
.tab-btn { padding:12px 16px; border:none; background:none; color:var(--text-muted); cursor:pointer; font-size:.85em; white-space:nowrap; border-bottom:2px solid transparent; margin-bottom:-1px; transition:color .15s,border-color .15s; font-weight:500; }
.tab-btn:hover { color:var(--accent); }
.tab-btn.active { color:var(--accent); border-bottom-color:var(--accent); font-weight:600; }
/* ── LAYOUT ── */
.container { max-width:1440px; margin:0 auto; padding:24px; }
.tab-content { display:none; }
.tab-content.active { display:block; }
/* ── CARDS ── */
.cards-row { display:grid; grid-template-columns:repeat(auto-fit,minmax(170px,1fr)); gap:16px; margin-bottom:24px; }
.card { background:var(--card-bg); border-radius:4px; padding:18px 20px; border-top:3px solid var(--border); box-shadow:var(--card-shadow); }
.card.c-crit { border-top-color:var(--danger); }
.card.c-high { border-top-color:var(--warning); }
.card.c-med  { border-top-color:var(--info); }
.card.c-low  { border-top-color:var(--success); }
.card.c-info { border-top-color:var(--accent); }
.card h3 { font-size:.7em; text-transform:uppercase; letter-spacing:1.2px; color:var(--text-muted); margin-bottom:8px; font-weight:600; }
.card .val { font-size:2em; font-weight:700; color:var(--text); }
.card .sub { font-size:.76em; color:var(--text-muted); margin-top:4px; }
/* ── SECTION ── */
.section { background:var(--card-bg); border-radius:4px; padding:20px; margin-bottom:16px; box-shadow:var(--card-shadow); border:1px solid var(--border); }
.sec-head { display:flex; justify-content:space-between; align-items:center; margin-bottom:16px; padding-bottom:12px; border-bottom:1px solid var(--border); flex-wrap:wrap; gap:8px; }
.sec-head h2 { color:var(--text); font-size:1em; font-weight:600; }
/* ── GRIDS ── */
.g2 { display:grid; grid-template-columns:1fr 1fr; gap:16px; }
.g3 { display:grid; grid-template-columns:1fr 1fr 1fr; gap:16px; }
@media(max-width:900px){.g2,.g3{grid-template-columns:1fr;}}
/* ── CHARTS ── */
.chart-box { position:relative; height:260px; }
.chart-box-sm { position:relative; height:190px; }
.chart-offline { display:none; text-align:center; padding:30px 10px; color:var(--text-muted); font-size:.85em; }
/* ── TABLES ── */
.tbl-wrap { overflow-x:auto; }
table { width:100%; border-collapse:collapse; }
th { background:var(--bg3); color:var(--text); padding:9px 12px; text-align:left; font-size:.78em; cursor:pointer; user-select:none; white-space:nowrap; font-weight:600; text-transform:uppercase; letter-spacing:.6px; }
th:hover { color:var(--accent); }
th.sa::after { content:' ▲'; font-size:.65em; opacity:.7; }
th.sd::after { content:' ▼'; font-size:.65em; opacity:.7; }
td { padding:9px 12px; border-bottom:1px solid var(--border); font-size:.85em; max-width:280px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; color:var(--text); }
tr:hover td { background:rgba(0,82,204,.04); }
td.wrap { white-space:normal; word-break:break-word; max-width:320px; }
/* ── SEARCH ── */
.search-box { width:100%; padding:7px 12px; background:var(--bg2); border:2px solid var(--border); border-radius:3px; color:var(--text); font-size:.85em; margin-bottom:12px; }
.search-box:focus { outline:none; border-color:var(--accent); }
/* ── BADGES ── */
.badge { display:inline-block; padding:2px 8px; border-radius:3px; font-size:.72em; font-weight:700; letter-spacing:.3px; }
.b-crit  { background:#ffebe6; color:#de350b; }
.b-high  { background:#fffae6; color:#974f0c; }
.b-med   { background:#e6f0ff; color:#0052cc; }
.b-low   { background:#e3fcef; color:#006644; }
.b-ok    { background:#e3fcef; color:#006644; }
.b-stop  { background:#ffebe6; color:#de350b; }
.b-na    { background:#f4f5f7; color:#6b778c; }
body.dark-mode .b-crit  { background:rgba(248,81,73,.18); color:#f85149; }
body.dark-mode .b-high  { background:rgba(210,153,34,.18); color:#d29922; }
body.dark-mode .b-med   { background:rgba(88,166,255,.18); color:#58a6ff; }
body.dark-mode .b-low   { background:rgba(63,185,80,.18); color:#3fb950; }
body.dark-mode .b-ok    { background:rgba(63,185,80,.18); color:#3fb950; }
body.dark-mode .b-stop  { background:rgba(248,81,73,.18); color:#f85149; }
body.dark-mode .b-na    { background:rgba(139,148,158,.15); color:#8b949e; }
/* ── STATUS DOT ── */
.dot { display:inline-block; width:8px; height:8px; border-radius:50%; margin-right:5px; vertical-align:middle; }
.d-green{background:#36b37e;} .d-red{background:#de350b;} .d-gray{background:#97a0af;}
/* ── FILTER BUTTONS ── */
.flt-row { display:flex; gap:6px; flex-wrap:wrap; margin-bottom:12px; }
.flt-btn { padding:5px 12px; border:1px solid var(--border); border-radius:3px; background:var(--bg2); color:var(--text-muted); cursor:pointer; font-size:.78em; font-weight:500; }
.flt-btn.active,.flt-btn:hover { background:var(--accent); color:#fff; border-color:var(--accent); }
/* ── PAGINATION ── */
.pg-row { display:flex; justify-content:center; align-items:center; gap:4px; padding:12px 0 2px; flex-wrap:wrap; }
.pg-btn { padding:5px 10px; border:1px solid var(--border); border-radius:3px; background:var(--bg2); color:var(--text); cursor:pointer; font-size:.78em; }
.pg-btn.active { background:var(--accent); color:#fff; border-color:var(--accent); }
.pg-btn:hover:not(.active):not(:disabled) { border-color:var(--accent); color:var(--accent); }
.pg-btn:disabled { opacity:.4; cursor:default; }
.pg-info { font-size:.78em; color:var(--text-muted); padding:0 4px; }
/* ── ACTION BTNS ── */
.btn { padding:7px 14px; border:none; border-radius:3px; cursor:pointer; font-size:.82em; font-weight:500; }
.btn-acc { background:var(--accent); color:#fff; }
.btn-acc:hover { background:var(--accent-hover); }
.btn-out { background:transparent; border:1px solid var(--border); color:var(--text); border-radius:3px; }
.btn-out:hover { border-color:var(--accent); color:var(--accent); }
/* ── REMEDIATION PANEL ── */
#rem-panel { position:fixed; top:0; right:0; width:420px; max-width:95vw; height:100vh; background:var(--bg2); border-left:1px solid var(--border); padding:24px; transform:translateX(100%); transition:transform .25s ease; z-index:1000; overflow-y:auto; box-shadow:-4px 0 20px rgba(9,30,66,.15); }
#rem-panel.open { transform:translateX(0); }
.rem-head { display:flex; justify-content:space-between; align-items:flex-start; margin-bottom:18px; padding-bottom:14px; border-bottom:1px solid var(--border); }
.rem-title { font-size:.9em; font-weight:600; color:var(--text); flex:1; margin-right:10px; line-height:1.5; }
.close-btn { background:none; border:none; color:var(--text-muted); cursor:pointer; font-size:1.2em; padding:0; flex-shrink:0; line-height:1; }
.rem-lbl { font-size:.68em; text-transform:uppercase; letter-spacing:1px; color:var(--text-muted); margin:14px 0 5px; font-weight:600; }
.rem-body { font-size:.875em; line-height:1.65; background:var(--bg3); padding:12px 14px; border-radius:3px; border-left:3px solid var(--accent); }
.mitre-chip { display:inline-block; background:rgba(0,82,204,.1); color:var(--accent); border:1px solid rgba(0,82,204,.25); padding:3px 10px; border-radius:3px; font-size:.74em; margin-top:6px; font-weight:600; }
body.dark-mode .mitre-chip { background:rgba(88,166,255,.12); border-color:rgba(88,166,255,.3); }
/* ── OVERLAY ── */
#overlay { display:none; position:fixed; top:0; left:0; width:100%; height:100%; background:rgba(9,30,66,.55); z-index:999; }
#overlay.on { display:block; }
/* ── RISK GAUGE ── */
.gauge-wrap { text-align:center; padding:10px 0; }
.gauge-num { font-size:2.8em; font-weight:700; line-height:1; margin-top:-36px; }
.gauge-lbl { font-size:.82em; font-weight:700; text-transform:uppercase; letter-spacing:2px; margin-top:8px; }
.gc-faible  { color:#36b37e; } .gc-modere  { color:#ff8b00; }
.gc-eleve   { color:#ff5630; } .gc-critique{ color:#de350b; }
/* ── INFO ROWS ── */
.irow { display:flex; align-items:baseline; padding:9px 0; border-bottom:1px solid var(--border); }
.irow:last-child { border-bottom:none; }
.ilbl { color:var(--text-muted); font-size:.8em; width:170px; flex-shrink:0; font-weight:500; }
.ival { font-size:.875em; font-weight:500; }
/* ── DETAIL BTN ── */
.det-btn { padding:3px 9px; background:var(--bg3); border:1px solid var(--border); border-radius:3px; cursor:pointer; font-size:.72em; color:var(--text-muted); white-space:nowrap; }
.det-btn:hover { border-color:var(--accent); color:var(--accent); }
/* ── EMPTY STATE ── */
.empty { text-align:center; padding:36px; color:var(--text-muted); font-size:.88em; }
/* ── FOOTER ── */
.footer { background:var(--footer-bg); color:rgba(255,255,255,.45); text-align:center; padding:18px 20px; font-size:.78em; margin-top:10px; }
/* ── SCROLLBAR ── */
::-webkit-scrollbar { width:5px; height:5px; }
::-webkit-scrollbar-track { background:var(--bg); }
::-webkit-scrollbar-thumb { background:var(--border); border-radius:3px; }
::-webkit-scrollbar-thumb:hover { background:var(--accent); }
"""

    # --- JavaScript ---
    js = r"""
// ─── UTILS ───
function esc(s) {
    return String(s == null ? '' : s)
        .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
function badge(sev) {
    const m = {critical:'b-crit CRITIQUE',high:'b-high HAUTE',medium:'b-med MOYENNE',low:'b-low BASSE'};
    const p = (m[sev]||'b-na N/A').split(' ');
    return `<span class="badge ${p[0]}">${p[1]}</span>`;
}
function dot(on) {
    return on ? '<span class="dot d-green"></span>' : '<span class="dot d-red"></span>';
}

// ─── TABS ───
function showTab(id) {
    document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
    document.querySelectorAll('.tab-btn').forEach(el => el.classList.remove('active'));
    const tc = document.getElementById('t-' + id);
    const tb = document.querySelector('[data-tab="'+id+'"]');
    if (tc) tc.classList.add('active');
    if (tb) tb.classList.add('active');
}

// ─── THEME ───
let _dark = false;
function toggleTheme() {
    _dark = !_dark;
    document.body.classList.toggle('dark-mode');
    document.getElementById('theme-btn').textContent = _dark ? 'Mode Clair' : 'Mode Sombre';
    redrawCharts();
}

// ─── CHARTS ───
const CHARTS = {};
function cTheme() {
    return {
        txt: getComputedStyle(document.body).getPropertyValue('--text').trim() || '#eee',
        grid: _dark ? 'rgba(255,255,255,0.08)' : 'rgba(0,0,0,0.08)',
        bg2: getComputedStyle(document.body).getPropertyValue('--bg2').trim() || '#16213e'
    };
}
function redrawCharts() {
    const t = cTheme();
    Object.values(CHARTS).forEach(c => {
        if (!c) return;
        if (c.options.scales && c.options.scales.x) c.options.scales.x.ticks.color = t.txt;
        if (c.options.scales && c.options.scales.y) c.options.scales.y.ticks.color = t.txt;
        if (c.options.plugins && c.options.plugins.legend) c.options.plugins.legend.labels.color = t.txt;
        c.update();
    });
}
function initCharts() {
    if (typeof Chart === 'undefined') {
        document.querySelectorAll('.chart-offline').forEach(el => el.style.display = 'block');
        document.querySelectorAll('.chart-box canvas,.chart-box-sm canvas').forEach(el => el.style.display = 'none');
        return;
    }
    Chart.defaults.font.family = "'Segoe UI', Arial, sans-serif";
    const t = cTheme();
    const ac = DATA.alert_counts || {};
    const rs = DATA.risk_score || {};
    const rsc = rs.total || 0;
    const rColor = rsc>=70?'#e74c3c':rsc>=40?'#e67e22':rsc>=20?'#f39c12':'#27ae60';

    // A — Risk gauge
    const ca = document.getElementById('ch-risk');
    if (ca) CHARTS.risk = new Chart(ca, {
        type:'doughnut',
        data:{ datasets:[{ data:[rsc,100-rsc], backgroundColor:[rColor,'rgba(255,255,255,0.06)'], borderWidth:0 }] },
        options:{ circumference:180, rotation:-90, cutout:'72%',
            animation:{ duration:1100 },
            plugins:{ legend:{display:false}, tooltip:{enabled:false} } }
    });

    // B — Severity distribution
    const cb = document.getElementById('ch-sev');
    if (cb) CHARTS.sev = new Chart(cb, {
        type:'bar',
        data:{ labels:['Critique','Haute','Moyenne','Basse'],
               datasets:[{ data:[ac.critical||0,ac.high||0,ac.medium||0,ac.low||0],
                           backgroundColor:['#e74c3c','#f39c12','#3498db','#27ae60'], borderRadius:5 }] },
        options:{ responsive:true, maintainAspectRatio:false,
            plugins:{ legend:{display:false} },
            scales:{ y:{beginAtZero:true,grid:{color:t.grid},ticks:{color:t.txt}},
                     x:{grid:{display:false},ticks:{color:t.txt}} } }
    });

    // C — Top processes RAM
    const procs = (DATA.processes&&DATA.processes.top_memory||[]).slice(0,12);
    const cc = document.getElementById('ch-proc');
    if (cc) CHARTS.proc = new Chart(cc, {
        type:'bar',
        data:{ labels:procs.map(p=>p.name),
               datasets:[{ label:'Mémoire (MB)', data:procs.map(p=>+(p.memory_mb||0).toFixed(1)),
                           backgroundColor:'rgba(0,82,204,0.75)', borderColor:'#0052cc', borderWidth:1, borderRadius:2 }] },
        options:{ indexAxis:'y', responsive:true, maintainAspectRatio:false,
            plugins:{ legend:{display:false} },
            scales:{ x:{beginAtZero:true,grid:{color:t.grid},ticks:{color:t.txt}},
                     y:{grid:{display:false},ticks:{color:t.txt,font:{size:11}}} } }
    });

    // D — Services pie
    const sv = DATA.services || {};
    const cd = document.getElementById('ch-svc');
    if (cd) CHARTS.svc = new Chart(cd, {
        type:'doughnut',
        data:{ labels:['Running','Stopped'],
               datasets:[{ data:[sv.running||0,sv.stopped||0],
                           backgroundColor:['#27ae60','#e74c3c'], borderWidth:2, borderColor:t.bg2 }] },
        options:{ responsive:true, maintainAspectRatio:false, cutout:'58%',
            plugins:{ legend:{display:true,position:'bottom',labels:{color:t.txt,padding:10,font:{size:11}}} } }
    });

    // E — Events by log
    const ev = DATA.events || {};
    const ce = document.getElementById('ch-ev');
    if (ce) CHARTS.ev = new Chart(ce, {
        type:'bar',
        data:{ labels:['Sécurité','Système','Application'],
               datasets:[{ label:'Événements', data:[ev.security||0,ev.system||0,ev.application||0],
                           backgroundColor:['#e74c3c','#f39c12','#3498db'], borderRadius:5 }] },
        options:{ responsive:true, maintainAspectRatio:false,
            plugins:{ legend:{display:false} },
            scales:{ y:{beginAtZero:true,grid:{color:t.grid},ticks:{color:t.txt}},
                     x:{grid:{display:false},ticks:{color:t.txt}} } }
    });

    // F — Top alert categories
    const catCounts = {};
    (DATA.alerts||[]).forEach(a => { catCounts[a.category] = (catCounts[a.category]||0)+1; });
    const cats = Object.entries(catCounts).sort((a,b)=>b[1]-a[1]).slice(0,8);
    const cf = document.getElementById('ch-cat');
    if (cf) CHARTS.cat = new Chart(cf, {
        type:'bar',
        data:{ labels:cats.map(([k])=>k),
               datasets:[{ label:"Alertes", data:cats.map(([,v])=>v),
                           backgroundColor:'rgba(7,71,166,0.75)', borderColor:'#0747a6', borderWidth:1, borderRadius:2 }] },
        options:{ indexAxis:'y', responsive:true, maintainAspectRatio:false,
            plugins:{ legend:{display:false} },
            scales:{ x:{beginAtZero:true,grid:{color:t.grid},ticks:{color:t.txt}},
                     y:{grid:{display:false},ticks:{color:t.txt}} } }
    });
}

// ─── SORTING ───
const _sortState = {};
function sortTable(tableId, col, type) {
    type = type||'text';
    const key = tableId+'_'+col;
    const asc = _sortState[key] !== 'asc';
    _sortState[key] = asc ? 'asc' : 'desc';
    const table = document.getElementById(tableId);
    if (!table) return;
    table.querySelectorAll('th').forEach((th,i) => {
        th.classList.remove('sa','sd');
        if (i===col) th.classList.add(asc?'sa':'sd');
    });
    const tbody = table.querySelector('tbody');
    const rows = Array.from(tbody.querySelectorAll('tr[data-r]'));
    rows.sort((a,b) => {
        const av = a.cells[col]&&(a.cells[col].dataset.s||a.cells[col].textContent.trim())||'';
        const bv = b.cells[col]&&(b.cells[col].dataset.s||b.cells[col].textContent.trim())||'';
        if (type==='num') return asc?(+av||0)-(+bv||0):(+bv||0)-(+av||0);
        return asc?av.localeCompare(bv,'fr'):bv.localeCompare(av,'fr');
    });
    rows.forEach(r => tbody.appendChild(r));
    if (tableId==='t-svc') pgRender('t-svc','pg-svc');
    if (tableId==='t-proc') pgRender('t-proc','pg-proc');
}

// ─── SEARCH ───
function setupSearch(inId, tableId) {
    const inp = document.getElementById(inId);
    if (!inp) return;
    inp.addEventListener('input', function() {
        const f = this.value.toLowerCase();
        document.querySelectorAll('#'+tableId+' tbody tr[data-r]').forEach(r => {
            r.style.display = r.textContent.toLowerCase().includes(f) ? '' : 'none';
        });
        if (tableId==='t-svc') { pgState['t-svc']&&(pgState['t-svc'].p=1); pgRender('t-svc','pg-svc'); }
        if (tableId==='t-proc') { pgState['t-proc']&&(pgState['t-proc'].p=1); pgRender('t-proc','pg-proc'); }
    });
}

// ─── PAGINATION ───
const pgState = {};
function pgSetup(tableId, size) { pgState[tableId] = { p:1, size }; }
function pgRender(tableId, cId) {
    const st = pgState[tableId]; if (!st) return;
    const tbody = document.querySelector('#'+tableId+' tbody'); if (!tbody) return;
    const rows = Array.from(tbody.querySelectorAll('tr[data-r]')).filter(r=>r.style.display!=='none');
    const tot = rows.length;
    const tp = Math.ceil(tot/st.size)||1;
    if (st.p > tp) st.p = tp;
    // Show/hide rows based on ALL rows (not just visible)
    const allRows = Array.from(tbody.querySelectorAll('tr[data-r]'));
    let vis = 0;
    allRows.forEach(r => {
        if (r.style.display==='none') return; // filtered out by search
        vis++;
        const page = Math.ceil(vis/st.size);
        r.style.display = (page===st.p) ? '' : 'none';
    });
    const cont = document.getElementById(cId); if (!cont) return;
    const s = (st.p-1)*st.size+1, e = Math.min(st.p*st.size,tot);
    if (tp<=1) { cont.innerHTML = `<span class="pg-info">${tot} entrée${tot!==1?'s':''}</span>`; return; }
    let h = `<span class="pg-info">${s}–${e} sur ${tot}</span>`;
    h += `<button class="pg-btn" onclick="pgGo('${tableId}','${cId}',${st.p-1})" ${st.p===1?'disabled':''}>‹</button>`;
    for (let p=1;p<=tp;p++) {
        if (p===1||p===tp||(p>=st.p-1&&p<=st.p+1)) h += `<button class="pg-btn ${p===st.p?'active':''}" onclick="pgGo('${tableId}','${cId}',${p})">${p}</button>`;
        else if (h.slice(-15)!=='…</span>') h += `<span style="color:var(--text-muted);padding:0 3px">…</span>`;
    }
    h += `<button class="pg-btn" onclick="pgGo('${tableId}','${cId}',${st.p+1})" ${st.p===tp?'disabled':''}>›</button>`;
    cont.innerHTML = h;
}
function pgGo(tableId, cId, p) {
    const st = pgState[tableId]; if (!st) return;
    const tbody = document.querySelector('#'+tableId+' tbody');
    const tot = Array.from(tbody.querySelectorAll('tr[data-r]')).filter(r=>r.style.display!=='none'&&r.style.display!=='').length||
                Array.from(tbody.querySelectorAll('tr[data-r]')).length;
    st.p = Math.max(1, Math.min(p, Math.ceil(tot/st.size)||1));
    pgRender(tableId, cId);
}

// ─── ALERT FILTER ───
let _alertSev = 'all';
function filterAlerts(sev) {
    _alertSev = sev;
    document.querySelectorAll('.af-btn').forEach(b => b.classList.toggle('active', b.dataset.sev===sev));
    document.querySelectorAll('#t-alerts tbody tr[data-r]').forEach(r => {
        r.style.display = (sev==='all'||r.dataset.sev===sev) ? '' : 'none';
    });
}

// ─── SERVICES FILTER ───
function filterSvc(status) {
    document.querySelectorAll('.sf-btn').forEach(b => b.classList.toggle('active', b.dataset.st===status));
    document.querySelectorAll('#t-svc tbody tr[data-r]').forEach(r => {
        const txt = r.textContent;
        r.style.display = (status==='all'||(status==='run'&&txt.includes('Running'))||(status==='stop'&&txt.includes('Stopped'))) ? '':'none';
    });
    pgState['t-svc']&&(pgState['t-svc'].p=1);
    pgRender('t-svc','pg-svc');
}

// ─── CSV EXPORT ───
function exportCSV() {
    const alts = (DATA.alerts||[]).filter(a=>_alertSev==='all'||a.severity===_alertSev);
    const hdr = ['ID','Horodatage','Sévérité','Catégorie','Message','Détails','Remédiation','MITRE'];
    const rows = alts.map(a=>[a.id||'',a.timestamp||'',a.severity||'',a.category||'',a.message||'',a.details||'',a.remediation||'',a.mitre_tactic||'']);
    const csv = [hdr,...rows].map(r=>r.map(v=>'"'+String(v).replace(/"/g,'""')+'"').join(',')).join('\n');
    const blob = new Blob(['﻿'+csv],{type:'text/csv;charset=utf-8'});
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a'); a.href=url; a.download='alertes-'+new Date().toISOString().split('T')[0]+'.csv'; a.click();
    URL.revokeObjectURL(url);
}

// ─── REMEDIATION PANEL ───
function openRem(id) {
    const a = (DATA.alerts||[]).find(x=>x.id===id); if (!a) return;
    document.getElementById('rem-t').textContent = a.message||'';
    document.getElementById('rem-sev').innerHTML = badge(a.severity);
    document.getElementById('rem-cat').textContent = a.category||'';
    document.getElementById('rem-det').textContent = a.details||'Aucun détail disponible.';
    document.getElementById('rem-fix').textContent = a.remediation||'Aucune remédiation définie.';
    const me = document.getElementById('rem-mitre');
    if (a.mitre_tactic) {
        me.innerHTML = `<span class="mitre-chip">${a.mitre_tactic} — ${a.mitre_tactic_name||''}</span>`;
        me.style.display='';
    } else { me.style.display='none'; }
    document.getElementById('rem-panel').classList.add('open');
    document.getElementById('overlay').classList.add('on');
}
function closeRem() {
    document.getElementById('rem-panel').classList.remove('open');
    document.getElementById('overlay').classList.remove('on');
}

// ─── RENDERERS ───
function renderOverview() {
    const sys = DATA.system||{};
    const el = document.getElementById('ov-sys');
    if (el) el.innerHTML = [
        ['Hostname', sys.hostname],['Système', sys.os_name],['Build', sys.os_build],
        ['Modèle', sys.model],['RAM', sys.total_ram_gb?(sys.total_ram_gb+' GB'):'N/A'],
        ['Utilisateur', sys.current_user],['Collecté le', sys.collection_time]
    ].map(([k,v])=>`<div class="irow"><span class="ilbl">${k}</span><span class="ival">${esc(v||'N/A')}</span></div>`).join('');

    const ac = DATA.alert_counts||{};
    const setCard = (id,val) => { const e=document.getElementById(id); if(e) e.textContent=val; };
    setCard('ov-crit',ac.critical||0); setCard('ov-high',ac.high||0);
    setCard('ov-med',ac.medium||0);   setCard('ov-low',ac.low||0);
    setCard('ov-total',ac.total||0);

    const rs = DATA.risk_score||{};
    const gn = document.getElementById('gauge-num');
    const gl = document.getElementById('gauge-lbl');
    const cls = 'gc-'+(rs.level_class||'faible');
    if (gn) { gn.textContent=rs.total||0; gn.className='gauge-num '+cls; }
    if (gl) { gl.textContent=rs.level||'Faible'; gl.className='gauge-lbl '+cls; }
}

function renderSystem() {
    const sys = DATA.system||{};
    const el = document.getElementById('sys-tbl');
    if (!el) return;
    el.innerHTML = [
        ['Hostname',sys.hostname],['Domaine',sys.domain],['Système',sys.os_name],
        ['Version',sys.os_version],['Build',sys.os_build],['Fabricant',sys.manufacturer],
        ['Modèle',sys.model],['RAM',sys.total_ram_gb?(sys.total_ram_gb+' GB'):'N/A'],
        ['Utilisateur courant',sys.current_user],['Heure collecte',sys.collection_time],['Dernier démarrage',sys.last_boot]
    ].map(([k,v])=>`<div class="irow"><span class="ilbl">${k}</span><span class="ival">${esc(v||'N/A')}</span></div>`).join('');
}

function renderUsers() {
    const users = (DATA.users&&DATA.users.users_list)||[];
    const tbody = document.querySelector('#t-users tbody');
    if (!tbody) return;
    if (!users.length) { tbody.innerHTML='<tr><td colspan="4" class="empty">Aucun utilisateur</td></tr>'; return; }
    tbody.innerHTML = users.map(u=>{
        const en = u.enabled;
        return `<tr data-r><td>${esc(u.name)}</td>
        <td>${dot(en)}<span class="badge ${en?'b-ok':'b-na'}">${en?'Actif':'Inactif'}</span></td>
        <td>${esc(u.last_logon||'Jamais')}</td>
        <td style="font-size:.78em;color:var(--text-muted)">${esc(u.sid||'')}</td></tr>`;
    }).join('');
}

function renderAdmins() {
    const admins = (DATA.administrators&&DATA.administrators.list)||[];
    const tbody = document.querySelector('#t-admins tbody');
    if (!tbody) return;
    if (!admins.length) { tbody.innerHTML='<tr><td colspan="3" class="empty">Aucun administrateur trouvé</td></tr>'; return; }
    tbody.innerHTML = admins.map(a=>`<tr data-r>
        <td>${esc(a.name)}</td><td>${esc(a.source||'Local')}</td><td>${esc(a.object_class||'')}</td></tr>`).join('');
}

function renderProcesses() {
    const procs = (DATA.processes&&DATA.processes.all)||(DATA.processes&&DATA.processes.top_memory)||[];
    const tbody = document.querySelector('#t-proc tbody');
    if (!tbody) return;
    tbody.innerHTML = procs.map(p=>{
        const mb = (p.memory_mb||0).toFixed(1);
        const cpu = (p.cpu_time||0).toFixed(2);
        const hasPath = p.path && p.path.trim();
        return `<tr data-r>
            <td>${esc(p.name)}</td>
            <td>${esc(p.pid)}</td>
            <td data-s="${mb}">${mb} MB</td>
            <td data-s="${cpu}">${cpu}s</td>
            <td class="wrap" style="color:${hasPath?'inherit':'var(--text-muted)'}">
                ${esc(hasPath?p.path:'Non disponible')}</td></tr>`;
    }).join('');
    pgSetup('t-proc',25); pgRender('t-proc','pg-proc');
}

function renderServices() {
    const svcs = (DATA.services&&DATA.services.list)||[];
    const tbody = document.querySelector('#t-svc tbody');
    if (!tbody) return;
    tbody.innerHTML = svcs.map(s=>{
        const run = s.status==='Running';
        return `<tr data-r>
            <td>${esc(s.name)}</td>
            <td>${esc(s.display_name)}</td>
            <td>${dot(run)}<span class="badge ${run?'b-ok':'b-stop'}">${s.status||'N/A'}</span></td>
            <td>${esc(s.start_type||'')}</td>
            <td style="font-size:.78em">${esc(s.service_type||'')}</td></tr>`;
    }).join('');
    pgSetup('t-svc',25); pgRender('t-svc','pg-svc');
}

function renderPorts() {
    const ports = (DATA.ports&&DATA.ports.list)||[];
    const tbody = document.querySelector('#t-ports tbody');
    if (!tbody) return;
    const sens = {21:'FTP',23:'Telnet',25:'SMTP',135:'RPC',139:'NetBIOS',445:'SMB',3389:'RDP',5900:'VNC',4444:'Shell',1433:'MSSQL',3306:'MySQL'};
    tbody.innerHTML = ports.map(p=>{
        const sp = sens[p.local_port];
        const portDisp = sp
            ? `<span style="color:var(--warning);font-weight:600">${p.local_port}</span> <span class="badge b-high" style="font-size:.68em">${sp}</span>`
            : esc(p.local_port);
        const isEst = p.state==='Established';
        return `<tr data-r>
            <td>${esc(p.local_address)}</td>
            <td>${portDisp}</td>
            <td><span class="badge ${isEst?'b-med':'b-low'}">${esc(p.state)}</span></td>
            <td>${esc(p.process_name||'N/A')}</td>
            <td>${esc(p.remote_address||'')}</td></tr>`;
    }).join('');
}

function renderSecurity() {
    const def = DATA.defender||{};
    const fw  = DATA.firewall||{};
    const ev  = DATA.events||{};
    const bf  = ev.brute_force_targets||[];

    const de = document.getElementById('sec-def');
    if (de) de.innerHTML = [
        ['Antivirus', def.antivirus_enabled, true],
        ['Protection temps réel', def.realtime_protection, true],
        ['Surveillance comportementale', def.behavior_monitor, true],
        ['Inspection réseau (NIS)', def.nis_enabled, true],
    ].map(([k,v,isBool]) => {
        const disp = isBool ? (v===true?`${dot(true)}<span class="badge b-ok">Actif</span>`
                               :(v===false?`${dot(false)}<span class="badge b-crit">Inactif</span>`
                                :`<span class="badge b-na">N/A</span>`))
                           : esc(v||'N/A');
        return `<div class="irow"><span class="ilbl">${k}</span><span class="ival">${disp}</span></div>`;
    }).join('')
    + `<div class="irow"><span class="ilbl">Version signatures</span><span class="ival">${esc(def.antivirus_signature_version||'N/A')}</span></div>`
    + `<div class="irow"><span class="ilbl">Âge signatures</span><span class="ival">${def.antivirus_signature_age!=null?def.antivirus_signature_age+' jour(s)':'N/A'}</span></div>`
    + `<div class="irow"><span class="ilbl">Dernier scan rapide</span><span class="ival">${esc(def.quick_scan||def.last_scan||'N/A')}</span></div>`;

    const fe = document.getElementById('sec-fw');
    if (fe) {
        const profs = fw.profiles||[];
        fe.innerHTML = profs.length
            ? profs.map(p=>`<div class="irow"><span class="ilbl">${esc(p.name)}</span><span class="ival">
                ${p.enabled?`${dot(true)}<span class="badge b-ok">Actif</span>`:`${dot(false)}<span class="badge b-crit">Inactif</span>`}
               </span></div>`).join('')
            : `<div style="color:var(--text-muted);font-size:.85em;padding:10px 0">${esc(fw.status||'Informations pare-feu non disponibles')}</div>`;
    }

    const ee = document.getElementById('sec-ev');
    if (ee) {
        const idCounts = ev.event_id_counts||{};
        const topIds = Object.entries(idCounts).sort((a,b)=>b[1]-a[1]).slice(0,8);
        const eventNames = {4624:'Connexion réussie',4625:'Connexion échouée',4647:'Déconnexion',
                            4720:'Compte créé',4726:'Compte supprimé',7045:'Service installé',
                            7036:'État service changé',6008:'Arrêt inattendu',1000:'Crash application',4740:'Verrouillage compte'};
        ee.innerHTML = `<div class="irow"><span class="ilbl">Total</span><span class="ival">${ev.total||0}</span></div>`
            +`<div class="irow"><span class="ilbl">Sécurité</span><span class="ival">${ev.security||0}</span></div>`
            +`<div class="irow"><span class="ilbl">Système</span><span class="ival">${ev.system||0}</span></div>`
            +`<div class="irow"><span class="ilbl">Application</span><span class="ival">${ev.application||0}</span></div>`
            +`<div class="irow"><span class="ilbl">Période</span><span class="ival">${esc(ev.date_range||'N/A')}</span></div>`
            +(ev.failed_logins?`<div class="irow"><span class="ilbl">Connexions échouées</span><span class="ival" style="color:var(--warning)">${ev.failed_logins}</span></div>`:'')
            +(bf.length?`<div class="irow"><span class="ilbl">Comptes ciblés (brute)</span><span class="ival" style="color:var(--danger)">${bf.length} compte(s)</span></div>`:'')
            +(topIds.length?`<div style="margin-top:12px;font-size:.8em;color:var(--text-muted);font-weight:600;text-transform:uppercase;letter-spacing:.8px">Top Event IDs</div>`
              +topIds.map(([id,cnt])=>`<div class="irow"><span class="ilbl">ID ${id} — ${eventNames[+id]||'Autre'}</span><span class="ival">${cnt}×</span></div>`).join(''):'');
    }
}

function renderAlerts() {
    const alts = DATA.alerts||[];
    const tbody = document.querySelector('#t-alerts tbody');
    if (!tbody) return;
    if (!alts.length) { tbody.innerHTML='<tr><td colspan="5" class="empty">Aucune alerte détectée</td></tr>'; return; }
    tbody.innerHTML = alts.map(a=>`<tr data-r data-sev="${esc(a.severity)}">
        <td style="font-size:.78em;color:var(--text-muted)">${esc(a.id||'')}</td>
        <td>${badge(a.severity)}</td>
        <td>${esc(a.category)}</td>
        <td class="wrap">${esc(a.message)}</td>
        <td><button class="det-btn" onclick="openRem('${esc(a.id||'')}')">Détails →</button></td>
    </tr>`).join('');
}

// ─── INIT ───
document.addEventListener('DOMContentLoaded', function() {
    renderOverview();
    renderSystem();
    renderUsers();
    renderAdmins();
    renderProcesses();
    renderServices();
    renderPorts();
    renderSecurity();
    renderAlerts();
    setupSearch('s-users','t-users');
    setupSearch('s-proc','t-proc');
    setupSearch('s-svc','t-svc');
    setupSearch('s-ports','t-ports');
    setupSearch('s-alerts','t-alerts');
    document.getElementById('overlay').addEventListener('click', closeRem);
    setTimeout(initCharts, 80);
});
"""

    # --- Build HTML ---
    html = (
        '<!DOCTYPE html>\n<html lang="fr">\n<head>\n'
        '<meta charset="UTF-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1.0">\n'
        '<title>Tableau de Bord de Sécurité — ' + STATS.get("system", {}).get("hostname", "N/A") + '</title>\n'
        '<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js">'
        '</script>\n'
        '<style>' + css + '</style>\n'
        '</head>\n<body>\n'
        '<script>const DATA = ' + data_json_safe + ';</script>\n'

        # HEADER
        + '<div class="header">\n'
        + '  <div class="header-info"><h1>Tableau de Bord de Sécurité</h1>'
        + f'  <p>Généré le {generated_at} — {STATS.get("system",{}).get("hostname","N/A")}</p></div>\n'
        + '  <div class="header-right">\n'
        + f'  <span class="risk-pill rp-{risk_class}">Risque : {risk_level} ({risk_total}/100)</span>\n'
        + '  <button id="theme-btn" class="theme-btn" onclick="toggleTheme()">Mode Sombre</button>\n'
        + '  </div>\n</div>\n'

        # TAB BAR
        + '<div class="tab-bar">\n'
        + '  <button class="tab-btn active" data-tab="overview" onclick="showTab(\'overview\')">Vue d\'ensemble</button>\n'
        + '  <button class="tab-btn" data-tab="system" onclick="showTab(\'system\')">Système</button>\n'
        + '  <button class="tab-btn" data-tab="identities" onclick="showTab(\'identities\')">Identités</button>\n'
        + '  <button class="tab-btn" data-tab="processes" onclick="showTab(\'processes\')">Processus</button>\n'
        + '  <button class="tab-btn" data-tab="services" onclick="showTab(\'services\')">Services</button>\n'
        + '  <button class="tab-btn" data-tab="network" onclick="showTab(\'network\')">Réseau</button>\n'
        + '  <button class="tab-btn" data-tab="security" onclick="showTab(\'security\')">Sécurité</button>\n'
        + '  <button class="tab-btn" data-tab="alerts" onclick="showTab(\'alerts\')">Alertes <span id="a-badge" style="background:var(--danger);color:#fff;border-radius:10px;padding:1px 7px;font-size:.75em;margin-left:4px">' + str(len(all_alerts)) + '</span></button>\n'
        + '</div>\n'

        # ── TAB: VUE D'ENSEMBLE ──
        + '<div id="t-overview" class="tab-content active">\n<div class="container">\n'
        # Alert count cards
        + '<div class="cards-row">\n'
        + '<div class="card c-crit"><h3>Critiques</h3><div class="val" id="ov-crit">0</div><div class="sub">Alertes critiques</div></div>\n'
        + '<div class="card c-high"><h3>Hautes</h3><div class="val" id="ov-high">0</div><div class="sub">Alertes haute priorité</div></div>\n'
        + '<div class="card c-med"><h3>Moyennes</h3><div class="val" id="ov-med">0</div><div class="sub">Alertes modérées</div></div>\n'
        + '<div class="card c-low"><h3>Basses</h3><div class="val" id="ov-low">0</div><div class="sub">Alertes basses</div></div>\n'
        + '<div class="card c-info"><h3>Total</h3><div class="val" id="ov-total">0</div><div class="sub">Toutes alertes</div></div>\n'
        + '</div>\n'
        # Charts row
        + '<div class="g2">\n'
        + '<div class="section"><div class="sec-head"><h2>Score de Risque Global</h2></div>\n'
        + '<div style="display:flex;flex-direction:column;align-items:center">\n'
        + '<canvas id="ch-risk" width="260" height="140"></canvas>\n'
        + '<p class="chart-offline">Graphique non disponible (connexion requise)</p>\n'
        + '<div class="gauge-wrap"><div class="gauge-num" id="gauge-num">0</div><div class="gauge-lbl" id="gauge-lbl">Faible</div></div>\n'
        + '</div></div>\n'
        + '<div class="section"><div class="sec-head"><h2>Distribution des Alertes</h2></div>\n'
        + '<div class="chart-box-sm"><canvas id="ch-sev"></canvas></div>\n'
        + '<p class="chart-offline">Graphique non disponible (connexion requise)</p>\n'
        + '</div>\n</div>\n'
        # System info summary
        + '<div class="section"><div class="sec-head"><h2>Informations Système</h2></div>\n'
        + '<div id="ov-sys"></div>\n</div>\n'
        + '</div></div>\n'

        # ── TAB: SYSTÈME ──
        + '<div id="t-system" class="tab-content">\n<div class="container">\n'
        + '<div class="section"><div class="sec-head"><h2>Informations Système Détaillées</h2></div>\n'
        + '<div id="sys-tbl"></div>\n</div>\n'
        + '</div></div>\n'

        # ── TAB: IDENTITÉS ──
        + '<div id="t-identities" class="tab-content">\n<div class="container">\n'
        + '<div class="section"><div class="sec-head"><h2>Utilisateurs Locaux</h2></div>\n'
        + '<input id="s-users" class="search-box" placeholder="Rechercher un utilisateur...">\n'
        + '<div class="tbl-wrap"><table id="t-users"><thead><tr>'
        + '<th onclick="sortTable(\'t-users\',0)">Nom</th>'
        + '<th onclick="sortTable(\'t-users\',1)">État</th>'
        + '<th onclick="sortTable(\'t-users\',2)">Dernière connexion</th>'
        + '<th>SID</th>'
        + '</tr></thead><tbody></tbody></table></div>\n</div>\n'
        + '<div class="section"><div class="sec-head"><h2>Administrateurs Locaux</h2></div>\n'
        + '<div class="tbl-wrap"><table id="t-admins"><thead><tr>'
        + '<th onclick="sortTable(\'t-admins\',0)">Nom</th>'
        + '<th onclick="sortTable(\'t-admins\',1)">Source</th>'
        + '<th>Type</th>'
        + '</tr></thead><tbody></tbody></table></div>\n</div>\n'
        + '</div></div>\n'

        # ── TAB: PROCESSUS ──
        + '<div id="t-processes" class="tab-content">\n<div class="container">\n'
        + '<div class="g2">\n'
        + '<div class="section"><div class="sec-head"><h2>Top Processus — Mémoire</h2></div>\n'
        + '<div class="chart-box"><canvas id="ch-proc"></canvas></div>\n'
        + '<p class="chart-offline">Graphique non disponible (connexion requise)</p>\n'
        + '</div>\n'
        + '<div class="section"><div class="sec-head"><h2>Statistiques</h2></div>\n'
        + '<div class="irow"><span class="ilbl">Total processus</span><span class="ival" id="prc-tot">—</span></div>\n'
        + '<div class="irow"><span class="ilbl">Mémoire totale</span><span class="ival" id="prc-mem">—</span></div>\n'
        + '<script>document.addEventListener("DOMContentLoaded",function(){'
        + 'const p=DATA.processes||{};'
        + 'const e1=document.getElementById("prc-tot");if(e1)e1.textContent=p.total||0;'
        + 'const e2=document.getElementById("prc-mem");if(e2)e2.textContent=p.total_memory_mb?(+p.total_memory_mb).toFixed(0)+" MB":"N/A";'
        + '});</script>\n'
        + '</div>\n</div>\n'
        + '<div class="section"><div class="sec-head"><h2>Tous les Processus</h2><span id="pg-proc"></span></div>\n'
        + '<input id="s-proc" class="search-box" placeholder="Rechercher un processus...">\n'
        + '<div class="tbl-wrap"><table id="t-proc"><thead><tr>'
        + '<th onclick="sortTable(\'t-proc\',0)">Nom</th>'
        + '<th onclick="sortTable(\'t-proc\',1,\'num\')">PID</th>'
        + '<th onclick="sortTable(\'t-proc\',2,\'num\')">Mémoire</th>'
        + '<th onclick="sortTable(\'t-proc\',3,\'num\')">CPU (s)</th>'
        + '<th>Chemin</th>'
        + '</tr></thead><tbody></tbody></table></div>\n</div>\n'
        + '</div></div>\n'

        # ── TAB: SERVICES ──
        + '<div id="t-services" class="tab-content">\n<div class="container">\n'
        + '<div class="g2">\n'
        + '<div class="section"><div class="sec-head"><h2>État des Services</h2></div>\n'
        + '<div class="chart-box-sm"><canvas id="ch-svc"></canvas></div>\n'
        + '<p class="chart-offline">Graphique non disponible (connexion requise)</p>\n'
        + '</div>\n'
        + '<div class="section"><div class="sec-head"><h2>Statistiques</h2></div>\n'
        + '<div class="irow"><span class="ilbl">Total</span><span class="ival" id="svc-tot">—</span></div>\n'
        + '<div class="irow"><span class="ilbl">Running</span><span class="ival" style="color:var(--success)" id="svc-run">—</span></div>\n'
        + '<div class="irow"><span class="ilbl">Stopped</span><span class="ival" style="color:var(--danger)" id="svc-stp">—</span></div>\n'
        + '<script>document.addEventListener("DOMContentLoaded",function(){'
        + 'const s=DATA.services||{};'
        + 'const e1=document.getElementById("svc-tot");if(e1)e1.textContent=s.total||0;'
        + 'const e2=document.getElementById("svc-run");if(e2)e2.textContent=s.running||0;'
        + 'const e3=document.getElementById("svc-stp");if(e3)e3.textContent=s.stopped||0;'
        + '});</script>\n'
        + '</div>\n</div>\n'
        + '<div class="section"><div class="sec-head"><h2>Liste des Services</h2><span id="pg-svc"></span></div>\n'
        + '<div class="flt-row">'
        + '<button class="flt-btn sf-btn active" data-st="all" onclick="filterSvc(\'all\')">Tous</button>'
        + '<button class="flt-btn sf-btn" data-st="run" onclick="filterSvc(\'run\')">Running</button>'
        + '<button class="flt-btn sf-btn" data-st="stop" onclick="filterSvc(\'stop\')">Stopped</button>'
        + '</div>\n'
        + '<input id="s-svc" class="search-box" placeholder="Rechercher un service...">\n'
        + '<div class="tbl-wrap"><table id="t-svc"><thead><tr>'
        + '<th onclick="sortTable(\'t-svc\',0)">Nom</th>'
        + '<th onclick="sortTable(\'t-svc\',1)">Affichage</th>'
        + '<th onclick="sortTable(\'t-svc\',2)">État</th>'
        + '<th onclick="sortTable(\'t-svc\',3)">Démarrage</th>'
        + '<th>Type</th>'
        + '</tr></thead><tbody></tbody></table></div>\n</div>\n'
        + '</div></div>\n'

        # ── TAB: RÉSEAU ──
        + '<div id="t-network" class="tab-content">\n<div class="container">\n'
        + '<div class="cards-row">\n'
        + '<div class="card c-info"><h3>Total connexions</h3><div class="val" id="net-tot">—</div></div>\n'
        + '<div class="card c-low"><h3>En écoute</h3><div class="val" id="net-lst">—</div></div>\n'
        + '<div class="card c-med"><h3>Établies</h3><div class="val" id="net-est">—</div></div>\n'
        + '<script>document.addEventListener("DOMContentLoaded",function(){'
        + 'const p=DATA.ports||{};'
        + 'const a=document.getElementById("net-tot");if(a)a.textContent=p.total||0;'
        + 'const b=document.getElementById("net-lst");if(b)b.textContent=p.listening||0;'
        + 'const c=document.getElementById("net-est");if(c)c.textContent=p.established||0;'
        + '});</script>\n'
        + '</div>\n'
        + '<div class="section"><div class="sec-head"><h2>Connexions TCP</h2></div>\n'
        + '<input id="s-ports" class="search-box" placeholder="Rechercher par port, adresse, processus...">\n'
        + '<div class="tbl-wrap"><table id="t-ports"><thead><tr>'
        + '<th onclick="sortTable(\'t-ports\',0)">Adresse locale</th>'
        + '<th onclick="sortTable(\'t-ports\',1,\'num\')">Port</th>'
        + '<th onclick="sortTable(\'t-ports\',2)">État</th>'
        + '<th onclick="sortTable(\'t-ports\',3)">Processus</th>'
        + '<th>Adresse distante</th>'
        + '</tr></thead><tbody></tbody></table></div>\n</div>\n'
        + '</div></div>\n'

        # ── TAB: SÉCURITÉ ──
        + '<div id="t-security" class="tab-content">\n<div class="container">\n'
        + '<div class="g2">\n'
        + '<div class="section"><div class="sec-head"><h2>Microsoft Defender</h2></div><div id="sec-def"></div></div>\n'
        + '<div class="section"><div class="sec-head"><h2>Pare-feu Windows</h2></div><div id="sec-fw"></div></div>\n'
        + '</div>\n'
        + '<div class="g2">\n'
        + '<div class="section"><div class="sec-head"><h2>Événements Windows</h2></div><div id="sec-ev"></div></div>\n'
        + '<div class="section"><div class="sec-head"><h2>Répartition des Événements</h2></div>\n'
        + '<div class="chart-box-sm"><canvas id="ch-ev"></canvas></div>\n'
        + '<p class="chart-offline">Graphique non disponible (connexion requise)</p>\n'
        + '</div>\n</div>\n'
        + '</div></div>\n'

        # ── TAB: ALERTES ──
        + '<div id="t-alerts" class="tab-content">\n<div class="container">\n'
        + '<div class="g2">\n'
        + '<div class="section"><div class="sec-head"><h2>Alertes par Catégorie</h2></div>\n'
        + '<div class="chart-box-sm"><canvas id="ch-cat"></canvas></div>\n'
        + '<p class="chart-offline">Graphique non disponible (connexion requise)</p>\n'
        + '</div>\n'
        + '<div class="section"><div class="sec-head"><h2>Actions</h2></div>\n'
        + '<p style="font-size:.85em;color:var(--text-muted);margin-bottom:14px">Cliquez sur "Détails →" pour voir la remédiation d\'une alerte.</p>\n'
        + '<button class="btn btn-acc" onclick="exportCSV()">Exporter CSV</button>\n'
        + '</div>\n</div>\n'
        + '<div class="section"><div class="sec-head"><h2>Toutes les Alertes</h2></div>\n'
        + '<div class="flt-row">'
        + '<button class="flt-btn af-btn active" data-sev="all" onclick="filterAlerts(\'all\')">Toutes</button>'
        + '<button class="flt-btn af-btn" data-sev="critical" onclick="filterAlerts(\'critical\')">Critique</button>'
        + '<button class="flt-btn af-btn" data-sev="high" onclick="filterAlerts(\'high\')">Haute</button>'
        + '<button class="flt-btn af-btn" data-sev="medium" onclick="filterAlerts(\'medium\')">Moyenne</button>'
        + '<button class="flt-btn af-btn" data-sev="low" onclick="filterAlerts(\'low\')">Basse</button>'
        + '</div>\n'
        + '<input id="s-alerts" class="search-box" placeholder="Rechercher dans les alertes...">\n'
        + '<div class="tbl-wrap"><table id="t-alerts"><thead><tr>'
        + '<th>ID</th>'
        + '<th onclick="sortTable(\'t-alerts\',1)">Sévérité</th>'
        + '<th onclick="sortTable(\'t-alerts\',2)">Catégorie</th>'
        + '<th onclick="sortTable(\'t-alerts\',3)">Message</th>'
        + '<th>Actions</th>'
        + '</tr></thead><tbody></tbody></table></div>\n</div>\n'
        + '</div></div>\n'

        # REMEDIATION PANEL
        + '<div id="rem-panel">\n'
        + '<div class="rem-head"><div class="rem-title" id="rem-t"></div>'
        + '<button class="close-btn" onclick="closeRem()">✕</button></div>\n'
        + '<div><span id="rem-sev"></span> &nbsp; <span style="font-size:.8em;color:var(--text-muted)" id="rem-cat"></span></div>\n'
        + '<div class="rem-lbl">Détails</div><div class="rem-body" id="rem-det"></div>\n'
        + '<div class="rem-lbl">Remédiation recommandée</div><div class="rem-body" id="rem-fix"></div>\n'
        + '<div id="rem-mitre"></div>\n'
        + '</div>\n'
        + '<div id="overlay"></div>\n'

        # FOOTER
        + '<div class="footer">\n'
        + '<p>Tableau de Bord de Sécurité — Mini-Projet 10</p>\n'
        + '<p>Python/PowerShell pour la Sécurité — Dr. Salah Gontara</p>\n'
        + '</div>\n'

        + '<script>' + js + '</script>\n'
        + '</body>\n</html>'
    )

    filepath = RESULTS_DIR / "dashboard.html"
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(html)
    print(f"  [OK] dashboard.html ({len(html)//1024} KB)")

# =============================================================================
# FONCTION PRINCIPALE
# =============================================================================

def main():
    print("=" * 60)
    print("  ANALYSEUR DE TABLEAU DE BORD D'AUDIT")
    print("  Python/PowerShell pour la Sécurité")
    print("=" * 60)

    RESULTS_DIR.mkdir(exist_ok=True)

    print("\n1. Chargement et analyse des données...")

    analyze_system()
    analyze_users()
    analyze_administrators()
    analyze_processes()
    analyze_services()
    analyze_ports()
    analyze_defender()
    analyze_firewall()
    analyze_events()

    # Score de risque (calculé après toutes les analyses)
    print("\n2. Calcul du score de risque...")
    compute_risk_score()
    STATS["risk_score"] = RISK_SCORE

    # Rapports
    print("\n3. Génération des rapports...")

    STATS["alerts"] = ALERT_SEVERITY
    STATS["total_alerts"] = sum(len(v) for v in ALERT_SEVERITY.values())

    save_json(STATS, "summary.json")

    all_alerts = []
    for sev in ["critical", "high", "medium", "low"]:
        for a in ALERT_SEVERITY[sev]:
            all_alerts.append(a)
    save_csv(all_alerts if all_alerts else [], "alerts.csv")

    generate_html_dashboard()

    print("\n" + "=" * 60)
    print("  ANALYSE TERMINÉE")
    print(f"  Score de risque: {RISK_SCORE['total']}/100 ({RISK_SCORE['level']})")
    print(f"  Alertes totales: {len(all_alerts)}")
    print(f"    - Critiques : {len(ALERT_SEVERITY['critical'])}")
    print(f"    - Hautes    : {len(ALERT_SEVERITY['high'])}")
    print(f"    - Moyennes  : {len(ALERT_SEVERITY['medium'])}")
    print(f"    - Basses    : {len(ALERT_SEVERITY['low'])}")
    print(f"  Fichiers générés dans: {RESULTS_DIR}/")
    print("=" * 60)

if __name__ == "__main__":
    main()
