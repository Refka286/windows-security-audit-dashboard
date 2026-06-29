# =============================================================================
# SCRIPT PYTHON D'ANALYSE - TABLEAU DE BORD D'AUDIT ET DE DETECTION
# =============================================================================
# Auteur : Dr. Salah Gontara
# Cours  : Python/PowerShell pour la Sécurité
# =============================================================================

import json
import os
import csv
from datetime import datetime
from pathlib import Path

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
        # Créer un CSV vide avec en-têtes
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            f.write("")
        print(f"  [OK] {filename} (vide)")
        return

    headers = list(data[0].keys()) if isinstance(data, list) and data else []
    if not headers:
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            f.write("")
        print(f"  [OK] {filename} (vide)")
        return

    with open(filepath, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        writer.writerows(data)
    print(f"  [OK] {filename}")

def add_alert(severity, message, category, details=None):
    """Ajoute une alerte à la liste"""
    alert = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "severity": severity,
        "category": category,
        "message": message
    }
    if details:
        alert["details"] = details
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
        "os_name": data.get("os_name", "N/A"),
        "os_version": data.get("os_version", "N/A"),
        "os_build": data.get("os_build", "N/A"),
        "total_ram_gb": data.get("total_physical_ram", "N/A"),
        "current_user": data.get("current_user", "N/A"),
        "collection_time": data.get("collection_time", "N/A")
    }

    # Alertes système
    build = data.get("os_build", "")
    if build and int(build) < 19041:
        add_alert("medium", "Version Windows potentiellement obsolète",
                  "System", f"Build {build} - Mise à jour recommandée")

    print(f"    [OK] {data.get('hostname')} - {data.get('os_name')}")

def analyze_users():
    """Analyse les utilisateurs locaux"""
    print("2.2 Analyse utilisateurs...")

    data = load_json("users.json")
    if not data:
        print("    [ERREUR] users.json non trouvé")
        return

    users = data if isinstance(data, list) else []

    enabled_users = [u for u in users if u.get("enabled") == True]
    disabled_users = [u for u in users if u.get("enabled") == False]
    never_logged = [u for u in users if u.get("last_logon") == "Jamais"]

    STATS["users"] = {
        "total": len(users),
        "enabled": len(enabled_users),
        "disabled": len(disabled_users),
        "never_logged": len(never_logged),
        "users_list": users[:10]  # Limité aux 10 premiers
    }

    # Alertes utilisateurs
    if len(users) > 5:
        add_alert("low", f"{len(users)} utilisateurs locaux trouvés",
                  "Users", "Vérifier la nécessité de tous les comptes")

    for user in never_logged:
        add_alert("medium", f"Compte jamais connecté: {user.get('name')}",
                  "Users", "Compte potentiellement obsolète")

    print(f"    [OK] {len(users)} utilisateurs ({len(enabled_users)} actifs)")

def analyze_administrators():
    """Analyse les administrateurs locaux"""
    print("2.3 Analyse administrateurs...")

    data = load_json("administrators.json")
    if not data:
        print("    [ERREUR] administrators.json non trouvé")
        return

    admins = data if isinstance(data, list) else []

    # Filtrer par type
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

    # Alertes administrateurs
    if len(admins) > 3:
        add_alert("high", f"{len(admins)} comptes dans Administrators",
                  "Privilege", "Nombre élevé de privilèges administratifs")

    for admin in admins:
        name = admin.get("name", "")
        if "Guest" in name or "Administrator" in name and "Default" not in name:
            add_alert("medium", f"Compte administratif: {name}",
                      "Privilege", f"Source: {admin.get('source')}")

    print(f"    [OK] {len(admins)} administrateurs")

def analyze_processes():
    """Analyse les processus"""
    print("2.4 Analyse processus...")

    data = load_json("processes.json")
    if not data:
        print("    [ERREUR] processes.json non trouvé")
        return

    processes = data if isinstance(data, list) else []

    # Top processus par mémoire
    top_memory = sorted(processes, key=lambda x: x.get("memory_mb", 0), reverse=True)[:10]

    STATS["processes"] = {
        "total": len(processes),
        "top_memory": top_memory,
        "total_memory_mb": sum(p.get("memory_mb", 0) for p in processes)
    }

    # Alertes processus
    suspicious_names = ["nc.exe", "netcat", "psexec", "mimikatz", "wce.exe",
                        "pwdump", "fgdump", "rainbow", "hashcat"]

    for proc in processes:
        name = proc.get("name", "").lower()
        for suspicious in suspicious_names:
            if suspicious.lower() in name:
                add_alert("high", f"Processus suspect: {proc.get('name')}",
                          "Process", f"PID: {proc.get('pid')}, Path: {proc.get('path')}")

    # Processus sans chemin (potentiellement suspects)
    no_path = [p for p in processes if not p.get("path")]
    if no_path:
        add_alert("low", f"{len(no_path)} processus sans chemin défini",
                  "Process", "Peut indiquer des processus temporaires ou masqués")

    print(f"    [OK] {len(processes)} processus (Top: {top_memory[0]['name'] if top_memory else 'N/A'})")

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

    # Services critiques à surveiller
    critical_services = ["wuauserv", "WdNisSvc", "WinDefend", "MpsSvc",
                          "EventLog", "RpcSs", "DHCP", "DNS"]

    STATS["services"] = {
        "total": len(services),
        "running": len(running),
        "stopped": len(stopped),
        "list_sample": services[:20]
    }

    # Alertes services
    for svc in services:
        name = svc.get("name", "").lower()
        if name in critical_services and svc.get("status") == "Stopped":
            add_alert("medium", f"Service critique arrêté: {svc.get('display_name')}",
                      "Service", f"Service: {svc.get('name')}")

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

    # Ports sensibles
    sensitive_ports = {21: "FTP", 23: "Telnet", 25: "SMTP", 135: "RPC",
                       139: "NetBIOS", 445: "SMB", 3389: "RDP", 5900: "VNC"}

    STATS["ports"] = {
        "total": len(ports),
        "listening": len(listening),
        "established": len(established),
        "list_sample": ports[:30]
    }

    # Alertes ports
    for port_info in ports:
        port = port_info.get("local_port")
        if port in sensitive_ports:
            add_alert("medium", f"Port sensible ouvert: {port} ({sensitive_ports[port]})",
                      "Network", f"Processus: {port_info.get('process_name', 'N/A')}")

    # Connexions externes établies
    external = [p for p in established if not p.get("remote_address", "").startswith(("127.", "::1", "0."))]
    if external:
        add_alert("low", f"{len(external)} connexions externes établies",
                  "Network", "Vérifier les connexions légitimes")

    print(f"    [OK] {len(ports)} connexions ({len(listening)} en écoute)")

def analyze_defender():
    """Analyse l'état de Microsoft Defender"""
    print("2.7 Analyse Defender...")

    data = load_json("defender.json")
    if not data:
        print("    [ERREUR] defender.json non trouvé")
        return

    STATS["defender"] = data

    # Alertes Defender
    if data.get("antivirus_enabled") == False:
        add_alert("critical", "Antivirus Windows Désactivé",
                  "Security", "Protection antivirus inactive")

    if data.get("realtime_protection") == False:
        add_alert("critical", "Protection Temps Réel Désactivée",
                  "Security", "Protection temps réel inactive")

    if data.get("antivirus_signature_age"):
        age = data.get("antivirus_signature_age")
        if int(age) > 7:
            add_alert("high", f"Signatures antivirus obsolètes ({age} jours)",
                      "Security", "Mise à jour des définitions recommandée")

    enabled = data.get("antivirus_enabled", False)
    realtime = data.get("realtime_protection", False)
    print(f"    [OK] Antivirus: {'Actif' if enabled else 'Inactif'}, Temps Réel: {'Actif' if realtime else 'Inactif'}")

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
        "profiles": profiles
    }

    # Alertes pare-feu
    for profile in disabled_profiles:
        add_alert("high", f"Pare-feu désactivé: profil {profile.get('name')}",
                  "Network", "Activer le pare-feu pour ce profil")

    print(f"    [OK] {len(enabled_profiles)}/{len(profiles)} profils actifs")

def analyze_events():
    """Analyse les événements Windows"""
    print("2.9 Analyse événements...")

    data = load_json("events.json")
    if not data:
        print("    [ERREUR] events.json non trouvé")
        return

    events = data.get("events", []) if isinstance(data, dict) else []

    # Filtrer par type d'événement
    security_events = [e for e in events if e.get("log_name") == "Security"]
    system_events = [e for e in events if e.get("log_name") == "System"]
    app_events = [e for e in events if e.get("log_name") == "Application"]

    STATS["events"] = {
        "total": data.get("total_events", 0),
        "security": len(security_events),
        "system": len(system_events),
        "application": len(app_events),
        "date_range": data.get("date_range", "N/A")
    }

    # Alertes événements
    event_alerts = {
        4625: ("Échec de connexion", "high"),
        4720: ("Compte créé", "medium"),
        4726: ("Compte supprimé", "medium"),
        7045: ("Service installé", "high")
    }

    for event in events:
        eid = event.get("event_id")
        if eid in event_alerts:
            msg, severity = event_alerts[eid]
            add_alert(severity, f"Événement {eid}: {msg}",
                      "Event", event.get("message", "")[:100])

    print(f"    [OK] {data.get('total_events', 0)} événements collectés")

# =============================================================================
# GÉNÉRATION DU TABLEAU DE BORD HTML
# =============================================================================

def generate_html_dashboard():
    """Génère le tableau de bord HTML statique avec toutes les données intégrées"""
    print("\n3. Génération du tableau de bord HTML...")

    # Compteurs d'alertes
    total_alerts = len(ALERT_SEVERITY["critical"]) + len(ALERT_SEVERITY["high"]) + \
                   len(ALERT_SEVERITY["medium"]) + len(ALERT_SEVERITY["low"])

    html = f"""<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Tableau de Bord d'Audit et de Détection</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #1a1a2e; color: #eee; min-height: 100vh; }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; text-align: center; }}
        .header h1 {{ font-size: 2em; margin-bottom: 10px; }}
        .header p {{ opacity: 0.9; }}
        .container {{ max-width: 1400px; margin: 0 auto; padding: 20px; }}
        .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }}
        .stat-card {{ background: #16213e; border-radius: 10px; padding: 20px; text-align: center; }}
        .stat-card h3 {{ color: #667eea; font-size: 0.9em; text-transform: uppercase; }}
        .stat-card .value {{ font-size: 2.5em; font-weight: bold; margin: 10px 0; }}
        .stat-card.critical {{ border-left: 4px solid #e74c3c; }}
        .stat-card.warning {{ border-left: 4px solid #f39c12; }}
        .stat-card.success {{ border-left: 4px solid #27ae60; }}
        .section {{ background: #16213e; border-radius: 10px; padding: 20px; margin-bottom: 20px; }}
        .section h2 {{ color: #667eea; margin-bottom: 15px; padding-bottom: 10px; border-bottom: 1px solid #333; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #333; }}
        th {{ background: #0f3460; color: #667eea; }}
        tr:hover {{ background: #1a1a2e; }}
        .alert-critical {{ background: rgba(231, 76, 60, 0.2); border-left: 4px solid #e74c3c; }}
        .alert-high {{ background: rgba(243, 156, 18, 0.2); border-left: 4px solid #f39c12; }}
        .alert-medium {{ background: rgba(52, 152, 219, 0.2); border-left: 4px solid #3498db; }}
        .alert-low {{ background: rgba(46, 204, 113, 0.2); border-left: 4px solid #2ecc71; }}
        .badge {{ display: inline-block; padding: 4px 10px; border-radius: 15px; font-size: 0.8em; }}
        .badge-critical {{ background: #e74c3c; }}
        .badge-high {{ background: #f39c12; }}
        .badge-medium {{ background: #3498db; }}
        .badge-low {{ background: #27ae60; }}
        .grid-2 {{ display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }}
        @media (max-width: 768px) {{ .grid-2 {{ grid-template-columns: 1fr; }} }}
        .footer {{ text-align: center; padding: 20px; opacity: 0.7; font-size: 0.9em; }}
        .status-dot {{ display: inline-block; width: 8px; height: 8px; border-radius: 50%; margin-right: 5px; }}
        .status-dot.green {{ background: #2ecc71; }}
        .status-dot.red {{ background: #e74c3c; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Tableau de Bord d'Audit et de Détection</h1>
        <p>Généré le: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
    </div>

    <div class="container">
        <div class="stats-grid">
            <div class="stat-card {'critical' if len(ALERT_SEVERITY['critical']) > 0 else 'success'}">
                <h3>Alertes Critiques</h3>
                <div class="value">{len(ALERT_SEVERITY['critical'])}</div>
            </div>
            <div class="stat-card {'warning' if len(ALERT_SEVERITY['high']) > 0 else 'success'}">
                <h3>Alertes Hautes</h3>
                <div class="value">{len(ALERT_SEVERITY['high'])}</div>
            </div>
            <div class="stat-card">
                <h3>Alertes Moyennes</h3>
                <div class="value">{len(ALERT_SEVERITY['medium'])}</div>
            </div>
            <div class="stat-card">
                <h3>Alertes Basses</h3>
                <div class="value">{len(ALERT_SEVERITY['low'])}</div>
            </div>
        </div>
"""

    # Section Système
    system = STATS.get("system", {})
    html += f"""
        <div class="section">
            <h2>Informations Système</h2>
            <table>
                <tr><th>Paramètre</th><th>Valeur</th></tr>
                <tr><td>Hostname</td><td>{system.get('hostname', 'N/A')}</td></tr>
                <tr><td>Système</td><td>{system.get('os_name', 'N/A')}</td></tr>
                <tr><td>Version</td><td>{system.get('os_version', 'N/A')}</td></tr>
                <tr><td>Build</td><td>{system.get('os_build', 'N/A')}</td></tr>
                <tr><td>RAM Totale</td><td>{system.get('total_ram_gb', 'N/A')} GB</td></tr>
                <tr><td>Utilisateur Actuel</td><td>{system.get('current_user', 'N/A')}</td></tr>
            </table>
        </div>
"""

    # Section Utilisateurs
    users = STATS.get("users", {})
    html += f"""
        <div class="section">
            <h2>Utilisateurs Locaux</h2>
            <p><strong>Total:</strong> {users.get('total', 0)} | <strong>Actifs:</strong> {users.get('enabled', 0)} | <strong>Désactivés:</strong> {users.get('disabled', 0)} | <strong>Jamais connectés:</strong> {users.get('never_logged', 0)}</p>
            <table>
                <tr><th>Nom</th><th>Actif</th><th>Dernière connexion</th></tr>
"""
    for u in users.get('users_list', [])[:10]:
        status = '<span class="status-dot green"></span>Oui' if u.get('enabled') else '<span class="status-dot red"></span>Non'
        html += f"""                <tr><td>{u.get('name', 'N/A')}</td><td>{status}</td><td>{u.get('last_logon', 'Jamais')}</td></tr>
"""
    html += """            </table>
        </div>
"""

    # Section Processus
    processes = STATS.get("processes", {})
    html += f"""
        <div class="section">
            <h2>Processus</h2>
            <p><strong>Total:</strong> {processes.get('total', 0)} | <strong>Mémoire totale:</strong> {processes.get('total_memory_mb', 0):.2f} MB</p>
            <table>
                <tr><th>Nom</th><th>PID</th><th>Mémoire (MB)</th></tr>
"""
    for p in processes.get('top_memory', [])[:10]:
        html += f"""                <tr><td>{p.get('name', 'N/A')}</td><td>{p.get('pid', 'N/A')}</td><td>{p.get('memory_mb', 0):.2f}</td></tr>
"""
    html += """            </table>
        </div>
"""

    # Section Services
    services = STATS.get("services", {})
    html += f"""
        <div class="section">
            <h2>Services</h2>
            <p><strong>Total:</strong> {services.get('total', 0)} | <strong>Actifs:</strong> {services.get('running', 0)} | <strong>Arrêtés:</strong> {services.get('stopped', 0)}</p>
            <table>
                <tr><th>Nom</th><th>Affichage</th><th>État</th><th>Type</th></tr>
"""
    for s in services.get('list_sample', [])[:15]:
        status = '<span class="badge badge-low">Running</span>' if s.get('status') == 'Running' else '<span class="badge badge-high">Stopped</span>'
        html += f"""                <tr><td>{s.get('name', 'N/A')}</td><td>{s.get('display_name', 'N/A')}</td><td>{status}</td><td>{s.get('start_type', 'N/A')}</td></tr>
"""
    html += """            </table>
        </div>
"""

    # Section Ports
    ports = STATS.get("ports", {})
    html += f"""
        <div class="section">
            <h2>Ports et Connexions</h2>
            <p><strong>Total:</strong> {ports.get('total', 0)} | <strong>En écoute:</strong> {ports.get('listening', 0)} | <strong>Établies:</strong> {ports.get('established', 0)}</p>
            <table>
                <tr><th>Adresse Locale</th><th>Port</th><th>État</th><th>Processus</th></tr>
"""
    for p in ports.get('list_sample', [])[:15]:
        html += f"""                <tr><td>{p.get('local_address', 'N/A')}</td><td>{p.get('local_port', 'N/A')}</td><td>{p.get('state', 'N/A')}</td><td>{p.get('process_name', 'N/A')}</td></tr>
"""
    html += """            </table>
        </div>
"""

    # Section Sécurité
    defender = STATS.get("defender", {})
    firewall = STATS.get("firewall", {})
    antivirus = '<span class="badge badge-low">Actif</span>' if defender.get('antivirus_enabled') else '<span class="badge badge-critical">Inactif</span>'
    realtime = '<span class="badge badge-low">Actif</span>' if defender.get('realtime_protection') else '<span class="badge badge-critical">Inactif</span>'

    html += f"""
        <div class="section">
            <h2>État de Sécurité</h2>
            <div class="grid-2">
                <div>
                    <h3>Microsoft Defender</h3>
                    <p>Antivirus: {antivirus}</p>
                    <p>Protection Temps Réel: {realtime}</p>
                    <p>Signatures: {defender.get('antivirus_signature_version', 'N/A')}</p>
                </div>
                <div>
                    <h3>Pare-feu Windows</h3>
                    <p>Profils actifs: {firewall.get('profiles_enabled', 0)}/{firewall.get('profiles_total', 0)}</p>
"""
    for profile in firewall.get('profiles', []):
        status = '<span class="badge badge-low">Actif</span>' if profile.get('enabled') else '<span class="badge badge-critical">Inactif</span>'
        html += f"""                    <p>{profile.get('name', 'N/A')}: {status}</p>
"""
    html += """                </div>
            </div>
        </div>
"""

    # Section Événements
    events = STATS.get("events", {})
    html += f"""
        <div class="section">
            <h2>Événements Récents ({events.get('date_range', 'N/A')})</h2>
            <p><strong>Total:</strong> {events.get('total', 0)} | <strong>Sécurité:</strong> {events.get('security', 0)} | <strong>Système:</strong> {events.get('system', 0)} | <strong>Application:</strong> {events.get('application', 0)}</p>
        </div>
"""

    # Section Alertes
    html += """
        <div class="section">
            <h2>Alertes de Sécurité</h2>
"""
    if total_alerts == 0:
        html += """            <p>Aucune alerte détectée.</p>
"""
    else:
        for severity in ["critical", "high", "medium", "low"]:
            alerts = ALERT_SEVERITY[severity]
            if alerts:
                for alert in alerts:
                    html += f"""            <div class="alert-{severity}" style="padding: 10px; margin: 5px 0; border-radius: 5px;">
                <span class="badge badge-{severity}">{alert.get('severity', '').upper()}</span>
                <strong>{alert.get('category', '')}:</strong> {alert.get('message', '')}<br>
                <small>{alert.get('timestamp', '')}</small>
            </div>
"""
    html += """        </div>
    </div>

    <div class="footer">
        <p>Tableau de Bord d'Audit et de Détection - Mini-Projet 10</p>
        <p>Python/PowerShell pour la Sécurité - Dr. Salah Gontara</p>
    </div>
</body>
</html>"""

    filepath = RESULTS_DIR / "dashboard.html"
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(html)
    print(f"  [OK] dashboard.html")

# =============================================================================
# FONCTION PRINCIPALE
# =============================================================================

def main():
    print("=" * 60)
    print("  ANALYSEUR DE TABLEAU DE BORD D'AUDIT")
    print("  Python/PowerShell pour la Sécurité")
    print("=" * 60)

    # Vérifier que le dossier results existe
    RESULTS_DIR.mkdir(exist_ok=True)

    # Lancer les analyses
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

    # Générer les rapports
    print("\n2. Génération des rapports...")

    # Ajouter les alertes au summary
    STATS["alerts"] = ALERT_SEVERITY
    STATS["total_alerts"] = len(ALERT_SEVERITY["critical"]) + len(ALERT_SEVERITY["high"]) + \
                            len(ALERT_SEVERITY["medium"]) + len(ALERT_SEVERITY["low"])

    # Summary JSON
    save_json(STATS, "summary.json")

    # Alerts CSV - combiner toutes les alertes
    all_alerts = (ALERT_SEVERITY["critical"] + ALERT_SEVERITY["high"] +
                  ALERT_SEVERITY["medium"] + ALERT_SEVERITY["low"])
    save_csv(all_alerts if all_alerts else [], "alerts.csv")

    # Dashboard HTML
    generate_html_dashboard()

    # Résumé
    print("\n" + "=" * 60)
    print("  ANALYSE TERMINÉE")
    print(f"  Alertes totales: {len(all_alerts)}")
    print(f"    - Critiques: {len(ALERT_SEVERITY['critical'])}")
    print(f"    - Hautes: {len(ALERT_SEVERITY['high'])}")
    print(f"    - Moyennes: {len(ALERT_SEVERITY['medium'])}")
    print(f"    - Basses: {len(ALERT_SEVERITY['low'])}")
    print("=" * 60)
    print(f"\nFichiers générés dans: {RESULTS_DIR}/")

if __name__ == "__main__":
    main()
