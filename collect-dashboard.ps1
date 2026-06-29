# =============================================================================
# SCRIPT POWERSHELL DE COLLECTE - TABLEAU DE BORD D'AUDIT ET DE DETECTION
# =============================================================================
# Auteur : Dr. Salah Gontara
# Cours  : Python/PowerShell pour la Sécurité
# =============================================================================

[CmdletBinding()]
param(
    [string]$OutputPath = "data"
)

# Cr�er le dossier de sortie si inexistant
if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  COLLECTE D'AUDIT WINDOWS" -ForegroundColor Cyan
Write-Host "  Date: $timestamp" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

function Export-Json {
    param(
        [object]$Data,
        [string]$FileName
    )
    $fullPath = Join-Path $OutputPath $FileName
    if ($Data -eq $null) {
        $Data = @()
    }
    if ($Data -is [array] -and $Data.Count -eq 0) {
        $jsonContent = "[]"
    } else {
        $jsonContent = $Data | ConvertTo-Json -Depth 10
    }
    $jsonContent | Out-File -FilePath $fullPath -Encoding UTF8 -Force
    Write-Host "[OK] $FileName" -ForegroundColor Green
}

# =============================================================================
# 1. INFORMATIONS SYSTÈME
# =============================================================================
Write-Host "1. Collecte des informations syst�me..." -NoNewline

try {
    $os = Get-CimInstance Win32_OperatingSystem
    $cs = Get-CimInstance Win32_ComputerSystem

    $systemInfo = [PSCustomObject]@{
        hostname           = $cs.Name
        domain             = $cs.Domain
        os_name            = $os.Caption
        os_version         = $os.Version
        os_build           = $os.BuildNumber
        install_date       = $os.InstallDate
        last_boot          = $os.LastBootUpTime
        manufacturer        = $cs.Manufacturer
        model              = $cs.Model
        total_physical_ram = [math]::Round($cs.TotalPhysicalMemory / 1GB, 2)
        ram_unit           = "GB"
        current_user       = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        collection_time    = $timestamp
    }

    Export-Json -Data $systemInfo -FileName "system.json"
}
catch {
    Write-Host " [ERREUR]" -ForegroundColor Red
    Write-Host "   $_" -ForegroundColor Red
}

# =============================================================================
# 2. UTILISATEURS LOCAUX
# =============================================================================
Write-Host "2. Collecte des utilisateurs locaux..." -NoNewline

try {
    $users = Get-LocalUser | Select-Object Name, Enabled, LastLogon, Description, PasswordRequired, PasswordExpired, UserMayChangePassword, SID | ForEach-Object {
        [PSCustomObject]@{
            name                 = $_.Name
            enabled              = $_.Enabled
            last_logon           = if ($_.LastLogon) { $_.LastLogon.ToString("yyyy-MM-dd HH:mm:ss") } else { "Jamais" }
            description          = $_.Description
            password_required    = $_.PasswordRequired
            password_expired     = $_.PasswordExpired
            user_can_change_pwd  = $_.UserMayChangePassword
            sid                  = $_.SID.Value
        }
    }

    Export-Json -Data $users -FileName "users.json"
}
catch {
    Write-Host " [ERREUR]" -ForegroundColor Red
    Write-Host "   $_" -ForegroundColor Red
}

# =============================================================================
# 3. MEMBRES DU GROUPE ADMINISTRATORS
# =============================================================================
Write-Host "3. Collecte des administrateurs locaux..." -NoNewline

try {
    $adminGroup = Get-LocalGroupMember -Group "Administrators" -ErrorAction Stop | Select-Object Name, ObjectClass, PrincipalSource | ForEach-Object {
        [PSCustomObject]@{
            name              = $_.Name
            object_class      = $_.ObjectClass
            source            = $_.PrincipalSource
        }
    }

    Export-Json -Data $adminGroup -FileName "administrators.json"
}
catch {
    Write-Host " [INFO] Groupe Administrators non disponible" -ForegroundColor Yellow
    Export-Json -Data @() -FileName "administrators.json"
}

# =============================================================================
# 4. PROCESSUS
# =============================================================================
Write-Host "4. Collecte des processus..." -NoNewline

try {
    $processes = Get-Process | Select-Object Name, Id, CPU, WorkingSet, Path, Company, ProductVersion | ForEach-Object {
        [PSCustomObject]@{
            name          = $_.Name
            pid           = $_.Id
            cpu_time      = if ($_.CPU) { [math]::Round($_.CPU, 2) } else { 0 }
            memory_mb     = [math]::Round($_.WorkingSet / 1MB, 2)
            path          = $_.Path
            company       = $_.Company
            version       = $_.ProductVersion
        }
    }

    Export-Json -Data $processes -FileName "processes.json"
}
catch {
    Write-Host " [ERREUR]" -ForegroundColor Red
    Write-Host "   $_" -ForegroundColor Red
}

# =============================================================================
# 5. SERVICES
# =============================================================================
Write-Host "5. Collecte des services..." -NoNewline

try {
    $services = Get-Service | Select-Object Name, DisplayName, Status, StartType, ServiceType | ForEach-Object {
        [PSCustomObject]@{
            name          = $_.Name
            display_name  = $_.DisplayName
            status        = $_.Status.ToString()
            start_type    = $_.StartType.ToString()
            service_type  = $_.ServiceType.ToString()
        }
    }

    Export-Json -Data $services -FileName "services.json"
}
catch {
    Write-Host " [ERREUR]" -ForegroundColor Red
    Write-Host "   $_" -ForegroundColor Red
}

# =============================================================================
# 6. PORTS OUVERTS
# =============================================================================
Write-Host "6. Collecte des ports ouverts..." -NoNewline

try {
    $connections = Get-NetTCPConnection -State Listen,Established | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess | ForEach-Object {
        $process = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
        [PSCustomObject]@{
            local_address    = $_.LocalAddress
            local_port       = $_.LocalPort
            remote_address   = $_.RemoteAddress
            remote_port      = $_.RemotePort
            state            = $_.State.ToString()
            pid              = $_.OwningProcess
            process_name     = if ($process) { $process.Name } else { "N/A" }
        }
    }

    Export-Json -Data $connections -FileName "ports.json"
}
catch {
    Write-Host " [ERREUR]" -ForegroundColor Red
    Write-Host "   $_" -ForegroundColor Red
}

# =============================================================================
# 7. ÉVÉNEMENTS WINDOWS (Security, System, Application)
# =============================================================================
Write-Host "7. Collecte des �v�nements..." -NoNewline

try {
    $recentDate = (Get-Date).AddDays(-7)

    # Sécurité - 4624 (connexion), 4625 (échec), 4647 (fermeture)
    $securityEvents = @()
    try {
        $securityEvents = Get-WinEvent -FilterHashtable @{
            LogName = 'Security'
            Id = @(4624, 4625, 4647, 4720, 4726)
            StartTime = $recentDate
        } -MaxEvents 100 -ErrorAction SilentlyContinue | Select-Object TimeCreated, Id, Message | ForEach-Object {
            [PSCustomObject]@{
                time_created = $_.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
                event_id     = $_.Id
                log_name     = "Security"
                message      = $_.Message.Substring(0, [Math]::Min(300, $_.Message.Length))
            }
        }
    }
    catch { }

    # System - services, erreurs
    $systemEvents = @()
    try {
        $systemEvents = Get-WinEvent -FilterHashtable @{
            LogName = 'System'
            Id = @(7045, 7036, 6008)
            StartTime = $recentDate
        } -MaxEvents 50 -ErrorAction SilentlyContinue | Select-Object TimeCreated, Id, Message | ForEach-Object {
            [PSCustomObject]@{
                time_created = $_.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
                event_id     = $_.Id
                log_name     = "System"
                message      = $_.Message.Substring(0, [Math]::Min(300, $_.Message.Length))
            }
        }
    }
    catch { }

    # Application - erreurs
    $appEvents = @()
    try {
        $appEvents = Get-WinEvent -FilterHashtable @{
            LogName = 'Application'
            Id = @(1000, 1001)
            StartTime = $recentDate
        } -MaxEvents 30 -ErrorAction SilentlyContinue | Select-Object TimeCreated, Id, Message | ForEach-Object {
            [PSCustomObject]@{
                time_created = $_.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
                event_id     = $_.Id
                log_name     = "Application"
                message      = $_.Message.Substring(0, [Math]::Min(300, $_.Message.Length))
            }
        }
    }
    catch { }

    $allEvents = @()
    $allEvents += $securityEvents
    $allEvents += $systemEvents
    $allEvents += $appEvents

    $eventsData = [PSCustomObject]@{
        collected_at  = $timestamp
        date_range     = "7 derniers jours"
        total_events   = $allEvents.Count
        security_count = $securityEvents.Count
        system_count   = $systemEvents.Count
        app_count      = $appEvents.Count
        events         = $allEvents
    }

    Export-Json -Data $eventsData -FileName "events.json"
}
catch {
    Write-Host " [ERREUR]" -ForegroundColor Red
    Write-Host "   $_" -ForegroundColor Red
}

# =============================================================================
# 8. ÉTAT MICROSOFT DEFENDER
# =============================================================================
Write-Host "8. Collecte de l'�tat Defender..." -NoNewline

try {
    $defenderStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue

    if ($defenderStatus) {
        $defenderInfo = [PSCustomObject]@{
            antivirus_enabled          = $defenderStatus.AntivirusEnabled
            realtime_protection        = $defenderStatus.RealTimeProtectionEnabled
            behavior_monitor          = $defenderStatus.BehaviorMonitorEnabled
            antivirus_signature_age    = $defenderStatus.AntivirusSignatureAge
            last_scan                  = if ($defenderStatus.FullScanEndTime) { $defenderStatus.FullScanEndTime.ToString("yyyy-MM-dd HH:mm:ss") } else { "Jamais" }
            quick_scan                 = if ($defenderStatus.QuickScanEndTime) { $defenderStatus.QuickScanEndTime.ToString("yyyy-MM-dd HH:mm:ss") } else { "Jamais" }
            antivirus_signature_version = $defenderStatus.AntivirusSignatureVersion
            spyware_signature_version  = $defenderStatus.AntispywareSignatureVersion
            ioav_protection            = $defenderStatus.IOAVProtectionEnabled
           nis_enabled                = $defenderStatus.NISEnabled
        }
    }
    else {
        $defenderInfo = [PSCustomObject]@{
            status = "Impossible de récupérer l'état de Defender"
            note   = "Vérifiez que Windows Defender est actif"
        }
    }

    Export-Json -Data $defenderInfo -FileName "defender.json"
}
catch {
    Write-Host " [ERREUR]" -ForegroundColor Red
    Write-Host "   $_" -ForegroundColor Red
}

# =============================================================================
# 9. ÉTAT DU PARE-FEU WINDOWS
# =============================================================================
Write-Host "9. Collecte de l'�tat du pare-feu..." -NoNewline

try {
    $firewallProfiles = Get-NetFirewallProfile -ErrorAction Stop | Select-Object Name, Enabled, DefaultInbound, DefaultOutbound, LogBlocked, LogIgnored

    $firewallInfo = [PSCustomObject]@{
        profiles = $firewallProfiles | ForEach-Object {
            [PSCustomObject]@{
                name              = $_.Name
                enabled           = $_.Enabled
                default_inbound   = $_.DefaultInbound.ToString()
                default_outbound  = $_.DefaultOutbound.ToString()
                log_blocked       = $_.LogBlocked
                log_ignored       = $_.LogIgnored
            }
        }
        collection_time = $timestamp
    }

    Export-Json -Data $firewallInfo -FileName "firewall.json"
}
catch {
    Write-Host " [INFO] Pare-feu non disponible" -ForegroundColor Yellow
    $firewallInfo = [PSCustomObject]@{
        profiles = @()
        collection_time = $timestamp
        status = "Non disponible"
    }
    Export-Json -Data $firewallInfo -FileName "firewall.json"
}

# =============================================================================
# FIN DE LA COLLECTE
# =============================================================================
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  COLLECTE TERMINÉE" -ForegroundColor Cyan
Write-Host "  Fichiers générés dans : $OutputPath/" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
