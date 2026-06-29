# =============================================================================
# SCRIPT DE LANCEMENT UNIFIÉ - TABLEAU DE BORD D'AUDIT TEMPS RÉEL
# =============================================================================
# Auteur : Dr. Salah Gontara
# Cours  : Python/PowerShell pour la Sécurité
# =============================================================================

[CmdletBinding()]
param(
    [int]$RefreshInterval = 30,
    [switch]$Continuous
)

$ErrorActionPreference = "Continue"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ScriptDir

function Write-Banner {
    param([string]$Message)
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "  $Message" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
}

function Invoke-Collection {
    Write-Banner "COLLECTE DES DONNÉES"

    # Exécuter le script PowerShell de collecte
    & "$ScriptDir\collect-dashboard.ps1"

    # Exécuter le script Python d'analyse
    Write-Host ""
    Write-Host "Exécution de l'analyse Python..." -ForegroundColor Yellow
    python "$ScriptDir\analyze-dashboard.py"
}

# Exécution unique
if (-not $Continuous) {
    Invoke-Collection
    Write-Host ""
    Write-Host "Dashboard généré. Ouvrez results/dashboard.html dans un navigateur." -ForegroundColor Green
    Write-Host "Le dashboard se rafraîchit automatiquement toutes les 30 secondes." -ForegroundColor Cyan
    exit 0
}

# Mode continu
Write-Banner "TABLEAU DE BORD TEMPS RÉEL - MODE CONTINU"
Write-Host "Intervalle de rafraîchissement: $RefreshInterval secondes" -ForegroundColor Yellow
Write-Host "Appuyez sur Ctrl+C pour arrêter" -ForegroundColor Yellow
Write-Host ""

$iteration = 0
$running = $true

# Gestionnaire d'interruption
$null = [Console]::TreatControlCAsInput
$handler = {
    if ($Host.UI.RawUI.KeyAvailable) {
        $key = $Host.UI.RawUI.ReadKey()
        if (($key.Modifiers -eq [ConsoleModifiers]::Control) -and ($key.Key -eq [ConsoleKey]::C)) {
            $script:running = $false
        }
    }
}

Register-EngineEvent -SourceIdentifier PowerShell.Exiting -Action { $script:running = $false }

try {
    while ($running) {
        $iteration++
        Write-Host "[$((Get-Date).ToString('HH:mm:ss'))] Itération #$iteration" -ForegroundColor White

        # Collecte et analyse
        & "$ScriptDir\collect-dashboard.ps1" 2>$null
        python "$ScriptDir\analyze-dashboard.py" 2>$null

        Write-Host "  Dashboard mis à jour" -ForegroundColor Green

        # Attendre avant la prochaine itération
        $sleepCount = 0
        while ($sleepCount -lt $RefreshInterval -and $running) {
            Start-Sleep -Seconds 1
            $sleepCount++
        }
    }
}
finally {
    Write-Host ""
    Write-Banner "ARRÊT"
    Write-Host "Tableau de bord arrêté après $iteration itérations" -ForegroundColor Yellow
}