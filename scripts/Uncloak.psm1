<#
.SYNOPSIS
    Uncloak Enterprise NDR/EDR PowerShell Governance Module.
.DESCRIPTION
    Provides native PowerShell cmdlets for Windows administrators and SOC responders
    to inspect AD Tier assignments, tune FlowFeaturesV1 thresholds, push host overrides,
    and invoke immediate WFP containment.
#>

function Get-UncloakPolicy {
    [CmdletBinding()]
    param(
        [string]$ManagerUrl = "http://127.0.0.1:8830",
        [switch]$Local
    )
    if ($Local) {
        python -m uncloak policy status --json | ConvertFrom-Json
        return
    }
    try {
        Invoke-RestMethod -Uri "$($ManagerUrl.TrimEnd('/'))/api/policies" -Method Get -TimeoutSec 5
    }
    catch {
        Write-Warning "Central Manager unreachable at $ManagerUrl. Falling back to local policy store."
        python -m uncloak policy status --json | ConvertFrom-Json
    }
}

function Set-UncloakPolicy {
    [CmdletBinding()]
    param(
        [ValidateSet("Tier0", "Tier1", "Tier2", "Tier-0", "Tier-1", "Tier-2")]
        [string]$Tier,

        [ValidateSet("Autonomous", "Prompt", "AuditP1", "Quorum", "AuditOnly", "Inherit")]
        [string]$ContainmentMode = "Inherit",

        [string]$HostId,
        [string]$ManagerUrl = "http://127.0.0.1:8830",
        [switch]$MaintenanceMode
    )

    $ModeMap = @{
        "Autonomous" = "auto_wfp"
        "Prompt"     = "prompt_analyst"
        "AuditP1"    = "audit_p1"
        "Quorum"     = "quorum"
        "AuditOnly"  = "audit_only"
        "Inherit"    = "inherit"
    }

    $NormTier = if ($Tier) { $Tier -replace "^Tier(\d)$", "Tier-`$1" } else { $null }
    $Payload = @{
        host_id          = $HostId
        tier             = $NormTier
        mode             = $ModeMap[$ContainmentMode]
        maintenance_mode = [bool]$MaintenanceMode
    } | ConvertTo-Json

    try {
        $Response = Invoke-RestMethod -Uri "$($ManagerUrl.TrimEnd('/'))/api/host_override" `
            -Method Post -ContentType "application/json" -Body $Payload -TimeoutSec 5
        Write-Output $Response
    }
    catch {
        Write-Warning "Manager unreachable; applying override to local sensor policy store."
        $CliMode = switch ($ContainmentMode) {
            "Autonomous" { "autonomous" }
            "Prompt"     { "prompt" }
            "AuditP1"    { "audit_p1" }
            "Quorum"     { "quorum" }
            "AuditOnly"  { "audit" }
            default      { "inherit" }
        }
        if ($NormTier) {
            python -m uncloak policy set-tier --tier $NormTier
        }
        python -m uncloak policy override --mode $CliMode
    }
}

function Set-UncloakThreshold {
    [CmdletBinding()]
    param(
        [ValidateRange(0.10, 0.99)]
        [double]$AlertScore = 0.85,

        [ValidateRange(0.50, 0.99)]
        [double]$ActionScore = 0.90,

        [ValidateRange(0.01, 0.80)]
        [double]$MaxMadRatio = 0.18,

        [ValidateRange(2, 50)]
        [int]$MinBursts = 8,

        [string]$ManagerUrl = "http://127.0.0.1:8830"
    )

    $Payload = @{
        alert_confidence = $AlertScore
        block_confidence = $ActionScore
        max_mad_ratio    = $MaxMadRatio
        min_bursts       = $MinBursts
    } | ConvertTo-Json

    try {
        $Response = Invoke-RestMethod -Uri "$($ManagerUrl.TrimEnd('/'))/api/policies" `
            -Method Post -ContentType "application/json" -Body $Payload -TimeoutSec 5
        Write-Output $Response
    }
    catch {
        python -m uncloak policy set-thresholds --alert $AlertScore --block $ActionScore --mad $MaxMadRatio --bursts $MinBursts
    }
}

function Invoke-UncloakIsolation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$HostId,

        [string]$Reason = "SOC Emergency Containment",
        [string]$ManagerUrl = "http://127.0.0.1:8830"
    )

    Write-Verbose "Triggering WFP host isolation on $HostId ($Reason)"
    $Payload = @{ host_id = $HostId; reason = $Reason } | ConvertTo-Json
    Invoke-RestMethod -Uri "$($ManagerUrl.TrimEnd('/'))/api/isolate_host" `
        -Method Post -ContentType "application/json" -Body $Payload -TimeoutSec 5
}

Export-ModuleMember -Function Get-UncloakPolicy, Set-UncloakPolicy, Set-UncloakThreshold, Invoke-UncloakIsolation
