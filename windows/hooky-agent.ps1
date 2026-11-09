<#
.SYNOPSIS
    Hooky Windows Agent 1.3.0 - read-only security data collector for Windows.

.DESCRIPTION
    Collects Windows security configuration (accounts, password policy, UAC, LSA,
    SMB, RDP, TLS, firewall, Defender, BitLocker, updates, services, listeners,
    audit policy, enterprise controls) into a single JSON file that the
    Hooky Linux controller audits with its WIN-xxx check catalogue.

    The agent is READ-ONLY: it changes no system state and installs nothing.
    Requires Windows PowerShell 5.1 or newer (built into Windows 10/11/Server
    2016+). Run it elevated (as Administrator) for maximum coverage; without
    elevation some collectors return partial data and are reported as failed.

.USAGE
    # Mode A - collect to a file, then copy the JSON to the Linux controller:
    powershell -NoProfile -ExecutionPolicy Bypass -File .\hooky-agent.ps1

    # Mode B - collect and push straight to the Hooky webhook:
    powershell -NoProfile -ExecutionPolicy Bypass -File .\hooky-agent.ps1 ^
        -Uri http://linux-controller:8090/hook -Token '<your-hook-token>'

    # The Linux controller can also deploy and run this agent automatically:
    #   python3 hooky.py win user@windows-host

.PARAMETER OutFile
    Path of the JSON result file (default: .\hooky-agent-output.json)

.PARAMETER Uri
    Optional Hooky hook endpoint. When set, the JSON is also POSTed there
    with an 'X-Hooky-Token' header.

.PARAMETER Token
    Shared secret sent as X-Hooky-Token when pushing to -Uri.

.EXAMPLE
    .\hooky-agent.ps1 -OutFile C:\Temp\ws01.json -Uri http://10.0.0.5:8090/hook -Token s3cret
#>
param(
    [string]$OutFile = ".\hooky-agent-output.json",
    [string]$Uri = "",
    [string]$Token = ""
)

$ErrorActionPreference = "SilentlyContinue"
$AGENT_VERSION = "1.3.0"

# ---------------------------------------------------------------- preamble
$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
           ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

$script:Out = [ordered]@{
    schema        = "hooky-agent/1"
    agent_version = $AGENT_VERSION
    collected_at  = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss") + " UTC"
    computer      = $env:COMPUTERNAME
    os_family     = "Windows"
    elevated      = [bool]$IsAdmin
    ps_version    = $PSVersionTable.PSVersion.ToString()
    collectors    = [ordered]@{}
}

function Invoke-Collector([string]$Name, [scriptblock]$Script) {
    try {
        $data = & $Script
        $script:Out.collectors[$Name] = @{ ok = $true; error = $null; data = $data }
    } catch {
        $script:Out.collectors[$Name] = @{ ok = $false; error = $_.Exception.Message; data = $null }
    }
}

function Get-RegVal([string]$Path, [string]$Name) {
    try {
        $item = Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop
        return $item.$Name
    } catch {
        return $null
    }
}

function Get-RegKeyExists([string]$Path) {
    try { return (Test-Path -Path $Path) } catch { return $false }
}

Write-Host "Hooky Windows agent $AGENT_VERSION - read-only security collector"
Write-Host ("  elevation : {0}" -f $(if ($IsAdmin) { "Administrator (full coverage)" } else { "limited (partial coverage)" }))

# ---------------------------------------------------------------- collectors

Invoke-Collector "system" {
    $os = Get-CimInstance Win32_OperatingSystem
    $cs = Get-CimInstance Win32_ComputerSystem
    $cv = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
    $cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
    [ordered]@{
        computer_name   = [string]$cs.Name
        domain          = [string]$cs.Domain
        part_of_domain  = [bool]$cs.PartOfDomain
        manufacturer    = [string]$cs.Manufacturer
        model           = [string]$cs.Model
        os_caption      = [string]$os.Caption
        os_version      = [string]$os.Version
        os_arch         = [string]$os.OSArchitecture
        build_number    = [string]$cv.CurrentBuildNumber
        ubr             = $cv.UBR
        display_version = [string]$cv.DisplayVersion
        install_date    = $os.InstallDate.ToString("yyyy-MM-dd")
        last_boot       = $os.LastBootUpTime.ToString("yyyy-MM-dd HH:mm:ss")
        secure_boot     = (Get-RegVal "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State" "UEFISecureBootEnabled")
        cpu             = [string]$cpu.Name
        cpu_count       = @($cpu.NumberOfLogicalProcessors)[0]
        memory_gb       = [math]::Round([double]$cs.TotalVisibleMemorySize / 1MB, 1)
        pending_reboot  = [ordered]@{
            cbs_reboot_pending  = Get-RegKeyExists "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending"
            wu_reboot_required  = Get-RegKeyExists "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"
            pending_file_rename = ($null -ne (Get-RegVal "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" "PendingFileRenameOperations"))
        }
    }
}

Invoke-Collector "net_accounts" {
    # NOTE: net.exe output is localised; Hooky parses English keys and
    # falls back to SKIPPED with raw evidence on other locales.
    $raw = (net accounts 2>&1 | Out-String)
    $lines = @($raw -split "`r?`n" | Where-Object { $_.Trim() })
    $kv = [ordered]@{}
    foreach ($line in $lines) {
        $idx = $line.IndexOf(":")
        if ($idx -lt 1) { continue }
        $k = $line.Substring(0, $idx).Trim()
        $v = $line.Substring($idx + 1).Trim()
        if ($k) { $kv[$k] = $v }
    }
    @{ raw = $lines; parsed = $kv }
}

Invoke-Collector "local_users" {
    $users = @()
    $done = $false
    try {
        $users = @(Get-LocalUser | ForEach-Object {
            [ordered]@{
                name              = [string]$_.Name
                enabled           = [bool]$_.Enabled
                password_required = [bool]$_.PasswordRequired
                password_expires  = $(if ($_.PasswordExpires) { $_.PasswordExpires.ToString("yyyy-MM-dd") } else { $null })
                last_logon        = $(if ($_.LastLogon) { $_.LastLogon.ToString("yyyy-MM-dd HH:mm") } else { "never" })
                sid               = [string]$_.SID.Value
            }
        })
        $done = $true
    } catch { }
    if (-not $done) {
        # Fallback for older systems without the LocalAccounts module (ADSI)
        $adsi = [ADSI]"WinNT://.,computer"
        $users = @($adsi.Children | ForEach-Object {
            if ($_.SchemaClassName -eq "User") {
                [ordered]@{
                    name              = [string]$_.Name.Value
                    enabled           = (-not [bool]$_.AccountDisabled[0])
                    password_required = [bool]$_.PasswordRequired[0]
                    password_expires  = $null
                    last_logon        = "unknown"
                    sid               = $null
                }
            }
        })
    }
    $groups = [ordered]@{}
    foreach ($g in @("Administrators", "Remote Desktop Users", "Remote Management Users")) {
        $members = $null
        try {
            $members = @(Get-LocalGroupMember -Group $g -ErrorAction Stop | ForEach-Object {
                [ordered]@{
                    name             = [string]$_.Name
                    principal_source = [string]$_.PrincipalSource
                    object_class     = [string]$_.ObjectClass
                }
            })
        } catch {
            try {
                $adsiGrp = [ADSI]("WinNT://./" + $g + ",group")
                $members = @($adsiGrp.Invoke("Members") | ForEach-Object {
                    $n = $_.GetType().InvokeMember("Name", "GetProperty", $null, $_, $null)
                    [ordered]@{ name = [string]$n; principal_source = "unknown"; object_class = "unknown" }
                })
            } catch { $members = $null }
        }
        $groups[$g] = $members
    }
    @{ users = $users; groups = $groups }
}

Invoke-Collector "registry" {
    $r = [ordered]@{}
    $uacPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    $r["uac"] = [ordered]@{
        EnableLUA                     = Get-RegVal $uacPath "EnableLUA"
        ConsentPromptBehaviorAdmin    = Get-RegVal $uacPath "ConsentPromptBehaviorAdmin"
        PromptOnSecureDesktop         = Get-RegVal $uacPath "PromptOnSecureDesktop"
        LocalAccountTokenFilterPolicy = Get-RegVal $uacPath "LocalAccountTokenFilterPolicy"
    }
    $lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    $r["lsa"] = [ordered]@{
        RunAsPPL             = Get-RegVal $lsaPath "RunAsPPL"
        LmCompatibilityLevel = Get-RegVal $lsaPath "LmCompatibilityLevel"
        RestrictAnonymous    = Get-RegVal $lsaPath "RestrictAnonymous"
        RestrictAnonymousSAM = Get-RegVal $lsaPath "RestrictAnonymousSAM"
        NoLMHash             = Get-RegVal $lsaPath "NoLMHash"
    }
    $r["smb1"] = [ordered]@{
        SMB1           = Get-RegVal "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "SMB1"
        mrxsmb10_start = Get-RegVal "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10" "Start"
    }
    $tsPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"
    $r["rdp"] = [ordered]@{
        fDenyTSConnections     = Get-RegVal $tsPath "fDenyTSConnections"
        NLA_UserAuthentication = Get-RegVal ($tsPath + "\WinStations\RDP-Tcp") "UserAuthentication"
        PortNumber             = Get-RegVal ($tsPath + "\WinStations\RDP-Tcp") "PortNumber"
    }
    $tls = [ordered]@{}
    foreach ($p in @("SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1", "TLS 1.2")) {
        $protoPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$p\Server"
        $tls[$p] = [ordered]@{
            Enabled           = Get-RegVal $protoPath "Enabled"
            DisabledByDefault = Get-RegVal $protoPath "DisabledByDefault"
        }
    }
    $r["tls_server"] = $tls
    $r["autorun"] = [ordered]@{
        NoDriveTypeAutoRun = Get-RegVal "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoDriveTypeAutoRun"
    }
    $ssPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop"
    $r["screensaver"] = [ordered]@{
        ScreenSaveActive    = Get-RegVal $ssPath "ScreenSaveActive"
        ScreenSaverIsSecure = Get-RegVal $ssPath "ScreenSaverIsSecure"
        ScreenSaveTimeOut   = Get-RegVal $ssPath "ScreenSaveTimeOut"
    }
    $r["wu_policy"] = [ordered]@{
        NoAutoUpdate = Get-RegVal "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" "NoAutoUpdate"
    }
    $r["powershell_logging"] = [ordered]@{
        EnableScriptBlockLogging = Get-RegVal "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" "EnableScriptBlockLogging"
        EnableModuleLogging      = Get-RegVal "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" "EnableModuleLogging"
        EnableTranscripting      = Get-RegVal "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" "EnableTranscripting"
    }
    $r
}

Invoke-Collector "defender" {
    $status = Get-MpComputerStatus -ErrorAction Stop
    $pref = $null
    try { $pref = Get-MpPreference -ErrorAction Stop } catch { }
    [ordered]@{
        am_running             = [bool]$status.AMServiceEnabled
        realtime_enabled       = [bool]$status.RealTimeProtectionEnabled
        behavior_monitor       = [bool]$status.BehaviorMonitorEnabled
        ioav_enabled           = [bool]$status.IoavProtectionEnabled
        nis_enabled            = [bool]$status.NISEnabled
        antispyware_enabled    = [bool]$status.AntispywareEnabled
        signature_age_days     = $status.AntivirusSignatureAge
        signature_last_updated = $(if ($status.AntivirusSignatureLastUpdated) { $status.AntivirusSignatureLastUpdated.ToString("yyyy-MM-dd HH:mm") } else { $null })
        tamper_protection      = $status.TamperProtectionSource
        engine_version         = [string]$status.AMEngineVersion
        signature_version      = [string]$status.AntivirusSignatureVersion
        disable_realtime_pref  = $(if ($pref) { [bool]$pref.DisableRealtimeMonitoring } else { $null })
        exclusion_paths        = $(if ($pref) { @($pref.ExclusionPath) } else { @() })
        exclusion_extensions   = $(if ($pref) { @($pref.ExclusionExtension) } else { @() })
        exclusion_processes    = $(if ($pref) { @($pref.ExclusionProcess) } else { @() })
    }
}

Invoke-Collector "third_party_av" {
    $products = @(Get-CimInstance -Namespace "root/SecurityCenter2" -ClassName "AntiVirusProduct" |
        ForEach-Object { [ordered]@{ name = [string]$_.displayName; product_state = $_.productState } })
    @{ products = $products }
}

Invoke-Collector "firewall" {
    $profiles = @()
    try {
        $profiles = @(Get-NetFirewallProfile | ForEach-Object {
            [ordered]@{
                name              = [string]$_.Name
                enabled           = [bool]$_.Enabled
                default_inbound   = [string]$_.DefaultInboundAction
                default_outbound  = [string]$_.DefaultOutboundAction
                allow_local_rules = [bool]$_.AllowLocalFirewallRules
            }
        })
    } catch { }
    $raw = $null
    try { $raw = @((netsh advfirewall show allprofiles state | Out-String) -split "`r?`n" | Where-Object { $_.Trim() }) } catch { }
    @{ profiles = $profiles; netsh_raw = $raw }
}

Invoke-Collector "bitlocker" {
    $vols = @()
    $raw = $null
    try {
        $vols = @(Get-BitLockerVolume | ForEach-Object {
            [ordered]@{
                mount_point    = [string]$_.MountPoint
                volume_status  = [string]$_.VolumeStatus
                protection     = [string]$_.ProtectionStatus
                encryption_pct = $_.EncryptionPercentage
                key_protectors = @($_.KeyProtector | ForEach-Object { [string]$_.KeyProtectorType })
            }
        })
    } catch {
        try { $raw = @((manage-bde -status 2>&1 | Out-String) -split "`r?`n") } catch { $raw = $null }
    }
    @{ volumes = $vols; managebde_raw = $raw }
}

Invoke-Collector "hotfixes" {
    $hf = @()
    try {
        $hf = @(Get-HotFix | Sort-Object InstalledOn -Descending | ForEach-Object {
            [ordered]@{
                id           = [string]$_.HotFixID
                description  = [string]$_.Description
                installed_on = $(if ($_.InstalledOn) { $_.InstalledOn.ToString("yyyy-MM-dd") } else { $null })
            }
        })
    } catch { }
    @{ updates = $hf; count = $hf.Count }
}

Invoke-Collector "auditpol" {
    $raw = (auditpol /get /category:* 2>&1 | Out-String)
    @{ lines = @($raw -split "`r?`n" | Where-Object { $_.Trim() }) }
}

Invoke-Collector "listeners" {
    $rows = @()
    try {
        $procMap = @{}
        Get-Process | ForEach-Object { $procMap[[int]$_.Id] = [string]$_.ProcessName }
        $rows = @(Get-NetTCPConnection -State Listen -ErrorAction Stop | ForEach-Object {
            [ordered]@{
                local_address = [string]$_.LocalAddress
                local_port    = [int]$_.LocalPort
                pid           = [int]$_.OwningProcess
                process       = $(if ($procMap.ContainsKey([int]$_.OwningProcess)) { $procMap[[int]$_.OwningProcess] } else { "unknown" })
            }
        })
    } catch {
        $raw = (netstat -ano | Out-String)
        foreach ($ln in @($raw -split "`r?`n")) {
            $t = @($ln.Trim() -split "\s+")
            if ($t.Count -ge 5 -and $t[3] -eq "LISTENING") {
                $addr = $t[1] -replace ":[^:]*$", ""
                $port = ($t[1] -replace ".*:", "")
                $rows += [ordered]@{
                    local_address = [string]$addr
                    local_port    = [int]$port
                    pid           = [int]$t[4]
                    process       = "unknown"
                }
            }
        }
    }
    $rows
}

Invoke-Collector "services" {
    @(Get-CimInstance Win32_Service | ForEach-Object {
        [ordered]@{
            name         = [string]$_.Name
            display_name = [string]$_.DisplayName
            state        = [string]$_.State
            start_mode   = [string]$_.StartMode
            start_name   = [string]$_.StartName
            path_name    = [string]$_.PathName
        }
    })
}

Invoke-Collector "shares" {
    $rows = @()
    try {
        $rows = @(Get-SmbShare | ForEach-Object {
            [ordered]@{ name = [string]$_.Name; path = [string]$_.Path; description = [string]$_.Description }
        })
    } catch {
        try { $rows = @((net share | Out-String) -split "`r?`n") } catch { }
    }
    $rows
}

Invoke-Collector "enterprise" {
    # Enterprise controls (WIN-026..029): LAPS, SMB signing, AppLocker, RDP idle
    $o = [ordered]@{}
    $o["laps"] = [ordered]@{
        windows_laps_policy = Get-RegKeyExists "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS"
        legacy_laps_cse     = (Test-Path "$env:ProgramFiles\LAPS\CSE\Admpwd.dll") -or (Test-Path "$env:SystemRoot\System32\admpwd.dll")
    }
    $o["smb_signing"] = [ordered]@{
        server_require = Get-RegVal "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "RequireSecuritySignature"
        client_require = Get-RegVal "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" "RequireSecuritySignature"
    }
    $srpv2 = @()
    try {
        $srpv2 = @(Get-ChildItem "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2" -ErrorAction Stop |
            Select-Object -ExpandProperty PSChildName)
    } catch { }
    $appidsvc = $null
    try { $appidsvc = [string](Get-Service AppIDSvc -ErrorAction Stop).Status } catch { }
    $o["app_control"] = [ordered]@{ srpv2_rules = $srpv2; appidsvc = $appidsvc }
    $tsPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
    $o["rdp_timeout"] = [ordered]@{
        max_idle_time_ms          = Get-RegVal $tsPath "MaxIdleTime"
        max_disconnection_time_ms = Get-RegVal $tsPath "MaxDisconnectionTime"
        rdp_enabled               = Get-RegVal "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" "fDenyTSConnections"
    }
    $o
}

# ---------------------------------------------------------------- output

$json = $script:Out | ConvertTo-Json -Depth 10 -Compress
$fullPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutFile)
try {
    $enc = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($fullPath, $json, $enc)
    $n = ($script:Out.collectors.Keys | Where-Object { $script:Out.collectors[$_].ok }).Count
    Write-Host ("  collected : {0}/{1} collectors succeeded" -f $n, $script:Out.collectors.Keys.Count)
    Write-Host ("  results   : {0}" -f $fullPath)
} catch {
    Write-Error ("Hooky agent: cannot write result file {0}: {1}" -f $fullPath, $_.Exception.Message)
    exit 2
}

if ($Uri) {
    $headers = @{}
    if ($Token) {
        # current header name, plus the legacy name for older collectors
        $headers["X-Hooky-Token"] = $Token
        $headers["X-VulnScope-Token"] = $Token
    }
    try {
        Invoke-RestMethod -Method Post -Uri $Uri -Headers $headers `
            -ContentType "application/json" -Body $json -TimeoutSec 120 | Out-Null
        Write-Host ("  pushed to : {0}" -f $Uri)
    } catch {
        Write-Warning ("Hooky agent: push to {0} failed: {1}" -f $Uri, $_.Exception.Message)
        exit 3
    }
}

exit 0
