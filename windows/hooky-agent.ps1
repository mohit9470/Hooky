<#
.SYNOPSIS
    Hooky Windows Agent 1.4.0 - read-only security data collector for Windows.

.DESCRIPTION
    Collects Windows security configuration (accounts, password policy, UAC, LSA,
    SMB, RDP, TLS, firewall, Defender, BitLocker, updates, services, listeners,
    audit policy, enterprise controls) into a single JSON file that the
    Hooky Linux controller audits with its WIN-xxx check catalogue.

    The agent is READ-ONLY: it changes no system state and installs nothing.
    Requires Windows PowerShell 5.1 or newer (built into Windows 10/11/Server
    2016+). Run it elevated (as Administrator) for maximum coverage; without
    elevation some collectors return partial data and are reported as failed.

    WHAT IS NEW IN 1.4.0
      - 5-10x faster: collectors run in PARALLEL (runspace pool) and the slow
        WMI Win32_Service query was replaced with a fast registry + Get-Service
        scan (registry ImagePath is expanded, matching the old PathName data).
      - Live progress: one status line per collector with its runtime.
      - Visible errors: every collector failure / warning is captured into the
        result JSON (agent_errors) so SKIPPED checks in the report show a reason.
      - Hardened push: -UseBasicParsing, TLS 1.2, 30 s timeout, troubleshooting
        checklist on failure.
      - -Quick switch: skips the two slowest optional collectors (BitLocker and
        full update history) for a ~10 second triage scan.

.USAGE
    # Mode A - collect to a file, then copy the JSON to the Linux controller:
    powershell -NoProfile -ExecutionPolicy Bypass -File .\hooky-agent.ps1

    # Mode B - collect and push straight to the Hooky webhook:
    powershell -NoProfile -ExecutionPolicy Bypass -File .\hooky-agent.ps1 -Uri http://linux-controller:8090/hook -Token 'your-hook-token'

    # Fast triage scan (skips BitLocker + update history):
    powershell -NoProfile -ExecutionPolicy Bypass -File .\hooky-agent.ps1 -Quick

    # The Linux controller can also deploy and run this agent automatically:
    #   python3 hooky.py win user@windows-host

.PARAMETER OutFile
    Path of the JSON result file (default: .\hooky-agent-output.json)

.PARAMETER Uri
    Optional Hooky hook endpoint. When set, the JSON is also POSTed there
    with an 'X-Hooky-Token' header.

.PARAMETER Token
    Shared secret sent as X-Hooky-Token when pushing to -Uri.

.PARAMETER Quick
    Triage mode: skip BitLocker volumes and the full update history.
    The result JSON is flagged with "quick": true so the controller knows.

.EXAMPLE
    .\hooky-agent.ps1 -OutFile C:\Temp\ws01.json -Uri http://10.0.0.5:8090/hook -Token s3cret
#>

param(
    [string]$OutFile = ".\hooky-agent-output.json",
    [string]$Uri = "",
    [string]$Token = "",
    [switch]$Quick
)

$ErrorActionPreference = "SilentlyContinue"
$AGENT_VERSION = "1.4.0"

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
    quick         = [bool]$Quick
    collectors    = [ordered]@{}
    agent_errors  = @()
}

Write-Host "Hooky Windows agent $AGENT_VERSION - read-only security collector"
Write-Host ("  elevation : {0}" -f $(if ($IsAdmin) { "Administrator (full coverage)" } else { "limited (partial coverage)" }))
Write-Host ("  mode      : {0}" -f $(if ($Quick) { "quick triage (-Quick)" } else { "full scan" }))

# ---------------------------------------------------------------- helpers
# Helper text is prepended to every collector so it also works inside
# the parallel runspaces (each runspace is a fresh session).

$HelperText = @'
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
'@
# Make the helpers available in this session too (single source of truth).
Invoke-Expression $HelperText

# ---------------------------------------------------------------- collectors
# Every collector is SELF-CONTAINED: it only uses built-in cmdlets, the
# helpers above and $env: variables, so it can run inside any runspace.
# Each returns ONE object; failures are caught by the runner below.

$Collectors = [ordered]@{

"system" = {
    # OS / hardware inventory (3 fast WMI queries + registry build info)
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

"net_accounts" = {
    # Local password/Lockout policy via net.exe.
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

"local_users" = {
    # Local accounts + privileged group membership (ADSI fallback included)
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

"registry" = {
    # All policy-relevant registry values (UAC, LSA, SMB, RDP, TLS, ...)
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

"defender" = {
    # Microsoft Defender status + preference (exclusions, tamper protection)
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

"third_party_av" = {
    # Registered antivirus products (SecurityCenter2 covers 3rd-party AVs)
    $products = @(Get-CimInstance -Namespace "root/SecurityCenter2" -ClassName "AntiVirusProduct" |
        ForEach-Object { [ordered]@{ name = [string]$_.displayName; product_state = $_.productState } })
    @{ products = $products }
}

"firewall" = {
    # Firewall profile state (fast: profiles only, not every single rule)
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

"bitlocker" = {
    # BitLocker volume protection (skipped entirely in -Quick mode)
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

"hotfixes" = {
    # Installed Microsoft updates (skipped entirely in -Quick mode)
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

"auditpol" = {
    # Advanced audit policy (every subcategory and its setting)
    $raw = (auditpol /get /category:* 2>&1 | Out-String)
    @{ lines = @($raw -split "`r?`n" | Where-Object { $_.Trim() }) }
}

"listeners" = {
    # TCP ports that are listening, mapped to the owning process
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

"services" = {
    # v1.4.0: the old code used Get-CimInstance Win32_Service here, which is
    # the #1 cause of multi-minute runs (broken WMI makes it hang for MINUTES).
    # Fast equivalent, same output shape:
    #   - path/account/start config -> .NET registry read of
    #     HKLM\SYSTEM\CurrentControlSet\Services\<name> (sub-second, no WMI).
    #     GetValue() expands REG_EXPAND_SZ, so ImagePath matches the old
    #     Win32_Service PathName data used by the unquoted-path check.
    #   - live state (Running/Stopped) -> Get-Service (instant, no WMI).
    $reg = @{}
    try {
        $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey('LocalMachine', 'Default')
        $root = $base.OpenSubKey("SYSTEM\CurrentControlSet\Services")
        foreach ($name in $root.GetSubKeyNames()) {
            $k = $root.OpenSubKey($name)
            if ($null -eq $k) { continue }
            $t = $k.GetValue("Type", 0)
            # Type bits 16 (own process) / 32 (shared process) = Win32 services,
            # same set Win32_Service reports; drivers (1/2) are excluded.
            if ((($t -band 16) -eq 0) -and (($t -band 32) -eq 0)) { $k.Close(); continue }
            $reg[$name] = [ordered]@{
                path_name  = [string]$k.GetValue("ImagePath", "")
                start_name = [string]$k.GetValue("ObjectName", "")
                start_val  = [int]$k.GetValue("Start", -1)
            }
            $k.Close()
        }
        $root.Close()
        $base.Close()
    } catch { }
    $startMap = @{ 0 = "Boot"; 1 = "System"; 2 = "Automatic"; 3 = "Manual"; 4 = "Disabled" }
    @(Get-Service | ForEach-Object {
        $r = $reg[[string]$_.Name]
        $mode = $null
        try { $mode = [string]$_.StartType } catch { }
        if (-not $mode) {
            $mode = $(if ($r) { $startMap[[int]$r.start_val] } else { "Unknown" })
        }
        [ordered]@{
            name         = [string]$_.Name
            display_name = [string]$_.DisplayName
            state        = [string]$_.Status
            start_mode   = $mode
            start_name   = $(if ($r) { $r.start_name } else { "" })
            path_name    = $(if ($r) { $r.path_name } else { "" })
        }
    })
}

"shares" = {
    # SMB shares exported by this machine
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

"enterprise" = {
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

}  # end $Collectors

# In -Quick triage mode drop the two slowest optional collectors.
if ($Quick) {
    $Collectors.Remove("bitlocker")
    $Collectors.Remove("hotfixes")
}

# ---------------------------------------------------------------- runner
# All collectors run in PARALLEL on a 4-thread runspace pool. As each one
# finishes we print a live status line with its runtime, so the user can
# always see what the agent is doing and which collector is slow.

$pool = [runspacefactory]::CreateRunspacePool(1, 4)
$pool.Open()

$jobs = @()
$idx = 0
foreach ($name in @($Collectors.Keys)) {
    $idx++
    $ps = [powershell]::Create()
    $ps.RunspacePool = $pool
    [void]$ps.AddScript($HelperText + "`n" + [string]$Collectors[$name])
    $jobs += [pscustomobject]@{
        name   = $name
        ps     = $ps
        handle = $ps.BeginInvoke()
        sw     = [System.Diagnostics.Stopwatch]::StartNew()
        done   = $false
    }
}

$total = $jobs.Count
$doneCount = 0
$tAll = [System.Diagnostics.Stopwatch]::StartNew()

while ($doneCount -lt $total) {
    Start-Sleep -Milliseconds 120
    foreach ($j in $jobs) {
        if ($j.done -or -not $j.handle.IsCompleted) { continue }
        $j.done = $true
        $j.sw.Stop()
        $doneCount++
        $err = ""
        $data = $null
        try {
            $out = @($j.ps.EndInvoke($j.handle))
            $data = $out[0]
        } catch {
            $err = $_.Exception.Message
        }
        if ($j.ps.Streams.Error -and $j.ps.Streams.Error.Count -gt 0) {
            $msgs = @($j.ps.Streams.Error | ForEach-Object { [string]$_.Exception.Message })
            $script:Out.agent_errors += @($msgs | ForEach-Object { "{0}: {1}" -f $j.name, $_ })
            if (-not $err) { $err = ($msgs -join "; ") }
        }
        if ($null -ne $data -and -not $err) {
            $script:Out.collectors[$j.name] = @{ ok = $true; error = $null; data = $data }
            Write-Host ("  [{0,2}/{1}] {2,-14} ok     {3,7:N1}s" -f $doneCount, $total, $j.name, $j.sw.Elapsed.TotalSeconds)
        } else {
            if (-not $err) { $err = "collector returned no data" }
            $script:Out.collectors[$j.name] = @{ ok = $false; error = $err; data = $null }
            Write-Host ("  [{0,2}/{1}] {2,-14} FAILED {3,7:N1}s  ({4})" -f $doneCount, $total, $j.name, $j.sw.Elapsed.TotalSeconds, $err)
        }
        $j.ps.Dispose()
    }
}
$pool.Close()

# ---------------------------------------------------------------- output

$json = $script:Out | ConvertTo-Json -Depth 10 -Compress
$fullPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutFile)
try {
    $enc = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($fullPath, $json, $enc)
    $n = ($script:Out.collectors.Keys | Where-Object { $script:Out.collectors[$_].ok }).Count
    Write-Host ("  collected : {0}/{1} collectors ok in {2:N1}s" -f $n, $script:Out.collectors.Keys.Count, $tAll.Elapsed.TotalSeconds)
    if ($script:Out.agent_errors.Count -gt 0) {
        Write-Warning ("  {0} warning(s) were captured in the result JSON (agent_errors) - the report will explain the affected checks." -f $script:Out.agent_errors.Count)
    }
    Write-Host ("  results   : {0}" -f $fullPath)
} catch {
    Write-Error ("Hooky agent: cannot write result file {0}: {1}" -f $fullPath, $_.Exception.Message)
    exit 2
}

if ($Uri) {
    # Keep the legacy header name for older collectors (VulnScope lineage).
    $headers = @{}
    if ($Token) {
        $headers["X-Hooky-Token"] = $Token
        $headers["X-VulnScope-Token"] = $Token
    }
    # TLS 1.2 matters for https endpoints; harmless for plain http.
    try { [Net.ServicePointManager]::SecurityProtocol = ([Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12) } catch { }
    Write-Host ("  pushing   : {0}  ({1:N0} KB) ..." -f $Uri, ($json.Length / 1KB))
    $irmArgs = @{
        Method      = "Post"
        Uri         = $Uri
        Headers     = $headers
        ContentType = "application/json"
        Body        = $json
        TimeoutSec  = 30
    }
    # -UseBasicParsing avoids the IE first-launch / IE proxy pitfalls of
    # Windows PowerShell 5.1; it is a no-op on PowerShell 7+.
    if ($PSVersionTable.PSVersion.Major -lt 6) { $irmArgs["UseBasicParsing"] = $true }
    try {
        Invoke-RestMethod @irmArgs | Out-Null
        Write-Host ("  pushed ok : results delivered to the Linux controller")
    } catch {
        Write-Warning ("Hooky agent: push to {0} failed: {1}" -f $Uri, $_.Exception.Message)
        Write-Host  "  checklist : 1) Linux IP and port correct in -Uri?   2) is the collector still running there (python3 hooky.py hook)?"
        Write-Host  "              3) does the -Token match the collector's token?   4) any firewall between the two machines?"
        exit 3
    }
}

exit 0
