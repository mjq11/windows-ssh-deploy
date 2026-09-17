# Invoked by probe.py, which supplies the check mode and deployment parameters.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)

try {
    $result = [ordered]@{
        marker = 'WINDOWS_SSH_PROBE_OK'
        hostname = $env:COMPUTERNAME
        identity = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        powershell_version = $PSVersionTable.PSVersion.ToString()
        server_time = (Get-Date).ToString('o')
    }
    if ($CheckRelay) {
        $root = $RemoteRoot
        $configPath = Join-Path $root 'data\config.json'
        $packagePath = Join-Path $root 'app\package.json'
        $issues = [System.Collections.Generic.List[string]]::new()
        $relay = [ordered]@{
            task_state = $null
            version = $null
            config_exists = (Test-Path -LiteralPath $configPath -PathType Leaf)
            database_exists = (Test-Path -LiteralPath (Join-Path $root 'data\relay.sqlite') -PathType Leaf)
            health_status = $null
            health_service = $null
        }
        try {
            $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop
            $relay.task_state = [string]$task.State
            $relay.task_user = [string]$task.Principal.UserId
        } catch { $issues.Add('scheduled_task_unavailable') }
        try {
            $package = Get-Content -LiteralPath $packagePath -Raw | ConvertFrom-Json
            $relay.version = [string]$package.version
        } catch { $issues.Add('app_package_unavailable') }
        try {
            $config = Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json
            $relay.configured_port = $config.port
            $relay.codex_enabled = $config.codexEnabled
            $relay.codex_binary_exists = $false
            if (-not [string]::IsNullOrWhiteSpace([string]$config.codexBin)) {
                $relay.codex_binary_exists = Test-Path -LiteralPath $config.codexBin -PathType Leaf
            }
        } catch { $issues.Add('selected_config_fields_unavailable') }
        try {
            $health = Invoke-RestMethod -Uri ("http://127.0.0.1:{0}/healthz" -f $HealthPort) -TimeoutSec 5
            $relay.health_status = [string]$health.status
            $relay.health_service = [string]$health.service
        } catch { $issues.Add('health_request_failed') }
        if ($relay.configured_port -ne $HealthPort) { $issues.Add('configured_port_mismatch') }
        if (-not $relay.database_exists) { $issues.Add('database_missing') }
        if ($relay.task_state -ne 'Running') { $issues.Add('task_not_running') }
        if ($relay.health_status -ne 'ok' -or $relay.health_service -ne 'codex-relay') {
            $issues.Add('health_not_ok')
        }
        $relay.issues = @($issues.ToArray())
        $result.relay = $relay
        $result.relay_ok = $issues.Count -eq 0
    }
    $result | ConvertTo-Json -Depth 6 -Compress
    if ($CheckRelay -and -not $result.relay_ok) { exit 2 }
    exit 0
} catch {
    # Do not print exception messages that could include configuration contents.
    [Console]::Error.WriteLine('WINDOWS_SSH_PROBE_FAILED')
    exit 1
}
