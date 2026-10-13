param(
    [string]$TargetPath = "",
    [string[]]$ToolNames = @()
)

$ErrorActionPreference = "Stop"

function Find-Tool {
    param([string]$Name)
    $cmd = Get-Command $Name -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($cmd) {
        return [ordered]@{
            name = $Name
            available = $true
            path = $cmd.Source
            readiness = "discovered_unverified"
            smoke_validated = $false
            target_validated = $false
        }
    }

    return [ordered]@{
        name = $Name
        available = $false
        path = $null
        readiness = "unavailable"
        smoke_validated = $false
        target_validated = $false
    }
}

$defaultToolNames = @(
    "python", "node", "rea", "java", "jadx", "apktool", "frida",
    "ghidraRun", "analyzeHeadless", "ida64", "r2", "rz-bin",
    "readelf", "objdump", "nm", "strings", "dotnet", "ilspycmd",
    "unblob", "binwalk", "wasm-tools", "rz-ghidra"
)
# Probe only the backend needed for the current question when -ToolNames is supplied.
$selectedToolNames = if ($ToolNames.Count -gt 0) {
    @($ToolNames | ForEach-Object { $_ -split "," } | ForEach-Object { $_.Trim() } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)
} else { $defaultToolNames }

$result = [ordered]@{
    timestamp = (Get-Date).ToString("o")
    read_only = $true
    verification_scope = "PATH discovery only; no smoke or target analysis"
    scoped_tool_check = ($ToolNames.Count -gt 0)
    target = $null
    tools = @()
}

if ($TargetPath) {
    if (-not (Test-Path -LiteralPath $TargetPath)) {
        throw "Target not found: $TargetPath"
    }

    $item = Get-Item -LiteralPath $TargetPath
    $result.target = [ordered]@{
        path = $item.FullName
        length = if ($item.PSIsContainer) { $null } else { $item.Length }
        sha256 = if ($item.PSIsContainer) { $null } else { (Get-FileHash -Algorithm SHA256 -LiteralPath $item.FullName).Hash }
        extension = $item.Extension
    }
}

foreach ($name in $selectedToolNames) {
    $result.tools += Find-Tool -Name $name
}

$result | ConvertTo-Json -Depth 5
