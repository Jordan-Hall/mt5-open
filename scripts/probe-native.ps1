param(
    [Parameter(Mandatory)][string]$ConfigPath,
    [Parameter(Mandatory)][string]$LoginProfilePath,
    [Parameter(Mandatory)][string]$Address,
    [string]$Executable
)

$ErrorActionPreference = 'Stop'
$config = @{}
foreach ($line in Get-Content -LiteralPath $ConfigPath) {
    if ($line -match '^([A-Z][A-Z0-9_]+)=(.*)$') {
        $config[$Matches[1]] = $Matches[2].Trim()
    }
}
$account = $config['MT5_LOGIN']
if (-not $account) { $account = $config['MT5_ACCOUNT'] }
if (-not $account -or -not $config['MT5_PASSWORD'] -or -not $config['MT5_SERVER']) {
    throw 'Config must contain MT5_LOGIN or MT5_ACCOUNT, MT5_PASSWORD, and MT5_SERVER.'
}
$values = @{
    MT5_LOGIN = $account
    MT5_PASSWORD = $config['MT5_PASSWORD']
    MT5_SERVER = $config['MT5_SERVER']
    MT5_ADDRESS = $Address
    MT5_LOGIN_PROFILE = (Resolve-Path -LiteralPath $LoginProfilePath).Path
}
$previous = @{}
foreach ($name in $values.Keys) {
    $previous[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
    [Environment]::SetEnvironmentVariable($name, $values[$name], 'Process')
}
try {
    if ($Executable) {
        & $Executable
    } else {
        Push-Location (Split-Path $PSScriptRoot -Parent)
        try { cargo run --locked -p mt5_session --features live --example auth_probe -j1 }
        finally { Pop-Location }
    }
    if ($LASTEXITCODE -ne 0) { throw 'Native authentication or synchronization failed.' }
} finally {
    foreach ($name in $values.Keys) {
        [Environment]::SetEnvironmentVariable($name, $previous[$name], 'Process')
    }
}
