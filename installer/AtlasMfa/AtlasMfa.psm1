# AtlasMfa: the Atlas second factor for PowerShell sessions. It calls atlas-cli-mfa.exe, which talks to the AtlasCliMfa service
# (the service holds the device keys; this module and the exe hold none). Fail closed: any problem is a refusal.
Set-StrictMode -Version Latest

function Get-AtlasCliMfaPath {
  # The module lives in <install dir>\AtlasMfa\, the exe one level up.
  $p = Join-Path (Split-Path -Parent $PSScriptRoot) 'atlas-cli-mfa.exe'
  if (-not (Test-Path -LiteralPath $p)) { throw "atlas-cli-mfa.exe not found next to the AtlasMfa module ($p)" }
  $p
}

function Invoke-AtlasMfa {
  <#
  .SYNOPSIS  Asks for the Atlas second factor (push number-match, authenticator code, or offline code).
  .OUTPUTS   $true when allowed. Throws when refused, so a script stops at the call.
  .EXAMPLE   Invoke-AtlasMfa -Service deploy; ./deploy.ps1
  #>
  [CmdletBinding()]
  param([ValidatePattern('^[A-Za-z0-9._-]{1,31}$')][string]$Service = 'powershell')
  & (Get-AtlasCliMfaPath) check --service $Service
  switch ($LASTEXITCODE) {
    0 { return $true }
    2 { throw 'Atlas MFA is unavailable on this PC (service not running or broken install). Refusing.' }
    default { throw 'Atlas MFA refused.' }
  }
}

function Enter-AtlasElevation {
  <#
  .SYNOPSIS  Asks for the second factor, then starts an elevated process (UAC still asks as usual).
  .NOTES     This is a workflow guard: it does not stop someone who runs Start-Process -Verb RunAs directly.
             Windows gives third parties no hook into the UAC consent prompt.
  #>
  [CmdletBinding()]
  param([string]$FilePath = 'powershell.exe', [string[]]$ArgumentList)
  Invoke-AtlasMfa -Service elevation | Out-Null
  $args = @{ FilePath = $FilePath; Verb = 'RunAs' }
  if ($ArgumentList) { $args.ArgumentList = $ArgumentList }
  Start-Process @args
}

Export-ModuleMember -Function Invoke-AtlasMfa, Enter-AtlasElevation
