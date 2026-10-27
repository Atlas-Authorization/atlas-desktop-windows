<#
  Creates the documented break-glass local administrator and prints its generated password ONCE.
  Run elevated, on the PC (or from your endpoint tooling), then immediately vault the password and add the account name to
  `break_glass_accounts` in %ProgramData%\Atlas\config.json (or install with BREAK_GLASS_ACCOUNTS=AtlasBreakGlass).

  The account skips the Atlas step on this PC so an administrator can still sign in when the Atlas service,
  the network or the second factor is unavailable. Every use writes event id 100 (source AtlasLoginAgent, Application log)
  - alert on it. Use a different random password per PC and rotate it after each use.
#>
param([string]$Name = "AtlasBreakGlass")
$ErrorActionPreference = "Stop"
if (Get-LocalUser -Name $Name -ErrorAction SilentlyContinue) { throw "Local user '$Name' already exists." }

Add-Type -AssemblyName System.Security
$bytes = New-Object byte[] 24
[System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
$plain = ([Convert]::ToBase64String($bytes) -replace '[+/=]', 'x') + "aA1!"
$secure = ConvertTo-SecureString $plain -AsPlainText -Force

New-LocalUser -Name $Name -Password $secure -PasswordNeverExpires -AccountNeverExpires `
  -Description "Atlas break-glass administrator (audited, vault the password)" | Out-Null
Add-LocalGroupMember -SID "S-1-5-32-544" -Member $Name

Write-Host "Created local administrator '$Name'. Password (shown once, vault it now):"
Write-Host $plain
Write-Host "Audit: Event Viewer > Windows Logs > Application > source AtlasLoginAgent, event id 100."
$plain = $null
