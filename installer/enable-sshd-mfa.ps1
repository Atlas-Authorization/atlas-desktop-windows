<#
  Puts the Atlas second factor in front of every OpenSSH for Windows session, or takes it out again.
    ./enable-sshd-mfa.ps1 [-ExcludeUsers AtlasBreakGlass,svc-backup]     enable
    ./enable-sshd-mfa.ps1 -Remove                                          disable
  It adds a marked block to sshd_config:  Match User *,!<excluded>  ->  ForceCommand atlas-cli-mfa.exe ssh-wrap
  ForceCommand always runs, whatever command the client asked for; the client's command string reaches the user's shell only after
  the factor passed. sshd_config is backed up first, checked with `sshd -t`, and restored if the check fails. Needs elevation.
  Notes: scp/sftp and other non-interactive sessions need a factor that needs no typing (push); a user with only code factors is refused
  there. Set the AtlasCliMfa break-glass/kill switch plan (ROLLBACK.md) BEFORE enabling this on a PC you can only reach by ssh.
#>
param([string[]]$ExcludeUsers = @(), [switch]$Remove)
$ErrorActionPreference = 'Stop'
$cfg = Join-Path $env:ProgramData 'ssh\sshd_config'
if (-not (Test-Path -LiteralPath $cfg)) { throw "sshd_config not found at $cfg (is OpenSSH Server installed?)" }
$begin = '# BEGIN atlas-cli-mfa'; $end = '# END atlas-cli-mfa'
$text = [IO.File]::ReadAllText($cfg)
$pattern = "(?ms)^$([regex]::Escape($begin)).*?^$([regex]::Escape($end))\r?\n?"
$clean = [regex]::Replace($text, $pattern, '')
if (-not $Remove) {
  $exe = Join-Path $env:ProgramFiles 'Atlas\LoginAgent\atlas-cli-mfa.exe'
  if (-not (Test-Path -LiteralPath $exe)) { throw "atlas-cli-mfa.exe not found at $exe" }
  # sshd runs ForceCommand through the default shell: a path without spaces avoids quoting differences between cmd and PowerShell.
  $short = (New-Object -ComObject Scripting.FileSystemObject).GetFile($exe).ShortPath
  $users = '*' + (($ExcludeUsers | ForEach-Object { if ($_ -notmatch '^[A-Za-z0-9._-]+$') { throw "bad user name: $_" }; ",!$_" }) -join '')
  # Match blocks must come last in sshd_config; ours is appended after any existing ones, so it only wraps users they leave alone.
  $clean = $clean.TrimEnd() + "`r`n$begin`r`nMatch User $users`r`n    ForceCommand $short ssh-wrap`r`n$end`r`n"
}
$bak = "$cfg.atlas-bak"
Copy-Item -LiteralPath $cfg -Destination $bak -Force
[IO.File]::WriteAllText($cfg, $clean)
$sshd = Join-Path $env:SystemRoot 'System32\OpenSSH\sshd.exe'
if (Test-Path -LiteralPath $sshd) {
  & $sshd -t
  if ($LASTEXITCODE -ne 0) { Copy-Item -LiteralPath $bak -Destination $cfg -Force; throw 'sshd -t rejected the new configuration; the old one was restored.' }
}
Restart-Service sshd
Write-Host ($(if ($Remove) { 'Atlas MFA removed from sshd.' } else { 'Atlas MFA enabled for sshd. Test a new session BEFORE closing this one.' }))
