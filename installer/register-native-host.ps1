<#
  Registers the Atlas device sign-in native-messaging host with Chrome, Edge and Firefox (machine-wide), or removes it.
    ./register-native-host.ps1 -ChromeExtensionId <32-char id> [-FirefoxExtensionId device-sso@example.com]
    ./register-native-host.ps1 -Remove
  The host name is net.atlasauth.device_sso. Chrome and Edge only start the host for the extension ids listed in allowed_origins;
  Firefox for allowed_extensions. Ship the extension in browser-extension\ (or your own that sends {"type":"get_ticket"}).
#>
param([string]$ChromeExtensionId = '', [string]$FirefoxExtensionId = '', [switch]$Remove)
$ErrorActionPreference = 'Stop'
$name = 'net.atlasauth.device_sso'
$keys = @("HKLM:\SOFTWARE\Google\Chrome\NativeMessagingHosts\$name", "HKLM:\SOFTWARE\Microsoft\Edge\NativeMessagingHosts\$name", "HKLM:\SOFTWARE\Mozilla\NativeMessagingHosts\$name")
$dir = Join-Path $env:ProgramData 'Atlas-Public\native-host'
if ($Remove) {
  $keys | ForEach-Object { Remove-Item -LiteralPath $_ -Recurse -Force -ErrorAction SilentlyContinue }
  Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue
  return
}
if ($ChromeExtensionId -and $ChromeExtensionId -notmatch '^[a-p]{32}$') { throw 'ChromeExtensionId must be the 32-letter extension id' }
if ($FirefoxExtensionId -and $FirefoxExtensionId -notmatch '^[A-Za-z0-9._@-]{3,100}$') { throw 'bad FirefoxExtensionId' }
if (-not $ChromeExtensionId -and -not $FirefoxExtensionId) { throw 'give at least one extension id' }
$exe = Join-Path $env:ProgramFiles 'Atlas\LoginAgent\atlas-sso-native-host.exe'
New-Item -ItemType Directory -Force $dir | Out-Null
function Write-Manifest($file, $obj) { $p = Join-Path $dir $file; ($obj | ConvertTo-Json -Depth 4) | Set-Content -Path $p -Encoding ASCII; $p }
if ($ChromeExtensionId) {
  $m = Write-Manifest 'chromium.json' ([ordered]@{ name = $name; description = 'Atlas device sign-in'; path = $exe; type = 'stdio'; allowed_origins = @("chrome-extension://$ChromeExtensionId/") })
  foreach ($k in $keys[0], $keys[1]) { New-Item -Path $k -Force | Out-Null; Set-ItemProperty -Path $k -Name '(default)' -Value $m }
}
if ($FirefoxExtensionId) {
  $m = Write-Manifest 'firefox.json' ([ordered]@{ name = $name; description = 'Atlas device sign-in'; path = $exe; type = 'stdio'; allowed_extensions = @($FirefoxExtensionId) })
  New-Item -Path $keys[2] -Force | Out-Null; Set-ItemProperty -Path $keys[2] -Name '(default)' -Value $m
}
Write-Host 'Native messaging host registered.'
