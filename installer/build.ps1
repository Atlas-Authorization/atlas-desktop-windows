<#
  Builds the provider, signs it when (and only when) signing material is in the environment, and builds the MSI.

  Signing (all optional; nothing is signed and the MSI is named *-unsigned.msi when none is set):
    ATLAS_SIGN_CERT_THUMBPRINT              certificate in the machine/user store
    ATLAS_SIGN_PFX + ATLAS_SIGN_PFX_PASSWORD   path to a .pfx and its password
    ATLAS_SIGN_TIMESTAMP_URL                RFC 3161 timestamp server (default http://timestamp.digicert.com)

  Needs: Visual Studio 2022 build tools, CMake, vcpkg (VCPKG_ROOT), the WiX v4 dotnet tool (`dotnet tool install --global wix`),
  and signtool.exe on PATH when signing.
#>
param(
  [string]$Version = "0.1.0",
  [string]$Configuration = "Release",
  [string]$OutDir = "$PSScriptRoot\..\build\installer"
)
$ErrorActionPreference = "Stop"
$root = Resolve-Path "$PSScriptRoot\.."
Push-Location $root
try {
  cmake --preset windows-msvc-x64
  cmake --build --preset windows-msvc-x64
  ctest --preset windows-msvc-x64 --output-on-failure

  $bin = Join-Path $root "build\windows-msvc-x64\bin\$Configuration"
  if (-not (Test-Path "$bin\atlas_credential_provider.dll")) {
    $bin = Join-Path $root "build\windows-msvc-x64\src\provider\$Configuration"
  }
  foreach ($f in "atlas_credential_provider.dll", "atlas-enroll.exe", "atlas-passkey.exe", "atlas-sync.exe", "atlas-cli-mfa.exe", "atlas-sso-broker.exe", "atlas-sso-native-host.exe") {
    if (-not (Test-Path "$bin\$f")) { throw "missing build output: $bin\$f" }
  }

  $ts = $env:ATLAS_SIGN_TIMESTAMP_URL; if (-not $ts) { $ts = "http://timestamp.digicert.com" }
  $signArgs = $null
  if ($env:ATLAS_SIGN_CERT_THUMBPRINT) {
    $signArgs = @("sign", "/sha1", $env:ATLAS_SIGN_CERT_THUMBPRINT, "/fd", "SHA256", "/td", "SHA256", "/tr", $ts)
  } elseif ($env:ATLAS_SIGN_PFX) {
    $signArgs = @("sign", "/f", $env:ATLAS_SIGN_PFX, "/fd", "SHA256", "/td", "SHA256", "/tr", $ts)
    if ($env:ATLAS_SIGN_PFX_PASSWORD) { $signArgs += @("/p", $env:ATLAS_SIGN_PFX_PASSWORD) }
  }
  function Sign-File($path) { if ($signArgs) { & signtool @signArgs $path; if ($LASTEXITCODE) { throw "signtool failed for $path" } } }

  foreach ($f in "atlas_credential_provider.dll", "atlas-enroll.exe", "atlas-passkey.exe", "atlas-sync.exe", "atlas-cli-mfa.exe", "atlas-sso-broker.exe", "atlas-sso-native-host.exe") { Sign-File "$bin\$f" }

  New-Item -ItemType Directory -Force $OutDir | Out-Null
  $suffix = if ($signArgs) { "" } else { "-unsigned" }
  $msi = Join-Path $OutDir "AtlasLoginAgent-$Version$suffix.msi"
  wix build "$PSScriptRoot\Package.wxs" -arch x64 -d Version=$Version -d BinDir=$bin -o $msi
  if ($LASTEXITCODE) { throw "wix build failed" }
  Sign-File $msi
  Write-Host "Built $msi"
} finally { Pop-Location }
