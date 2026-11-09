<#
.SYNOPSIS
    Authenticode-sign the Windows binary of a published release.

.DESCRIPTION
    The release workflow signs and notarizes the macOS binary in CI, but publishes the Windows binary unsigned:
    Windows code signing uses a Certum certificate through SimplySign Desktop, which needs an interactive login
    (OTP from the mobile app) and has no clean headless path on GitHub-hosted runners. This script:

      1. downloads jfr-redact-<version>-windows-x86_64.exe from the GitHub release,
      2. signs it (SHA-256, RFC 3161 timestamp from Certum) and verifies signature + timestamp,
      3. uploads it back to the release, replacing the unsigned one.

    Preconditions: SimplySign Desktop logged in (cert visible in Cert:\CurrentUser\My); signtool (Windows SDK);
    gh authenticated against the repo.

.PARAMETER Version
    Release version without the "v" prefix, e.g. 0.2.0.

.PARAMETER Thumbprint
    SHA-1 thumbprint of the code-signing certificate. Defaults to $env:CERTUM_SIGN_THUMBPRINT, then
    $env:DISKSPACE_SIGN_THUMBPRINT (same certificate). Always pin by thumbprint; never use "signtool /a", which can
    silently pick the wrong certificate.

.PARAMETER NoUpload
    Sign under target\signed but do not touch the GitHub release.

.EXAMPLE
    .\scripts\Sign-Release.ps1 -Version 0.2.0
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string] $Version,
    [string] $Thumbprint,
    [string] $Repo = 'thegreystone/jfr-redact',
    [string] $TimestampUrl = 'http://time.certum.pl',
    [string] $SignTool,
    [switch] $NoUpload
)

$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..')

if (-not $Thumbprint) { $Thumbprint = $env:CERTUM_SIGN_THUMBPRINT }
if (-not $Thumbprint) { $Thumbprint = $env:DISKSPACE_SIGN_THUMBPRINT }
if (-not $Thumbprint) {
    throw 'No thumbprint. Set $env:CERTUM_SIGN_THUMBPRINT in your $PROFILE or pass -Thumbprint.'
}

if (-not $SignTool) {
    $SignTool = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin" -Recurse -Filter signtool.exe -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -match '\\x64\\' } |
        Sort-Object FullName -Descending |
        Select-Object -First 1 -ExpandProperty FullName
    if (-not $SignTool) {
        throw 'signtool.exe not found under Windows Kits 10. Install the Windows SDK or pass -SignTool.'
    }
}

$cert = Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.Thumbprint -eq $Thumbprint }
if (-not $cert) {
    throw "Cert $Thumbprint not found in Cert:\CurrentUser\My. Open SimplySign Desktop and log in (OTP from the mobile app), then retry."
}
Write-Host "Signing as: $($cert.Subject) (expires $($cert.NotAfter.ToShortDateString()))"

$binary = "jfr-redact-$Version-windows-x86_64.exe"
$work = Join-Path (Get-Location) 'target\signed'
if (Test-Path $work) { Remove-Item -Recurse -Force $work }
New-Item -ItemType Directory -Force $work | Out-Null

Write-Host "Downloading $binary from release v$Version..."
$release = gh release view "v$Version" --repo $Repo --json tagName 2>$null
if ($LASTEXITCODE -ne 0 -or -not $release) { throw "release v$Version not found on $Repo" }
gh release download "v$Version" --repo $Repo --pattern $binary --dir $work
if ($LASTEXITCODE -ne 0) { throw "gh release download failed for $binary (exit $LASTEXITCODE)" }
$exe = Join-Path $work $binary

Write-Host "Signing $binary..."
& $SignTool sign /tr $TimestampUrl /td sha256 /fd sha256 /sha1 $Thumbprint /d 'JFR Redact' /du "https://github.com/$Repo" $exe
if ($LASTEXITCODE -ne 0) { throw "signtool failed for $binary (exit $LASTEXITCODE)" }
$sig = Get-AuthenticodeSignature $exe
if ($sig.Status -ne 'Valid') { throw "Signature on $binary is $($sig.Status): $($sig.StatusMessage)" }
if (-not $sig.TimeStamperCertificate) {
    throw "Signature on $binary has no timestamp; without it the signature expires with the certificate."
}
Write-Host "  Subject:   $($sig.SignerCertificate.Subject)"
Write-Host "  Timestamp: $($sig.TimeStamperCertificate.Subject)"

if ($NoUpload) {
    Write-Host "Signed binary left in $work (upload skipped)."
    return
}

Write-Host "Replacing release asset..."
gh release upload "v$Version" --repo $Repo --clobber $exe
if ($LASTEXITCODE -ne 0) { throw "gh release upload failed (exit $LASTEXITCODE)" }
Write-Host "Done. Release v$Version now has a signed $binary." -ForegroundColor Green
