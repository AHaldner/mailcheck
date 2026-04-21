[CmdletBinding()]
param(
    [string]$Version = "latest",
    [string]$BinDir = "$env:LOCALAPPDATA\Programs\mailcheck"
)

$ErrorActionPreference = "Stop"

$Repo = "AHaldner/mailcheck"

function Get-ReleaseVersion {
    param([string]$RequestedVersion)

    if ($RequestedVersion -ne "latest") {
        return $RequestedVersion
    }

    $release = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest"
    if (-not $release.tag_name) {
        throw "Failed to resolve latest release version."
    }

    return $release.tag_name
}

function Get-ArchiveArch {
    $arch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture
    switch ($arch) {
        "X64" { return "amd64" }
        "Arm64" { return "arm64" }
        default { throw "Unsupported architecture: $arch" }
    }
}

function Get-ExpectedChecksum {
    param(
        [string]$ChecksumsPath,
        [string]$ArchiveName
    )

    foreach ($line in Get-Content -Path $ChecksumsPath) {
        if ($line -match "^(?<hash>[0-9a-fA-F]+)\s+(?<file>.+)$" -and $Matches.file -eq $ArchiveName) {
            return $Matches.hash.ToLowerInvariant()
        }
    }

    throw "Missing checksum entry for $ArchiveName."
}

$resolvedVersion = Get-ReleaseVersion -RequestedVersion $Version
$arch = Get-ArchiveArch
$releaseUrl = "https://github.com/$Repo/releases/download/$resolvedVersion"
$archiveName = "mailcheck_{0}_windows_{1}.zip" -f $resolvedVersion.TrimStart("v"), $arch
$checksumsName = "checksums.txt"
$tempDir = Join-Path ([System.IO.Path]::GetTempPath()) ("mailcheck-install-" + [System.Guid]::NewGuid().ToString("N"))

New-Item -ItemType Directory -Path $tempDir | Out-Null

try {
    $archivePath = Join-Path $tempDir $archiveName
    $checksumsPath = Join-Path $tempDir $checksumsName
    $extractDir = Join-Path $tempDir "extract"

    Invoke-WebRequest -Uri "$releaseUrl/$archiveName" -OutFile $archivePath
    Invoke-WebRequest -Uri "$releaseUrl/$checksumsName" -OutFile $checksumsPath

    $expectedChecksum = Get-ExpectedChecksum -ChecksumsPath $checksumsPath -ArchiveName $archiveName
    $actualChecksum = (Get-FileHash -Algorithm SHA256 -Path $archivePath).Hash.ToLowerInvariant()
    if ($actualChecksum -ne $expectedChecksum) {
        throw "Checksum mismatch for $archiveName. Expected $expectedChecksum, got $actualChecksum."
    }

    Expand-Archive -Path $archivePath -DestinationPath $extractDir -Force

    New-Item -ItemType Directory -Path $BinDir -Force | Out-Null
    Copy-Item -Path (Join-Path $extractDir "mailcheck.exe") -Destination (Join-Path $BinDir "mailcheck.exe") -Force

    Write-Host "Installed mailcheck to $(Join-Path $BinDir 'mailcheck.exe')"
    Write-Host "If needed, add $BinDir to your PATH."
}
finally {
    if (Test-Path $tempDir) {
        Remove-Item -Path $tempDir -Recurse -Force
    }
}
