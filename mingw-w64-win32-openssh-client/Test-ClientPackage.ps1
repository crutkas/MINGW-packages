[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateScript({ Test-Path $_ -PathType Container })]
    [string] $Root
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

$documentation = Join-Path $Root 'usr\share\doc\win32-openssh-client'
$mapping = Get-Content (Join-Path $documentation 'baseline-paths.json') -Raw |
    ConvertFrom-Json
$manifest = Get-Content (Join-Path $documentation 'manifest.json') -Raw |
    ConvertFrom-Json

$expectedPePaths = @(
    'usr/bin/libcrypto.dll'
    'usr/bin/scp.exe'
    'usr/bin/sftp.exe'
    'usr/bin/ssh-add.exe'
    'usr/bin/ssh-agent.exe'
    'usr/bin/ssh-keygen.exe'
    'usr/bin/ssh-keyscan.exe'
    'usr/bin/ssh-pkcs11-helper.exe'
    'usr/bin/ssh-sk-helper.exe'
    'usr/bin/ssh.exe'
    'usr/lib/ssh/libcrypto.dll'
    'usr/lib/ssh/sftp-server.exe'
    'usr/lib/ssh/ssh-pkcs11-helper.exe'
    'usr/lib/ssh/ssh-sk-helper.exe'
)
$forbiddenPaths = @(
    'usr/bin/sshd.exe'
    'usr/bin/sshd-auth.exe'
    'usr/bin/sshd-session.exe'
    'usr/bin/ssh-shellhost.exe'
    'usr/lib/ssh/ssh-keysign.exe'
    'usr/share/openssh/sshd_config_default'
)

function Resolve-PayloadPath {
    param([Parameter(Mandatory)][string] $RelativePath)

    return Join-Path $Root $RelativePath.Replace(
        '/',
        [System.IO.Path]::DirectorySeparatorChar
    )
}

function Get-PEMachine {
    param([Parameter(Mandatory)][string] $Path)

    $stream = [System.IO.File]::OpenRead($Path)
    try {
        $reader = [System.IO.BinaryReader]::new($stream)
        if ($reader.ReadUInt16() -ne 0x5A4D) {
            throw "'$Path' does not have an MZ header."
        }
        $stream.Position = 0x3c
        $peOffset = $reader.ReadInt32()
        if ($peOffset -lt 0 -or $peOffset -gt ($stream.Length - 6)) {
            throw "'$Path' has an invalid PE header offset."
        }
        $stream.Position = $peOffset
        if ($reader.ReadUInt32() -ne 0x00004550) {
            throw "'$Path' does not have a PE signature."
        }
        return $reader.ReadUInt16()
    }
    finally {
        $stream.Dispose()
    }
}

if ($mapping.paths.Count -ne 11) {
    throw "Expected 11 baseline path entries, found $($mapping.paths.Count)."
}
$replaceEntries = @($mapping.paths | Where-Object disposition -eq 'replace')
$removeEntries = @($mapping.paths | Where-Object disposition -eq 'remove')
if ($replaceEntries.Count -ne 10 -or $removeEntries.Count -ne 1) {
    throw 'Expected 10 baseline replacements and one removal.'
}
if ($removeEntries[0].baselinePath -ne 'usr/lib/ssh/ssh-keysign.exe') {
    throw 'ssh-keysign must be the sole removal disposition.'
}

$manifestPePaths = @($manifest.files.path | Sort-Object)
if (Compare-Object ($expectedPePaths | Sort-Object) $manifestPePaths) {
    throw 'The 14-file PE manifest differs from the validated payload contract.'
}
if ($manifest.source.revision -ne 'b8c08ef9da9450a94a9c5ef717d96a7bd83f3332' -or
    $manifest.source.vcpkgBaseline -ne '16fa044f80dd984c24deff5b7d0457e64c85a1e0') {
    throw 'The package manifest source pins are incorrect.'
}
if ($manifest.globalConfig.mode -ne 'executable-relative' -or
    $manifest.globalConfig.executable -ne 'usr/bin/ssh.exe' -or
    $manifest.globalConfig.relativePath -ne '../../etc/ssh/ssh_config' -or
    $manifest.globalConfig.packagePath -ne 'etc/ssh/ssh_config' -or
    $manifest.globalConfig.configurationIncluded -ne $false -or
    $manifest.globalConfig.unknownAlgorithmBehavior -ne 'error') {
    throw 'The package manifest portable global configuration contract is incorrect.'
}

foreach ($entry in $replaceEntries) {
    if (-not (Test-Path (Resolve-PayloadPath $entry.packagePath) -PathType Leaf)) {
        throw "Mapped replacement '$($entry.packagePath)' is missing."
    }
}
foreach ($relativePath in $forbiddenPaths) {
    if (Test-Path (Resolve-PayloadPath $relativePath)) {
        throw "Forbidden payload '$relativePath' is present."
    }
}

foreach ($relativePath in $expectedPePaths) {
    $fullPath = Resolve-PayloadPath $relativePath
    if (-not (Test-Path $fullPath -PathType Leaf)) {
        throw "Expected PE '$relativePath' is missing."
    }
    $machine = Get-PEMachine -Path $fullPath
    if ($machine -ne 0xAA64) {
        throw "'$relativePath' has machine 0x$($machine.ToString('X4')); expected 0xAA64."
    }
}

foreach ($entry in $manifest.files) {
    $actualHash = (Get-FileHash (Resolve-PayloadPath $entry.path) -Algorithm SHA256).
        Hash.ToLowerInvariant()
    if ($actualHash -ne $entry.sha256) {
        throw "Manifest SHA-256 mismatch for '$($entry.path)'."
    }
}

$hashManifest = Join-Path $documentation 'package-files.sha256'
foreach ($line in Get-Content $hashManifest) {
    if ($line -notmatch '^([0-9a-f]{64}) [ *](\./.+)$') {
        throw "Malformed package hash entry '$line'."
    }
    $expectedHash = $Matches[1]
    $relativePath = $Matches[2].Substring(2)
    $actualHash = (Get-FileHash (Resolve-PayloadPath $relativePath) -Algorithm SHA256).
        Hash.ToLowerInvariant()
    if ($actualHash -ne $expectedHash) {
        throw "Package SHA-256 mismatch for '$relativePath'."
    }
}

foreach ($relativePath in @(
    'etc/ssh/ssh_config'
    'usr/share/licenses/win32-openssh-client/LICENSE.txt'
    'usr/share/licenses/win32-openssh-client/NOTICE.txt'
    'usr/share/doc/win32-openssh-client/ssh_config_default'
    'usr/share/doc/win32-openssh-client/ssh_config.before'
    'usr/share/doc/win32-openssh-client/ssh_config.after'
    'usr/share/doc/win32-openssh-client/ssh_config.diff'
    'usr/share/doc/win32-openssh-client/ssh_config.transform.json'
    'usr/share/doc/win32-openssh-client/source-pins.json'
)) {
    if (-not (Test-Path (Resolve-PayloadPath $relativePath) -PathType Leaf)) {
        throw "Required metadata '$relativePath' is missing."
    }
}

$configPath = Resolve-PayloadPath 'etc/ssh/ssh_config'
$beforePath = Resolve-PayloadPath 'usr/share/doc/win32-openssh-client/ssh_config.before'
$afterPath = Resolve-PayloadPath 'usr/share/doc/win32-openssh-client/ssh_config.after'
$transformPath = Resolve-PayloadPath 'usr/share/doc/win32-openssh-client/ssh_config.transform.json'
$transform = Get-Content $transformPath -Raw | ConvertFrom-Json
if ($transform.source.sha256 -ne
        'f783f00ce880ead34b01d6db20f35f0e9141e199ffc32ca14cd330a3165853a4' -or
    $transform.output.sha256 -ne
        '8afa8d96895abae6a4770bde0916b985b28bef5979b016da5621d65f92e1c3de') {
    throw 'The SSH policy transformation hashes are incorrect.'
}
if ((Get-FileHash $beforePath -Algorithm SHA256).Hash.ToLowerInvariant() -ne
        $transform.source.sha256 -or
    (Get-FileHash $afterPath -Algorithm SHA256).Hash.ToLowerInvariant() -ne
        $transform.output.sha256 -or
    (Get-FileHash $configPath -Algorithm SHA256).Hash.ToLowerInvariant() -ne
        $transform.output.sha256) {
    throw 'The installed SSH policy does not match the transformation manifest.'
}
$removedAlgorithms = @($transform.removedAlgorithms.name | Sort-Object)
$expectedRemovedAlgorithms = @(
    'ssh-dss'
    'ssh-dss-cert-v01@openssh.com'
) | Sort-Object
if (Compare-Object $expectedRemovedAlgorithms $removedAlgorithms) {
    throw "Unexpected removed SSH algorithms: $($removedAlgorithms -join ', ')."
}
if ($transform.changes.Count -ne 1 -or
    $transform.changes[0].directive -ne 'PubkeyAcceptedKeyTypes' -or
    $transform.changes[0].removedSourceTokens.Count -ne 1 -or
    $transform.changes[0].removedSourceTokens[0] -ne 'ssh-dss*') {
    throw 'The SSH policy transformation changed an unexpected source shape.'
}

$pins = Get-Content (
    Resolve-PayloadPath 'usr/share/doc/win32-openssh-client/source-pins.json'
) -Raw | ConvertFrom-Json
if ($pins.automation.repository -ne 'crutkas/Win32-OpenSSH' -or
    $pins.automation.pullRequest -ne 2 -or
    $pins.automation.revision -ne
        'e20e4eca0ad3ed513b9c05bdd03fba86e7cb3947' -or
    $pins.automation.archiveSha256 -ne
        '077c2d1ff0c876915f3716d47dcbc963121ed45cbb408b8cd53cbbee045322bd') {
    throw 'The fork-local source provenance is incorrect.'
}

Write-Host 'Validated fork-local source pins, 11 baseline dispositions, 14 ARM64 PEs, per-file hashes, transformed config, licenses, and no server payload.'
