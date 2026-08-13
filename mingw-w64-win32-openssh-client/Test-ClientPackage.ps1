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
)) {
    if (-not (Test-Path (Resolve-PayloadPath $relativePath) -PathType Leaf)) {
        throw "Required metadata '$relativePath' is missing."
    }
}

Write-Host 'Validated 11 baseline dispositions, 14 ARM64 PEs, file hashes, config, licenses, and no server payload.'
