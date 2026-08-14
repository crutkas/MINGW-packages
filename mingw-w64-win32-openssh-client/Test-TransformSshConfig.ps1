[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

$packageDirectory = Split-Path $MyInvocation.MyCommand.Path -Parent
$transformer = Join-Path $packageDirectory 'Transform-SshConfig.ps1'
$source = Join-Path $packageDirectory 'ssh_config.git-for-windows'
$expectedSourceSha256 = 'f783f00ce880ead34b01d6db20f35f0e9141e199ffc32ca14cd330a3165853a4'
$actualSourceSha256 = (Get-FileHash $source -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actualSourceSha256 -ne $expectedSourceSha256) {
    throw "Test source SHA-256 is $actualSourceSha256; expected $expectedSourceSha256."
}

function Assert-TransformFails {
    param(
        [Parameter(Mandatory)][string] $InputText,
        [Parameter(Mandatory)][string] $ExpectedPattern,
        [switch] $UseWrongHash
    )

    $case = Join-Path $script:tempRoot ([guid]::NewGuid().ToString('N'))
    $null = New-Item $case -ItemType Directory
    $inputPath = Join-Path $case 'input'
    [System.IO.File]::WriteAllText(
        $inputPath,
        $InputText,
        [System.Text.UTF8Encoding]::new($false)
    )
    $hash = if ($UseWrongHash) {
        '0' * 64
    }
    else {
        (Get-FileHash $inputPath -Algorithm SHA256).Hash.ToLowerInvariant()
    }

    try {
        & $transformer `
            -SourcePath $inputPath `
            -DestinationPath (Join-Path $case 'output') `
            -ManifestPath (Join-Path $case 'manifest.json') `
            -DiffPath (Join-Path $case 'diff') `
            -ExpectedSourceSha256 $hash
        throw "Transform unexpectedly accepted test input: $InputText"
    }
    catch {
        if ($_.Exception.Message -notmatch $ExpectedPattern) {
            throw "Transform failed with '$($_.Exception.Message)', not '$ExpectedPattern'."
        }
    }
}

$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) "openssh-policy-transform-$PID"
$null = New-Item $tempRoot -ItemType Directory -Force
try {
    $output = Join-Path $tempRoot 'ssh_config.after'
    $manifestPath = Join-Path $tempRoot 'manifest.json'
    $diffPath = Join-Path $tempRoot 'ssh_config.diff'
    & $transformer `
        -SourcePath $source `
        -DestinationPath $output `
        -ManifestPath $manifestPath `
        -DiffPath $diffPath `
        -ExpectedSourceSha256 $expectedSourceSha256

    $beforeLines = Get-Content $source
    $afterLines = Get-Content $output
    if ($beforeLines.Count -ne $afterLines.Count) {
        throw 'The real policy transform unexpectedly changed the line count.'
    }
    $differences = @(Compare-Object $beforeLines $afterLines)
    if ($differences.Count -ne 2) {
        throw "Expected one changed policy line, found $($differences.Count / 2)."
    }
    $expectedAfter = 'PubkeyAcceptedKeyTypes ssh-ed25519*,ssh-rsa*,ecdsa-sha2*'
    $lastPolicyLine = @($afterLines | Where-Object { $_ -ne '' })[-1]
    if ($lastPolicyLine -ne $expectedAfter) {
        throw "Transformed policy ended with '$lastPolicyLine', not '$expectedAfter'."
    }

    $manifest = Get-Content $manifestPath -Raw | ConvertFrom-Json
    if ($manifest.source.sha256 -ne $expectedSourceSha256 -or
        $manifest.output.sha256 -ne
            (Get-FileHash $output -Algorithm SHA256).Hash.ToLowerInvariant()) {
        throw 'The transform manifest hashes do not match the before/after files.'
    }
    $removed = @($manifest.removedAlgorithms.name | Sort-Object)
    $expectedRemoved = @('ssh-dss', 'ssh-dss-cert-v01@openssh.com' | Sort-Object)
    if (Compare-Object $expectedRemoved $removed) {
        throw "Unexpected removed algorithm set: $($removed -join ', ')."
    }
    if ((Get-Content $diffPath -Raw) -notmatch [regex]::Escape($expectedAfter)) {
        throw 'The audit diff does not contain the transformed policy line.'
    }

    Assert-TransformFails `
        -InputText "HostKeyAlgorithms +ssh-ed25519,,ssh-dss`n" `
        -ExpectedPattern 'Malformed algorithm list'
    Assert-TransformFails `
        -InputText "ProxyCommand echo ssh-dss`n" `
        -ExpectedPattern 'Cannot safely parse unsupported algorithm text'
    Assert-TransformFails `
        -InputText "HostKeyAlgorithms +ssh-ed25519`n" `
        -ExpectedPattern 'Expected exactly one removal'
    Assert-TransformFails `
        -InputText "HostKeyAlgorithms +ssh-dss`n" `
        -ExpectedPattern 'SHA-256 is' `
        -UseWrongHash

    Write-Host 'Passed deterministic SSH policy transformation tests.'
}
finally {
    Remove-Item $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
}
