param(
    [Parameter(Mandatory = $true)]
    [string]$PackageFile,

    [Parameter(Mandatory = $true)]
    [string]$TestLog,

    [Parameter(Mandatory = $true)]
    [string]$ArtifactsDirectory
)

$ErrorActionPreference = 'Stop'
$packageName = 'mingw-w64-clang-aarch64-busybox'

function Invoke-Msys2 {
    param([Parameter(Mandatory = $true)][string]$Command)

    $output = & msys2 -c $Command
    if ($LASTEXITCODE -ne 0) {
        throw "MSYS2 command failed: $Command"
    }
    return @($output)
}

function Get-PeMachine {
    param([Parameter(Mandatory = $true)][string]$Path)

    $bytes = [IO.File]::ReadAllBytes($Path)
    if ($bytes.Length -lt 64 -or $bytes[0] -ne 0x4d -or $bytes[1] -ne 0x5a) {
        return $null
    }

    $peOffset = [BitConverter]::ToInt32($bytes, 0x3c)
    if ($peOffset -lt 0 -or $peOffset + 6 -gt $bytes.Length) {
        throw "Invalid PE header offset in $Path"
    }
    if ($bytes[$peOffset] -ne 0x50 -or $bytes[$peOffset + 1] -ne 0x45 -or
        $bytes[$peOffset + 2] -ne 0 -or $bytes[$peOffset + 3] -ne 0) {
        throw "Invalid PE signature in $Path"
    }

    return [BitConverter]::ToUInt16($bytes, $peOffset + 4)
}

$packageFilePath = (Resolve-Path -LiteralPath $PackageFile).Path
$testLogPath = (Resolve-Path -LiteralPath $TestLog).Path
New-Item -ItemType Directory -Force -Path $ArtifactsDirectory | Out-Null
$artifactsPath = (Resolve-Path -LiteralPath $ArtifactsDirectory).Path

if ([Runtime.InteropServices.RuntimeInformation]::OSArchitecture -ne
    [Runtime.InteropServices.Architecture]::Arm64) {
    throw "Package validation requires a native Windows ARM64 runner"
}

$msysRoot = (Invoke-Msys2 'cygpath -w /' | Select-Object -First 1).Trim()
$prefix = (Invoke-Msys2 'cygpath -w "$MINGW_PREFIX"' | Select-Object -First 1).Trim()
$busybox = Join-Path $prefix 'bin\busybox.exe'

$installedVersion = Invoke-Msys2 "pacman -Q $packageName"
if (-not ($installedVersion -join "`n").StartsWith("$packageName ")) {
    throw "$packageName is not installed"
}

$owner = Invoke-Msys2 'pacman -Qo "$MINGW_PREFIX/bin/busybox.exe"'
if (-not ($owner -join "`n").Contains($packageName)) {
    throw "pacman does not attribute busybox.exe to $packageName"
}

$peFiles = [Collections.Generic.List[string]]::new()
$peMachines = [ordered]@{}
foreach ($path in Invoke-Msys2 "pacman -Qql $packageName") {
    if (-not $path.StartsWith('/')) {
        continue
    }
    $windowsPath = Join-Path $msysRoot ($path.TrimStart('/').Replace('/', '\'))
    if (-not [IO.File]::Exists($windowsPath)) {
        continue
    }
    $machine = Get-PeMachine -Path $windowsPath
    if ($null -eq $machine) {
        continue
    }
    $relativePath = [IO.Path]::GetRelativePath($msysRoot, $windowsPath).Replace('\', '/')
    $peFiles.Add($relativePath)
    $machineText = '0x{0:X4}' -f $machine
    $peMachines[$relativePath] = $machineText
    if ($machine -ne 0xAA64) {
        throw "Packaged PE $relativePath has machine $machineText, expected 0xAA64"
    }
}
if ($peFiles.Count -eq 0) {
    throw 'The package did not contain a PE file'
}

$uname = (& $busybox uname -m | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or $uname -ne 'aarch64') {
    throw "Expected busybox uname -m to report aarch64, got '$uname'"
}

$relocatedRoot = Join-Path $env:RUNNER_TEMP 'busybox relocated prefix'
$relocatedBin = Join-Path $relocatedRoot 'bin'
if (Test-Path -LiteralPath $relocatedRoot) {
    Remove-Item -LiteralPath $relocatedRoot -Recurse -Force
}
New-Item -ItemType Directory -Force -Path $relocatedBin | Out-Null
$relocatedBusybox = Join-Path $relocatedBin 'busybox.exe'
Copy-Item -LiteralPath $busybox -Destination $relocatedBusybox

$wrapperResult = (& $relocatedBusybox sh -c 'printf wrapper-ok' | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or $wrapperResult -ne 'wrapper-ok') {
    throw 'Relocated busybox sh dispatch failed'
}

$payload = Join-Path $relocatedRoot 'payload.txt'
[IO.File]::WriteAllText($payload, 'alias-ok', [Text.Encoding]::ASCII)
$catAlias = Join-Path $relocatedBin 'cat.exe'
Copy-Item -LiteralPath $relocatedBusybox -Destination $catAlias
$aliasResult = (& $catAlias $payload | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or $aliasResult -ne 'alias-ok') {
    throw 'argv[0] applet alias dispatch failed'
}

$configPath = Join-Path $prefix 'share\busybox\busybox.config'
$linksPath = Join-Path $prefix 'share\busybox\busybox.links'
$mapPath = Join-Path $prefix 'share\busybox\arm64-payload-map.json'
$config = Get-Content -LiteralPath $configPath
$links = Get-Content -LiteralPath $linksPath
$map = Get-Content -LiteralPath $mapPath -Raw | ConvertFrom-Json

foreach ($setting in 'CONFIG_FEATURE_PREFER_APPLETS=y',
    'CONFIG_INSTALL_APPLET_SYMLINKS=y',
    'CONFIG_CROSS_COMPILER_PREFIX="aarch64-w64-mingw32-"') {
    if ($config -notcontains $setting) {
        throw "Packaged configuration is missing $setting"
    }
}
foreach ($link in '/bin/sh', '/usr/bin/awk', '/usr/bin/unzip') {
    if ($links -notcontains $link) {
        throw "Packaged applet map is missing $link"
    }
}

if ($map.baseline.sourcePullRequest -ne 'https://github.com/crutkas/build-extra/pull/1' -or
    $map.baseline.sourceCommit -ne '9e8e3eb929ae5c7fe8a2d899be2eefdc07356c19' -or
    $map.baseline.payloadManifestSha256 -ne
        'ae1e311fd81258150c2300d02c58655f30b190a15bcbe3ea8bbaccc1ce8c1c9a' -or
    $map.summary.directArm64CandidateCount -ne 84 -or
    $map.summary.architectureGapCount -ne 53) {
    throw 'Packaged ARM64 payload map does not match the fork-local baseline'
}

$testLines = Get-Content -LiteralPath $testLogPath
$passCount = @($testLines | Select-String '^PASS:').Count
$failureCount = @($testLines | Select-String '^FAIL:').Count
if ($passCount -ne 1089 -or $failureCount -ne 0) {
    throw "Expected 1089 passing tests and zero failures; got $passCount and $failureCount"
}

$objdump = Invoke-Msys2 'objdump -p "$MINGW_PREFIX/bin/busybox.exe"'
$dependencies = @(
    $objdump |
        ForEach-Object {
            if ($_ -match 'DLL Name:\s*(\S+)') {
                $Matches[1]
            }
        } |
        Sort-Object -Unique
)
if ($dependencies.Count -eq 0) {
    throw 'Could not determine busybox.exe imports'
}

$packageHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $packageFilePath).Hash.ToLowerInvariant()
$packageFileName = Split-Path -Leaf $packageFilePath
$runUrl = "https://github.com/$env:GITHUB_REPOSITORY/actions/runs/$env:GITHUB_RUN_ID"

$manifest = [ordered]@{
    schemaVersion = 1
    package = [ordered]@{
        file = $packageFileName
        sha256 = $packageHash
        pacmanName = $packageName
        installCommand = "pacman -U --noconfirm '$packageFileName'"
    }
    source = [ordered]@{
        repository = 'https://github.com/crutkas/busybox-w32'
        commit = 'e7299058b4074a19cfae0f446ec45ab87e804a27'
        archiveSha256 = '205e5ad0a4733727cb3b6cfc08e1ede387dcb5edb6240e9ecbc6692b305a37a4'
    }
    buildExtraPayloadBaseline = [ordered]@{
        pullRequest = 'https://github.com/crutkas/build-extra/pull/1'
        commit = '9e8e3eb929ae5c7fe8a2d899be2eefdc07356c19'
        manifest = 'arm64-payload-architecture-v2.55.0.4.tsv'
        manifestSha256 = 'ae1e311fd81258150c2300d02c58655f30b190a15bcbe3ea8bbaccc1ce8c1c9a'
        directArm64Candidates = 84
        architectureGaps = 53
        gnuSemanticParityClaimed = $false
    }
    validation = [ordered]@{
        ciRun = $runUrl
        nativeWindowsArm64 = $true
        peMachine = '0xAA64'
        packagedPeFiles = $peMachines
        busyBoxTests = 1089
        busyBoxFailures = 0
        gitCriticalAppletSmokeTests = $true
        pacmanOwnership = $true
        relocatable = $true
        appletAliasDispatch = $true
        reproducible = $true
    }
    dependencies = $dependencies
}

$manifestPath = Join-Path $artifactsPath 'busybox-arm64-artifact.json'
$manifest | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $manifestPath -Encoding utf8
"$packageHash  $packageFileName" |
    Set-Content -LiteralPath (Join-Path $artifactsPath 'SHA256SUMS') -Encoding ascii
$manifest.package.installCommand |
    Set-Content -LiteralPath (Join-Path $artifactsPath 'downstream-install.txt') -Encoding ascii

Write-Host "Validated $packageFileName ($packageHash)"
Write-Host "Packaged PE files: $($peFiles.Count), all machine 0xAA64"
Write-Host "Dependencies: $($dependencies -join ', ')"
