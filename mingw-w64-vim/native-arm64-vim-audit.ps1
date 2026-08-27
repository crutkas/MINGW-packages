[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string[]] $Archives,
    [Parameter(Mandatory = $true)]
    [string] $Root,
    [Parameter(Mandatory = $true)]
    [string] $ReportDirectory,
    [string[]] $DependencyArchives,
    [string] $DependencyPrefix,
    [string] $FallbackDependencyPrefix,
    [string] $MsysRoot
)

$ErrorActionPreference = 'Stop'
$Arm64Machine = 0xAA64
$osArch = [Runtime.InteropServices.RuntimeInformation]::OSArchitecture
$processArch = [Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture
if ($osArch -ne [Runtime.InteropServices.Architecture]::Arm64 -or
    $processArch -ne [Runtime.InteropServices.Architecture]::Arm64) {
    throw "Refusing ARM64 package audit on OS=$osArch process=$processArch"
}
$SystemImports = @(
    'advapi32.dll', 'bcrypt.dll', 'cabinet.dll', 'comctl32.dll', 'comdlg32.dll',
    'crypt32.dll', 'dwmapi.dll', 'gdi32.dll', 'imm32.dll', 'iphlpapi.dll',
    'kernel32.dll', 'mpr.dll', 'netapi32.dll', 'ntdll.dll', 'ole32.dll',
    'oleaut32.dll', 'psapi.dll', 'rpcrt4.dll', 'secur32.dll', 'setupapi.dll',
    'shell32.dll', 'shlwapi.dll', 'user32.dll', 'userenv.dll', 'ucrtbase.dll',
    'uuid.dll', 'version.dll', 'winhttp.dll', 'winmm.dll', 'winspool.drv',
    'ws2_32.dll'
)

function Get-PeMachine([string] $Path) {
    $bytes = [IO.File]::ReadAllBytes($Path)
    if ($bytes.Length -lt 64 -or $bytes[0] -ne 0x4d -or $bytes[1] -ne 0x5a) {
        throw "$Path is not a PE file"
    }
    $offset = [BitConverter]::ToInt32($bytes, 0x3c)
    if ($offset -lt 0 -or $offset + 6 -gt $bytes.Length) {
        throw "$Path has an invalid PE header offset"
    }
    if ([Text.Encoding]::ASCII.GetString($bytes, $offset, 4) -ne "PE`0`0") {
        throw "$Path has no PE signature"
    }
    return [BitConverter]::ToUInt16($bytes, $offset + 4)
}

function Assert-Arm64Pe([string] $Path) {
    $machine = Get-PeMachine $Path
    if ($machine -ne $Arm64Machine) {
        throw "$Path has PE machine 0x$($machine.ToString('X4')); expected 0xAA64"
    }
    [pscustomobject]@{
        Path = (Resolve-Path $Path).Path
        Machine = '0xAA64'
        Size = (Get-Item $Path).Length
        SHA256 = (Get-FileHash $Path -Algorithm SHA256).Hash
    }
}

function Get-Imports([string] $Path, [string] $ReadObj) {
    $output = & $ReadObj --coff-imports $Path 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "llvm-readobj failed for $Path`n$output"
    }
    @($output | Select-String '^\s*Name:\s+(.+)$' | ForEach-Object {
        $_.Matches[0].Groups[1].Value.Trim()
    } | Sort-Object -Unique)
}

function Write-DbSnapshot([string] $Name) {
    if (-not $MsysRoot) {
        return
    }
    $db = Join-Path $MsysRoot 'var\lib\pacman\local'
    $snapshot = Join-Path $ReportDirectory "$Name-pacman-db.tsv"
    if (-not (Test-Path $db)) {
        "missing`t$db" | Set-Content -Encoding utf8 $snapshot
        return
    }
    Get-ChildItem $db -Recurse -File | Sort-Object FullName | ForEach-Object {
        "$($_.FullName.Substring($db.Length + 1))`t$($_.Length)`t$((Get-FileHash $_.FullName -Algorithm SHA256).Hash)"
    } | Set-Content -Encoding utf8 $snapshot
}

$resolvedRoot = [IO.Path]::GetFullPath($Root)
if ($resolvedRoot -like 'C:\msys64*' -or (Split-Path $resolvedRoot -Leaf) -notlike 'native-arm64-vim-root*') {
    throw "Refusing unsafe package root: $resolvedRoot"
}
if (Test-Path $resolvedRoot) {
    Remove-Item $resolvedRoot -Recurse -Force
}
New-Item $resolvedRoot -ItemType Directory | Out-Null
New-Item $ReportDirectory -ItemType Directory -Force | Out-Null
New-Item (Join-Path $ReportDirectory 'archives') -ItemType Directory -Force | Out-Null

Write-DbSnapshot 'before'

$allMembers = @{}
$packageNames = [Collections.Generic.List[string]]::new()
$archiveRecords = foreach ($archive in $Archives) {
    $resolvedArchive = (Resolve-Path $archive).Path
    $name = Split-Path $resolvedArchive -Leaf
    Copy-Item $resolvedArchive (Join-Path $ReportDirectory "archives\$name")
    $members = & tar.exe -tf $resolvedArchive 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Could not list $resolvedArchive`n$members"
    }
    $members | Set-Content -Encoding utf8 (Join-Path $ReportDirectory "$name.members.txt")
    $pkginfo = & tar.exe -xOf $resolvedArchive .PKGINFO 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Could not read PKGINFO from $resolvedArchive`n$pkginfo"
    }
    $pkginfo | Set-Content -Encoding utf8 (Join-Path $ReportDirectory "$name.PKGINFO")
    $packageName = @($pkginfo | Select-String '^pkgname = (.+)$' | ForEach-Object {
        $_.Matches[0].Groups[1].Value.Trim()
    })
    if ($packageName.Count -ne 1) {
        throw "Could not identify exactly one package name in $name"
    }
    $packageNames.Add($packageName[0])

    $payloadMembers = @($members | ForEach-Object { $_.TrimStart('.', '/') } |
        Where-Object {
            $_ -and -not $_.EndsWith('/') -and $_ -notmatch '^(BUILDINFO|MTREE|PKGINFO)$'
        })
    foreach ($member in $payloadMembers) {
        if ($allMembers.ContainsKey($member)) {
            throw "Package archives overlap at '$member': $($allMembers[$member]) and $name"
        }
        $allMembers[$member] = $name
    }

    $peMembers = @($payloadMembers | Where-Object { $_ -match '\.(exe|dll|pyd)$' })
    if ($packageName[0] -eq 'mingw-w64-clang-aarch64-vim') {
        $expectedPeMembers = @(
            'clangarm64/bin/ex.exe', 'clangarm64/bin/rview.exe',
            'clangarm64/bin/rvim.exe', 'clangarm64/bin/view.exe',
            'clangarm64/bin/vim.exe', 'clangarm64/bin/vimdiff.exe',
            'clangarm64/bin/xxd.exe'
        )
        if (Compare-Object ($expectedPeMembers | Sort-Object) ($peMembers | Sort-Object)) {
            throw "The Vim binary split is not the exact seven-PE payload: $($peMembers -join ', ')"
        }
        if ($payloadMembers | Where-Object { $_ -like 'clangarm64/share/vim/vim92/*' }) {
            throw 'The Vim binary split incorrectly contains runtime files'
        }
    } elseif ($packageName[0] -eq 'mingw-w64-clang-aarch64-vim-runtime') {
        if ($peMembers.Count -ne 0) {
            throw "The architecture-independent runtime split contains PE files: $($peMembers -join ', ')"
        }
        foreach ($requiredRuntime in @(
            'clangarm64/share/vim/vim92/doc/help.txt',
            'clangarm64/share/vim/vim92/git-for-windows.vim',
            'clangarm64/share/vim/vim92/syntax/c.vim'
        )) {
            if ($payloadMembers -notcontains $requiredRuntime) {
                throw "The runtime split is missing $requiredRuntime"
            }
        }
    } else {
        throw "Unexpected candidate package name '$($packageName[0])'"
    }

    & tar.exe -xf $resolvedArchive -C $resolvedRoot
    if ($LASTEXITCODE -ne 0) {
        throw "Could not extract $resolvedArchive"
    }
    [pscustomobject]@{
        Filename = $name
        Size = (Get-Item $resolvedArchive).Length
        SHA256 = (Get-FileHash $resolvedArchive -Algorithm SHA256).Hash
        Members = @($members).Count
    }
}
if (Compare-Object @('mingw-w64-clang-aarch64-vim', 'mingw-w64-clang-aarch64-vim-runtime') `
        ($packageNames | Sort-Object)) {
    throw "Expected the Vim binary and runtime splits; got $($packageNames -join ', ')"
}
$archiveRecords | ConvertTo-Json | Set-Content -Encoding utf8 (Join-Path $ReportDirectory 'archives.json')

$dependencyExtractRoot = Join-Path $resolvedRoot 'dependency-prefix'
if ($DependencyArchives.Count -gt 0) {
    New-Item $dependencyExtractRoot -ItemType Directory -Force | Out-Null
    New-Item (Join-Path $ReportDirectory 'dependency-archives') -ItemType Directory -Force | Out-Null
    foreach ($dependencyArchive in $DependencyArchives) {
        $resolvedDependencyArchive = (Resolve-Path $dependencyArchive).Path
        $dependencyName = Split-Path $resolvedDependencyArchive -Leaf
        Copy-Item $resolvedDependencyArchive (Join-Path $ReportDirectory "dependency-archives\$dependencyName")
        & tar.exe -xf $resolvedDependencyArchive -C $dependencyExtractRoot
        if ($LASTEXITCODE -ne 0) {
            throw "Could not extract dependency archive $resolvedDependencyArchive"
        }
    }
    $DependencyPrefix = Join-Path $dependencyExtractRoot 'clangarm64'
}
if (-not $DependencyPrefix) {
    $DependencyPrefix = $FallbackDependencyPrefix
}
if (-not $DependencyPrefix) {
    throw 'Pass DependencyArchives, DependencyPrefix, or FallbackDependencyPrefix'
}

$readObj = if ($MsysRoot) { Join-Path $MsysRoot 'clangarm64\bin\llvm-readobj.exe' } else { $null }
if (-not $readObj -or -not (Test-Path $readObj)) {
    $readObj = (Get-Command llvm-readobj.exe -ErrorAction Stop).Source
}

$dependencyBin = Join-Path $DependencyPrefix 'bin'
$dependencyFiles = @{}
if (Test-Path $dependencyBin) {
    Get-ChildItem $dependencyBin -File | ForEach-Object {
        $dependencyFiles[$_.Name.ToLowerInvariant()] = $_.FullName
    }
}
if ($FallbackDependencyPrefix) {
    $fallbackBin = Join-Path $FallbackDependencyPrefix 'bin'
    if (Test-Path $fallbackBin) {
        Get-ChildItem $fallbackBin -File | ForEach-Object {
            $key = $_.Name.ToLowerInvariant()
            if (-not $dependencyFiles.ContainsKey($key)) {
                $dependencyFiles[$key] = $_.FullName
            }
        }
    }
}
$rootFiles = @{}
Get-ChildItem $resolvedRoot -Recurse -File | ForEach-Object {
    $rootFiles[$_.Name.ToLowerInvariant()] = $_.FullName
}

# iconv and gettext are loaded dynamically by Vim and therefore do not appear
# in the static import table.
$queue = [Collections.Generic.Queue[string]]::new()
Get-ChildItem $resolvedRoot -Recurse -File -Include *.exe,*.dll,*.pyd | ForEach-Object {
    $queue.Enqueue($_.FullName)
}
foreach ($seed in @('libiconv-2.dll', 'libintl-8.dll')) {
    if (-not $dependencyFiles.ContainsKey($seed)) {
        throw "Missing native ARM64 runtime dependency: $seed"
    }
    $destination = Join-Path $resolvedRoot "deps\$seed"
    New-Item (Split-Path $destination -Parent) -ItemType Directory -Force | Out-Null
    Copy-Item $dependencyFiles[$seed] $destination
    $rootFiles[$seed] = $destination
    $queue.Enqueue($destination)
}

$seen = @{}
$peRecords = [Collections.Generic.List[object]]::new()
$importRecords = [Collections.Generic.List[object]]::new()
while ($queue.Count -gt 0) {
    $pe = $queue.Dequeue()
    $key = (Resolve-Path $pe).Path.ToLowerInvariant()
    if ($seen.ContainsKey($key)) {
        continue
    }
    $seen[$key] = $true
    $peRecords.Add((Assert-Arm64Pe $pe))

    foreach ($import in (Get-Imports $pe $readObj)) {
        $lower = $import.ToLowerInvariant()
        $resolved = 'Windows system'
        if ($lower -like 'api-ms-win-*' -or $lower -like 'ext-ms-*' -or $SystemImports -contains $lower) {
            $importRecords.Add([pscustomobject]@{ Importer = $pe; Import = $import; Resolved = $resolved })
            continue
        }
        if ($rootFiles.ContainsKey($lower)) {
            $resolved = $rootFiles[$lower]
        } elseif ($dependencyFiles.ContainsKey($lower)) {
            $resolved = Join-Path $resolvedRoot "deps\$import"
            Copy-Item $dependencyFiles[$lower] $resolved
            $rootFiles[$lower] = $resolved
            $queue.Enqueue($resolved)
        } else {
            throw "Unresolved non-system import '$import' from '$pe'"
        }
        $importRecords.Add([pscustomobject]@{ Importer = $pe; Import = $import; Resolved = $resolved })
    }
}

foreach ($archive in (Get-ChildItem $resolvedRoot -Recurse -File -Include *.a,*.lib)) {
    $headers = & $readObj --file-headers $archive.FullName 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Could not inspect archive members in $($archive.FullName)`n$headers"
    }
    $machines = @($headers | Select-String '^\s*Machine:\s+(.+)$')
    if ($machines.Count -eq 0 -or @($machines | Where-Object { $_.Line -notmatch 'ARM64.*0xAA64' }).Count -ne 0) {
        throw "Archive contains an unknown or non-ARM64 member: $($archive.FullName)"
    }
    $headers | Set-Content -Encoding utf8 (Join-Path $ReportDirectory "$($archive.Name).headers.txt")
}

$peRecords | ConvertTo-Json | Set-Content -Encoding utf8 (Join-Path $ReportDirectory 'pe-scan.json')
$importRecords | ConvertTo-Json | Set-Content -Encoding utf8 (Join-Path $ReportDirectory 'imports.json')

$required = @('ex.exe', 'rview.exe', 'rvim.exe', 'view.exe', 'vim.exe', 'vimdiff.exe', 'xxd.exe')
$candidateBin = Join-Path $resolvedRoot 'clangarm64\bin'
$actual = @(Get-ChildItem $candidateBin -File -Filter *.exe | ForEach-Object Name | Sort-Object)
if (Compare-Object ($required | Sort-Object) $actual) {
    throw "Unexpected candidate executable split. Expected exactly: $($required -join ', '); actual: $($actual -join ', ')"
}

Write-DbSnapshot 'after'
if ($MsysRoot) {
    $before = Get-Content (Join-Path $ReportDirectory 'before-pacman-db.tsv')
    $after = Get-Content (Join-Path $ReportDirectory 'after-pacman-db.tsv')
    if (Compare-Object $before $after) {
        throw 'The MSYS2 package database changed during isolated audit'
    }
}

"Audited $($peRecords.Count) ARM64 PE files and $($importRecords.Count) imports." |
    Set-Content -Encoding utf8 (Join-Path $ReportDirectory 'audit-summary.txt')
