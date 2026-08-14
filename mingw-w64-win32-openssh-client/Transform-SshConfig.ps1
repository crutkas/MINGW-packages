[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateScript({ Test-Path $_ -PathType Leaf })]
    [string] $SourcePath,

    [Parameter(Mandatory)]
    [string] $DestinationPath,

    [Parameter(Mandatory)]
    [string] $ManifestPath,

    [Parameter(Mandatory)]
    [string] $DiffPath,

    [Parameter(Mandatory)]
    [ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string] $ExpectedSourceSha256
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

$utf8 = [System.Text.UTF8Encoding]::new($false, $true)
$unsupportedAlgorithms = @(
    'ssh-dss'
    'ssh-dss-cert-v01@openssh.com'
)
$algorithmDirectives = [System.Collections.Generic.HashSet[string]]::new(
    [System.StringComparer]::OrdinalIgnoreCase
)
foreach ($directive in @(
    'CASignatureAlgorithms'
    'HostbasedAcceptedAlgorithms'
    'HostbasedKeyTypes'
    'HostKeyAlgorithms'
    'PubkeyAcceptedAlgorithms'
    'PubkeyAcceptedKeyTypes'
)) {
    $null = $algorithmDirectives.Add($directive)
}

function Get-Sha256 {
    param([Parameter(Mandatory)][byte[]] $Bytes)

    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        return ([System.BitConverter]::ToString(
            $sha256.ComputeHash($Bytes)
        )).Replace('-', '').ToLowerInvariant()
    }
    finally {
        $sha256.Dispose()
    }
}

$sourceBytes = [System.IO.File]::ReadAllBytes($SourcePath)
$sourceSha256 = Get-Sha256 -Bytes $sourceBytes
if ($sourceSha256 -ne $ExpectedSourceSha256.ToLowerInvariant()) {
    throw "Source policy SHA-256 is $sourceSha256; expected $($ExpectedSourceSha256.ToLowerInvariant())."
}

$sourceText = $utf8.GetString($sourceBytes)
if ($sourceText.Length -gt 0 -and $sourceText[0] -eq [char]0xFEFF) {
    throw 'The source policy unexpectedly contains a UTF-8 BOM.'
}
if ($sourceText.Contains([char]0)) {
    throw 'The source policy contains a NUL byte.'
}

if ($sourceText.Contains("`r`n")) {
    $withoutCrLf = $sourceText.Replace("`r`n", '')
    if ($withoutCrLf.Contains("`r") -or $withoutCrLf.Contains("`n")) {
        throw 'The source policy uses mixed newline styles.'
    }
    $newline = "`r`n"
}
elseif ($sourceText.Contains("`n")) {
    if ($sourceText.Contains("`r")) {
        throw 'The source policy uses mixed newline styles.'
    }
    $newline = "`n"
}
elseif ($sourceText.Contains("`r")) {
    throw 'The source policy uses unsupported bare carriage-return newlines.'
}
else {
    $newline = "`n"
}

$hasFinalNewline = $sourceText.EndsWith($newline)
$lineText = if ($hasFinalNewline) {
    $sourceText.Substring(0, $sourceText.Length - $newline.Length)
}
else {
    $sourceText
}
$sourceLines = if ($lineText.Length -eq 0) {
    @()
}
else {
    [regex]::Split($lineText, [regex]::Escape($newline))
}
$sourceLines = @($sourceLines)

$outputLines = [System.Collections.Generic.List[string]]::new()
$changes = [System.Collections.Generic.List[object]]::new()
$removalCounts = [ordered]@{
    'ssh-dss' = 0
    'ssh-dss-cert-v01@openssh.com' = 0
}

for ($index = 0; $index -lt $sourceLines.Count; $index++) {
    $line = $sourceLines[$index]
    $trimmed = $line.TrimStart()
    if ($trimmed.Length -eq 0 -or $trimmed.StartsWith('#')) {
        $outputLines.Add($line)
        continue
    }

    $match = [regex]::Match(
        $line,
        '^(?<indent>[ \t]*)(?<directive>[A-Za-z][A-Za-z0-9]*)(?<separator>[ \t]+)(?<argument>[^ \t#]+)(?<suffix>[ \t]*(?:#.*)?)$'
    )
    if (-not $match.Success) {
        if ($line -match 'ssh-dss') {
            throw "Cannot safely parse unsupported algorithm text on line $($index + 1): $line"
        }
        $outputLines.Add($line)
        continue
    }

    $directive = $match.Groups['directive'].Value
    $argument = $match.Groups['argument'].Value
    if (-not $algorithmDirectives.Contains($directive)) {
        if ($argument -match 'ssh-dss') {
            throw "Unsupported algorithm text occurs outside a recognized algorithm-list directive on line $($index + 1): $line"
        }
        $outputLines.Add($line)
        continue
    }

    $modifier = ''
    $listText = $argument
    if ($listText[0] -in @('+', '-', '^')) {
        $modifier = [string] $listText[0]
        $listText = $listText.Substring(1)
    }
    $tokens = @($listText.Split([char] ','))
    if ($tokens.Count -eq 0 -or @($tokens | Where-Object { $_ -eq '' }).Count -ne 0) {
        throw "Malformed algorithm list on line $($index + 1): $line"
    }

    $keptTokens = [System.Collections.Generic.List[string]]::new()
    $removedSourceTokens = [System.Collections.Generic.List[string]]::new()
    $removedAlgorithms = [System.Collections.Generic.List[string]]::new()
    foreach ($token in $tokens) {
        if ($token -eq 'ssh-dss*') {
            $removedSourceTokens.Add($token)
            foreach ($algorithm in $unsupportedAlgorithms) {
                $removedAlgorithms.Add($algorithm)
                $removalCounts[$algorithm]++
            }
            continue
        }
        if ($unsupportedAlgorithms -contains $token) {
            $removedSourceTokens.Add($token)
            $removedAlgorithms.Add($token)
            $removalCounts[$token]++
            continue
        }
        if ($token -match 'ssh-dss') {
            throw "Unsupported algorithm is hidden in an unrecognized token '$token' on line $($index + 1)."
        }
        $keptTokens.Add($token)
    }

    if ($removedSourceTokens.Count -eq 0) {
        $outputLines.Add($line)
        continue
    }

    $after = $null
    if ($keptTokens.Count -gt 0) {
        $after = $match.Groups['indent'].Value +
            $directive +
            $match.Groups['separator'].Value +
            $modifier +
            ($keptTokens -join ',') +
            $match.Groups['suffix'].Value
        $outputLines.Add($after)
    }
    elseif ($match.Groups['suffix'].Value -match '#') {
        $after = $match.Groups['indent'].Value +
            $match.Groups['suffix'].Value.TrimStart()
        $outputLines.Add($after)
    }

    $changes.Add([ordered]@{
        line = $index + 1
        directive = $directive
        modifier = $modifier
        before = $line
        after = $after
        removedSourceTokens = @($removedSourceTokens)
        removedAlgorithms = @($removedAlgorithms)
    })
}

foreach ($algorithm in $unsupportedAlgorithms) {
    if ($removalCounts[$algorithm] -ne 1) {
        throw "Expected exactly one removal of '$algorithm', found $($removalCounts[$algorithm])."
    }
}
if ($changes.Count -eq 0) {
    throw 'The source policy did not contain an unsupported algorithm-list token.'
}

$outputText = [string]::Join($newline, $outputLines)
if ($hasFinalNewline) {
    $outputText += $newline
}
$outputBytes = $utf8.GetBytes($outputText)
$outputSha256 = Get-Sha256 -Bytes $outputBytes

$destinationDirectory = Split-Path $DestinationPath -Parent
if ($destinationDirectory) {
    $null = New-Item -ItemType Directory -Path $destinationDirectory -Force
}
[System.IO.File]::WriteAllBytes($DestinationPath, $outputBytes)

$diffLines = [System.Collections.Generic.List[string]]::new()
$diffLines.Add('--- ssh_config.before')
$diffLines.Add('+++ ssh_config.after')
foreach ($change in $changes) {
    $afterCount = if ($null -eq $change.after) { 0 } else { 1 }
    $diffLines.Add("@@ -$($change.line),1 +$($change.line),$afterCount @@")
    $diffLines.Add("-$($change.before)")
    if ($null -ne $change.after) {
        $diffLines.Add("+$($change.after)")
    }
}
$diffText = [string]::Join("`n", $diffLines) + "`n"
[System.IO.File]::WriteAllText($DiffPath, $diffText, $utf8)

$manifest = [ordered]@{
    schemaVersion = 1
    transform = 'remove-unsupported-win32-openssh-dss-algorithms'
    source = [ordered]@{
        file = 'ssh_config.before'
        sha256 = $sourceSha256
        bytes = $sourceBytes.Length
        lines = $sourceLines.Count
        newline = if ($newline -eq "`r`n") { 'CRLF' } else { 'LF' }
        finalNewline = $hasFinalNewline
    }
    output = [ordered]@{
        file = 'ssh_config.after'
        packagePath = 'etc/ssh/ssh_config'
        sha256 = $outputSha256
        bytes = $outputBytes.Length
        lines = $outputLines.Count
    }
    removedAlgorithms = @(
        foreach ($algorithm in $unsupportedAlgorithms) {
            [ordered]@{
                name = $algorithm
                occurrences = $removalCounts[$algorithm]
            }
        }
    )
    changes = @($changes)
}
$manifestText = ($manifest | ConvertTo-Json -Depth 8) + "`n"
[System.IO.File]::WriteAllText($ManifestPath, $manifestText, $utf8)

Write-Host "Transformed SSH policy: $sourceSha256 -> $outputSha256; removed $($unsupportedAlgorithms -join ', ')."
