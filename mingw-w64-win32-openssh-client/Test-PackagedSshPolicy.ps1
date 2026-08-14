[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateScript({ Test-Path $_ -PathType Container })]
    [string] $Root,

    [switch] $KeepSecureAcl
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

$ssh = Join-Path $Root 'usr\bin\ssh.exe'
$globalConfig = Join-Path $Root 'etc\ssh\ssh_config'
foreach ($path in @($ssh, $globalConfig)) {
    if (-not (Test-Path $path -PathType Leaf)) {
        throw "Required packaged policy test input '$path' is missing."
    }
}

function Invoke-Ssh {
    param([Parameter(Mandatory)][string[]] $ArgumentList)

    $previousPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $output = @(& $script:ssh @ArgumentList 2>&1 |
            ForEach-Object { $_.ToString() })
        return [pscustomobject]@{
            ExitCode = $LASTEXITCODE
            Output = $output
        }
    }
    finally {
        $ErrorActionPreference = $previousPreference
    }
}

function Get-ResolvedOption {
    param(
        [Parameter(Mandatory)][string[]] $ArgumentList,
        [Parameter(Mandatory)][string] $Option
    )

    $result = Invoke-Ssh -ArgumentList $ArgumentList
    if ($result.ExitCode -ne 0) {
        throw "ssh $($ArgumentList -join ' ') failed with exit code $($result.ExitCode).`n$($result.Output -join [Environment]::NewLine)"
    }
    $matches = @($result.Output | Where-Object {
        $_ -match "^$([regex]::Escape($Option))\s+(.+)$"
    })
    if ($matches.Count -ne 1) {
        throw "Expected one resolved '$Option' value, found $($matches.Count)."
    }
    return ([regex]::Match(
        $matches[0],
        "^$([regex]::Escape($Option))\s+(.+)$"
    )).Groups[1].Value
}

function Set-SecureAcl {
    param([Parameter(Mandatory)][string] $Path)

    $owner = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
    $acl = [System.Security.AccessControl.FileSecurity]::new()
    $acl.SetOwner($owner)
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($identity in @(
        $owner
        [System.Security.Principal.SecurityIdentifier]::new('S-1-5-18')
        [System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
    )) {
        $rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
            $identity,
            [System.Security.AccessControl.FileSystemRights]::FullControl,
            [System.Security.AccessControl.AccessControlType]::Allow
        )
        $null = $acl.AddAccessRule($rule)
    }
    Set-Acl $Path $acl
}

$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) "packaged-ssh-policy-$PID"
$profileSsh = Join-Path $env:USERPROFILE '.ssh'
$profileConfig = Join-Path $profileSsh 'config'
$include = Join-Path $tempRoot 'included policy.conf'
$explicit = Join-Path $tempRoot 'explicit config.conf'
$malformed = Join-Path $tempRoot 'malformed.conf'
$empty = Join-Path $tempRoot 'empty.conf'
$profileSshExisted = Test-Path $profileSsh -PathType Container
$profileConfigExisted = Test-Path $profileConfig -PathType Leaf
$savedProfileBytes = if ($profileConfigExisted) {
    [System.IO.File]::ReadAllBytes($profileConfig)
}
$savedProfileAcl = if ($profileConfigExisted) {
    Get-Acl $profileConfig
}
$savedAcl = Get-Acl $globalConfig

try {
    $null = New-Item $tempRoot -ItemType Directory -Force
    $null = New-Item $profileSsh -ItemType Directory -Force
    [System.IO.File]::WriteAllLines($include, @(
        'Host included-policy'
        '    Port 2204'
    ), [System.Text.UTF8Encoding]::new($false))
    [System.IO.File]::WriteAllLines($profileConfig, @(
        "Include `"$($include.Replace('\', '/'))`""
        'Host user-precedence'
        '    Port 3301'
    ), [System.Text.UTF8Encoding]::new($false))
    Set-SecureAcl $profileConfig
    [System.IO.File]::WriteAllLines($explicit, @(
        'Host explicit-policy'
        '    Port 4401'
    ), [System.Text.UTF8Encoding]::new($false))
    [System.IO.File]::WriteAllText(
        $malformed,
        "NotARealOpenSSHOption yes`n",
        [System.Text.UTF8Encoding]::new($false)
    )
    [System.IO.File]::WriteAllText(
        $empty,
        '',
        [System.Text.UTF8Encoding]::new($false)
    )

    Set-SecureAcl $globalConfig

    $script:ssh = $ssh
    $globalAlgorithms = Get-ResolvedOption `
        -ArgumentList @('-G', 'packaged-policy') `
        -Option 'pubkeyacceptedalgorithms'
    $defaultAlgorithms = Get-ResolvedOption `
        -ArgumentList @('-F', $empty, '-G', 'packaged-policy') `
        -Option 'pubkeyacceptedalgorithms'
    if ($globalAlgorithms -eq $defaultAlgorithms) {
        throw 'The executable-relative global policy did not alter the resolved algorithm list.'
    }
    if ($globalAlgorithms -match 'ssh-dss') {
        throw "The transformed global policy still resolves ssh-dss: $globalAlgorithms"
    }

    if ((Get-ResolvedOption @('-G', 'user-precedence') 'port') -ne '3301') {
        throw 'User configuration did not retain precedence over global policy.'
    }
    if ((Get-ResolvedOption @('-G', 'included-policy') 'port') -ne '2204') {
        throw 'User Include configuration was not applied.'
    }
    if ((Get-ResolvedOption @('-F', $explicit, '-G', 'explicit-policy') 'port') -ne '4401') {
        throw '-F configuration did not retain precedence.'
    }
    $malformedResult = Invoke-Ssh @('-F', $malformed, '-G', 'malformed-policy')
    if ($malformedResult.ExitCode -eq 0 -or
        ($malformedResult.Output -join "`n") -notmatch
            'Bad configuration option|bad configuration options') {
        throw 'Malformed -F configuration did not fail with a parser diagnostic.'
    }

    Write-Host 'Passed packaged global policy tests: executable-relative discovery, transformed algorithms, user/-F precedence, Include, and malformed config failure.'
}
finally {
    if ($profileConfigExisted) {
        [System.IO.File]::WriteAllBytes($profileConfig, $savedProfileBytes)
        Set-Acl $profileConfig $savedProfileAcl
    }
    else {
        Remove-Item $profileConfig -Force -ErrorAction SilentlyContinue
    }
    if (-not $profileSshExisted -and
        (Test-Path $profileSsh -PathType Container) -and
        -not (Get-ChildItem $profileSsh -Force)) {
        Remove-Item $profileSsh -Force
    }
    if (-not $KeepSecureAcl) {
        Set-Acl $globalConfig $savedAcl
    }
    Remove-Item $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
}
