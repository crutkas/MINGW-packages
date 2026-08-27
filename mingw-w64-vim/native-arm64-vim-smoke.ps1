[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $Root,
    [Parameter(Mandatory = $true)]
    [string] $ReportDirectory,
    [Parameter(Mandatory = $true)]
    [string] $MsysRoot
)

$ErrorActionPreference = 'Stop'
$osArch = [Runtime.InteropServices.RuntimeInformation]::OSArchitecture
$processArch = [Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture
if ($osArch -ne [Runtime.InteropServices.Architecture]::Arm64 -or
    $processArch -ne [Runtime.InteropServices.Architecture]::Arm64) {
    throw "Refusing to execute ARM64 outputs on OS=$osArch process=$processArch"
}

$root = (Resolve-Path $Root).Path
$bin = Join-Path $root 'clangarm64\bin'
$vim = Join-Path $bin 'vim.exe'
$xxd = Join-Path $bin 'xxd.exe'
$runtime = Join-Path $root 'clangarm64\share\vim\vim92'
$work = Join-Path $root 'native-smoke'
$home = Join-Path $work 'home'
$temp = Join-Path $work 'tmp'
New-Item $ReportDirectory -ItemType Directory -Force | Out-Null
New-Item $home, $temp -ItemType Directory -Force | Out-Null

$env:HOME = $home
$env:USERPROFILE = $home
$env:TEMP = $temp
$env:TMP = $temp
$env:PATH = "$bin;$(Join-Path $root 'deps');$env:PATH"
$shellPath = Join-Path $MsysRoot 'usr\bin\sh.exe'
$cygpath = Join-Path $MsysRoot 'usr\bin\cygpath.exe'
if (-not (Test-Path $shellPath) -or -not (Test-Path $cygpath)) {
    throw "The selected MSYS2 root lacks sh.exe or cygpath.exe: $MsysRoot"
}
$shell = (Get-Item $shellPath).FullName
$env:SHELL = $shell
Remove-Item Env:VIM -ErrorAction SilentlyContinue
Remove-Item Env:VIMRUNTIME -ErrorAction SilentlyContinue

function Invoke-Logged {
    param([string] $File, [string[]] $Arguments, [string] $Log, [string] $WorkingDirectory = $work)
    $stdout = Join-Path $ReportDirectory "$Log.stdout.txt"
    $stderr = Join-Path $ReportDirectory "$Log.stderr.txt"
    $info = [Diagnostics.ProcessStartInfo]::new()
    $info.FileName = $File
    $info.WorkingDirectory = $WorkingDirectory
    $info.UseShellExecute = $false
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    foreach ($argument in $Arguments) {
        $info.ArgumentList.Add($argument)
    }
    $process = [Diagnostics.Process]::Start($info)
    $standardOutput = $process.StandardOutput.ReadToEndAsync()
    $standardError = $process.StandardError.ReadToEndAsync()
    $process.WaitForExit()
    $standardOutput.Result | Set-Content -Encoding utf8 $stdout
    $standardError.Result | Set-Content -Encoding utf8 $stderr
    return $process.ExitCode
}

function Invoke-Checked {
    param([string] $File, [string[]] $Arguments, [string] $Log, [string] $WorkingDirectory = $work)
    $exitCode = Invoke-Logged $File $Arguments $Log $WorkingDirectory
    if ($exitCode -ne 0) {
        throw "$File failed with exit code $exitCode; see $Log.stdout.txt and $Log.stderr.txt"
    }
}

Invoke-Checked $vim @('--version') 'version'
$version = Get-Content (Join-Path $ReportDirectory 'version.stdout.txt') -Raw
if ($version -notmatch 'VIM - Vi IMproved 9\.2' -or $version -notmatch 'Huge version without GUI') {
    throw 'Unexpected Vim version/features'
}
foreach ($feature in @('+channel', '+cscope', '+gettext', '+iconv', '+job', '+multi_byte', '+terminal')) {
    if ($version -notmatch [regex]::Escape($feature)) {
        throw "Required Git for Windows Vim feature is missing: $feature"
    }
}
foreach ($feature in @('-lua', '-perl', '-python3', '-ruby')) {
    if ($version -notmatch [regex]::Escape($feature)) {
        throw "An unaudited dynamic interpreter was enabled: $feature"
    }
}

$probe = Join-Path $work 'probe.vim'
@"
set encoding=utf-8
syntax on
call writefile([
\ `$VIMRUNTIME,
\ globpath(`$VIMRUNTIME, 'syntax/c.vim'),
\ &runtimepath,
\ &shell,
\ &shellcmdflag,
\ &shellslash,
\ string(has('win32')),
\ string(has('multi_byte')),
\ string(has('syntax'))
\ ], 'probe.txt')
qa!
"@ | Set-Content -Encoding utf8 $probe
Invoke-Checked $vim @('-n', '-es', '-S', $probe) 'runtime'
$probeResult = Get-Content (Join-Path $work 'probe.txt')
$discoveredRuntime = (Resolve-Path $probeResult[0]).Path
if ($discoveredRuntime -ne (Resolve-Path $runtime).Path -or
    -not (Test-Path $probeResult[1]) -or $probeResult[6..8] -contains '0') {
    throw "Runtime/syntax discovery failed: $($probeResult -join '; ')"
}

"let g:native_arm64_vimrc = 'loaded'" | Set-Content -Encoding ascii (Join-Path $home '.vimrc')
$vimrcProbe = Join-Path $work 'vimrc-probe.vim'
"call writefile([get(g:, 'native_arm64_vimrc', 'missing')], 'vimrc.txt')`nqa!" |
    Set-Content -Encoding ascii $vimrcProbe
Invoke-Checked $vim @('-n', '-es', '-S', $vimrcProbe) 'vimrc'
if ((Get-Content (Join-Path $work 'vimrc.txt') -Raw).Trim() -ne 'loaded') {
    throw 'The Git for Windows ~/.vimrc lookup was not preserved'
}

$utf8 = Join-Path $work 'utf8.txt'
[IO.File]::WriteAllText($utf8, "alpha`nGrüße 世界`n", [Text.UTF8Encoding]::new($false))
Invoke-Checked $vim @('-Nu', 'NONE', '-i', 'NONE', '-n', '-es', $utf8,
    '-c', 'call append(line("$"), "Ex-command-ok")', '-c', 'set fileencoding=utf-8 fileformat=unix', '-c', 'wq!') 'edit'
$utf8Bytes = [IO.File]::ReadAllBytes($utf8)
$utf8Text = [Text.Encoding]::UTF8.GetString($utf8Bytes)
if ($utf8Text -notmatch 'Grüße 世界' -or $utf8Text -notmatch 'Ex-command-ok' -or
    ([Text.Encoding]::ASCII.GetString($utf8Bytes) -match "`r`n")) {
    throw 'UTF-8/LF edit-write validation failed'
}

$crlf = Join-Path $work 'crlf.txt'
Invoke-Checked $vim @('-Nu', 'NONE', '-i', 'NONE', '-n', '-es',
    '-c', 'call setline(1, ["one", "two"])', '-c', 'set fileformat=dos', '-c', "execute 'write! ' . fnameescape('$($crlf.Replace('\', '/'))')", '-c', 'qa!') 'crlf'
$crlfBytes = [IO.File]::ReadAllBytes($crlf)
if ([Text.Encoding]::ASCII.GetString($crlfBytes) -ne "one`r`ntwo`r`n") {
    throw 'CRLF write validation failed'
}

$shellProbe = Join-Path $work 'shell-probe.vim'
"silent !printf subprocess-ok > subprocess.txt`nif v:shell_error | cquit 91 | endif`nqa!" |
    Set-Content -Encoding ascii $shellProbe
Invoke-Checked $vim @('-n', '-es', '-S', $shellProbe) 'subprocess'
if ((Get-Content (Join-Path $work 'subprocess.txt') -Raw).Trim() -ne 'subprocess-ok') {
    throw 'POSIX subprocess/shell behavior failed'
}

$convertedFile = Join-Path $work 'msys-path-conversion.txt'
'before' | Set-Content -Encoding ascii $convertedFile
$vimUnix = (& $cygpath -u $vim).Trim()
$fileUnix = (& $cygpath -u $convertedFile).Trim()
$launcher = Join-Path $work 'msys-launch.sh'
$launcherUnix = (& $cygpath -u $launcher).Trim()
[IO.File]::WriteAllText(
    $launcher,
    "#!/bin/sh`n`"$vimUnix`" -Nu NONE -i NONE -n -es `"$fileUnix`" -c `"call append(line('$'), 'converted')`" -c 'wq!'`n",
    [Text.UTF8Encoding]::new($false))
Invoke-Checked $shell @($launcherUnix) 'msys-path-conversion'
if ((Get-Content $convertedFile -Raw) -notmatch "before\r?\nconverted") {
    throw 'MSYS-to-native Win32 argument path conversion failed'
}

$input = Join-Path $work 'bytes.bin'
$dump = Join-Path $work 'bytes.xxd'
$roundtrip = Join-Path $work 'bytes.roundtrip.bin'
[IO.File]::WriteAllBytes($input, [byte[]](0..255))
Invoke-Checked $xxd @($input, $dump) 'xxd'
Invoke-Checked $xxd @('-r', $dump, $roundtrip) 'xxd-reverse'
if ((Get-FileHash $input -Algorithm SHA256).Hash -ne
    (Get-FileHash $roundtrip -Algorithm SHA256).Hash) {
    throw 'xxd roundtrip failed'
}

$git = Get-Command git.exe -ErrorAction Stop
$repo = Join-Path $work 'git-repo'
New-Item $repo -ItemType Directory | Out-Null
Invoke-Checked $git.Source @('init', '--quiet', $repo) 'git-init'
Invoke-Checked $git.Source @('-C', $repo, 'config', 'user.name', 'ARM64 Vim Smoke') 'git-name'
Invoke-Checked $git.Source @('-C', $repo, 'config', 'user.email', 'arm64-vim-smoke@example.invalid') 'git-email'
'payload' | Set-Content -Encoding ascii (Join-Path $repo 'tracked.txt')
Invoke-Checked $git.Source @('-C', $repo, 'add', 'tracked.txt') 'git-add'
$editor = Join-Path $work 'git-editor.cmd'
@"
@echo off
"$vim" -Nu NONE -i NONE -n -es "%~1" -c "call setline(1, 'native ARM64 Vim commit')" -c "wq!"
"@ | Set-Content -Encoding ascii $editor
$env:GIT_EDITOR = "`"$editor`""
Invoke-Checked $git.Source @('-C', $repo, 'commit', '--quiet') 'git-commit'
Invoke-Checked $git.Source @('-C', $repo, 'log', '-1', '--format=%s') 'git-log'
if ((Get-Content (Join-Path $ReportDirectory 'git-log.stdout.txt') -Raw).Trim() -ne 'native ARM64 Vim commit') {
    throw 'Git editor/commit-message workflow failed'
}

$failureExitCode = Invoke-Logged $vim @('-Nu', 'NONE', '-i', 'NONE', '-n', '-es',
    '-c', 'this-command-must-fail', '-c', 'qa!') 'failure'
if ($failureExitCode -eq 0) {
    throw 'Invalid Ex command incorrectly returned success'
}

"Native ARM64 Vim smoke passed on OS=$osArch process=$processArch." |
    Set-Content -Encoding utf8 (Join-Path $ReportDirectory 'smoke-summary.txt')

$sealEntries = @()
foreach ($base in @($ReportDirectory, $root)) {
    Get-ChildItem $base -Recurse -File | Where-Object Name -ne 'seal.sha256' |
        Sort-Object FullName | ForEach-Object {
            $relative = [IO.Path]::GetRelativePath($base, $_.FullName).Replace('\', '/')
            $label = if ($base -eq $ReportDirectory) { "evidence/$relative" } else { "root/$relative" }
            $sealEntries += "$((Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant())  $label"
        }
}
$sealEntries | Sort-Object | Set-Content -Encoding ascii (Join-Path $ReportDirectory 'seal.sha256')
