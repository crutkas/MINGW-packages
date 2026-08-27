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
$testHome = Join-Path $work 'home'
$temp = Join-Path $work 'tmp'
New-Item $ReportDirectory -ItemType Directory -Force | Out-Null
New-Item $testHome, $temp -ItemType Directory -Force | Out-Null

$env:HOME = $testHome
$env:USERPROFILE = $testHome
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

if (-not ('NativeSmokeProcessJob' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;

public sealed class NativeSmokeProcessJob : IDisposable
{
    private const uint JobObjectLimitKillOnJobClose = 0x00002000;
    private IntPtr handle;

    public NativeSmokeProcessJob()
    {
        handle = CreateJobObject(IntPtr.Zero, null);
        if (handle == IntPtr.Zero)
            throw new Win32Exception(Marshal.GetLastWin32Error());

        var limits = new JobObjectExtendedLimitInformation();
        limits.BasicLimitInformation.LimitFlags = JobObjectLimitKillOnJobClose;
        int size = Marshal.SizeOf(limits);
        IntPtr buffer = Marshal.AllocHGlobal(size);
        try
        {
            Marshal.StructureToPtr(limits, buffer, false);
            if (!SetInformationJobObject(handle, 9, buffer, (uint)size))
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }
        catch
        {
            CloseHandle(handle);
            handle = IntPtr.Zero;
            throw;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    public void Add(Process process)
    {
        if (!AssignProcessToJobObject(handle, process.Handle))
            throw new Win32Exception(Marshal.GetLastWin32Error());
    }

    public void Terminate()
    {
        if (!TerminateJobObject(handle, 1))
            throw new Win32Exception(Marshal.GetLastWin32Error());
    }

    public void Dispose()
    {
        if (handle != IntPtr.Zero)
        {
            CloseHandle(handle);
            handle = IntPtr.Zero;
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JobObjectBasicLimitInformation
    {
        public long PerProcessUserTimeLimit;
        public long PerJobUserTimeLimit;
        public uint LimitFlags;
        public UIntPtr MinimumWorkingSetSize;
        public UIntPtr MaximumWorkingSetSize;
        public uint ActiveProcessLimit;
        public UIntPtr Affinity;
        public uint PriorityClass;
        public uint SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IoCounters
    {
        public ulong ReadOperationCount;
        public ulong WriteOperationCount;
        public ulong OtherOperationCount;
        public ulong ReadTransferCount;
        public ulong WriteTransferCount;
        public ulong OtherTransferCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JobObjectExtendedLimitInformation
    {
        public JobObjectBasicLimitInformation BasicLimitInformation;
        public IoCounters IoInfo;
        public UIntPtr ProcessMemoryLimit;
        public UIntPtr JobMemoryLimit;
        public UIntPtr PeakProcessMemoryUsed;
        public UIntPtr PeakJobMemoryUsed;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateJobObject(IntPtr securityAttributes, string name);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetInformationJobObject(
        IntPtr job, int informationClass, IntPtr information, uint informationLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool TerminateJobObject(IntPtr job, uint exitCode);

    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr handle);
}
'@
}

function Invoke-Logged {
    param(
        [string] $File,
        [string[]] $Arguments,
        [string] $Log,
        [string] $WorkingDirectory = $work,
        [int] $TimeoutSeconds = 120
    )
    $stdout = Join-Path $ReportDirectory "$Log.stdout.txt"
    $stderr = Join-Path $ReportDirectory "$Log.stderr.txt"
    $progress = Join-Path $ReportDirectory 'smoke-progress.txt'
    "$(Get-Date -AsUTC -Format o) START $Log ($File)" |
        Add-Content -Encoding utf8 $progress
    $info = [Diagnostics.ProcessStartInfo]::new()
    $info.FileName = $File
    $info.WorkingDirectory = $WorkingDirectory
    $info.UseShellExecute = $false
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    foreach ($argument in $Arguments) {
        $info.ArgumentList.Add($argument)
    }
    $job = [NativeSmokeProcessJob]::new()
    $process = $null
    try {
        $process = [Diagnostics.Process]::Start($info)
        $job.Add($process)
        $standardOutput = $process.StandardOutput.ReadToEndAsync()
        $standardError = $process.StandardError.ReadToEndAsync()
        $exited = $process.WaitForExit($TimeoutSeconds * 1000)
        if (-not $exited) {
            $job.Terminate()
            $process.WaitForExit(10000) | Out-Null
        }
    } catch {
        if ($null -ne $process -and -not $process.HasExited) {
            $process.Kill($true)
        }
        throw
    } finally {
        $job.Dispose()
    }

    $outputCompleted = [Threading.Tasks.Task]::WaitAny(
        [Threading.Tasks.Task[]] @($standardOutput, [Threading.Tasks.Task]::Delay(10000))) -eq 0
    $errorCompleted = [Threading.Tasks.Task]::WaitAny(
        [Threading.Tasks.Task[]] @($standardError, [Threading.Tasks.Task]::Delay(10000))) -eq 0
    if ($outputCompleted) {
        $standardOutput.GetAwaiter().GetResult() | Set-Content -Encoding utf8 $stdout
    } else {
        '<stdout did not close after the process exited>' | Set-Content -Encoding utf8 $stdout
        $process.StandardOutput.Dispose()
    }
    if ($errorCompleted) {
        $standardError.GetAwaiter().GetResult() | Set-Content -Encoding utf8 $stderr
    } else {
        '<stderr did not close after the process exited>' | Set-Content -Encoding utf8 $stderr
        $process.StandardError.Dispose()
    }

    if (-not $exited) {
        "$(Get-Date -AsUTC -Format o) TIMEOUT $Log after ${TimeoutSeconds}s" |
            Add-Content -Encoding utf8 $progress
        throw "$File timed out after $TimeoutSeconds seconds; see $Log.stdout.txt and $Log.stderr.txt"
    }
    if (-not $outputCompleted -or -not $errorCompleted) {
        "$(Get-Date -AsUTC -Format o) STREAM-TIMEOUT $Log" |
            Add-Content -Encoding utf8 $progress
        throw "$File left a redirected output stream open; see $Log.stdout.txt and $Log.stderr.txt"
    }

    $exitCode = $process.ExitCode
    "$(Get-Date -AsUTC -Format o) END $Log exit=$exitCode" |
        Add-Content -Encoding utf8 $progress
    return $exitCode
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

"let g:native_arm64_vimrc = 'loaded'" | Set-Content -Encoding ascii (Join-Path $testHome '.vimrc')
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
Invoke-Checked $cygpath @('-u', $vim) 'cygpath-vim'
$vimUnix = (Get-Content (Join-Path $ReportDirectory 'cygpath-vim.stdout.txt') -Raw).Trim()
Invoke-Checked $cygpath @('-u', $convertedFile) 'cygpath-file'
$fileUnix = (Get-Content (Join-Path $ReportDirectory 'cygpath-file.stdout.txt') -Raw).Trim()
$launcher = Join-Path $work 'msys-launch.sh'
Invoke-Checked $cygpath @('-u', $launcher) 'cygpath-launcher'
$launcherUnix = (Get-Content (Join-Path $ReportDirectory 'cygpath-launcher.stdout.txt') -Raw).Trim()
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
