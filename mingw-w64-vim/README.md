# Native Windows ARM64 Vim candidate

This fork-only lane builds Vim as a native Win32 ARM64 (`IMAGE_FILE_MACHINE_ARM64`,
LLP64) console application in the `CLANGARM64` environment. It does not build an
`aarch64-pc-msys` binary and has no x64 fallback.

The candidate replaces exactly these seven x64 Git for Windows payload files:

| Git payload path | Native behavior |
| --- | --- |
| `/usr/bin/vim.exe` | Huge console Vim |
| `/usr/bin/ex.exe` | Ex mode selected from `argv[0]` |
| `/usr/bin/view.exe` | Read-only mode selected from `argv[0]` |
| `/usr/bin/rvim.exe` | Restricted mode selected from `argv[0]` |
| `/usr/bin/rview.exe` | Restricted read-only mode selected from `argv[0]` |
| `/usr/bin/vimdiff.exe` | Diff mode selected from `argv[0]` |
| `/usr/bin/xxd.exe` | Hex dump and reverse tool |

The runtime split supplies `syntax`, `ftplugin`, tutor data, and help under
`/clangarm64/share/vim/vim92`. Vim also recognizes the relocated Git layout
`../share/vim/vim92` from the executable directory. Git's `~/.vimrc`, `.vim`,
`.viminfo`, POSIX shell settings, and MSYS argument conversion remain supported.
The candidate retains the Huge console feature set used by Git (`channel`,
`cscope`, `gettext`, `iconv`, `job`, `multi_byte`, and `terminal`). It
deliberately reports `-lua`, `-perl`, `-python3`, and `-ruby`: the MSYS package's
dynamic interpreter hooks cannot be allowed to discover x64 DLLs. Those optional
interfaces require separately assembled and audited native ARM64 interpreter
closures before they can be enabled.

`/usr/bin/vimtutor` cannot safely move to the native package: it is a POSIX shell
script whose terminal setup and path handling depend on the MSYS environment.
It remains owned by the MSYS Vim/runtime payload. The Git payload assembler must
relocate the seven candidate PEs and runtime split, retain `vimtutor`, and put
the audited ARM64 `libiconv`/`libintl` dependency closure on the Windows DLL
search path. That payload-assembly change is the remaining integration
dependency; publication is intentionally outside this package lane.

On a `windows-11-arm` runner, `native-arm64-vim-audit.ps1` extracts the package
splits into a fresh root, records archives and `.PKGINFO`, rejects every non-AA64
PE or archive member, resolves and audits imports, and proves the package database
did not change. `native-arm64-vim-smoke.ps1` refuses emulated hosts and validates
startup, Ex editing, UTF-8, LF/CRLF, runtime/syntax and vimrc discovery, shell
subprocesses, MSYS-to-Win32 argument conversion, Git commit-message editing,
`xxd`, and expected failures.
