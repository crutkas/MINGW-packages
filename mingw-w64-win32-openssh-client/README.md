# Native ARM64 Win32 OpenSSH client

This package source-builds the native Win32 OpenSSH client validated by
`crutkas/Win32-OpenSSH#1`. It does not consume that workflow's expiring
artifact.

## Reproducibility pins

- Packaging automation:
  `crutkas/Win32-OpenSSH@01cfe49d781acc5f44ca9239a3a2407f5f8f9026`
- OpenSSH source:
  `PowerShell/openssh-portable@b8c08ef9da9450a94a9c5ef717d96a7bd83f3332`
  (`v10.0.0.0`)
- vcpkg registry:
  `microsoft/vcpkg@16fa044f80dd984c24deff5b7d0457e64c85a1e0`

The third-party inputs are immutable revisions already pinned by the
fork-local validation commit. The OpenSSH archive is SHA-256 pinned, and the
vcpkg VCS source is checked out by exact commit.

Build only on native Windows ARM64 in an MSYS2 `CLANGARM64` shell. The Visual
Studio 2022 ARM64 C++ tools and v143 ARM64 Spectre libraries are required:

```sh
cd mingw-w64-win32-openssh-client
MINGW_ARCH=clangarm64 makepkg-mingw -sCLf --noconfirm --skippgpcheck
```

Expected artifact:

```text
mingw-w64-clang-aarch64-win32-openssh-client-10.0.0.0-1-any.pkg.tar.zst
```

## Payload and baseline disposition

`baseline-paths.json` provides the machine-readable disposition of all 11
OpenSSH x64 paths in `crutkas/build-extra#1`: 10 native replacements and one
removal. `usr/lib/ssh/ssh-keysign.exe` is deliberately absent because Win32
OpenSSH does not build it and Windows host-based authentication is unsupported.

The package contains `ssh`, `scp`, `sftp`, `ssh-add`, `ssh-agent`,
`ssh-keygen`, `ssh-keyscan`, `sftp-server`, PKCS#11 and security-key helpers,
and the required `libcrypto.dll` copies. Helpers needed by the Windows runtime
are colocated beside `ssh.exe` while canonical copies remain under
`usr/lib/ssh`. It includes licenses, a pacman-managed client configuration
default, provenance, per-file SHA-256, `.MTREE`, `.PKGINFO`, and `.BUILDINFO`.

It excludes `sshd`, authentication/session daemons, shell host, service
scripts, server configuration, event manifests, moduli, and all PDBs.

## Installation and integration caveats

This package conflicts with the MSYS `openssh` package because both own the
Git for Windows `/usr` client paths. It intentionally does **not** provide or
replace `openssh`: native Win32 process, path, agent-service, and configuration
semantics are not the MSYS OpenSSH ABI.

For an integration image that has deliberately changed its Git dependency from
MSYS OpenSSH to this package:

```sh
pacman -Rdd --noconfirm openssh
pacman -U --noconfirm ./mingw-w64-clang-aarch64-win32-openssh-client-10.0.0.0-1-any.pkg.tar.zst
```

Downstream Git packaging must update its dependency explicitly rather than
relying on an `openssh` virtual provide. The native Windows agent is a Windows
service, not an MSYS Unix-domain socket. Validate user configuration discovery
and `GIT_SSH_COMMAND` in the final image; do not assume every MSYS `/etc/ssh`
path or shell quoting behavior is interchangeable. `ssh-pageant.exe` is
outside the 11-path migration contract and is not supplied by this package.
