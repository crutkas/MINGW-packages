# Native ARM64 Win32 OpenSSH client

This package source-builds the native Win32 OpenSSH client from fork-local
`crutkas/Win32-OpenSSH#2`. It does not consume an expiring workflow artifact.
The package is restricted to `clangarm64`; x64 packages and the default Win32
OpenSSH `%ProgramData%\ssh\ssh_config` behavior are unchanged.

## Reproducibility pins

- Packaging automation:
  `crutkas/Win32-OpenSSH@e20e4eca0ad3ed513b9c05bdd03fba86e7cb3947`
  (`crutkas-portable-ssh-config`, PR #2)
- OpenSSH source:
  `PowerShell/openssh-portable@b8c08ef9da9450a94a9c5ef717d96a7bd83f3332`
  (`v10.0.0.0`)
- vcpkg registry:
  `microsoft/vcpkg@16fa044f80dd984c24deff5b7d0457e64c85a1e0`

The fork-local automation archive is pinned to SHA-256
`077c2d1ff0c876915f3716d47dcbc963121ed45cbb408b8cd53cbbee045322bd`.
The third-party inputs remain the immutable revisions validated by that
fork-local commit. The OpenSSH archive is SHA-256 pinned, and the vcpkg VCS
source is checked out by exact commit.

Build only on native Windows ARM64 in an MSYS2 `CLANGARM64` shell. The Visual
Studio 2022 ARM64 C++ tools and v143 ARM64 Spectre libraries are required:

```sh
cd mingw-w64-win32-openssh-client
MINGW_ARCH=clangarm64 makepkg-mingw -sCLf --noconfirm --skippgpcheck
```

Expected artifact:

```text
mingw-w64-clang-aarch64-win32-openssh-client-10.0.0.0-2-any.pkg.tar.zst
```

## Executable-relative global configuration

Only the ARM64 `ssh.exe` build receives:

```text
-PortableGlobalConfig ../../etc/ssh/ssh_config
```

At runtime the native client resolves and canonicalizes this path relative to
`usr/bin/ssh.exe`. Relocating the complete tree therefore preserves global
policy discovery without relying on the current directory, environment
variables, the registry, or `%ProgramData%`. User configuration, `-F`, and
`Include` continue through the standard OpenSSH parser and precedence rules.

The package carries the exact Git for Windows policy bytes from the frozen
package layer as `ssh_config.before`, with SHA-256
`f783f00ce880ead34b01d6db20f35f0e9141e199ffc32ca14cd330a3165853a4`.
`Transform-SshConfig.ps1` rejects any source hash or parser-shape drift and
removes only the `ssh-dss` and `ssh-dss-cert-v01@openssh.com` algorithms
represented by the `ssh-dss*` algorithm-list token. The transformed policy
SHA-256 is
`8afa8d96895abae6a4770bde0916b985b28bef5979b016da5621d65f92e1c3de`.
All comments, order, supported algorithms, whitespace, and newlines are
preserved. The installed documentation includes the before/after files, a
unified diff, and a JSON hash/change manifest.

The config remains a pacman `backup` file, so package upgrades preserve local
administrator edits.

## Payload and baseline disposition

`baseline-paths.json` provides the machine-readable disposition of all 11
OpenSSH x64 paths in `crutkas/build-extra#1`: 10 native replacements and one
removal. `usr/lib/ssh/ssh-keysign.exe` is deliberately absent because Win32
OpenSSH does not build it and Windows host-based authentication is unsupported.

The package contains `ssh`, `scp`, `sftp`, `ssh-add`, `ssh-agent`,
`ssh-keygen`, `ssh-keyscan`, `sftp-server`, PKCS#11 and security-key helpers,
and the required `libcrypto.dll` copies. Helpers needed by the Windows runtime
are colocated beside `ssh.exe` while canonical copies remain under
`usr/lib/ssh`. It includes licenses, the transformed pacman-managed global
configuration, source/config provenance, per-file SHA-256, `.MTREE`,
`.PKGINFO`, and `.BUILDINFO`.

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
pacman -U --noconfirm ./mingw-w64-clang-aarch64-win32-openssh-client-10.0.0.0-2-any.pkg.tar.zst
```

Downstream Git packaging must update its dependency explicitly rather than
relying on an `openssh` virtual provide. The native Windows agent is a Windows
service, not an MSYS Unix-domain socket. Validate user configuration discovery
and `GIT_SSH_COMMAND` in the final image. `ssh-pageant.exe` is outside the
11-path migration contract and is not supplied by this package.

## Verification

The fork-local ARM64 workflow performs two clean native builds and compares
package SHA-256 values. It runs the upstream unit executables, source
configuration integration tests, and installed/relocated package tests in a
path containing spaces and Unicode. Coverage includes transformed global
policy, user and `-F` precedence, `Include`, malformed config failure, keys,
known_hosts, ProxyCommand, agent, scp, sftp, PTY, and Git-over-SSH
clone/fetch/push. It also validates all PE machine values as `0xAA64`, pacman
ownership and `-Qkk`, source/build/per-file hashes, helper/libcrypto layout,
the deliberate `ssh-keysign` removal, and absence of server payload.
