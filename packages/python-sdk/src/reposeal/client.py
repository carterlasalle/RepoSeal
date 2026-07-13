"""Subprocess client that preserves RepoSeal's single Rust security implementation."""

from __future__ import annotations

import json
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, TypedDict, cast


Decision = Literal["verified", "review", "blocked"]
Risk = Literal["low", "medium", "high", "critical"]


class VerificationReport(TypedDict):
    """Stable verification-report subset plus complete dynamic evidence arrays."""

    schema_version: Literal[1]
    request_id: str
    request: dict[str, Any]
    canonical: dict[str, Any] | None
    decision: Decision
    risk: Risk
    signals: list[dict[str, Any]]
    evidence: list[dict[str, Any]]
    evaluated_at: str
    report_hash: str


@dataclass(slots=True)
class RepoSealError(RuntimeError):
    """RepoSeal operational failure; policy decisions are returned as reports."""

    message: str
    exit_code: int
    stderr: str

    def __str__(self) -> str:
        return self.message


class RepoSeal:
    """Invoke the local RepoSeal binary without a shell."""

    def __init__(
        self,
        binary: str = "reposeal",
        *,
        policy: str | Path | None = None,
        lockfile: str | Path = "agent.lock",
        cwd: str | Path | None = None,
        env: dict[str, str] | None = None,
    ) -> None:
        self.binary = binary
        self.policy = str(policy) if policy is not None else None
        self.lockfile = str(lockfile)
        self.cwd = str(cwd) if cwd is not None else None
        self.env = {**os.environ, **(env or {})}

    def verify(self, reference: str, *, offline: bool = False) -> VerificationReport:
        args = ["verify", reference, "--json", "--lock", self.lockfile]
        if offline:
            args.append("--offline")
        if self.policy:
            args.extend(["--policy", self.policy])
        return cast(VerificationReport, self._run_json(args, {0, 2, 10}))

    def scan(self, path: str | Path = ".") -> dict[str, Any]:
        return self._run_json(["scan", str(path), "--json"], {0, 10})

    def guard(self, command: str) -> dict[str, Any]:
        args = ["guard", "--command", command, "--json", "--lock", self.lockfile]
        if self.policy:
            args.extend(["--policy", self.policy])
        return self._run_json(args, {0, 2, 10})

    def _run_json(self, args: list[str], accepted: set[int]) -> dict[str, Any]:
        completed = subprocess.run(
            [self.binary, *args],
            cwd=self.cwd,
            env=self.env,
            shell=False,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        if completed.returncode not in accepted:
            raise RepoSealError(
                f"RepoSeal exited {completed.returncode}",
                completed.returncode,
                completed.stderr,
            )
        try:
            value = json.loads(completed.stdout)
        except json.JSONDecodeError as error:
            raise RepoSealError("RepoSeal returned invalid JSON", completed.returncode, completed.stderr) from error
        if not isinstance(value, dict):
            raise RepoSealError("RepoSeal JSON was not an object", completed.returncode, completed.stderr)
        return cast(dict[str, Any], value)

