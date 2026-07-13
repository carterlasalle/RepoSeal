#!/usr/bin/env python3
"""Validate RepoSeal's versioned docs, schemas, fixtures, and integration manifests."""

from __future__ import annotations

import json
import re
import sys
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MARKDOWN_LINK = re.compile(r"(?<!!)\[[^\]]+\]\(([^)]+)\)")
REQUIRED = [
    "README.md", "SECURITY.md", "CONTRIBUTING.md", "CHANGELOG.md",
    "docs/PRD.md", "docs/SPECIFICATION.md", "docs/TECHNICAL_REQUIREMENTS.md",
    "docs/TECHNICAL_DESIGN.md", "docs/THREAT_MODEL.md", "docs/IMPLEMENTATION_PLAN.md",
    "docs/TEST_STRATEGY.md", "docs/TRACEABILITY.md", "docs/USER_GUIDE.md",
    "docs/INTEGRATIONS.md", "docs/RELEASE_V1.md", "docs/adr/README.md",
]


def main() -> int:
    errors: list[str] = []
    for relative in REQUIRED:
        if not (ROOT / relative).is_file():
            errors.append(f"missing required file: {relative}")

    markdown = sorted(path for path in ROOT.rglob("*.md") if ".git" not in path.parts)
    for source in markdown:
        text = source.read_text(encoding="utf-8")
        for target in MARKDOWN_LINK.findall(text):
            clean = target.split("#", 1)[0].strip("<>")
            if not clean or clean.startswith(("http://", "https://", "mailto:")):
                continue
            resolved = (source.parent / clean).resolve()
            try:
                resolved.relative_to(ROOT)
            except ValueError:
                errors.append(f"{source.relative_to(ROOT)} link escapes repository: {clean}")
                continue
            if not resolved.exists():
                errors.append(f"{source.relative_to(ROOT)} missing link: {clean}")

    schemas = sorted((ROOT / "spec").glob("*.schema.json"))
    if len(schemas) < 3:
        errors.append("expected at least three versioned JSON schemas")
    for schema in schemas:
        try:
            value = json.loads(schema.read_text(encoding="utf-8"))
        except json.JSONDecodeError as error:
            errors.append(f"invalid JSON schema {schema.name}: {error}")
            continue
        if value.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
            errors.append(f"{schema.name} is not JSON Schema 2020-12")
        if not value.get("$id") or not value.get("title"):
            errors.append(f"{schema.name} lacks $id/title")

    for fixture in sorted((ROOT / "benchmarks").rglob("cases.json")):
        value = json.loads(fixture.read_text(encoding="utf-8"))
        if value.get("schemaVersion") != 1 or not value.get("cases"):
            errors.append(f"invalid benchmark corpus: {fixture.relative_to(ROOT)}")
        if "inert" not in value.get("safety", ""):
            errors.append(f"benchmark lacks inert safety declaration: {fixture.relative_to(ROOT)}")

    cargo = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))
    version = cargo["workspace"]["package"]["version"]
    for package_path in [
        ROOT / "packages/typescript-sdk/package.json",
        ROOT / "packages/vscode-extension/package.json",
        ROOT / "packages/opencode-plugin/package.json",
    ]:
        package = json.loads(package_path.read_text(encoding="utf-8"))
        if package["version"] != version:
            errors.append(f"version mismatch: {package_path.relative_to(ROOT)}")
    python = tomllib.loads((ROOT / "packages/python-sdk/pyproject.toml").read_text(encoding="utf-8"))
    if python["project"]["version"] != version:
        errors.append("Python SDK version mismatch")

    if errors:
        for error in errors:
            print(f"error: {error}", file=sys.stderr)
        return 1
    print(f"RepoSeal repository checks passed: {len(markdown)} docs, {len(schemas)} schemas")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

