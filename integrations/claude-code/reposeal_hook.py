#!/usr/bin/env python3
"""Claude Code PreToolUse hook that fails closed on unsafe acquisition."""

import json
import subprocess
import sys


def main() -> int:
    event = json.load(sys.stdin)
    command = event.get("tool_input", {}).get("command")
    if not isinstance(command, str):
        print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "allow"}}))
        return 0
    result = subprocess.run(
        ["reposeal", "guard", "--command", command, "--json"],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    try:
        report = json.loads(result.stdout)
    except json.JSONDecodeError:
        report = {"decision": "blocked", "signals": [{"message": "RepoSeal unavailable or returned invalid JSON"}]}
    decision = report.get("decision", "blocked")
    reason = "; ".join(item.get("message", "") for item in report.get("signals", [])) or "RepoSeal verified"
    output = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "allow" if decision == "verified" else "deny",
            "permissionDecisionReason": reason,
        }
    }
    print(json.dumps(output))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

