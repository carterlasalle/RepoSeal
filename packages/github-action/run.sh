#!/usr/bin/env bash
set -euo pipefail

action=${1:?action required}
shift

if [[ "$action" == "install" ]]; then
  version=${1:?version required}
  cargo install --locked --git https://github.com/carterlasalle/RepoSeal --tag "v${version}" reposeal
  exit 0
fi

policy=${1:-.reposeal/policy.yaml}
lockfile=${2:-agent.lock}
if [[ -f "$lockfile" ]]; then
  reposeal lock verify "$lockfile"
fi
if [[ -f "$policy" ]]; then
  reposeal policy check "$policy"
fi
scan_args=(scan . --json)
if [[ -f .reposealignore ]]; then
  scan_args+=(--ignore-file .reposealignore)
fi
reposeal "${scan_args[@]}" > reposeal-scan.json
test "$(python3 -c 'import json; print(any(f["severity"] == "critical" for f in json.load(open("reposeal-scan.json"))["findings"]))')" = "False"
