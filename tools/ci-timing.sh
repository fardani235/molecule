#!/usr/bin/env bash
# Capture per-job durations for the latest run of a workflow.
# Usage: tools/ci-timing.sh <workflow-file-name> [branch]
# Example: tools/ci-timing.sh build-artifacts.yml main
set -euo pipefail

WORKFLOW="${1:?usage: ci-timing.sh <workflow-file> [branch]}"
BRANCH="${2:-main}"

RUN_ID="$(gh run list --workflow "$WORKFLOW" --branch "$BRANCH" \
  --limit 1 --json databaseId --jq '.[0].databaseId')"

if [[ -z "$RUN_ID" || "$RUN_ID" == "null" ]]; then
  echo "No runs found for $WORKFLOW on $BRANCH" >&2
  exit 1
fi

echo "Run: $RUN_ID ($WORKFLOW @ $BRANCH)"
echo
echo "| Job | Duration (s) |"
echo "|---|---|"
gh run view "$RUN_ID" --json jobs --jq '
  .jobs[]
  | select(.startedAt != null and .completedAt != null)
  | "| \(.name) | \(((.completedAt | fromdateiso8601) - (.startedAt | fromdateiso8601))) |"
'
