#!/bin/bash
# SPIKE job-started hook (spike/job-admission). Prints variable NAMES and
# non-secret identifier values only. Never prints token values.
echo "::stop-commands::sandspikehookquote"
echo "SAND-HOOK start epoch=$(date +%s) utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "SAND-HOOK env-names: $(env | cut -d= -f1 | sort | tr '\n' ' ')"
for v in GITHUB_RUN_ID GITHUB_RUN_ATTEMPT GITHUB_RUN_NUMBER GITHUB_JOB GITHUB_WORKFLOW GITHUB_WORKFLOW_REF GITHUB_WORKFLOW_SHA GITHUB_SHA GITHUB_REF GITHUB_EVENT_NAME GITHUB_ACTOR GITHUB_ACTOR_ID GITHUB_TRIGGERING_ACTOR GITHUB_REPOSITORY GITHUB_REPOSITORY_ID GITHUB_REPOSITORY_OWNER_ID RUNNER_NAME GITHUB_EVENT_PATH FOO BASH_ENV ACTIONS_RUNNER_HOOK_JOB_STARTED; do
  if [ -n "${!v+x}" ]; then printf 'SAND-HOOK %s=%s\n' "$v" "${!v}"; else printf 'SAND-HOOK %s=<unset>\n' "$v"; fi
done
for v in GITHUB_TOKEN ACTIONS_RUNTIME_TOKEN ACTIONS_RUNTIME_URL ACTIONS_RESULTS_URL ACTIONS_CACHE_URL ACTIONS_ID_TOKEN_REQUEST_URL ACTIONS_ID_TOKEN_REQUEST_TOKEN; do
  if [ -n "${!v+x}" ]; then echo "SAND-HOOK presence $v=PRESENT"; else echo "SAND-HOOK presence $v=absent"; fi
done
[ -f "$GITHUB_EVENT_PATH" ] && echo "SAND-HOOK event.json exists bytes=$(wc -c < "$GITHUB_EVENT_PATH")"
echo "SAND-HOOK _actions: $(find "$HOME/actions-runner/_work/_actions" -maxdepth 3 -type d 2>/dev/null | sed "s#$HOME/actions-runner/_work/_actions##" | tr '\n' ' ')"
echo "SAND-HOOK workspace entries: $(ls -A "$GITHUB_WORKSPACE" 2>/dev/null | wc -l | tr -d ' ')"
echo "SAND-HOOK runner procs: $(pgrep -fl 'Runner\.(Worker|Listener)' | awk '{print $2}' | xargs -n1 basename 2>/dev/null | sort | uniq -c | tr '\n' ' ')"
echo "::sandspikehookquote::"
case "$GITHUB_JOB" in
  target|smoke) echo "SAND-HOOK verdict=ALLOW (blocking 40s for host-side REST polling)"; sleep 40; echo "SAND-HOOK allow exit epoch=$(date +%s)"; exit 0 ;;
  *) echo "SAND-HOOK verdict=DENY job=$GITHUB_JOB; exit 1"; exit 1 ;;
esac
