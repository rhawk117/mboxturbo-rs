#!/usr/bin/env bash
set -euo pipefail

readonly LOGGING_UTILS="./scripts/log.sh"
readonly ISSUE_TITLE="[SECURITY] Weekly Supply Chain Audit Failed"
readonly WORKFLOW_URL="${GITHUB_SERVER_URL:?}/${GITHUB_REPOSITORY:?}/actions/runs/${GITHUB_RUN_ID:?}"
readonly REPORT_FILE="${RUNNER_TEMP:?}/security-report.md"
readonly SARIF_FILE="${RUNNER_TEMP}/pysentry-results.sarif"

existing_issue=""

main() {
  setup_environment
  find_existing_issue

  if [[ "$AUDIT_RESULT" == success ]]; then
    resolve_security_issue
    return
  fi

  download_audit_report
  write_failure_report
  publish_security_issue
}

setup_environment() {
  local repository_root
  repository_root=$(git rev-parse --show-toplevel)
  cd "$repository_root"

  # shellcheck disable=SC1090
  source "$LOGGING_UTILS"
}

find_existing_issue() {
  log::step "Find Existing Security Issue"

  existing_issue=$(gh issue list \
    --state open \
    --search '"Weekly supply chain audit failed" in:title' \
    --limit 100 \
    --json number,title,author \
    --jq '[.[] | select(.title == "Weekly supply chain audit failed" and .author.login == "github-actions[bot]") | .number][0] // empty')

  log::step_end
}

download_audit_report() {
  log::step "Download Security Findings"

  if ! gh run download "$GITHUB_RUN_ID" \
    --name pysentry-weekly \
    --dir "$RUNNER_TEMP"; then
    log::warn "No SARIF artifact found; linking workflow logs instead."
  fi

  log::step_end
}

format_findings() {
  if [[ ! -s "$SARIF_FILE" ]] || ! jq -e '.runs | type == "array"' "$SARIF_FILE" >/dev/null; then
    printf '%s\n' 'No valid SARIF was generated. Check the workflow logs for scanner errors.'
    return
  fi

  jq -r '
    [.runs[]?.results[]?] as $findings |
    "**SARIF findings:** \($findings | length)\n",
    (
      $findings[:25][] |
      "- **\(.ruleId // "unknown")** (\(.level // "unspecified")): " +
      ((.message.text // "No description") | gsub("[\r\n]"; " ") | .[:300])
    ),
    (
      if ($findings | length) > 25 then
        "\nShowing 25 findings. See the complete SARIF artifact."
      else
        empty
      end
    )
  ' "$SARIF_FILE"
}

write_failure_report() {
  log::step "Generate Security Report"

  {
    printf '%s\n' '## Weekly Supply Chain Audit Failed' ''
    printf -- "- **Result:** %s\n" "$AUDIT_RESULT"
    printf -- '- **Commit:** %s\n' "$GITHUB_SHA"
    printf -- '- **Run:** [View logs and artifacts](%s)\n' "$WORKFLOW_URL"
    printf '\n%s\n\n' '### Findings'
    format_findings
  } >"$REPORT_FILE"

  cat "$REPORT_FILE" >>"$GITHUB_STEP_SUMMARY"
  log::step_end
}

publish_security_issue() {
  log::step "Publish Security Issue"

  if [[ -z "$existing_issue" ]]; then
    gh issue create --title "$ISSUE_TITLE" --body-file "$REPORT_FILE"
  else
    gh issue edit "$existing_issue" --body-file "$REPORT_FILE"
  fi

  log::step_end
}

resolve_security_issue() {
  log::step "Resolve Security Issue"

  if [[ -n "$existing_issue" ]]; then
    gh issue close "$existing_issue" \
      --reason completed \
      --comment "Weekly audit passed: $WORKFLOW_URL"
  fi

  printf 'Weekly security audit passed: %s\n' "$WORKFLOW_URL" >>"$GITHUB_STEP_SUMMARY"
  log::step_end
}

main "$@"
