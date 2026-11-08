#!/usr/bin/env bash
set -euo pipefail

main() {
  : "${GITHUB_STEP_SUMMARY:?GITHUB_STEP_SUMMARY is required}"

  local outcome=${LABELER_OUTCOME:-}
  local new_labels=${NEW_LABELS:-}
  local all_labels=${ALL_LABELS:-}

  if [[ -n "${new_labels}" ]]; then
    local notice=${new_labels}
    notice=${notice//'%'/'%25'}
    notice=${notice//$'\r'/'%0D'}
    notice=${notice//$'\n'/'%0A'}

    printf '::notice title=PR Labeler::Added labels: %s\n' "${notice}"
  fi

  {
    printf '%s\n' '## Pull Request Labels' ''

    if [[ ${outcome} != success ]]; then
      printf '%s\n' \
        ':warning: The labeler step did not succeed; label state may be incomplete.' \
        ''
    fi

    printf '%s\n' '### Labels Added' ''
    format_labels "${new_labels}" '_No new labels._'

    printf '%s\n' '' '### Current PR Labels' ''
    format_labels "${all_labels}" 'No labels found.'
  } >>"${GITHUB_STEP_SUMMARY}"
}

format_labels() {
  local raw=$1 fallback=$2 label
  local -a labels=()
  local found=false

  IFS=',' read -r -a labels <<<"${raw}"

  for label in "${labels[@]}"; do
    label="${label#"${label%%[![:space:]]*}"}"
    label="${label%"${label##*[![:space:]]}"}"

    [[ -n "${label}" ]] || continue

    # shellcheck disable=SC2016
    printf -- '- `%s`\n' "${label//\`/\\\`}"
    found=true
  done

  if [[ ${found} == false ]]; then
    printf '%s\n' "${fallback}"
  fi
}

main "$@"
