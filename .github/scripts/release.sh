#!/usr/bin/env bash

set -euo pipefail

readonly VERSION_BUMP="${VERSION_BUMP:-recover}"
readonly LOGGING_UTILS="./scripts/log.sh"
readonly PYTHON_PROJECT="."
readonly CARGO_MANIFEST="Cargo.toml"
readonly CORE_MANIFEST="crates/mboxturbo/Cargo.toml"
readonly PYTHON_MANIFEST="pyproject.toml"
readonly RELEASE_BOT_USERNAME="github-actions[bot]"
readonly RELEASE_BOT_EMAIL="41898282+github-actions[bot]@users.noreply.github.com"

release_version=""
release_tag=""

main() {
  setup_environment
  validate_release_context
  validate_current_release

  if [[ "${VERSION_BUMP}" != recover ]]; then
    bump_release
    synchronize_cargo_version
    synchronize_cli_extra_pin
    record_version_bump
  fi

  write_release_outputs
}

panic() {
  log::error "$*"
  exit 1
}

setup_environment() {
  local repository_root
  repository_root=$(git rev-parse --show-toplevel)
  cd "${repository_root}"

  # shellcheck disable=SC1090
  source "${LOGGING_UTILS}"
}

validate_release_context() {
  [[ "${GITHUB_EVENT_NAME:-}" == workflow_dispatch ]] || panic "Releases require workflow_dispatch."

  [[ "${GITHUB_REF:-}" == refs/heads/main ]] || panic "Releases must originate from main."

  [[ "${REPOSITORY_IS_FORK:-true}" == false ]] || panic "Releases are disabled in forks."

  case "${VERSION_BUMP}" in
    recover | major | minor | patch) ;;
    *) panic "Invalid version bump: ${VERSION_BUMP}" ;;
  esac
}

cargo_workspace_version() {
  local version
  version=$(awk '/^\[workspace\.package\]$/ { in_package = 1; next }
    /^\[/ { in_package = 0 }
    in_package && /^version = / { gsub(/"/, "", $3); print $3; exit }' "${CARGO_MANIFEST}") ||
    panic "Cargo workspace version could not be read from ${CARGO_MANIFEST}."
  [[ -n "${version}" ]] || panic "No workspace version found in ${CARGO_MANIFEST}."
  printf '%s\n' "${version}"
}

validate_current_release() {
  log::step "Validate Current Release"

  release_version=$(uv version --project "${PYTHON_PROJECT}" --short)
  release_tag="v${release_version}"

  local cargo_version
  cargo_version=$(cargo_workspace_version)

  [[ "${cargo_version}" == "${release_version}" ]] ||
    panic "Cargo workspace (${cargo_version}) and Python package (${release_version}) versions differ."

  git show-ref --verify --quiet "refs/tags/${release_tag}" ||
    panic "Previous release tag does not exist: ${release_tag}"

  log::step_end
}

bump_release() {
  log::step "Bump Release Version (${VERSION_BUMP})"

  local working_tree_status
  working_tree_status=$(git status --porcelain)
  [[ -z "${working_tree_status}" ]] || panic "Working tree is not clean."

  uv lock --check --project "${PYTHON_PROJECT}" ||
    panic "uv.lock is stale before the version bump; run uv lock and commit it."

  uv version --project "${PYTHON_PROJECT}" --bump "${VERSION_BUMP}" --no-sync

  release_version=$(uv version --project "${PYTHON_PROJECT}" --short)
  release_tag="v${release_version}"

  if git show-ref --verify --quiet "refs/tags/${release_tag}"; then
    panic "Release tag already exists: ${release_tag}"
  fi

  log::step_end
}

synchronize_cargo_version() {
  log::step "Synchronize Cargo Workspace Version"

  awk -v version="${release_version}" '/^\[workspace\.package\]$/ { in_package = 1 }
    /^\[/ && !/^\[workspace\.package\]$/ { in_package = 0 }
    in_package && /^version = / { $0 = "version = \"" version "\"" }
    { print }' "${CARGO_MANIFEST}" >"${CARGO_MANIFEST}.tmp"

  mv "${CARGO_MANIFEST}.tmp" "${CARGO_MANIFEST}"

  local updated_cargo_version
  updated_cargo_version=$(cargo_workspace_version)
  [[ "${updated_cargo_version}" == "${release_version}" ]] ||
    panic "Cargo workspace version did not update to ${release_version}."

  synchronize_headers_pin

  cargo update --workspace

  log::step_end
}

synchronize_cli_extra_pin() {
  log::step "Synchronize CLI Extra Pin"

  local pin="mboxturbo-cli==${release_version}"
  sed -E "s/^(cli = \\[\")mboxturbo-cli==[^\"]*(\"\\])$/\\1${pin}\\2/" \
    "${PYTHON_MANIFEST}" >"${PYTHON_MANIFEST}.tmp"
  mv "${PYTHON_MANIFEST}.tmp" "${PYTHON_MANIFEST}"

  grep -qxF "cli = [\"${pin}\"]" "${PYTHON_MANIFEST}" ||
    panic "CLI extra pin did not update to ${pin}."

  uv lock --project "${PYTHON_PROJECT}"
  uv lock --project "${PYTHON_PROJECT}" --check

  log::step_end
}

synchronize_headers_pin() {
  awk -v version="${release_version}" '/^mboxturbo-headers = / {
      sub(/version = "[^"]*"/, "version = \"=" version "\"")
    }
    { print }' "${CORE_MANIFEST}" >"${CORE_MANIFEST}.tmp"

  mv "${CORE_MANIFEST}.tmp" "${CORE_MANIFEST}"

  local pinned_version
  pinned_version=$(awk '/^mboxturbo-headers = / {
      match($0, /version = "=[^"]*"/)
      print substr($0, RSTART + 12, RLENGTH - 13)
      exit
    }' "${CORE_MANIFEST}")
  [[ "${pinned_version}" == "${release_version}" ]] ||
    panic "mboxturbo-headers pin did not update to ${release_version}."
}

record_version_bump() {
  log::step "Record Version Bump (${release_tag})"

  git config user.name "${RELEASE_BOT_USERNAME}"
  git config user.email "${RELEASE_BOT_EMAIL}"

  git add -- "${CARGO_MANIFEST}" "${CORE_MANIFEST}" Cargo.lock "${PYTHON_MANIFEST}" uv.lock

  git commit -m "chore(release): ${release_tag}"
  git tag -a "${release_tag}" -m "Release ${release_tag}"

  git push --atomic origin \
    HEAD:refs/heads/main \
    "refs/tags/${release_tag}:refs/tags/${release_tag}"

  log::step_end
}

write_release_outputs() {
  {
    printf 'version=%s\n' "${release_version}"
    printf 'tag=%s\n' "${release_tag}"
  } >>"${GITHUB_OUTPUT:?GITHUB_OUTPUT is required}"
}

main "$@"
