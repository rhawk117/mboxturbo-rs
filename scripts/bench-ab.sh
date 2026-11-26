#!/usr/bin/env bash
# Interleaved A/B of the export bench: a git-archive copy of REF against the working tree.
# Usage: scripts/bench-ab.sh [REF] [ROUNDS]   (defaults: main, 3)
# MBOXTURBO_BENCH_MESSAGES and MBOXTURBO_BENCH_SEED size the shared fixture.

set -euo pipefail

# shellcheck source=scripts/log.sh disable=SC1091
source "$(dirname "${BASH_SOURCE[0]}")/log.sh"

readonly REF=${1:-main}
readonly ROUNDS=${2:-3}
ROOT=$(git rev-parse --show-toplevel)
readonly ROOT

if [[ ! ${ROUNDS} =~ ^[1-9][0-9]*$ ]]; then
  log::error "ROUNDS must be a positive integer, got '${ROUNDS}'"
  exit 2
fi

WORK=$(mktemp -d "${TMPDIR:-/tmp}/bench-ab.XXXXXX")
readonly WORK
trap 'rm -rf "${WORK}"' EXIT

# One fixture for both trees, so page-cache state matches.
export MBOXTURBO_BENCH_DIR=${MBOXTURBO_BENCH_DIR:-${ROOT}/target}

bench() {
  local tree=$1 target=$2
  (cd "${tree}" && CARGO_TARGET_DIR=${target} cargo bench -p mboxturbo --bench export "${@:3}")
}

run() {
  local label=$1 tree=$2 target=$3 round=$4 line
  local out="${WORK}/out.txt" err="${WORK}/err.txt"
  if ! bench "${tree}" "${target}" >"${out}" 2>"${err}"; then
    log::error "bench run failed (${label}, round ${round}):"
    cat "${err}" >&2
    exit 1
  fi
  while IFS= read -r line; do
    case ${line} in
      select* | parquet* | raw-parquet* | copy*) printf '%-22s round %s  %s\n' "${label}" "${round}" "${line}" ;;
    esac
  done <"${out}"
}

log::step "Extracting ${REF}"
mkdir "${WORK}/ref"
git -C "${ROOT}" archive "${REF}" | tar -x -C "${WORK}/ref"
# The bench's API block calls the export driver, which REF lacks: give REF's copy the block in
# scripts/ab/export_main.rs, which calls write_parquet instead.
awk -v main_side="${ROOT}/scripts/ab/export_main.rs" '
  /^\/\/ ab:api begin/ { while ((getline line < main_side) > 0) print line; skip = 1; next }
  /^\/\/ ab:api end/ { skip = 0; next }
  !skip { print }
' "${ROOT}/crates/mboxturbo/benches/export.rs" >"${WORK}/ref/crates/mboxturbo/benches/export.rs"
if ! grep -q 'name = "export"' "${WORK}/ref/crates/mboxturbo/Cargo.toml"; then
  printf '\n[[bench]]\nname = "export"\nharness = false\n' >>"${WORK}/ref/crates/mboxturbo/Cargo.toml"
fi

log::step "Building both trees"
bench "${WORK}/ref" "${WORK}/target-ref" --no-run
bench "${ROOT}" "${WORK}/target-head" --no-run

log::step "Warm-up (discarded)"
run ref "${WORK}/ref" "${WORK}/target-ref" warmup >/dev/null
run head "${ROOT}" "${WORK}/target-head" warmup >/dev/null

log::step "Rounds"
for ((round = 1; round <= ROUNDS; round++)); do
  run "${REF}" "${WORK}/ref" "${WORK}/target-ref" "${round}"
  run "HEAD (working tree)" "${ROOT}" "${WORK}/target-head" "${round}"
done
