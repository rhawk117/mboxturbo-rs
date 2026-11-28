#!/usr/bin/env bash
# Interleaved A/B of a bench: a git-archive copy of REF against the working tree.
# Usage: scripts/bench-ab.sh [REF] [ROUNDS] [BENCH]   (defaults: main, 3, export)
# BENCH is export or index; index runs REF's own benches/index.rs and prints the index rows.
# MBOXTURBO_BENCH_MESSAGES and MBOXTURBO_BENCH_SEED size the shared fixture.

set -euo pipefail

# shellcheck source=scripts/log.sh disable=SC1091
source "$(dirname "${BASH_SOURCE[0]}")/log.sh"

readonly REF=${1:-main}
readonly ROUNDS=${2:-3}
readonly BENCH=${3:-export}
ROOT=$(git rev-parse --show-toplevel)
readonly ROOT

if [[ ! ${ROUNDS} =~ ^[1-9][0-9]*$ ]]; then
  log::error "ROUNDS must be a positive integer, got '${ROUNDS}'"
  exit 2
fi

case ${BENCH} in
  export | index) ;;
  *)
    log::error "BENCH must be export or index, got '${BENCH}'"
    exit 2
    ;;
esac

if [[ ${BENCH} == export ]]; then
  for marker in 'ab:api begin' 'ab:api end' 'ab:new begin' 'ab:new end'; do
    count=$(grep -c "^ *// ${marker}" "${ROOT}/crates/mboxturbo/benches/export.rs" || true)
    if ((count != 1)); then
      log::error "crates/mboxturbo/benches/export.rs must contain '// ${marker}' exactly once"
      exit 2
    fi
  done
fi

WORK=$(mktemp -d "${TMPDIR:-/tmp}/bench-ab.XXXXXX")
readonly WORK
trap 'rm -rf "${WORK}"' EXIT

# One fixture for both trees, so page-cache state matches.
export MBOXTURBO_BENCH_DIR=${MBOXTURBO_BENCH_DIR:-${ROOT}/target}

# REF's copy has the ab:new block cut out, which leaves the parameters and imports it used
# unused, so REF builds with lints capped at warnings; codegen is unchanged.
bench() {
  local tree=$1 target=$2 flags=${RUSTFLAGS:-}
  if [[ ${tree} == "${WORK}/ref" ]]; then
    flags="${flags} --cap-lints=warn"
  fi
  (cd "${tree}" && RUSTFLAGS=${flags} CARGO_TARGET_DIR=${target} cargo bench -p mboxturbo --bench "${BENCH}" "${@:3}")
}

run() {
  local label=$1 tree=$2 target=$3 round=$4 line
  local out="${WORK}/out.txt" err="${WORK}/err.txt"
  local status=0
  set +e
  bench "${tree}" "${target}" >"${out}" 2>"${err}"
  status=$?
  set -e
  if ((status != 0)); then
    log::error "bench run failed (${label}, round ${round}):"
    cat "${err}" >&2
    exit 1
  fi
  while IFS= read -r line; do
    if [[ ${line} =~ ${ROWS} ]]; then
      printf '%-22s round %s  %s\n' "${label}" "${round}" "${line}"
    fi
  done <"${out}"
}

if [[ ${BENCH} == index ]]; then
  ROWS='^(build|save|random-access|index-lookup|sequential|index-sweep|open)'
else
  ROWS='^(select|parquet|raw-parquet|copy|mbox|eml|jsonl|csv|ipc)'
fi
readonly ROWS

# The rows of the ab:new block time sinks REF lacks, so REF's copy drops the block.
strip_new() {
  awk '
    /^ *\/\/ ab:new begin/ { skip = 1; next }
    /^ *\/\/ ab:new end/ { skip = 0; next }
    !skip { print }
  '
}

log::step "Extracting ${REF}"
mkdir "${WORK}/ref"
git -C "${ROOT}" archive "${REF}" | tar -x -C "${WORK}/ref"
BENCH_SRC=crates/mboxturbo/benches/export.rs
BENCH_COMMON=crates/mboxturbo/benches/common
mkdir -p "${WORK}/ref/${BENCH_COMMON}"
cp "${ROOT}/${BENCH_COMMON}/mod.rs" "${WORK}/ref/${BENCH_COMMON}/mod.rs"
if [[ ${BENCH} == index ]]; then
  :
elif git -C "${ROOT}" cat-file -e "${REF}:crates/mboxturbo/src/export.rs" 2>/dev/null; then
  strip_new <"${ROOT}/${BENCH_SRC}" >"${WORK}/ref/${BENCH_SRC}"
else
  # REF lacks the export driver the bench's API block calls: give REF's copy the block in
  # scripts/ab/export_main.rs, which calls write_parquet instead.
  awk -v main_side="${ROOT}/scripts/ab/export_main.rs" '
    /^\/\/ ab:api begin/ { while ((getline line < main_side) > 0) print line; skip = 1; next }
    /^\/\/ ab:api end/ { skip = 0; next }
    !skip { print }
  ' "${ROOT}/${BENCH_SRC}" | strip_new >"${WORK}/ref/${BENCH_SRC}"
fi
if [[ ${BENCH} == export ]] && ! grep -q 'name = "export"' "${WORK}/ref/crates/mboxturbo/Cargo.toml"; then
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
