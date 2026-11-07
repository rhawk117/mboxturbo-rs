#!/usr/bin/env bash

declare -gA _LOG_PREFIX=(
  [info]=$'\033[0;34m  info\033[0m  '
  [success]=$'\033[0;32m    ok\033[0m  '
  [warn]=$'\033[1;33m  warn\033[0m  '
  [error]=$'\033[0;31m error\033[0m  '
  [step]=$'\n\033[1m\033[0;36m▶ '
  [step_end]=''
)

_LOG_CI=false

if [[ ${CI:-false} == true ]]; then
  _LOG_CI=true
  _LOG_PREFIX=(
    [info]='::notice::'
    [success]='::notice::'
    [warn]='::warning::'
    [error]='::error::'
    [step]='::group::'
    [step_end]='::endgroup::'
  )
fi

log::_emit() {
  local level=$1 suffix=''
  shift

  [[ $level == step_end && $_LOG_CI == false ]] && return 0
  [[ $level == step && $_LOG_CI == false ]] && suffix=$'\033[0m'

  if [[ $_LOG_CI == false && ($level == warn || $level == error) ]]; then
    printf '%s%s%s\n' "${_LOG_PREFIX[$level]}" "$*" "$suffix" >&2
  else
    printf '%s%s%s\n' "${_LOG_PREFIX[$level]}" "$*" "$suffix"
  fi
}

log::info() {
  log::_emit info "$@"
}
log::success() {
  log::_emit success "$@"
}
log::warn() {
  log::_emit warn "$@"
}

log::error() {
  log::_emit error "$@"
}

log::step() {
  log::_emit step "$@"
}

log::step_end() {
  log::_emit step_end
}
