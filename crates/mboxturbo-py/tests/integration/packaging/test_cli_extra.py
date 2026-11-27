"""Packaging metadata: the cli extra pins the CLI wheel to this exact release."""

import tomllib
from pathlib import Path
from typing import Any

import pytest

pytestmark = pytest.mark.integration

REPOSITORY_ROOT = Path(__file__).resolve().parents[5]


def load_pyproject(relative: str) -> dict[str, Any]:
    return tomllib.loads((REPOSITORY_ROOT / relative).read_text(encoding='utf-8'))


def test_cli_extra_pins_the_cli_wheel_to_the_project_version() -> None:
    root = load_pyproject('pyproject.toml')

    assert root['project']['optional-dependencies']['cli'] == [
        f'mboxturbo-cli=={root["project"]["version"]}'
    ]


def test_cli_wheel_is_a_maturin_bin_package() -> None:
    cli = load_pyproject('crates/mboxturbo-cli/pyproject.toml')

    assert cli['project']['name'] == 'mboxturbo-cli'
    assert cli['tool']['maturin']['bindings'] == 'bin'
