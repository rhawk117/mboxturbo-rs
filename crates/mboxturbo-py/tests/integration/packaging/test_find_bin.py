"""find_mboxturbo_bin locates the CLI in the environment's script directories."""

import os
import sysconfig
from pathlib import Path

import pytest

import mboxturbo

pytestmark = pytest.mark.integration

EXECUTABLE = 'mboxturbo' + (sysconfig.get_config_var('EXE') or '')


@pytest.fixture
def scripts_dirs(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> tuple[Path, Path]:
    primary = tmp_path / 'scripts'
    user = tmp_path / 'user-scripts'
    primary.mkdir()
    user.mkdir()

    def get_path(name: str, scheme: str | None = None) -> str:
        assert name == 'scripts'
        return str(user if scheme else primary)

    monkeypatch.setattr(sysconfig, 'get_path', get_path)
    monkeypatch.setattr(
        'mboxturbo._bin.__file__', str(tmp_path / 'site' / 'mboxturbo' / '_bin.py')
    )
    return primary, user


def make_executable(directory: Path, mode: int = 0o755) -> Path:
    path = directory / EXECUTABLE
    path.write_text('#!/bin/sh\n', encoding='utf-8')
    path.chmod(mode)
    return path


def test_returns_executable_in_scripts_directory(scripts_dirs: tuple[Path, Path]) -> None:
    expected = make_executable(scripts_dirs[0])

    assert mboxturbo.find_mboxturbo_bin() == expected


def test_scripts_directory_wins_over_user_directory(
    scripts_dirs: tuple[Path, Path],
) -> None:
    primary = make_executable(scripts_dirs[0])
    make_executable(scripts_dirs[1])

    assert mboxturbo.find_mboxturbo_bin() == primary


def test_falls_back_to_user_directory(scripts_dirs: tuple[Path, Path]) -> None:
    expected = make_executable(scripts_dirs[1])

    assert mboxturbo.find_mboxturbo_bin() == expected


@pytest.mark.skipif(os.name == 'nt', reason='POSIX permission bits')
def test_non_executable_file_is_skipped(scripts_dirs: tuple[Path, Path]) -> None:
    make_executable(scripts_dirs[0], mode=0o644)
    expected = make_executable(scripts_dirs[1])

    assert mboxturbo.find_mboxturbo_bin() == expected


def test_finds_executable_in_bin_beside_the_package(
    scripts_dirs: tuple[Path, Path],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    primary, user = scripts_dirs

    def get_path(name: str, scheme: str | None = None) -> str:
        assert name == 'scripts'
        return str(tmp_path / 'venv' / 'bin') if not scheme else str(user)

    monkeypatch.setattr(sysconfig, 'get_path', get_path)
    bin_dir = tmp_path / 'site' / 'bin'
    bin_dir.mkdir(parents=True)
    expected = make_executable(bin_dir)

    assert not any(primary.iterdir())
    assert mboxturbo.find_mboxturbo_bin() == expected


def test_missing_binary_raises_with_every_searched_directory(
    scripts_dirs: tuple[Path, Path],
) -> None:
    with pytest.raises(FileNotFoundError) as caught:
        mboxturbo.find_mboxturbo_bin()

    assert isinstance(caught.value, mboxturbo.MboxTurboBinNotFoundError)
    assert isinstance(caught.value, mboxturbo.MboxTurboError)
    message = str(caught.value)
    assert message.index(str(scripts_dirs[0])) < message.index(str(scripts_dirs[1]))
    assert 'pip install "mboxturbo[cli]"' in message


def test_error_class_is_exported() -> None:
    assert 'MboxTurboBinNotFoundError' in mboxturbo.__all__
    assert 'find_mboxturbo_bin' in mboxturbo.__all__
