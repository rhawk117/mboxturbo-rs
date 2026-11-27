"""Locate the mboxturbo command-line executable installed by the cli extra."""

import os
import sysconfig
from pathlib import Path

from mboxturbo._core import MboxTurboError

_EXECUTABLE = 'mboxturbo' + (sysconfig.get_config_var('EXE') or '')


class MboxTurboBinNotFoundError(FileNotFoundError, MboxTurboError):
    """The mboxturbo executable is not installed in the current environment."""


def _search_directories() -> list[Path]:
    """Return the directories to search, in priority order, without duplicates."""
    candidates = [
        Path(sysconfig.get_path('scripts')),
        Path(sysconfig.get_path('scripts', f'{os.name}_user')),
        Path(sysconfig.get_path('scripts', sysconfig.get_preferred_scheme('user'))),
        Path(__file__).resolve().parent.parent / Path(sysconfig.get_path('scripts')).name,
    ]
    return list(dict.fromkeys(candidates))


def find_mboxturbo_bin() -> Path:
    """Return the path of the mboxturbo executable installed in this environment.

    Searches the interpreter's scripts directory, the user scripts directory and the
    scripts directory beside the package for a ``pip install --target`` install. The
    ``PATH`` is not consulted, so the binary always matches this installation.

    Raises:
        MboxTurboBinNotFoundError: No executable was found; install ``mboxturbo[cli]``.
    """
    directories = _search_directories()
    for directory in directories:
        candidate = directory / _EXECUTABLE
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return candidate
    searched = ', '.join(str(directory) for directory in directories)
    message = (
        f'mboxturbo executable not found; searched: {searched}. '
        'Install it with: pip install "mboxturbo[cli]"'
    )
    raise MboxTurboBinNotFoundError(message)
