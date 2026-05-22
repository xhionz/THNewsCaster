"""Shared test fixtures.

Prevents any test from accidentally hitting the network when KEV enrichment
runs: pre-populating the module cache with an empty dict short-circuits the
CISA KEV fetch in thnewscaster.tools._load_kev.
"""
import sys
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


@pytest.fixture(autouse=True)
def _no_kev_network():
    import thnewscaster.tools as tools
    saved = tools._kev_cache
    tools._kev_cache = {}      # already "loaded" -> _load_kev returns immediately
    yield
    tools._kev_cache = saved
