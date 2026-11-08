import pytest
from attacks.simulator import make_pair


@pytest.fixture
def peers():
    with make_pair() as pair:
        yield pair


@pytest.fixture(autouse=True)
def isolated_filesystem_storage(monkeypatch):
    monkeypatch.setenv("CRYTOSAGE_STORAGE_BACKEND", "filesystem")
