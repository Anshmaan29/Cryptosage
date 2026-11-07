import pytest
from attacks.simulator import make_pair


@pytest.fixture
def peers():
    with make_pair() as pair:
        yield pair
