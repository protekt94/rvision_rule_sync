from pathlib import Path
import pytest


def pytest_addoption(parser):
    parser.addoption('--private-fixtures', type=Path, help='Optional directory with private vendor/custom/.roc regression inputs')
    parser.addoption('--private-custom-prefix', default='CUSTOM-', help='Custom prefix in optional private fixtures')


def pytest_ignore_collect(collection_path, config):
    if collection_path.name == 'private' and config.getoption('--private-fixtures') is None:
        return True


@pytest.fixture(scope='session')
def private_fixtures(request):
    path = request.config.getoption('--private-fixtures')
    if path is None or not path.is_dir():
        pytest.fail('--private-fixtures must name an existing directory')
    return path


@pytest.fixture(scope='session')
def private_custom_prefix(request):
    return request.config.getoption('--private-custom-prefix')
