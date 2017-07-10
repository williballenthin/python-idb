import os
import os.path

import pytest

import idb


CD = os.path.dirname(__file__)


@pytest.yield_fixture
def empty_idb():
    path = os.path.join(CD, 'data', 'empty', 'empty.idb')
    with idb.from_file(path) as db:
        yield db


@pytest.yield_fixture
def kernel32_idb():
    path = os.path.join(CD, 'data', 'v6.95', 'x32', 'kernel32.idb')
    with idb.from_file(path) as db:
        yield db


@pytest.yield_fixture
def small_idb():
    path = os.path.join(CD, 'data', 'small', 'small-colored.idb')
    with idb.from_file(path) as db:
        yield db


def load_idb(path):
    with open(path, 'rb') as f:
        return idb.from_buffer(f.read())


# decorator for tests that apply to all versions of IDA
kernel32_all_versions = pytest.mark.parametrize("kernel32_idb", [
    load_idb(os.path.join(CD, 'data', 'v6.95', 'x32', 'kernel32.idb')),
    # TODO: .i64 support
    pytest.param(load_idb(os.path.join(CD, 'data', 'v6.95', 'x64', 'kernel32.i64')),
                 marks=pytest.mark.xfail),
    load_idb(os.path.join(CD, 'data', 'v7.0b', 'x32', 'kernel32.idb')),
    # TODO: .i64 support
    pytest.param(load_idb(os.path.join(CD, 'data', 'v7.0b', 'x64', 'kernel32.i64')),
                 marks=pytest.mark.xfail),
], ids=[
    '6.95/x32',
    '6.95/x64',
    'v7.0/x32',
    'v7.0/x64',
])


# decorator for tests that apply to x32 and x64 versions of IDA v6.95
kernel32_v695 = pytest.mark.parametrize("kernel32_idb", [
    load_idb(os.path.join(CD, 'data', 'v6.95', 'x32', 'kernel32.idb')),
    # TODO: .i64 support
    pytest.param(load_idb(os.path.join(CD, 'data', 'v6.95', 'x64', 'kernel32.i64')),
                 marks=pytest.mark.xfail),
], ids=[
    '6.95/x32',
    '6.95/x64',
])


# decorator for tests that apply to x32 and x64 versions of IDA v7.0 beta
kernel32_v70b = pytest.mark.parametrize("kernel32_idb", [
    load_idb(os.path.join(CD, 'data', 'v7.0b', 'x32', 'kernel32.idb')),
    # TODO: .i64 support
    pytest.param(load_idb(os.path.join(CD, 'data', 'v7.0b', 'x64', 'kernel32.i64')),
                 marks=pytest.mark.xfail),
], ids=[
    '7.0b/x32',
    '7.0b/x64',
])
