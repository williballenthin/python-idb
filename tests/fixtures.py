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


def xfail(spec):
    return ('xfail', spec)


def skip(spec):
    return ('skip', spec)


def kern32_test(specs):
    '''
    Example::

        @kern32_test([
                 (695, 32, 'bar'),
                 (695, 64, 'bar'),
            xfail(700, 32, 'bar'),
        ])
        def test_foo(kernel32_idb, version, bitness, expected):
            assert 'bar' == expected
    '''
    params = []
    ids = []
    for spec in specs:
        if spec[0] == 'xfail':
            marks = pytest.mark.xfail
            spec = spec[1]
        elif spec[0] == 'skip':
            marks = pytest.mark.skip
            spec = spec[1]
        else:
            marks = None

        version = spec[0]
        bitness = spec[1]
        expected = spec[2:]

        if version == 695:
            sversion = 'v6.95'
        elif version == 700:
            sversion = 'v7.0b'
        else:
            raise ValueError('unexpected version')

        if bitness == 32:
            sbitness = 'x32'
            filename = 'kernel32.idb'
        elif bitness == 64:
            sbitness = 'x64'
            filename = 'kernel32.i64'
        else:
            raise ValueError('unexpected bitness')

        path = os.path.join(CD, 'data', sversion, sbitness, filename)
        db = load_idb(path)

        if marks:
            params.append(pytest.param(db, version, bitness, *expected, marks=marks))
        else:
            params.append(pytest.param(db, version, bitness, *expected))

        ids.append(sversion + '/' + sbitness)

    return pytest.mark.parametrize('kernel32_idb,version,bitness,expected', params, ids=ids)


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
