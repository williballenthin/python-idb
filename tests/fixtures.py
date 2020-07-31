import os
import os.path

import pytest

import idb
import six

if six.PY2:
    from functools32 import lru_cache
else:
    from functools import lru_cache

try:
    import capstone

    no_capstone = False
except:
    no_capstone = True

CD = os.path.dirname(__file__)


@pytest.yield_fixture
def empty_idb():
    path = os.path.join(CD, "data", "empty", "empty.idb")
    with idb.from_file(path) as db:
        yield db


@pytest.yield_fixture
def kernel32_idb():
    path = os.path.join(CD, "data", "v6.95", "x32", "kernel32.idb")
    with idb.from_file(path) as db:
        yield db


@pytest.yield_fixture
def small_idb():
    path = os.path.join(CD, "data", "small", "small-colored.idb")
    with idb.from_file(path) as db:
        yield db


@pytest.yield_fixture
def compressed_idb():
    path = os.path.join(CD, "data", "compressed", "kernel32.idb")
    with idb.from_file(path) as db:
        yield db


@pytest.yield_fixture
def compressed_i64():
    path = os.path.join(CD, "data", "compressed", "kernel32.i64")
    with idb.from_file(path) as db:
        yield db


@pytest.yield_fixture
def elf_idb():
    path = os.path.join(CD, "data", "elf", "ls.idb")
    with idb.from_file(path) as db:
        yield db


@lru_cache(maxsize=16)
def load_idb(path):
    with open(path, "rb") as f:
        return idb.from_buffer(f.read())


def xfail(*spec):
    return ("xfail", spec)


def skip(*spec):
    return ("skip", spec)


def if_exists(*spec):
    return ("if_exists", spec)


@pytest.fixture
def runslow(request):
    return request.config.getoption("--runslow")


@pytest.fixture
def rundebug(request):
    return request.config.getoption("--rundebug")


def kern32_test(specs=None):
    """
    Example::

        @kern32_test([
                 (695, 32, 'bar'),
                 (695, 64, 'bar'),
            xfail(700, 32, 'bar'),
        ])
        def test_foo(kernel32_idb, version, bitness, expected):
            assert 'bar' == expected
    """
    if specs is None:
        specs = [
            (695, 32, None),
            (695, 64, None),
            (700, 32, None),
            (700, 64, None),
            (720, 32, None),
            (720, 64, None),
            (730, 32, None),
            (730, 64, None),
        ]

    ids = []
    params = []

    for spec in specs:
        version, bitness, expected = (
            spec if isinstance(spec[0], float) or isinstance(spec[0], int) else spec[1]
        )

        version_map = {
            500: "v5.0",
            695: "v6.95",
            700: "v7.0b",
            720: "v7.2",
            730: "v7.3",
        }
        sversion = version_map[version] if version in version_map else str(version)

        sbitness, filename = {
            32: ("x32", "kernel32.idb"),
            64: ("x64", "kernel32.i64"),
        }[bitness]

        path = os.path.join(CD, "data", sversion, sbitness, filename)
        skipped = False

        if spec[0] == "xfail":
            marks = pytest.mark.xfail
        elif spec[0] == "skip":
            skipped = True
            marks = pytest.mark.skip
        elif spec[0] == "if_exists":
            skipped = not os.path.exists(path)
            marks = pytest.mark.skipif(
                condition=skipped, reason="not exists idb file: " + path
            )
        else:
            marks = None

        db = load_idb(path) if not skipped else None

        if marks:
            params.append(pytest.param(db, version, bitness, expected, marks=marks))
        else:
            params.append(pytest.param(db, version, bitness, expected))

        ids.append(sversion + "/" + sbitness)

    return pytest.mark.parametrize(
        "kernel32_idb,version,bitness,expected", params, ids=ids
    )


requires_capstone = pytest.mark.skipif(no_capstone, reason="capstone not installed")
