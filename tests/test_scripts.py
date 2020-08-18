from contextlib import contextmanager

import pytest

from fixtures import DefaultKern32Specs, get_kern32_path
from scripts import (
    dump_btree,
    dump_types,
    dump_user,
    dump_scripts,
    extract_function_names,
    extract_md5,
    extract_version,
)


@contextmanager
def not_raises(exception):
    try:
        yield
    except exception:
        raise pytest.fail("Unexpected raise {0}".format(exception))


def kern32_script_test(scripts, specs=None):
    if specs is None:
        specs = DefaultKern32Specs
    ids = []
    params = []
    for script in scripts:
        for spec in specs:
            version, bitness, expected = (
                spec
                if isinstance(spec[0], float) or isinstance(spec[0], int)
                else spec[1]
            )
            path, sversion, sbitness = get_kern32_path(version, bitness)
            params.append(pytest.param(path, version, bitness, expected, script))
            ids.append("/".join([sversion, sbitness, script.__name__]))
    return pytest.mark.parametrize(
        "kernel32_idb_path, version, bitness, expected, script", params, ids=ids
    )


SlowScripts = [dump_btree, extract_function_names]
Scripts = [dump_types, dump_user, dump_scripts, extract_md5, extract_version]


@pytest.mark.slow
@kern32_script_test(SlowScripts)
def test_slow_scripts(kernel32_idb_path, version, bitness, expected, script):
    with not_raises(Exception):
        script.main([kernel32_idb_path])


@kern32_script_test(Scripts)
def test_scripts(kernel32_idb_path, version, bitness, expected, script):
    with not_raises(Exception):
        script.main([kernel32_idb_path])
