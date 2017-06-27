from fixtures import *

import idb.analysis


def test_root(kernel32_idb):
    root = idb.analysis.Root(kernel32_idb)

    assert root.version == 695
    assert root.get_field_tag('version') == 'A'
    assert root.get_field_index('version') == -1

    assert root.version_string == '6.95'
    assert root.open_count == 1
    assert root.created.isoformat() == '2017-06-20T22:31:34'
    assert root.crc == 0xdf9bdf12
    assert root.md5 == '00bf1bf1b779ce1af41371426821e0c2'


def test_loader(kernel32_idb):
    loader = idb.analysis.Loader(kernel32_idb)

    assert loader.plugin == 'pe.ldw'
    assert loader.format.startswith('Portable executable') == True
