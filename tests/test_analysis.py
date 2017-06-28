from fixtures import *

import idb.analysis


import logging
logging.basicConfig(level=logging.DEBUG)


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


def test_entrypoints(kernel32_idb):
    entrypoints = idb.analysis.EntryPoints(kernel32_idb)

    addresses = entrypoints.addresses
    assert len(addresses) == 1
    assert 0x68901695 in addresses
    assert addresses[0x68901695] == 'DllEntryPoint'

    ordinals = entrypoints.ordinals
    assert len(ordinals) == 0x623
    assert 0x1 in ordinals
    assert 0x623 in ordinals
    assert ordinals[0x1] == 'BaseThreadInitThunk'

    allofthem = entrypoints.all
    assert len(allofthem) == 0x624
