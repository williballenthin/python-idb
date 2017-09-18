import pytest

import idb.netnode

from fixtures import *


debug = pytest.mark.skipif(
    not pytest.config.getoption("--rundebug"),
    reason="need --rundebug option to run"
)


ROOT_NODEID = 'Root Node'


@kern32_test()
def test_name(kernel32_idb, version, bitness, expected):
    root = idb.netnode.Netnode(kernel32_idb, ROOT_NODEID)
    assert root.name() == ROOT_NODEID

    nn = idb.netnode.Netnode(kernel32_idb, 0x401000)
    with pytest.raises(KeyError):
        _ = nn.name()


@kern32_test()
def test_valobj(kernel32_idb, version, bitness, expected):
    # In[29]:  idaapi.netnode("Root Node").valobj()
    # Out[29]: 'Z:\\home\\user\\Downloads\\kernel32\\kernel32.dll\x00'
    root = idb.netnode.Netnode(kernel32_idb, ROOT_NODEID)
    assert root.value_exists() is True
    assert root.valobj().endswith(b'kernel32.dll\x00')
    assert root.valstr().endswith('kernel32.dll')


@kern32_test([
    (695, 32, [1, 2, 65, 66, 1300, 1301, 1302, 1303, 1305, 1349, 4307348]),
    (695, 64, [1, 2, 65, 66, 1300, 1301, 1302, 1303, 1305, 1349, 4307348]),
    (700, 32, [1, 2, 65, 66, 1300, 1301, 1302, 1303, 1305, 1349, 1352, 4307348]),
    (700, 64, [1, 2, 65, 66, 1300, 1301, 1302, 1303, 1305, 1349, 1352, 4307348]),
])
def test_sups(kernel32_idb, version, bitness, expected):
    root = idb.netnode.Netnode(kernel32_idb, ROOT_NODEID)
    assert list(root.sups()) == expected


@kern32_test()
def test_alts(kernel32_idb, version, bitness, expected):
    root = idb.netnode.Netnode(kernel32_idb, ROOT_NODEID)
    assert list(root.alts()) == [-8, -6, -5, -4, -3, -2, -1]


# the small netnode has a root btree node with a single child.
# this is a little tricky to handle, so we ensure it works as expected.
def test_small(small_idb):
    root = idb.netnode.Netnode(small_idb, ROOT_NODEID)
    assert list(root.alts()) == [-8, -5, -4, -3, -2, -1]
