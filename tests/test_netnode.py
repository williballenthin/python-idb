from fixtures import *

import logging
import datetime
import binascii

import idb.netnode


#logging.basicConfig(level=logging.DEBUG)


debug = pytest.mark.skipif(
    not pytest.config.getoption("--rundebug"),
    reason="need --rundebug option to run"
    )


ROOT_NODEID = 'Root Node'


def test_name(kernel32_idb):
    root = idb.netnode.Netnode(kernel32_idb, ROOT_NODEID)
    assert root.name() == ROOT_NODEID

    nn = idb.netnode.Netnode(kernel32_idb, 0x401000)
    with pytest.raises(KeyError):
        _ = nn.name()


def test_valobj(kernel32_idb):
    # In[29]:  idaapi.netnode("Root Node").valobj()
    # Out[29]: 'Z:\\home\\user\\Downloads\\kernel32\\kernel32.dll\x00'
    root = idb.netnode.Netnode(kernel32_idb, ROOT_NODEID)
    assert root.value_exists() == True
    assert root.valobj() == b'Z:\\home\\user\\Documents\\code\\python-idb\\tests\\data\\kernel32\\kernel32.dll\x00'
    assert root.valstr() == 'Z:\\home\\user\\Documents\\code\\python-idb\\tests\\data\\kernel32\\kernel32.dll'


def test_sups(kernel32_idb):
    root = idb.netnode.Netnode(kernel32_idb, ROOT_NODEID)
    assert list(root.sups()) == [1, 2, 65, 66, 1300, 1301, 1302, 1303, 1305, 1349, 4307348]


def test_alts(kernel32_idb):
    root = idb.netnode.Netnode(kernel32_idb, ROOT_NODEID)
    assert list(root.alts()) == [-8, -6, -5, -4, -3, -2, -1]
