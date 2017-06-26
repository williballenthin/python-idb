from fixtures import *

import datetime
import binascii


def test_name(kernel32_idb):
    root = kernel32_idb.netnode('Root Node')
    assert root.name() == 'Root Node'

    nn = kernel32_idb.netnode(0x401000)
    assert nn.name() == ''


def test_root_node(kernel32_idb):
    root = kernel32_idb.netnode('Root Node')
    assert root is not None

    root = root.deref()
    assert root is not None

    assert root.altval(idb.netnode.ROOT_INDEX.VERSION) == 695
    assert root.supstr(idb.netnode.ROOT_INDEX.VERSION_STRING) == '6.95'
    assert root.altval(idb.netnode.ROOT_INDEX.OPEN_COUNT) == 1

    ts = root.altval(idb.netnode.ROOT_INDEX.CREATED)
    ts = datetime.datetime.utcfromtimestamp(ts)
    assert ts.isoformat() == '2017-06-20T22:31:34'

    assert root.altval(idb.netnode.ROOT_INDEX.CRC) == 0xdf9bdf12

    md5 = root.supval(idb.netnode.ROOT_INDEX.MD5)
    md5 = binascii.hexlify(md5).decode('ascii')
    assert md5 == '00bf1bf1b779ce1af41371426821e0c2'
