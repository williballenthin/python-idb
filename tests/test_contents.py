from fixtures import *

import datetime
import binascii

import idb.netnode


def atest_root(kernel32_idb):
    root = idb.netnode.get_nodeid(kernel32_idb, 'Root Node')
    assert idb.netnode.get_int(kernel32_idb, root, 'A', idb.netnode.ROOT_INDEX.VERSION) == 695
    assert idb.netnode.get_string(kernel32_idb, root, 'S', idb.netnode.ROOT_INDEX.VERSION_STRING) == '6.95'
    assert idb.netnode.get_int(kernel32_idb, root, 'A', idb.netnode.ROOT_INDEX.OPEN_COUNT) == 1
    ts = idb.netnode.get_int(kernel32_idb, root, 'A', idb.netnode.ROOT_INDEX.CREATED)
    ts = datetime.datetime.utcfromtimestamp(ts)
    assert ts.isoformat() == '2017-06-20T22:31:34'
    assert idb.netnode.get_int(kernel32_idb, root, 'A', idb.netnode.ROOT_INDEX.CRC) == 0xdf9bdf12
    md5 = idb.netnode.get_bytes(kernel32_idb, root, 'S', idb.netnode.ROOT_INDEX.MD5)
    md5 = binascii.hexlify(md5).decode('ascii')
    assert md5 == '00bf1bf1b779ce1af41371426821e0c2'
