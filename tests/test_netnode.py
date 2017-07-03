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


def test_name(kernel32_idb):
    root = idb.netnode.Netnode(kernel32_idb, idb.netnode.ROOT_NODEID)
    assert root.name() == idb.netnode.ROOT_NODEID

    nn = idb.netnode.Netnode(kernel32_idb, 0x401000)
    with pytest.raises(KeyError):
        _ = nn.name()


def test_valobj(kernel32_idb):
    # In[29]:  idaapi.netnode("Root Node").valobj()
    # Out[29]: 'Z:\\home\\user\\Downloads\\kernel32\\kernel32.dll\x00'
    root = idb.netnode.Netnode(kernel32_idb, idb.netnode.ROOT_NODEID)
    assert root.value_exists() == True
    assert root.valobj() == b'Z:\\home\\user\\Documents\\code\\python-idb\\tests\\data\\kernel32\\kernel32.dll\x00'
    assert root.valstr() == 'Z:\\home\\user\\Documents\\code\\python-idb\\tests\\data\\kernel32\\kernel32.dll'


def test_root_node(kernel32_idb):
    '''
    see also test_analysis for a higher-level interface.
    '''
    root = idb.netnode.Netnode(kernel32_idb, idb.netnode.ROOT_NODEID)
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


def test_sups(kernel32_idb):
    root = idb.netnode.Netnode(kernel32_idb, idb.netnode.ROOT_NODEID)
    assert list(root.sups()) == [1, 2, 65, 66, 1300, 1301, 1302, 1303, 1305, 1349, 4307348]


def test_alts(kernel32_idb):
    root = idb.netnode.Netnode(kernel32_idb, idb.netnode.ROOT_NODEID)
    assert list(root.alts()) == [-8, -6, -5, -4, -3, -2, -1]


def test_loader(kernel32_idb):
    '''
    see also test_analysis for a higher-level interface.
    '''
    loader = idb.netnode.Netnode(kernel32_idb, idb.netnode.LOADER_NODEID)
    assert loader is not None

    assert loader.supval(idb.netnode.LOADER_INDEX.PLUGIN) == b'pe.ldw\x00'
    assert loader.supval(idb.netnode.LOADER_INDEX.FORMAT).startswith(b'Portable executable')


@debug
def test_all_the_values(kernel32_idb):
    # this is primarily to demonstrate what the btree keys and values look like.

    minkey = binascii.unhexlify('24204d4158204c494e4b')
    cursor = kernel32_idb.id0.find(minkey)

    import hexdump
    while True:
        if cursor.key[0] == 0x2E:
            k = idb.netnode.parse_key(cursor.key)
            print('nodeid: %x tag: %s index: %s' % (
                k.nodeid,
                k.tag,
                hex(k.index) if k.index is not None else 'None'))
        else:
            hexdump.hexdump(cursor.key)

        hexdump.hexdump(bytes(cursor.value))
        print('--')

        try:
            cursor.next()
        except IndexError:
            break


