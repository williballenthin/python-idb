import idb.netnode
from fixtures import *

debug = pytest.mark.skipif(not rundebug, reason="need --rundebug option to run")

ROOT_NODEID = "Root Node"


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
    if version >= 740 or version == 500:
        assert root.valobj().endswith(
            b"ba1bc09b7bb290656582b4e4d896105caf00825b557ce45621e76741cd5dc262\x00"
        )
        assert root.valstr().endswith(
            "ba1bc09b7bb290656582b4e4d896105caf00825b557ce45621e76741cd5dc262"
        )
    else:
        assert root.valobj().endswith(b"kernel32.dll\x00")
        assert root.valstr().endswith("kernel32.dll")


@kern32_test(
    [
        (695, 32, [1, 2, 65, 66, 1300, 1301, 1302, 1303, 1305, 1349, 4307348]),
        (695, 64, [1, 2, 65, 66, 1300, 1301, 1302, 1303, 1305, 1349, 4307348]),
        (700, 32, [1, 2, 65, 66, 1300, 1301, 1302, 1303, 1305, 1349, 1352, 4307348]),
        (700, 64, [1, 2, 65, 66, 1300, 1301, 1302, 1303, 1305, 1349, 1352, 4307348]),
    ]
)
def test_sups(kernel32_idb, version, bitness, expected):
    root = idb.netnode.Netnode(kernel32_idb, ROOT_NODEID)
    assert list(root.sups()) == expected


@kern32_test()
def test_alts(kernel32_idb, version, bitness, expected):
    root = idb.netnode.Netnode(kernel32_idb, ROOT_NODEID)
    uint = kernel32_idb.uint
    alts = list(root.alts())
    if version > 680:
        assert alts == [
            uint(-8),
            uint(-6),
            uint(-5),
            uint(-4),
            uint(-3),
            uint(-2),
            uint(-1),
        ]
    elif version >= 630:
        assert alts == [
            uint(-6),
            uint(-5),
            uint(-4),
            uint(-3),
            uint(-2),
            uint(-1),
        ]
    else:
        assert alts == [
            uint(-5),
            uint(-4),
            uint(-3),
            uint(-2),
            uint(-1),
        ]


# the small netnode has a root btree node with a single child.
# this is a little tricky to handle, so we ensure it works as expected.
def test_small(small_idb):
    root = idb.netnode.Netnode(small_idb, ROOT_NODEID)
    uint32 = small_idb.uint
    assert list(root.alts()) == [
        uint32(-8),
        uint32(-5),
        uint32(-4),
        uint32(-3),
        uint32(-2),
        uint32(-1),
    ]
