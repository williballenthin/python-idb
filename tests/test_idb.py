import binascii

import idb.fileformat
import idb.netnode
from fixtures import *


def h2b(somehex):
    """
    convert the given hex string into bytes.

    binascii.unhexlify is many more characters to type :-).
    """
    return binascii.unhexlify(somehex)


def b2h(somebytes):
    """
    convert the given bytes into a hex *string*.

    binascii.hexlify returns a bytes, which is slightly annoying.
    also, its many more characters to type.
    """
    return binascii.hexlify(somebytes).decode("ascii")


def h(number):
    """
    convert a number to a hex representation, with no leading '0x'.

    Example::

        assert h(16)   == '10'
        assert hex(16) == '0x10'
    """
    return "%02x" % number


@kern32_test(
    [(695, 32, 4), (695, 64, 8), (700, 32, 4), (700, 64, 8),]
)
def test_wordsize(kernel32_idb, version, bitness, expected):
    assert kernel32_idb.wordsize == expected


@kern32_test(
    [(695, 32, None), (695, 64, None), (700, 32, None), (700, 64, None),]
)
def test_validate(kernel32_idb, version, bitness, expected):
    # should be no ValueErrors here.
    assert kernel32_idb.validate() is True


def do_test_compressed(db):
    for section in db.sections:
        if section is None:
            continue
        assert section.header.is_compressed is True
        assert (
            section.header.compression_method == idb.fileformat.COMPRESSION_METHOD.ZLIB
        )

    # should be no ValueErrors here.
    assert db.validate() is True


def test_compressed(compressed_idb, compressed_i64):
    do_test_compressed(compressed_idb)
    do_test_compressed(compressed_i64)


@kern32_test(
    [(695, 32, b"IDA1"), (695, 64, b"IDA2"), (700, 32, b"IDA1"), (700, 64, b"IDA2"),]
)
def test_header_magic(kernel32_idb, version, bitness, expected):
    assert kernel32_idb.header.signature == expected
    assert kernel32_idb.header.sig2 == 0xAABBCCDD


@kern32_test(
    [(695, 32, 0x2000), (695, 64, 0x2000), (700, 32, 0x2000), (700, 64, 0x2000),]
)
def test_id0_page_size(kernel32_idb, version, bitness, expected):
    assert kernel32_idb.id0.page_size == expected


@kern32_test(
    [(695, 32, 0x1), (695, 64, 0x1), (700, 32, 0x1), (700, 64, 0x1),]
)
def test_id0_root_page(kernel32_idb, version, bitness, expected):
    assert kernel32_idb.id0.root_page == expected


@kern32_test(
    [
        # collected empirically
        (695, 32, 1592),
        (695, 64, 1979),
        (700, 32, 1566),
        (700, 64, 1884),
    ]
)
def test_id0_page_count(kernel32_idb, version, bitness, expected):
    assert kernel32_idb.id0.page_count == expected


@kern32_test(
    [
        # collected empirically
        (695, 32, 422747),
        (695, 64, 422753),
        (700, 32, 426644),
        (700, 64, 426647),
    ]
)
def test_id0_record_count(kernel32_idb, version, bitness, expected):
    assert kernel32_idb.id0.record_count == expected


@kern32_test(
    [(695, 32, None), (695, 64, None), (700, 32, None), (700, 64, None),]
)
def test_id0_root_entries(kernel32_idb, version, bitness, expected):
    """
    Args:
      expected: ignored
    """
    for entry in kernel32_idb.id0.get_page(kernel32_idb.id0.root_page).get_entries():
        assert entry.key is not None


@kern32_test(
    [
        (695, 32, "24204d4158204c494e4b"),
        (695, 64, "24204d4158204c494e4b"),
        (700, 32, "24204d4158204c494e4b"),
        (700, 64, "24204d4158204c494e4b"),
    ]
)
def test_cursor_min(kernel32_idb, version, bitness, expected):
    # test cursor movement from min key
    # min leaf keys:
    #   24204d4158204c494e4b
    #   24204d4158204e4f4445
    #   24204e45542044455343
    #   2e0000000044689ae208
    minkey = kernel32_idb.id0.get_min().key
    assert minkey == h2b(expected)

    cursor = kernel32_idb.id0.find(minkey)
    cursor.next()
    assert b2h(cursor.key) == "24204d4158204e4f4445"
    cursor.prev()
    assert b2h(cursor.key) == "24204d4158204c494e4b"
    with pytest.raises(IndexError):
        cursor.prev()


@kern32_test(
    [
        (695, 32, "4e776373737472"),
        (695, 64, "4e776373737472"),
        (700, 32, "4e776373737472"),
        (700, 64, "4e776373737472"),
    ]
)
def test_cursor_max(kernel32_idb, version, bitness, expected):
    # test cursor movement from max key
    # max leaf keys:
    #   4e7763736e636d70
    #   4e7763736e637079
    #   4e7763736e6370795f73
    #   4e77637372636872
    #   4e776373737472
    maxkey = kernel32_idb.id0.get_max().key
    assert maxkey == h2b(expected)

    cursor = kernel32_idb.id0.find(maxkey)
    cursor.prev()
    assert b2h(cursor.key) == "4e77637372636872"
    cursor.next()
    assert b2h(cursor.key) == "4e776373737472"
    with pytest.raises(IndexError):
        cursor.next()


@kern32_test(
    [(695, 32, None), (700, 32, None),]
)
def test_find_exact_match1(kernel32_idb, version, bitness, expected):
    # this is found in the root node, first index
    key = h2b("2e6892663778689c4fb7")
    assert kernel32_idb.id0.find(key).key == key
    assert b2h(kernel32_idb.id0.find(key).value) == "13"


@kern32_test(
    [(695, 32, None), (700, 32, None),]
)
def test_find_exact_match2(kernel32_idb, version, bitness, expected):
    # this is found in the second level, third index
    key = h2b("2e689017765300000009")
    assert kernel32_idb.id0.find(key).key == key
    assert b2h(kernel32_idb.id0.find(key).value) == "02"


@kern32_test(
    [
        (695, 32, "24204636383931344133462e6c705375624b6579"),
        (700, 32, "24204636383931344132452e6c705265736572766564"),
    ]
)
def test_find_exact_match3(kernel32_idb, version, bitness, expected):
    # this is found in the root node, last index.
    key = h2b("2eff001bc44e")
    assert kernel32_idb.id0.find(key).key == key
    assert b2h(kernel32_idb.id0.find(key).value) == expected


@kern32_test(
    [(695, 32, None), (700, 32, None),]
)
def test_find_exact_match4(kernel32_idb, version, bitness, expected):
    # this is found on a leaf node, first index
    key = h2b("2e6890142c5300001000")
    assert kernel32_idb.id0.find(key).key == key
    assert b2h(kernel32_idb.id0.find(key).value) == "01080709"


@kern32_test(
    [(695, 32, None), (700, 32, None),]
)
def test_find_exact_match5(kernel32_idb, version, bitness, expected):
    # this is found on a leaf node, fourth index
    key = h2b("2e689a288c530000000a")
    assert kernel32_idb.id0.find(key).key == key
    assert b2h(kernel32_idb.id0.find(key).value) == "02"


@kern32_test(
    [(695, 32, None), (700, 32, None),]
)
def test_find_exact_match6(kernel32_idb, version, bitness, expected):
    # this is found on a leaf node, last index
    key = h2b("2e6890157f5300000009")
    assert kernel32_idb.id0.find(key).key == key
    assert b2h(kernel32_idb.id0.find(key).value) == "02"


@kern32_test()
def test_find_exact_match_min(kernel32_idb, version, bitness, expected):
    minkey = h2b("24204d4158204c494e4b")
    assert kernel32_idb.id0.find(minkey).key == minkey


@kern32_test()
def test_find_exact_match_max(kernel32_idb, version, bitness, expected):
    if version <= 700:
        maxkey = h2b("4e776373737472")
        assert kernel32_idb.id0.find(maxkey).key == maxkey


@kern32_test()
def test_find_exact_match_error(kernel32_idb, version, bitness, expected):
    # check our error handling
    with pytest.raises(KeyError):
        kernel32_idb.id0.find(b"does not exist!")


@kern32_test([(695, 32, None)])
def test_find_prefix(kernel32_idb, version, bitness, expected):
    # nodeid: ff000006 ($fixups)
    fixup_nodeid = "2eff000006"
    key = h2b(fixup_nodeid)

    # the first match is the N (name) tag
    cursor = kernel32_idb.id0.find_prefix(key)
    assert b2h(cursor.key) == fixup_nodeid + h(ord("N"))

    # nodeid: ff000006 ($fixups) tag: S
    supvals = fixup_nodeid + h(ord("S"))
    key = h2b(supvals)

    # the first match is for index 0x68901025
    cursor = kernel32_idb.id0.find_prefix(key)
    assert b2h(cursor.key) == fixup_nodeid + h(ord("S")) + "68901025"

    with pytest.raises(KeyError):
        cursor = kernel32_idb.id0.find_prefix(b"does not exist")


@kern32_test()
def test_find_prefix2(kernel32_idb, version, bitness, expected):
    """
    this test is derived from some issues encountered while doing import analysis.
    ultimately, we're checking prefix matching when the first match is found
     in a branch node.
    """
    impnn = idb.netnode.Netnode(kernel32_idb, "$ imports")

    expected_alts = list(range(0x30))
    expected_alts.append(kernel32_idb.uint(-1))
    assert list(impnn.alts()) == expected_alts
    assert list(impnn.sups()) == list(range(0x30))

    # capture the number of supvals in each netnode referenced from the import netnode
    dist = []
    for alt in impnn.alts():
        if alt == kernel32_idb.uint(-1):
            break

        ref = idb.netnode.as_uint(impnn.get_val(alt, tag="A"))
        nn = idb.netnode.Netnode(kernel32_idb, ref)
        dist.append((alt, len(list(nn.sups()))))

    # this distribution was collected empirically.
    # the import analysis is correct (verified in IDA), so by extension, this should be correct as well.
    assert dist == [
        (0, 4),
        (1, 388),
        (2, 77),
        (3, 50),
        (4, 42),
        (5, 13),
        (6, 28),
        (7, 4),
        (8, 33),
        (9, 68),
        (10, 1),
        (11, 9),
        (12, 1),
        (13, 7),
        (14, 1),
        (15, 24),
        (16, 9),
        (17, 6),
        (18, 26),
        (19, 9),
        (20, 54),
        (21, 24),
        (22, 8),
        (23, 9),
        (24, 7),
        (25, 5),
        (26, 1),
        (27, 2),
        (28, 26),
        (29, 1),
        (30, 18),
        (31, 5),
        (32, 3),
        (33, 2),
        (34, 3),
        (35, 6),
        (36, 11),
        (37, 11),
        (38, 5),
        (39, 6),
        (40, 11),
        (41, 7),
        (42, 10),
        (43, 14),
        (44, 38),
        (45, 16),
        (46, 6),
        (47, 7),
    ]


@kern32_test([(695, 32, None)])
def test_cursor_easy_leaf(kernel32_idb, version, bitness, expected):
    # this is found on a leaf, second to last index.
    # here's the surrounding layout:
    #
    #      00:00: 2eff00002253689cc95b = ff689cc95b40ff8000c00bd30201
    #    > 00:01: 2eff00002253689cc99b = ff689cc99b32ff8000c00be35101
    #      00:00: 2eff00002253689cc9cd = ff689cc9cd2bff8000c00be12f01
    key = h2b("2eff00002253689cc99b")
    cursor = kernel32_idb.id0.find(key)

    cursor.next()
    assert b2h(cursor.key) == "2eff00002253689cc9cd"

    cursor.prev()
    cursor.prev()
    assert b2h(cursor.key) == "2eff00002253689cc95b"


@kern32_test([(695, 32, None)])
def test_cursor_branch(kernel32_idb, version, bitness, expected):
    # starting at a key that is found in a branch node, test next and prev.
    # these should traverse to leaf nodes and pick the min/max entries, respectively.
    #
    #   576 contents (branch):
    #     ...
    #     000638: 2eff00002253689b9535 = ff689b953573ff441098aa0c040c16000000000000
    #   > 000639: 2eff00002253689bea8e = ff689bea8e8257ff8000c00aa2c601
    #     00000e: 2eff00002253689ccaf1 = ff689ccaf113ff8000c00be25301
    #     ...
    #
    #   638 contents (leaf):
    #     00:00: 2eff00002253689b95db = ff689b95db54ff441098ad08040c14000000000000
    #     00:01: 2eff00002253689b9665 = ff689b96655bff441098b008040815000000000000
    #     00:00: 2eff00002253689b970f = ff689b970f808bff441098b30804141f000000000000
    #     ...
    #     00:01: 2eff00002253689be79b = ff689be79b1bff8000c00a9d4b01
    #     00:00: 2eff00002253689be7b6 = ff689be7b68270ff8000c00af6a101
    #   > 00:00: 2eff00002253689bea26 = ff689bea2668ff8000c00a9f4301
    #
    #
    #   639 contents (leaf):
    #   > 00:00: 2eff00002253689bece5 = ff689bece514ff8000c00bc6b701
    #     00:00: 2eff00002253689becf9 = ff689becf942ff8000c008cf9e01
    #     00:00: 2eff00002253689bed3b = ff689bed3b42ff8000c0090b9c01
    #     ...
    #     00:00: 2eff00002253689cc95b = ff689cc95b40ff8000c00bd30201
    #     00:01: 2eff00002253689cc99b = ff689cc99b32ff8000c00be35101
    #     00:00: 2eff00002253689cc9cd = ff689cc9cd2bff8000c00be12f01

    key = h2b("2eff00002253689bea8e")
    cursor = kernel32_idb.id0.find(key)
    cursor.next()
    assert b2h(cursor.key) == "2eff00002253689bece5"

    key = h2b("2eff00002253689bea8e")
    cursor = kernel32_idb.id0.find(key)
    cursor.prev()
    assert b2h(cursor.key) == "2eff00002253689bea26"


@kern32_test([(695, 32, None)])
def test_cursor_complex_leaf_next(kernel32_idb, version, bitness, expected):
    # see the scenario in `test_cursor_branch`.
    key = h2b("2eff00002253689bea26")
    cursor = kernel32_idb.id0.find(key)
    cursor.next()
    assert b2h(cursor.key) == "2eff00002253689bea8e"


@kern32_test([(695, 32, None)])
def test_cursor_complex_leaf_prev(kernel32_idb, version, bitness, expected):
    # see the scenario in `test_cursor_branch`.
    key = h2b("2eff00002253689bece5")
    cursor = kernel32_idb.id0.find(key)
    cursor.prev()
    assert b2h(cursor.key) == "2eff00002253689bea8e"


@pytest.mark.slow
@kern32_test()
def test_cursor_enum_all_asc(kernel32_idb, version, bitness, expected):
    minkey = kernel32_idb.id0.get_min().key
    cursor = kernel32_idb.id0.find(minkey)
    count = 1
    while True:
        try:
            cursor.next()
        except IndexError:
            break
        count += 1

    assert kernel32_idb.id0.record_count == count


@pytest.mark.slow
@kern32_test()
def test_cursor_enum_all_desc(kernel32_idb, version, bitness, expected):
    maxkey = kernel32_idb.id0.get_max().key
    cursor = kernel32_idb.id0.find(maxkey)
    count = 1
    while True:
        try:
            cursor.prev()
        except IndexError:
            break
        count += 1

    assert kernel32_idb.id0.record_count == count


@kern32_test(
    [(695, 32, None), (695, 64, None), (700, 32, None), (700, 64, None),]
)
def test_id1(kernel32_idb, version, bitness, expected):
    id1 = kernel32_idb.id1
    segments = id1.segments

    # collected empirically
    assert len(segments) == 2
    for segment in segments:
        assert segment.bounds.start < segment.bounds.end
    assert segments[0].bounds.start == 0x68901000
    assert segments[1].bounds.start == 0x689DD000

    assert id1.get_segment(0x68901000).bounds.start == 0x68901000
    assert id1.get_segment(0x68901001).bounds.start == 0x68901000
    assert id1.get_segment(0x689DC000 - 1).bounds.start == 0x68901000
    assert id1.get_next_segment(0x68901000).bounds.start == 0x689DD000
    assert id1.get_flags(0x68901000) == 0x2590


def test_id1_2(elf_idb):
    assert list(map(lambda s: s.offset, elf_idb.id1.segments)) == [
        0x0,
        0x8C,
        0x1CEC,
        0x47E4C,
        0x7382C,
        0x7385C,
        0x73F9C,
    ]


@kern32_test(
    [
        # collected empirically
        (695, 32, 14252),
        (695, 64, 14252),
        (700, 32, 14247),
        (700, 64, 14247),
    ]
)
def test_nam_name_count(kernel32_idb, version, bitness, expected):
    assert kernel32_idb.nam.name_count == expected


@kern32_test(
    [
        # collected empirically
        (695, 32, 8),
        (695, 64, 15),
        (700, 32, 8),
        (700, 64, 15),
    ]
)
def test_nam_page_count(kernel32_idb, version, bitness, expected):
    assert kernel32_idb.nam.page_count == expected

    nam = kernel32_idb.nam
    if bitness == 32:
        assert nam.name_count < len(nam.buffer)
    elif bitness == 64:
        assert nam.name_count < len(nam.buffer)


@kern32_test(
    [
        # collected empirically
        (695, 32, 14252),
        (695, 64, 14252),
        (700, 32, 14247),
        (700, 64, 14247),
    ]
)
def test_nam_names(kernel32_idb, version, bitness, expected):
    names = kernel32_idb.nam.names()
    assert len(names) == expected
    assert names[0] == 0x68901010
    assert names[-1] == 0x689DE228


@kern32_test(
    [(695, 32, None), (695, 64, None), (700, 32, None), (700, 64, None),]
)
def test_til(kernel32_idb, version, bitness, expected):
    til = kernel32_idb.til

    assert til.signature == "IDATIL"

    assert til.size_i == 4
    assert til.size_b == 1
    assert til.size_e == 4

    syms = til.syms.defs
    types = til.types.defs

    assert len(types) == 106
    assert len(syms) == 61

    # 1	GUID	typedef _GUID
    assert types[0].name == "GUID"
    # 2
    # struct _GUID
    # {
    #   unsigned __int32 Data1;
    #   unsigned __int16 Data2;
    #   unsigned __int16 Data3;
    #   unsigned __int8 Data4[8];
    # };
    assert types[1].name == "_GUID"
    assert types[1].fields == ["Data1", "Data2", "Data3", "Data4"]
    # TODO: don't known how to use the type_info field
    # assert types[0].type_info == '\x0d!$##\x1b\x09"'

    # 5	JOBOBJECTINFOCLASS	typedef _JOBOBJECTINFOCLASS
    assert types[4].name == "JOBOBJECTINFOCLASS"
    # 6
    # enum _JOBOBJECTINFOCLASS
    # {
    #   JobObjectBasicAccountingInformation = 0x1,
    #   JobObjectBasicLimitInformation = 0x2,
    #   JobObjectBasicProcessIdList = 0x3,
    #   JobObjectBasicUIRestrictions = 0x4,
    #   JobObjectSecurityLimitInformation = 0x5,
    #   JobObjectEndOfJobTimeInformation = 0x6,
    #   JobObjectAssociateCompletionPortInformation = 0x7,
    #   MaxJobObjectInfoClass = 0x8,
    # };
    assert types[5].name == "_JOBOBJECTINFOCLASS"
    assert types[5].fields == [
        "JobObjectBasicAccountingInformation",
        "JobObjectBasicLimitInformation",
        "JobObjectBasicProcessIdList",
        "JobObjectBasicUIRestrictions",
        "JobObjectSecurityLimitInformation",
        "JobObjectEndOfJobTimeInformation",
        "JobObjectAssociateCompletionPortInformation",
        "MaxJobObjectInfoClass",
    ]

    assert syms[0].name == "JobObjectBasicAccountingInformation"
    assert syms[1].name == "JobObjectBasicLimitInformation"
    assert syms[2].name == "JobObjectBasicProcessIdList"
    assert syms[3].name == "JobObjectBasicUIRestrictions"
    assert syms[4].name == "JobObjectSecurityLimitInformation"
    assert syms[5].name == "JobObjectEndOfJobTimeInformation"
    assert syms[6].name == "JobObjectAssociateCompletionPortInformation"
    assert syms[7].name == "MaxJobObjectInfoClass"

    assert syms[0].ordinal == 0x1
    assert syms[1].ordinal == 0x2
    assert syms[2].ordinal == 0x3
    assert syms[3].ordinal == 0x4
    assert syms[4].ordinal == 0x5
    assert syms[5].ordinal == 0x6
    assert syms[6].ordinal == 0x7
    assert syms[7].ordinal == 0x8

    assert syms[0].type_info == b"=\x14_JOBOBJECTINFOCLASS"
    assert syms[1].type_info == b"=\x14_JOBOBJECTINFOCLASS"
    assert syms[2].type_info == b"=\x14_JOBOBJECTINFOCLASS"
    assert syms[3].type_info == b"=\x14_JOBOBJECTINFOCLASS"
    assert syms[4].type_info == b"=\x14_JOBOBJECTINFOCLASS"
    assert syms[5].type_info == b"=\x14_JOBOBJECTINFOCLASS"
    assert syms[6].type_info == b"=\x14_JOBOBJECTINFOCLASS"
    assert syms[7].type_info == b"=\x14_JOBOBJECTINFOCLASS"

    # 59	ULARGE_INTEGER	typedef _ULARGE_INTEGER
    assert types[58].name == "ULARGE_INTEGER"
    # 60
    # union _ULARGE_INTEGER
    # {
    #   struct
    #   {
    #     DWORD LowPart;
    #     DWORD HighPart;
    #   };
    #   _ULARGE_INTEGER::$0354AA9C204208F00D0965D07BBE7FAC u;
    #   ULONGLONG QuadPart;
    # };
    assert types[59].name == "_ULARGE_INTEGER"
    assert types[59].fields == [
        "u",
        "QuadPart",
    ]
    # 61
    # struct _ULARGE_INTEGER::$0354AA9C204208F00D0965D07BBE7FAC
    # {
    #   DWORD LowPart;
    #   DWORD HighPart;
    # };
    assert types[60].name == "_ULARGE_INTEGER::$0354AA9C204208F00D0965D07BBE7FAC"
    assert types[60].fields == [
        "LowPart",
        "HighPart",
    ]


def test_til_affix():
    cd = os.path.dirname(__file__)
    idbpath = os.path.join(cd, "data", "til", "TILTest.dll.i64")
    with idb.from_file(idbpath) as db:
        til = db.til
        assert til.signature == "IDATIL"
        assert til.size_i == 4
        assert til.size_b == 1
        assert til.size_e == 4

        syms = til.syms.defs
        types = til.types.defs

        # 24
        # class Base {
        # public:
        #     Base(const int32_t field0, const int32_t field1, const int32_t field2)
        #             : field0_{field0},
        #               field1_{field1},
        #               field2_{field2} {
        #     }
        #
        #     int32_t field0_, field1_, field2_;
        #
        #     int32_t foo() const { return field0_ + field1_; }
        #
        #     int32_t bar() const { return field1_ + field2_; }
        # };
        base = types[23]
        assert base.name == "Base"
        assert base.fields == [
            "field0_",
            "field1_",
            "field2_",
        ]

        assert base.type.is_struct()
        base_members = base.type.type_details.members
        assert base_members[0].type.is_int()
        assert base_members[1].type.is_int()
        assert base_members[2].type.is_int()

        # 25
        # class Derive : Base {
        # public:
        #     Derive(const int32_t field0, const int32_t field1, const int32_t field2, int32_t field3, int32_t field4,
        #            int32_t field5) : Base(field0, field1, field2), field3_(field3), field4_(field4), field5_(field5) {}
        #
        #     int32_t field3_, field4_, field5_;
        # };
        derive = types[24]
        assert derive.name == "Derive"
        assert derive.fields == [
            "field3_",
            "field4_",
            "field5_",
        ]

        assert derive.type.is_struct()
        derive_members = derive.type.type_details.members
        assert derive_members[0].is_baseclass()
        assert (
            derive_members[0].type.get_final_tinfo().get_name() == base.type.get_name()
        )

        assert derive_members[1].type.is_int()
        assert derive_members[2].type.is_int()
        assert derive_members[3].type.is_int()

        # struct Outside {
        #     struct {
        #         std::string field0, field1, field2;
        #     } inside;
        #
        #     std::string foo;
        #     std::string bar;
        # };

        # 34
        t34 = types[33]
        assert t34.name == "Outside::<unnamed_type_inside>"
        assert t34.fields == [
            "field0",
            "field1",
            "field2",
        ]
        assert t34.type.is_struct()

        # 35
        t35 = types[34]
        assert t35.name == "Outside"
        assert t35.fields == [
            "inside",
            "foo",
            "bar",
        ]
        assert t35.type.is_struct()
        members = t35.type.type_details.members
        assert members[0].type.get_final_tinfo().is_struct()

        # class Sorter {
        # public:
        #     virtual int compare(const void *first, const void *second) = 0;
        # };

        # 52
        t52 = types[51]
        assert t52.name == "Sorter"
        assert t52.fields == [
            "__vftable",
        ]
        assert t52.type.is_struct()
        t52_typ = t52.type.type_details.members[0].type
        assert t52_typ.is_ptr()
        assert t52_typ.get_pointed_object().is_decl_typedef()
        assert t52_typ.get_pointed_object().get_final_tinfo().is_struct()
        # 53
        t53 = types[52]
        assert t53.name == "Sorter_vtbl"
        assert t53.fields == [
            "compare",
            "this",
        ]
        assert t53.type.is_struct()

        # 209
        # PTP_CLEANUP_GROUP_CANCEL_CALLBACK typedef void (__fastcall *)(void *, void *)
        #
        t209 = types[208]
        assert t209.name == "PTP_CLEANUP_GROUP_CANCEL_CALLBACK"
        assert t209.type.is_funcptr()
        assert (
            t209.type.get_typestr()
            == "void (__fastcall *PTP_CLEANUP_GROUP_CANCEL_CALLBACK)(void*, void*)"
        )

        # 79
        # _TP_CALLBACK_ENVIRON_V3::<unnamed_type_u>::<unnamed_type_s>
        # struct
        # {
        #   unsigned __int32 LongFunction : 1;
        #   unsigned __int32 Persistent : 1;
        #   unsigned __int32 Private : 30;
        # }
        assert (
            types[78].type.get_typestr()
            == """struct _TP_CALLBACK_ENVIRON_V3::<unnamed_type_u>::<unnamed_type_s>
{
  unsigned int32 LongFunction : 1;
  unsigned int32 Persistent : 1;
  unsigned int32 Private : 30;
}"""
        )

        # 115
        # _TypeDescriptor
        # struct
        # {
        #   const void *pVFTable;
        #   void *spare;
        #   char name[];
        # }
        assert (
            types[114].type.get_typestr()
            == """struct _TypeDescriptor
{
  void* pVFTable;
  void* spare;
  int8[] name;
}"""
        )
