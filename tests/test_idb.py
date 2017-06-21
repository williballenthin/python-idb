from fixtures import *


def test_validate(empty_idb):
    # should be no ValueErrors here.
    assert empty_idb.validate() is True


def test_header(empty_idb):
    assert empty_idb.header.signature == b'IDA1'
    assert empty_idb.header.sig2 == 0xAABBCCDD


def test_section_contents(empty_idb):
    assert empty_idb.section_id0.contents[0x13:0x1C] == b'B-tree v2'
    assert empty_idb.section_id1.contents[:0x3] == b'VA*'
    assert empty_idb.section_nam.contents[:0x3] == b'VA*'
    assert empty_idb.section_til.contents[:0x6] == b'IDATIL'
