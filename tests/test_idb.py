from fixtures import *

import logging
import binascii


#logging.basicConfig(level=logging.DEBUG)


def test_validate(empty_idb, kernel32_idb):
    # should be no ValueErrors here.
    assert empty_idb.validate() is True
    assert kernel32_idb.validate() is True


def test_header(empty_idb):
    assert empty_idb.header.signature == b'IDA1'
    assert empty_idb.header.sig2 == 0xAABBCCDD


def test_id0(kernel32_idb):
    assert kernel32_idb.id0.next_free_offset == 0x30
    assert kernel32_idb.id0.page_size == 0x2000
    assert kernel32_idb.id0.root_page == 0x1
    assert kernel32_idb.id0.record_count == 0x6735b
    assert kernel32_idb.id0.page_count == 0x638

    p1 = kernel32_idb.id0.get_page(0x1)
    for entry in p1.get_entries():
        assert entry.key is not None

    p1.validate()


def test_find_exact_match(kernel32_idb):
    # this is found in the root node, first index
    key = binascii.unhexlify('2e6892663778689c4fb7')
    assert binascii.hexlify(kernel32_idb.id0.find(key).key) == binascii.hexlify(key)
    assert binascii.hexlify(kernel32_idb.id0.find(key).value) == b'13'

    # this is found in the second level, third index
    key = binascii.unhexlify('2e689017765300000009')
    assert binascii.hexlify(kernel32_idb.id0.find(key).key) == binascii.hexlify(key)
    assert binascii.hexlify(kernel32_idb.id0.find(key).value) == b'02'

    # this is found in the root node, last index.
    key = binascii.unhexlify('2eff001bc44e')
    assert binascii.hexlify(kernel32_idb.id0.find(key).key) == binascii.hexlify(key)
    assert binascii.hexlify(kernel32_idb.id0.find(key).value) == b'24204636383931344133462e6c705375624b6579'

    # this is found on a leaf node, first index
    key = binascii.unhexlify('2e6890142c5300001000')
    assert binascii.hexlify(kernel32_idb.id0.find(key).key) == binascii.hexlify(key)
    assert binascii.hexlify(kernel32_idb.id0.find(key).value) == b'01080709'

    # this is found on a leaf node, fourth index
    key = binascii.unhexlify('2e689a288c530000000a')
    assert binascii.hexlify(kernel32_idb.id0.find(key).key) == binascii.hexlify(key)
    assert binascii.hexlify(kernel32_idb.id0.find(key).value) == b'02'

    # this is found on a leaf node, last index
    key = binascii.unhexlify('2e6890157f5300000009')
    assert binascii.hexlify(kernel32_idb.id0.find(key).key) == binascii.hexlify(key)
    assert binascii.hexlify(kernel32_idb.id0.find(key).value) == b'02'


def test_id1(kernel32_idb):
    segments = kernel32_idb.id1.segments
    # collected empirically
    assert len(segments) == 2
    for segment in segments:
        assert segment.bounds.start < segment.bounds.end
    assert segments[0].bounds.start == 0x68901000
    assert segments[1].bounds.start == 0x689DD000

    id1 = kernel32_idb.id1
    assert id1.get_segment(0x68901000).bounds.start == 0x68901000
    assert id1.get_segment(0x68901001).bounds.start == 0x68901000
    assert id1.get_segment(0x689dc000 - 1).bounds.start == 0x68901000
    assert id1.get_next_segment(0x68901000).bounds.start == 0x689DD000
    assert id1.get_flags(0x68901000) == 0x2590
    assert id1.get_byte(0x68901000) == 0x90


def test_nam(kernel32_idb):
    names = kernel32_idb.nam.names()
    # collected empirically
    assert len(names) == 14252
    assert names[0] == 0x68901010
    assert names[-1] == 0x689DE228
