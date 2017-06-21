from fixtures import *

import logging
#logging.basicConfig(level=logging.DEBUG)


def test_validate(empty_idb, kernel32_idb):
    # should be no ValueErrors here.
    assert empty_idb.validate() is True
    assert kernel32_idb.validate() is True


def test_header(empty_idb):
    assert empty_idb.header.signature == b'IDA1'
    assert empty_idb.header.sig2 == 0xAABBCCDD


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
