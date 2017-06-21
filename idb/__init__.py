'''
lots of inspiration from: https://github.com/nlitsme/pyidbutil
'''
import struct
import contextlib
from collections import namedtuple

import vstruct
from vstruct.primitives import v_bytes
from vstruct.primitives import v_uint8
from vstruct.primitives import v_uint16
from vstruct.primitives import v_uint32
from vstruct.primitives import v_uint64


# via: https://github.com/BinaryAnalysisPlatform/qira/blob/master/extra/parseida/parseidb.py
BTREE_PAGE_SIZE = 8192


class FileHeader(vstruct.VStruct):
    def __init__(self):
        vstruct.VStruct.__init__(self)
        self.signature = v_bytes(size=0x4)  # IDA1
        self.unk04 = v_uint32()
        self.unk08 = v_uint32()
        self.unk0C = v_uint32()
        self.unk10 = v_uint32()
        self.unk14 = v_uint32()
        self.unk18 = v_uint16()
        self.sig2  = v_uint32()  # | DD CC BB AA |
        self.unk1E = v_uint16()

        # not exactly the file size
        # smaller than size2?
        self.size1 = v_uint32()
        self.unk24 = v_uint32()
        self.unk28 = v_uint32()
        self.unk2C = v_uint32()

        # not exactly the file size
        # larger than size1?
        self.size2 = v_uint32()
        self.unk34 = v_uint32()

        # changes upon each save
        self.csum1 = v_bytes(size=0x4)
        # does not change upon each save
        self.csum2 = v_bytes(size=0x8)

        self.unk44 = v_uint32()
        self.unk48 = v_uint32()
        self.unk4C = v_uint32()
        self.unk50 = v_uint32()
        self.unk54 = v_uint32()
        self.unk58 = v_uint32()
        self.unk5C = v_uint32()
        self.unk60 = v_bytes(size=0x10)
        self.unk70 = v_bytes(size=0x10)
        self.unk80 = v_bytes(size=0x10)
        self.unk90 = v_bytes(size=0x10)
        self.unkA0 = v_bytes(size=0x10)
        self.unkB0 = v_bytes(size=0x10)
        self.unkC0 = v_bytes(size=0x10)
        self.unkD0 = v_bytes(size=0x10)
        self.unkE0 = v_bytes(size=0x10)
        self.unkF0 = v_bytes(size=0x0D)

    def validate(self):
        if self.signature != b'IDA1':
            raise ValueError('bad signature')
        if self.sig2 != 0xAABBCCDD:
            raise ValueError('bad sig2')
        return True


class Section(vstruct.VStruct):
    def __init__(self):
        vstruct.VStruct.__init__(self)
        self.length = v_uint32()
        self.unk4 = v_uint32()
        self.contents = v_bytes()

    def pcb_length(self):
        self['contents'].vsSetLength(self.length)

    def validate(self):
        if self.length == 0:
            raise ValueError('zero size')
        if self.length != len(self.contents):
            raise ValueError('bad size')
        return True


class ID0(vstruct.VStruct):
    def __init__(self):
        vstruct.VStruct.__init__(self)
        self.unk00 = v_bytes(size=0x10)
        self.unk10 = v_bytes(size=0x03)
        self.signature = v_bytes(size=0x09)

    def validate(self):
        if self.signature != b'B-tree v2':
            raise ValueError('bad signature')
        return True


class SegmentBounds(vstruct.VStruct):
    '''
    specifies the range of a segment.
    '''
    def __init__(self, wordsize=4):
        vstruct.VStruct.__init__(self)

        self.wordsize = wordsize
        if wordsize == 4:
            self.v_word = v_uint32
            self.word_fmt = "I"
        elif wordsize == 8:
            self.v_word = v_uint64
            self.word_fmt = "Q"
        else:
            raise RuntimeError('unexpected wordsize')

        self.start = self.v_word()
        self.end = self.v_word()


class ID1(vstruct.VStruct):
    '''
    contains flags for each byte.
    '''
    PAGE_SIZE = 0x2000

    def __init__(self, wordsize=4):
        vstruct.VStruct.__init__(self)

        self.wordsize = wordsize
        if wordsize == 4:
            self.v_word = v_uint32
            self.word_fmt = "I"
        elif wordsize == 8:
            self.v_word = v_uint64
            self.word_fmt = "Q"
        else:
            raise RuntimeError('unexpected wordsize')

        self.signature = v_bytes(size=0x04)
        self.unk04 = v_uint32()     # 0x3
        self.segment_count = v_uint32()
        self.unk0C = v_uint32()     # 0x800
        self.page_count = v_uint32()
        # varrays are not actually very list-like, so the struct field will be ._segments
        # and the property will be .segments.
        self._segments = vstruct.VArray()
        self.segments = []
        self.padding = v_bytes()
        self.buffer = v_bytes()

    SegmentDescriptor = namedtuple('SegmentDescriptor', ['bounds', 'offset'])

    def pcb_segment_count(self):
        # TODO: pass wordsize
        self['_segments'].vsAddElements(self.segment_count, SegmentBounds)
        offset = 0
        for i in range(self.segment_count):
            segment = self._segments[i]
            offset += 4 * (segment.end - segment.start)
            self.segments.append(ID1.SegmentDescriptor(segment, offset))
        offset = 0x20 + (self.segment_count * (2 * self.wordsize))
        padsize = ID1.PAGE_SIZE - offset + 0xC  # TODO: where does this 0xC come from???
        self['padding'].vsSetLength(padsize)

    def pcb_page_count(self):
        self['buffer'].vsSetLength(ID1.PAGE_SIZE * self.page_count)

    def get_segment(self, ea):
        '''
        find the segment that contains the given effective address.

        Returns:
          SegmentDescriptor: segment metadata and location.

        Raises:
          KeyError: if the given address is not in a segment.
        '''
        for segment in self.segments:
            if segment.bounds.start <= ea < segment.bounds.end:
                return segment
        raise KeyError(ea)

    def get_next_segment(self, ea):
        '''
        Fetch the next segment.

        Arguments:
          ea (int): an effective address that should fall within a segment.

        Returns:
          int: the effective address of the start of a segment.

        Raises:
          IndexError: if no more segments are found after the given segment.
          KeyError: if the given effective address does not fall within a segment.
        '''
        for i, segment in enumerate(self.segments):
            if segment.bounds.start <= ea < segment.bounds.end:
                if i == len(self.segments):
                    # this is the last segment, there are no more.
                    raise IndexError(ea)
                else:
                    # there's at least one more, and that's the next one.
                    return self.segments[i + 1]
        raise KeyError(ea)

    def get_flags(self, ea):
        '''
        Fetch the flags for the given effective address.

        > Each byte of the program has 32-bit flags (low 8 bits keep the byte value).
        > These 32 bits are used in GetFlags/SetFlags functions.
        via: https://www.hex-rays.com/products/ida/support/idapython_docs/idc-module.html

        Arguments:
          ea (int): the effective address.

        Returns:
          int: the flags for the given address.

        Raises:
          KeyError: if the given address does not fall within a segment.
        '''
        seg = self.get_segment(ea)
        offset = seg.offset + 4 * (ea - seg.bounds.start)
        return struct.unpack_from('<I', self.buffer, offset)[0]

    def get_byte(self, ea):
        '''
        Fetch the byte at the given effective address.

        Arguments:
          ea (int): the effective address.

        Returns:
          int: the byte at the given address.

        Raises:
          KeyError: if the given address does not fall within a segment.
        '''
        return self.get_flags(ea) & 0xFF

    def validate(self):
        if self.signature != b'VA*\x00':
            raise ValueError('bad signature')
        if self.unk04 != 0x3:
            raise ValueError('unexpected unk04 value')
        if self.unk0C != 0x800:
            raise ValueError('unexpected unk0C value')
        for segment in self.segments:
            if segment.bounds.start > segment.bounds.end:
                raise ValueError('segment ends before it starts')
        return True



class NAM(vstruct.VStruct):
    '''
    contains pointers to named items.
    '''
    PAGE_SIZE = 0x2000

    def __init__(self, wordsize=4):
        vstruct.VStruct.__init__(self)

        self.wordsize = wordsize
        if wordsize == 4:
            self.v_word = v_uint32
            self.word_fmt = "I"
        elif wordsize == 8:
            self.v_word = v_uint64
            self.word_fmt = "Q"
        else:
            raise RuntimeError('unexpected wordsize')

        self.signature = v_bytes(size=0x04)
        self.unk04 = v_uint32()      # 0x3
        self.non_empty = v_uint32()  # (0x1 non-empty) or (0x0 empty)
        self.unk0C = v_uint32()      # 0x800
        self.page_count = v_uint32()
        self.unk14 = self.v_word()   # 0x0
        self.name_count = v_uint32()
        self.padding = v_bytes(size=NAM.PAGE_SIZE - (6 * 4 + wordsize))
        self.buffer = v_bytes()

    def pcb_page_count(self):
        self['buffer'].vsSetLength(self.page_count * NAM.PAGE_SIZE)

    def validate(self):
        if self.signature != b'VA*\x00':
            raise ValueError('bad signature')
        if self.unk04 != 0x3:
            raise ValueError('unexpected unk04 value')
        if self.non_empty not in (0x0, 0x1):
            raise ValueError('unexpected non_empty value')
        if self.unk0C != 0x800:
            raise ValueError('unexpected unk0C value')
        if self.unk14 != 0x0:
            raise ValueError('unexpected unk14 value')
        return True

    def names(self):
        fmt = "<{0.name_count:d}{0.word_fmt:s}".format(self)
        size = struct.calcsize(fmt)
        if size > len(self.buffer):
            raise ValueError('buffer too small')
        return struct.unpack(fmt, self.buffer[:size])


class TIL(vstruct.VStruct):
    def __init__(self):
        vstruct.VStruct.__init__(self)
        self.signature = v_bytes(size=0x06)

    def validate(self):
        if self.signature != b'IDATIL':
            raise ValueError('bad signature')
        return True


class IDB(vstruct.VStruct):
    def __init__(self):
        vstruct.VStruct.__init__(self)
        self.header = FileHeader()
        self.section_id0  = Section()
        # not padding, because it doesn't align the following section.
        self.unk1 = v_uint8()
        self.section_id1  = Section()
        self.unk2 = v_uint8()
        self.section_nam  = Section()
        self.unk3 = v_uint8()
        self.section_til = Section()

        self.id0 = None
        self.id1 = None
        self.nam = None
        self.til = None

    def pcb_section_til(self):
        id0 = ID0()
        id0.vsParse(self.section_id0.contents)
        # vivisect doesn't allow you to assign vstructs to
        #  attributes that are not part of the struct,
        # so we need to override and use the default object behavior.
        object.__setattr__(self, 'id0', id0)

        id1 = ID1()
        id1.vsParse(self.section_id1.contents)
        object.__setattr__(self, 'id1', id1)

        nam = NAM()
        nam.vsParse(self.section_nam.contents)
        object.__setattr__(self, 'nam', nam)

        til = TIL()
        til.vsParse(self.section_til.contents)
        object.__setattr__(self, 'til', til)

    def validate(self):
        self.header.validate()
        self.section_id0.validate()
        self.section_id1.validate()
        self.section_nam.validate()
        self.section_til.validate()
        self.id0.validate()
        self.id1.validate()
        self.nam.validate()
        self.til.validate()
        return True

    def SegStart(self, ea):
        return self.id1.get_segment(ea).bounds.start

    def SegEnd(self, ea):
        return self.id1.get_segment(ea).bounds.end

    def FirstSeg(self):
        return self.id1.segments[0].bounds.start

    def NextSeg(self, ea):
        return self.id1.get_next_segment(ea).bounds.start

    def GetFlags(self, ea):
        return self.id1.get_flags(ea)

    def IdbByte(self, ea):
        return self.id1.get_byte(ea)


@contextlib.contextmanager
def from_file(path):
    with open(path, 'rb') as f:
        buf = f.read()
        db = IDB()
        db.vsParse(buf)
        yield db
