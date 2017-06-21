'''
lots of inspiration from: https://github.com/nlitsme/pyidbutil
'''
import struct
import logging
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


logger = logging.getLogger(__name__)


class FileHeader(vstruct.VStruct):
    def __init__(self):
        vstruct.VStruct.__init__(self)
        self.offsets = []
        self.checksums = []

        self.signature = v_bytes(size=0x4)  # IDA1
        self.unk04 = v_uint16()
        self.offset1 = v_uint64()
        self.offset2 = v_uint64()
        self.unk16 = v_uint32()
        self.sig2 = v_uint32()  # | DD CC BB AA |
        self.version = v_uint16()
        self.offset3 = v_uint64()
        self.offset4 = v_uint64()
        self.offset5 = v_uint64()
        self.checksum1 = v_uint32()
        self.checksum2 = v_uint32()
        self.checksum3 = v_uint32()
        self.checksum4 = v_uint32()
        self.checksum5 = v_uint32()
        self.offset6 = v_uint64()
        self.checksum6 = v_uint32()

    def pcb_version(self):
        if self.version != 0x6:
            raise NotImplementedError('unsupported version: %d' % (self.version))

    def pcb_offset6(self):
        self.offsets.append(self.offset1)
        self.offsets.append(self.offset2)
        self.offsets.append(self.offset3)
        self.offsets.append(self.offset4)
        self.offsets.append(self.offset5)
        self.offsets.append(self.offset6)

    def pcb_checksum6(self):
        self.checksums.append(self.checksum1)
        self.checksums.append(self.checksum2)
        self.checksums.append(self.checksum3)
        self.checksums.append(self.checksum4)
        self.checksums.append(self.checksum5)
        self.checksums.append(self.checksum6)

    def validate(self):
        if self.signature != b'IDA1':
            raise ValueError('bad signature')
        if self.sig2 != 0xAABBCCDD:
            raise ValueError('bad sig2')
        if self.version != 0x6:
            raise ValueError('unsupported version')
        return True


class SectionHeader(vstruct.VStruct):
    def __init__(self):
        vstruct.VStruct.__init__(self)
        self.is_compressed = v_uint8()
        self.length = v_uint64()


class Section(vstruct.VStruct):
    def __init__(self):
        vstruct.VStruct.__init__(self)
        self.header = SectionHeader()
        self.contents = v_bytes()

    def pcb_header(self):
        if self.header.is_compressed:
            # TODO: support this.
            raise NotImplementedError('compressed section')

        self['contents'].vsSetLength(self.header.length)

    def validate(self):
        if self.header.length == 0:
            raise ValueError('zero size')
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
        offset = 0x14 + (self.segment_count * (2 * self.wordsize))
        padsize = ID1.PAGE_SIZE - offset
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


SectionDescriptor = namedtuple('SectionDescriptor', ['name', 'cls'])

# section order:
#   - id0
#   - id1
#   - nam
#   - seg
#   - til
#   - id2
#
# via: https://github.com/williballenthin/pyidbutil/blob/master/idblib.py#L262
SECTIONS = [
    SectionDescriptor('id0', ID0),
    SectionDescriptor('id1', ID1),
    SectionDescriptor('nam', NAM),
    SectionDescriptor('seg', None),
    SectionDescriptor('til', TIL),
    SectionDescriptor('id2', None),
]


class IDB(vstruct.VStruct):
    def __init__(self, buf):
        vstruct.VStruct.__init__(self)
        self.buf = memoryview(buf)

        self.header = FileHeader()
        self.sections = []

        '''
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
        '''

    def pcb_header(self):
        # TODO: pass along checksum
        for offset in self.header.offsets:
            if offset == 0:
                self.sections.append(None)
                continue

            sectionbuf = self.buf[offset:]
            section = Section()
            section.vsParse(sectionbuf)
            self.sections.append(section)

        for i, sectiondef in enumerate(SECTIONS):
            if i > len(self.sections):
                logger.debug('missing section: %s', sectiondef.name)
                continue

            section = self.sections[i]
            if not section:
                logger.debug('missing section: %s', sectiondef.name)
                continue

            if not sectiondef.cls:
                logger.warn('section class not implemented: %s', sectiondef.name)
                continue

            s = sectiondef.cls()
            s.vsParse(section.contents)
            # vivisect doesn't allow you to assign vstructs to
            #  attributes that are not part of the struct,
            # so we need to override and use the default object behavior.
            object.__setattr__(self, sectiondef.name, s)
            logger.debug('parsed section: %s', sectiondef.name)

    def validate(self):
        self.header.validate()
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
        buf = memoryview(f.read())
        #buf = f.read()
        db = IDB(buf)
        db.vsParse(buf)
        yield db
