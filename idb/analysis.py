import binascii
import datetime
import itertools
import logging
import types
from collections import Counter, namedtuple
from random import randint

import six
import vstruct
from vstruct.primitives import *

import idb
import idb.netnode
import idb.typeinf
import idb.typeinf_flags

logger = logging.getLogger(__name__)

_counter = Counter()


def name_generator(prefix="unknown"):
    def inner(index=randint(0, 0xFFFFFFFF)):
        _counter[index] += 1
        return "{}{}".format(prefix, _counter[index])

    return inner


def is_flag_set(flags, flag):
    return flags & flag == flag


def as_unix_timestamp(buf, wordsize=None):
    """
    parse unix timestamp bytes into a timestamp.
    """
    q = struct.unpack_from("<I", buf, 0x0)[0]
    return datetime.datetime.utcfromtimestamp(q)


def as_md5(buf, wordsize=None):
    """
    parse raw md5 bytes into a hex-formatted string.
    """
    return binascii.hexlify(buf).decode("ascii")


def as_sha256(buf, wordsize=None):
    """
    parse raw sha256 bytes into a hex-formatted string.
    """
    return binascii.hexlify(buf).decode("ascii")


def cast(buf, V, wordsize=None):
    """
    apply a vstruct class to a sequence of bytes.

    Args:
        buf (bytes): the bytes to parse.
        V (type[vstruct.VStruct]): the vstruct class.

    Returns:
        V: the parsed instance of V.

    Example::

        s = cast(buf, Stat)
        assert s.gid == 0x1000
    """
    v = V(wordsize=wordsize)
    v.vsParse(buf)
    return v


def as_cast(V):
    """
    create a partial function that casts buffers to the given vstruct.

    Args:
        V (type[vstruct.VStruct]): the vstruct class.

    Returns:
        callable[bytes]->V: the function that parses buffers into V instances.

    Example::

        S = as_cast(Stat)
        s = S(buf)
        assert s.gid == 0x1000
    """

    def inner(buf, wordsize=None):
        return cast(buf, V, wordsize=wordsize)

    setattr(inner, "V", V.__name__)
    return inner


def unpack_dd(buf, offset=0):
    """
    unpack up to 32-bits using the IDA-specific data packing format.

    Args:
      buf (bytes): the region to parse.
      offset (int): the offset into the region from which to unpack. default: 0.

    Returns:
      (int, int): the parsed dword, and the number of bytes consumed.

    Raises:
      KeyError: if the bounds of the region are exceeded.
    """
    if offset != 0:
        # this isn't particularly fast... but its more readable.
        buf = buf[offset:]

    header = six.indexbytes(buf, 0x0)
    if header & 0x80 == 0:
        return header, 1
    elif header & 0xC0 != 0xC0:
        return ((header & 0x7F) << 8) + six.indexbytes(buf, 0x1), 2
    else:
        if header & 0xE0 == 0xE0:
            hi = (six.indexbytes(buf, 0x1) << 8) + six.indexbytes(buf, 0x2)
            low = (six.indexbytes(buf, 0x3) << 8) + six.indexbytes(buf, 0x4)
            size = 5
        else:
            hi = ((header & 0x3F) << 8) + six.indexbytes(buf, 0x1)
            low = (six.indexbytes(buf, 0x2) << 8) + six.indexbytes(buf, 0x3)
            size = 4
        return (hi << 16) + low, size


def unpack_dw(buf, offset=0):
    """
    unpack word.
    """
    if offset != 0:
        buf = buf[offset:]

    header = six.indexbytes(buf, 0x0)
    if header & 0x80 == 0:
        return header, 1
    elif header & 0xC0 != 0xC0:
        return ((header << 8) + six.indexbytes(buf, 0x1)) & 0x7FFF, 2
    else:
        return (six.indexbytes(buf, 0x1) << 8) + six.indexbytes(buf, 0x2), 3


def unpack_dq(buf, offset=0):
    """
    unpack qword.
    """
    if offset != 0:
        buf = buf[offset:]

    dw1, d1 = unpack_dd(buf)
    dw2, d2 = unpack_dd(buf, offset=d1)
    return (dw2 << 32) + dw1, d1 + d2


def unpack_dds(buf):
    offset = 0
    while offset < len(buf):
        val, size = unpack_dd(buf, offset=offset)
        yield val
        offset += size


def unpack_dqs(buf):
    offset = 0
    while offset < len(buf):
        val, size = unpack_dq(buf, offset=offset)
        yield val
        offset += size


class Unpacker:
    def __init__(self, buf, wordsize, offset=0, should_log=False):
        self.offset = offset
        self.wordsize = wordsize
        self.buf = buf
        self.should_log = should_log

    def _do_unpack(self, unpack_fn):
        v, delta = unpack_fn(self.buf, offset=self.offset)
        if self.should_log:
            logger.debug("%s at %x: %x", unpack_fn.__name__, self.offset, v)
        self.offset += delta
        return v

    def dd(self):
        return self._do_unpack(unpack_dd)

    def dq(self):
        return self._do_unpack(unpack_dq)

    def dw(self):
        return self._do_unpack(unpack_dw)

    def addr(self):
        if self.wordsize == 4:
            return self._do_unpack(unpack_dd)
        elif self.wordsize == 8:
            return self._do_unpack(unpack_dq)
        else:
            raise RuntimeError("unexpected wordsize")

    def off(self):
        offset = self.addr()
        mask = (2 ** (self.wordsize * 8)) - 1
        if offset & (1 << ((self.wordsize * 8) - 1)):
            return offset | ~mask
        else:
            return offset


Field = namedtuple("Field", ["name", "tag", "index", "cast", "minver"])
# namedtuple default args.
# via: https://stackoverflow.com/a/18348004/87207
Field.__new__.__defaults__ = (None,) * len(Field._fields)


class IndexType:
    def __init__(self, name):
        self.name = name

    def str(self):
        return self.name.upper()


ALL = IndexType("all")
ADDRESSES = IndexType("addresses")
NUMBERS = IndexType("numbers")
NODES = IndexType("nodes")

VARIABLE_INDEXES = (ALL, ADDRESSES, NUMBERS, NODES)


class _Analysis(object):
    """
    this is basically a metaclass for analyzers of IDA Pro netnode namespaces (named nodeid).
    provide set of fields, and parse them from netnodes (nodeid, tag, and optional index)
     when accessed.
    """

    def __init__(self, db, nodeid, fields):
        self.idb = db
        self.nodeid = nodeid
        self.netnode = idb.netnode.Netnode(db, nodeid)
        self.fields = fields

        idb_version = idb.netnode.Netnode(db, "Root Node").altval(index=-1)

        # note that order of fields is important:
        #   fields with matching minvers override previously defined fields of the same name
        self._fields_by_name = {
            f.name: f
            for f in self.fields
            if (not f.minver) or (f.minver and idb_version >= f.minver)
        }

    def _is_address(self, index):
        """
        does the given index fall within a segment?
        """
        try:
            self.idb.id1.get_segment(index)
            return True
        except KeyError:
            return False

    def _is_node(self, index):
        """
        does the index look like a raw nodeid?
        """
        if self.idb.wordsize == 4:
            return index & 0xFF000000 == 0xFF000000
        elif self.idb.wordsize == 8:
            return index & 0xFF00000000000000 == 0xFF00000000000000
        else:
            raise RuntimeError("unexpected wordsize")

    def _is_number(self, index):
        """
        does the index look like not (address or node)?
        """
        if self._is_node(index):
            return False

        if index < 0x1000:
            return True

        if self._is_address(index):
            return False

        return True

    def __getattr__(self, key):
        """
        for the given field name, fetch the value from the appropriate netnode.
        if the field matches multiple indices, then return a mapping from index to value.

        Example::

            assert root.version == 695

        Example::

            assert 0x401000 in entrypoints.ordinals

        Example::

            assert entrypoints.ordinals[0] == 'DllMain'

        Args:
          key (str): the name of the field to fetch.

        Returns:
          any: if a parser was provided, then the parsed data.
            otherwise, the bytes associatd with the field.
            if the field matches multiple indices, then the result is mapping from index to value.

        Raises:
          KeyError: if the field does not exist.
        """
        if key not in self._fields_by_name:
            return super(_Analysis, self).__getattribute__(key)

        field = self._fields_by_name[key]
        if field.index in VARIABLE_INDEXES:

            if field.index == ADDRESSES:
                nfilter = self._is_address
            elif field.index == NUMBERS:
                nfilter = self._is_number
            elif field.index == NODES:
                nfilter = self._is_node
            elif field.index == ALL:
                nfilter = lambda x: True
            else:
                raise ValueError("unexpected index")

            # indexes are variable, so map them to the values
            ret = {}
            for sup in self.netnode.supentries(tag=field.tag):
                if not nfilter(sup.parsed_key.index):
                    continue

                if field.cast is None:
                    ret[sup.parsed_key.index] = bytes(sup.value)
                else:
                    v = field.cast(bytes(sup.value), wordsize=self.idb.wordsize)
                    ret[sup.parsed_key.index] = v
            return ret
        else:
            # normal field with an explicit index
            v = self.netnode.supval(field.index, tag=field.tag)
            if field.cast is None:
                return bytes(v)
            else:
                return field.cast(bytes(v), wordsize=self.idb.wordsize)

    def get_field_tag(self, name):
        """
        get the tag associated with the given field name.

        Example::

            assert root.get_field_tag('version') == 'A'

        Args:
          key (str): the name of the field to fetch.

        Returns:
          str: a single character string tag.
        """
        return self._fields_by_name[name].tag

    def get_field_index(self, name):
        """
        get the index associated with the given field name.
        Example::

            assert root.get_field_index('version') == root.db.uint(-1)

        Args:
          key (str): the name of the field to fetch.

        Returns:
          int or IndexType: the index, if its specified.
            otherwise, this will be an `IndexType` that indicates what indices are expected.
        """
        return self._fields_by_name[name].index


def Analysis(nodeid, fields):
    """
    build a partial constructor for _Analysis with the given nodeid and fields.

    Example::

        Root = Analysis('Root Node', [Field(...), ...])
        root = Root(some_idb)
        assert root.version == 695
    """

    def inner(db):
        return _Analysis(db, nodeid, fields)

    return inner


class Reader(idb.typeinf.TypeString):
    def __init__(self, buf, wordsize):
        idb.typeinf.TypeString.__init__(self, buf)
        self.word = self.u32 if wordsize == 4 else self.u64
        self.word_ = self.u32_ if wordsize == 4 else self.u64_

    def bytes(self, size):
        return self.read(size)

    def str(self, size, encoding="utf-8"):
        return self.read(size).decode(encoding)

    def u16(self, big=False):
        if big:
            return struct.unpack(">H", self.read(2))[0]
        return struct.unpack("<H", self.read(2))[0]

    def u32(self, big=False):
        if big:
            return struct.unpack(">L", self.read(4))[0]
        return struct.unpack("<L", self.read(4))[0]

    def u64(self, big=False):
        if big:
            return struct.unpack(">Q", self.read(8))[0]
        return struct.unpack("<Q", self.read(8))[0]

    def u8_(self):
        return self.u8()

    def u16_(self):
        val = self.u8()
        if val == 0xFF:
            val = self.u16(big=True)
        elif val & 0x80:
            val = ((val & 0x3F) << 8) | self.u8()
        return val

    def u32_(self):
        val = self.u8()
        if val == 0xFF:
            val = self.u32(big=True)
        elif val & 0xC0 == 0xC0:
            val = (
                ((val & 0x1F) << 24) | (self.u8() << 16) | (self.u8() << 8) | self.u8()
            )
        elif val & 0x80:
            val = ((val & 0x3F) << 8) | self.u8()
        return val

    def u64_(self):
        val = self.u32_()
        val = val | (self.u32_() << 32)
        return val


class IdaInfo(vstruct.VStruct):
    """
    did not use vstruct to parse, but for compatibility, just inherit VStruct, and parse in vsParse()
    """

    # ref: https://www.hex-rays.com/products/ida/support/sdkdoc/structidainfo.html

    def __init__(self, wordsize):
        vstruct.VStruct.__init__(self)
        if wordsize in (4, 8):
            self.wordsize = wordsize
        else:
            raise ValueError("unexpected wordsize")

        """
        v7.0:
        nodeid: ff000002 tag: S index: 0x41b994
        00000000: 69 64 61 00 BC 02 6D 65  74 61 70 63 00 00 00 00  ida...metapc....
        00000010: 00 00 00 00 00 00 A3 00  0B 02 00 00 14 00 00 00  ................
        00000020: 0B 00 00 00 00 00 00 00  F7 FF FF DF 03 00 00 00  ................
        00000030: 00 00 00 00 FF FF FF FF  01 00 00 00 95 16 90 68  ...............h
        00000040: 95 16 90 68 FF FF FF FF  FF FF FF FF 00 10 90 68  ...h...........h
        00000050: 30 E2 9D 68 00 10 90 68  30 E2 9D 68 00 10 90 68  0..h...h0..h...h
        00000060: 00 70 9E 68 10 00 00 00  00 00 00 FF 00 00 10 FF  .p.h............
        00000070: 00 00 00 00 00 02 01 0F  0F 00 40 40 00 00 00 00  ..........@@....
        00000080: 00 00 00 00 00 00 00 00  00 00 02 06 67 BE A3 0E  ............g...
        00000090: 07 00 40 06 00 07 00 18  28 00 50 00 54 03 00 00  ..@.....(.P.T...
        000000A0: 01 00 00 00 01 1B 0A 00  00 00 00 00 61 00 00 00  ............a...
        000000B0: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
        000000C0: 07 00 00 00 00 01 33 04  01 04 00 02 04 08 08 00  ......3.........
        000000D0: 00 00 00 00 00 00 00 00                           ........

        v6.95:
        00000000: 49 44 41 B7 02 6D 65 74  61 70 63 00 00 23 00 0B  IDA..metapc..#..
        00000010: 00 00 00 00 00 00 00 00  00 00 00 00 00 FF FF FF  ................
        00000020: FF FF FF 95 16 90 68 95  16 90 68 00 10 90 68 30  ......h...h...h0
        00000030: E2 9D 68 00 10 90 68 30  E2 9D 68 00 10 90 68 00  ..h...h0..h...h.
        00000040: 70 9E 68 10 00 00 00 0A  00 00 18 00 01 00 00 02  p.h.............
        00000050: 01 01 00 01 02 01 01 00  00 00 00 00 0F 08 00 09  ................
        00000060: 06 00 01 01 1B 07 61 00  00 00 00 00 00 00 00 00  ......a.........
        00000070: 00 00 00 00 00 00 00 00  00 00 00 01 00 00 00 01  ................
        00000080: 01 01 FF FF FF FF 01 00  00 00 FF FF FF FF 67 BE  ..............g.
        00000090: A3 0E 07 00 40 06 07 00  00 00 00 00 00 00 FD BF  ....@...........
        000000A0: 0F 00 28 00 50 00 40 40  00 00 00 00 00 00 00 00  ..(.P.@@........
        000000B0: 00 00 00 00 00 00 02 01  33 04 01 04 00 02 04 08  ........3.......
        000000C0: 14 00 00 00 08 00 00 00  00 00 00 00 00 00 00 00  ................
        000000D0: 00 00 00 00 00 00 00 00  00 00 00 00 00 01 00 00  ................
        000000E0: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
        000000F0: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
        """

        self.tag = None
        self.zero = None
        self.version = None
        self.procname_size = None
        self.procname = None
        self.lflags = None
        self.demnames = None
        self.filetype = None
        self.fcoresize = None
        self.corestart = None
        self.ostype = None
        self.apptype = None
        self.start_sp = None
        self.af = None
        self.start_ip = None
        self.begin_ea = None
        self.min_ea = None
        self.max_ea = None
        self.omin_ea = None
        self.omax_ea = None
        self.lowoff = None
        self.highoff = None
        self.maxref = None
        self.ascii_break = None
        self.wide_high_byte_first = None
        self.indent = None
        self.comment = None
        self.xrefnum = None
        self.entab = None
        self.specsegs = None
        self.voids = None
        self.showauto = None
        self.auto = None
        self.border = None
        self.null = None
        self.genflags = None
        self.showpref = None
        self.prefseg = None
        self.asmtype = None
        self.xrefs = None
        self.binpref = None
        self.cmtflag = None
        self.nametype = None
        self.showbads = None
        self.prefflag = None
        self.packbase = None
        self.asciiflags = None
        self.listnames = None
        self.asciipref = None
        self.asciisernum = None
        self.asciizeroes = None
        self.tribyte_order = None
        self.mf = None
        self.org = None
        self.assume = None
        self.checkarg = None
        self.start_ss = None
        self.start_cs = None
        self.main = None
        self.short_dn = None
        self.long_dn = None
        self.datatypes = None
        self.strtype = None
        self.af2 = None
        self.namelen = None
        self.margin = None
        self.lenxref = None
        self.lprefix = None
        self.lprefixlen = None
        self.compiler = None
        self.model = None
        self.sizeof_int = None
        self.sizeof_bool = None
        self.sizeof_enum = None
        self.sizeof_algn = None
        self.sizeof_short = None
        self.sizeof_long = None
        self.sizeof_llong = None
        self.change_counter = None
        self.sizeof_ldbl = None
        self.abiname = None
        self.abibits = None
        self.refcmts = None
        self.database_change_count = None

    def vsParse(self, sbytes, offset=0, fast=False):
        reader = Reader(sbytes, wordsize=self.wordsize)
        reader.pos = offset
        u8 = reader.u8
        u16 = reader.u16
        u32 = reader.u32
        u64 = reader.u64
        word = reader.word

        self.tag = reader.str(3)  # 'IDA' below 7.0, 'ida' in 7.0
        if self.tag == "ida":
            self.zero = u8()
        elif self.tag != "IDA":
            raise NotImplementedError("raise unknown database tag: " + self.tag)

        self.version = u16()
        if self.version == 700 and self.tag == "IDA":
            self.procname_size = u8()
        # 8 bytes for < 7.0
        # 16 bytes for > 7.0
        # 6.95 database upgraded to v7.0b
        # we have a single byte that describes how long the procname is.
        if self.procname_size is not None:
            self.procname = reader.str(self.procname_size)
        elif self.version < 700:
            self.procname = reader.str(8)
        elif self.version >= 700:
            self.procname = reader.str(16)
        import re

        self.procname = re.sub(r"\x00.*", "", self.procname)

        if self.version < 700:
            self.lflags = u8()
            self.demnames = u8()
            self.filetype = u16()
            self.fcoresize = word()  # 0x11
            self.corestart = word()
            self.ostype = u16()  # 0x19
            self.apptype = u16()
            self.start_sp = word()  # 0x1d
            self.af = u16()  # 0x21 Analysis Kernel options1+2
            self.start_ip = word()  # 0x23
            self.begin_ea = word()
            self.min_ea = word()
            self.max_ea = word()
            self.omin_ea = word()
            self.omax_ea = word()
            self.lowoff = word()
            self.highoff = word()
            self.maxref = word()
            self.ascii_break = u8()  # 71
            self.wide_high_byte_first = u8()
            self.indent = u8()
            self.comment = u8()
            self.xrefnum = u8()
            self.entab = u8()
            self.specsegs = u8()
            self.voids = u8()
            reader.seek(1)
            self.showauto = u8()  # 80
            self.auto = u8()
            self.border = u8()
            self.null = u8()
            self.genflags = u8()
            self.showpref = u8()
            self.prefseg = u8()
            self.asmtype = u8()
            self.baseaddr = word()  # 88
            self.xrefs = u8()
            self.binpref = u16()
            self.cmtflag = u8()  # 95
            self.nametype = u8()
            self.showbads = u8()
            self.prefflag = u8()
            self.packbase = u8()
            self.asciiflags = u8()
            self.listnames = u8()
            self.asciipref = reader.bytes(16)  # 102
            self.asciisernum = word()  # 118
            self.asciizeroes = u8()  # 122
            reader.seek(2)  # 123
            self.tribyte_order = u8()  # 125
            self.mf = u8()
            self.org = u8()
            self.assume = u8()
            self.checkarg = u8()
            self.start_ss = word()  # 131
            self.start_cs = word()
            self.main = word()
            self.short_dn = word()  # 143
            self.long_dn = word()
            self.datatypes = word()
            self.strtype = word()
            self.af2 = u16()  # 159
            self.namelen = u16()
            self.margin = u16()
            self.lenxref = u16()
            self.lprefix = reader.str(16)  # 167
            self.lprefixlen = u8()  # 183
            self.compiler = u8()
            self.model = u8()
            self.sizeof_int = u8()
            self.sizeof_bool = u8()
            self.sizeof_enum = u8()
            self.sizeof_algn = u8()
            self.sizeof_short = u8()
            self.sizeof_long = u8()
            self.sizeof_llong = u8()
            if len(sbytes) < 193:
                return reader.pos

            self.change_counter = u32()  # 193 0xc0
            self.sizeof_ldbl = u8()
            reader.seek(4)
            self.abiname = reader.str(size=16)
            self.abibits = u32()
            self.refcmts = u8()
        else:
            if self.tag == "IDA":
                u8 = reader.u8_
                u16 = reader.u16_
                u32 = reader.u32_
                u64 = reader.u64_
                word = reader.word_

            self.genflags = u16()
            self.lflags = u32()
            self.database_change_count = u32()
            self.filetype = u16()
            self.ostype = u16()
            self.apptype = u16()
            self.asmtype = u8()
            self.specsegs = u8()
            self.af = u32()
            self.af2 = u32()
            self.baseaddr = word()  # 48
            self.start_ss = word()
            self.start_cs = word()
            self.start_ip = word()
            self.start_ea = word()
            self.start_sp = word()
            self.main = word()
            self.min_ea = word()
            self.max_ea = word()
            self.omin_ea = word()
            self.omax_ea = word()
            self.lowoff = word()
            self.highoff = word()
            self.maxref = word()
            self.privrange_start_ea = word()
            self.privrange_end_ea = word()
            self.netdelta = word()
            self.xrefnum = u8()  # 116
            self.type_xrefnum = u8()
            self.refcmtnum = u8()
            self.xrefflag = u8()
            self.max_autoname_len = u16()  # 120

            if self.tag == "ida":
                reader.seek(17)

            self.nametype = u8()
            self.short_demnames = u32()  # 124
            self.long_demnames = u32()
            self.demnames = u8()  # 132
            self.listnames = u8()
            self.indent = u8()
            self.comment = u8()
            self.marzgin = u16()  # 136
            self.lenxref = u16()
            self.outflags = u32()  # 140
            self.cmtflg = u8()  # 144
            self.limiter = u8()
            self.bin_prefix_size = u16()  # 146
            self.prefflag = u8()  # 148
            self.strlit_flags = u8()
            self.strlit_break = u8()
            self.strlit_zeroes = u8()
            self.strtype = u32()

            self.strlit_pref_size = u8()
            if self.tag == "ida":
                self.strlit_pref = reader.str(16)
            else:
                self.strlit_pref = reader.str(self.strlit_pref_size)

            self.strlit_sernum = word()
            self.datatypes = word()
            self.cc_id = u8()
            self.cc_cm = u8()
            self.cc_size_i = u8()
            self.cc_size_b = u8()
            self.cc_size_e = u8()
            self.cc_defalign = u8()
            self.cc_size_s = u8()
            self.cc_size_l = u8()
            self.cc_size_ll = u8()
            self.cc_size_ldbl = u8()
            self.abibits = u32()
            self.appcall_options = u32()
        return reader.pos


Root = Analysis(
    "Root Node",
    [
        Field("imagebase", "A", -6, idb.netnode.as_int),
        Field("crc", "A", -5, idb.netnode.as_int),
        Field("open_count", "A", -4, idb.netnode.as_int),
        Field("created", "A", -2, as_unix_timestamp),
        Field("version", "A", -1, idb.netnode.as_int),
        Field("md5", "S", 1302, as_md5),
        Field("version_string", "S", 1303, idb.netnode.as_string),
        Field("sha256", "S", 1349, as_sha256),
        Field("idainfo", "S", 0x41B994, as_cast(IdaInfo)),
        Field("input_file_path", "V", None, idb.netnode.as_string),
    ],
)

Loader = Analysis(
    "$ loader name",
    [
        Field("plugin", "S", 0, idb.netnode.as_string),
        Field("format", "S", 1, idb.netnode.as_string),
    ],
)

# see `scripts/dump_user.py` for intepretation.
OriginalUser = Analysis("$ original user", [Field("data", "S", 0, bytes),])

# see `scripts/dump_user.py` for intepretation.
User = Analysis("$ user1", [Field("data", "S", 0, bytes),])


# this works for v6.95.
# for v7.0b, the data looks something like:
#
#     00000000: FF 68 90 10 00 C0 0D A0  00 90 00 00              .h..........
#
# which looks pack_dd/dq to me.
# TODO: need a way to detect versions and switch analysis implementations.


class FileRegion(vstruct.VStruct):
    def __init__(self, wordsize):
        vstruct.VStruct.__init__(self)
        if wordsize == 4:
            v_word = v_uint32
        elif wordsize == 8:
            v_word = v_uint64
        else:
            raise ValueError("unexpected wordsize")

        self.start = v_word()
        self.end = v_word()
        self.rva = v_uint32()


class FileRegionV70:
    def __init__(self, buf, wordsize):
        self.buf = buf
        u = Unpacker(buf, wordsize=wordsize)
        self.start = u.addr()
        self.end = self.start + u.addr()
        self.rva = u.addr()


# '$ fileregions' maps from idb segment start address to details about it.
#
# supvals:
#   format1:
#     index: start effective address
#     value:
#       0x0: start effective address
#       0x4: end effective address
#       0x8: rva start?
FileRegions = Analysis(
    "$ fileregions",
    [
        Field("regions", "S", ADDRESSES, as_cast(FileRegion)),
        Field("regions", "S", ADDRESSES, FileRegionV70, minver=700),
    ],
)


class func_t:
    FUNC_TAIL = 0x00008000

    def __init__(self, buf, wordsize):
        self.buf = buf
        u = Unpacker(buf, wordsize=wordsize)

        self.startEA = u.addr()
        self.endEA = self.startEA + u.addr()
        self.flags = u.dw()

        self.frame = None
        self.frsize = None
        self.frregs = None
        self.argsize = None
        self.owner = None
        self.refqty = None

        if not is_flag_set(self.flags, func_t.FUNC_TAIL):
            try:
                self.frame = u.addr()
                self.frsize = u.addr()
                self.frregs = u.dw()
                self.argsize = u.addr()
                # there is some other stuff here, based on IDB version/features
            except IndexError:
                # some of these we don't have, so we'll fall back to the default value of None.
                # eg. owner, refqty only present in some idb versions
                # eg. all of these, if high bit of flags not set.
                pass
        else:
            # We are in a function tail. Chunks can be above or below the tail
            # owner
            try:
                self.owner = self.startEA - u.off()
                self.refqty = u.dd()
            except IndexError:
                # see warning note above
                pass


# '$ funcs' maps from function effective address to details about it.
#
# supvals:
#   format1:
#     index: effective address
#     value: func_t
Functions = Analysis(
    "$ funcs",
    [
        Field("functions", "S", ADDRESSES, func_t),
        Field("comments", "C", ADDRESSES, idb.netnode.as_string),
        Field("repeatable_comments", "R", ADDRESSES, idb.netnode.as_string),
    ],
)


class PString(vstruct.VStruct):
    """
    short pascal string, prefixed with single byte length.
    """

    def __init__(self, length_is_total=True):
        vstruct.VStruct.__init__(self)
        self.length = v_uint8()
        self.s = v_str()
        self.length_is_total = length_is_total

    def pcb_length(self):
        length = self.length
        if self.length_is_total:
            length = length - 1
        self["s"].vsSetLength(length)


class TypeString(vstruct.VStruct):
    def __init__(self):
        vstruct.VStruct.__init__(self)
        self.header = v_uint8()
        self.length = v_uint8()
        self.s = v_str()

    def pcb_header(self):
        if self.header != 0x3D:
            raise RuntimeError("unexpected type header")

    def pcb_length(self):
        length = self.length
        self["s"].vsSetLength(length - 1)


class StructMember:
    def __init__(self, db, identity):
        self.idb = db

        if isinstance(identity, six.integer_types):
            # if doesn't start with 0xFF0000..., add it.
            nodebase = idb.netnode.Netnode.get_nodebase(db)
            if identity < nodebase:
                identity += nodebase
            self.netnode = idb.netnode.Netnode(db, identity)
            self.nodeid = identity
        elif isinstance(identity, six.string_types):
            self.netnode = idb.netnode.Netnode(db, identity)
            self.nodeid = self.netnode.nodeid
        else:
            raise ValueError("Expected identify is integer or string")

    def get_fullname(self):
        return self.netnode.name()

    def get_name(self):
        return self.netnode.name().partition(".")[2]

    def get_typeinfo(self):
        return self.netnode.supval(tag="S", index=0x3000)

    def get_type(self):
        # nodeid: ff000078 tag: S index: 0x3000
        # 00000000: 3D 0A 48 49 4E 53 54 41  4E 43 45 00              =.HINSTANCE.

        try:
            v = self.netnode.supval(tag="S", index=0x3000)
            s = TypeString()
            s.vsParse(v)
            return s.s
        except KeyError:
            return None

    def get_enum_id(self):
        return self.netnode.altval(tag="A", index=0xB)

    def get_struct_id(self):
        return self.netnode.altval(tag="A", index=0x3)

    def get_member_comment(self):
        return self.netnode.supstr(tag="S", index=0x0)

    def get_repeatable_member_comment(self):
        return self.netnode.supstr(tag="S", index=0x1)

    # TODO: tag='A', index=0x10
    # TODO: tag='S', index=0x9, "ptrseg"

    def __str__(self):
        try:
            typ = self.get_type()
        except KeyError:
            return "StructMember(name: %s)" % (self.get_name())
        else:
            return "StructMember(name: %s, type: %s)" % (self.get_name(), typ)


class STRUCT_FLAGS:
    # via: https://www.hex-rays.com/products/ida/support/sdkdoc/group___s_f__.html

    # is variable size structure (varstruct)? More...
    SF_VAR = 0x00000001

    # is a union? More...
    SF_UNION = 0x00000002

    # has members of type "union"?
    SF_HASUNI = 0x00000004

    # don't include in the chooser list
    SF_NOLIST = 0x00000008

    # the structure comes from type library
    SF_TYPLIB = 0x00000010

    # the structure is collapsed
    SF_HIDDEN = 0x00000020

    # the structure is a function frame
    SF_FRAME = 0x00000040

    # alignment (shift amount: 0..31)
    SF_ALIGN = 0x00000F80

    # ghost copy of a local type
    SF_GHOST = 0x00001000


class Struct:
    """
    Example::

        struc = Struct(idb, 0xFF000075)
        assert struc.get_name() == 'EXCEPTION_INFO'
        assert len(struc.get_members()) == 5
        assert list(struc.get_members())[0].get_type() == 'DWORD'
    """

    def __init__(self, db, identity):
        """from https://github.com/nlitsme/pyidbutil/blob/7705bcde167fd34a5800bfe54ba99d195b44bbbb/idblib.py#L1380
            Decodes info for structures
            (structnode, N)          = structname
            (structnode, D, address) = xref-type
            (structnode, M, 0)       = packed struct info
            (structnode, S, 27)      = packed value(addr, byte)
        """

        self.idb = db

        if isinstance(identity, six.integer_types):
            # if doesn't start with 0xFF0000..., add it.
            nodebase = idb.netnode.Netnode.get_nodebase(db)
            if identity < nodebase:
                identity += nodebase
            self.netnode = idb.netnode.Netnode(db, identity)
            self.nodeid = identity
        elif isinstance(identity, six.string_types):
            self.netnode = idb.netnode.Netnode(db, identity)
            self.nodeid = self.netnode.nodeid
        else:
            raise ValueError("Expected identify is integer or string")

    def get_name(self):
        return self.netnode.name()

    def get_members(self):
        v = self.netnode.supval(tag="M", index=0)
        u = Unpacker(v, wordsize=self.idb.wordsize)
        flags = u.dd()
        count = u.dd()

        for i in range(count):
            nodeid_offset = u.addr()
            _ = u.addr()
            _ = u.addr()
            _ = u.dd()
            _ = u.dd()

            member_nodeid = self.netnode.nodebase + nodeid_offset
            yield StructMember(self.idb, member_nodeid)

    def find_member_by_name(self, name):
        for m in self.get_members():
            if m.get_name() == name:
                return m
        return None


def chunks(l, n):
    """
    Yield successive n-sized chunks from l.
    via: https://stackoverflow.com/a/312464/87207
    """
    if isinstance(l, types.GeneratorType):
        while True:
            v = list(itertools.islice(l, n))
            if not v:
                return
            yield v
    else:
        i = 0
        while True:
            try:
                v = l[i : i + n]
                yield v
            except IndexError:
                return
            i += n


def pairs(l):
    return chunks(l, 2)


Chunk = namedtuple("Chunk", ["effective_address", "length"])
FunctionParameter = namedtuple("FunctionParameter", ["type", "name"])
FunctionSignature = namedtuple(
    "FunctionSignature", ["calling_convention", "rtype", "unk", "parameters"]
)
StackChangePoint = namedtuple("StackChangePoint", ["effective_address", "change"])


def create_pstring_list(buf):
    _lst = []
    ofs = 0
    while ofs < len(buf.strip(b"\x00")):
        _len = struct.unpack_from("<B", buf, ofs)[0]
        _lst.append(buf[ofs : ofs + _len][1:].decode("utf-8"))
        ofs += _len
        if _len == 0:
            ofs += 1
    return _lst


class Function:
    """
    Example::

        func = Function(idb, 0x401000)
        assert func.get_name() == 'DllEntryPoint'
        assert func.get_signature() == '... DllEntryPoint(...)'
    """

    def __init__(self, db, fva):
        self.idb = db
        self.nodeid = fva
        self.netnode = idb.netnode.Netnode(db, self.nodeid)

    def get_name(self):
        try:
            return self.netnode.name()
        except KeyError:
            return "sub_%X" % (self.nodeid)

    def get_signature(self):
        try:
            typebuf = self.netnode.supval(tag="S", index=0x3000)
            namebuf = self.netnode.supval(tag="S", index=0x3001)
            typ = six.indexbytes(typebuf, 0x0)
            if not idb.typeinf_flags.is_type_func(typ):
                raise RuntimeError("is not function")

            names = create_pstring_list(namebuf)
            typedata = idb.typeinf.FuncTypeData()
            ts = idb.typeinf.TypeString(typebuf)
            typedata.deserialize(self.idb.til, ts, names, [])
            inf = Root(self.idb).idainfo

            return idb.typeinf.TInfo(
                typ, typedata, til=self.idb.til, name=self.get_name(), inf=inf
            )
        except KeyError:
            return None

    def get_chunks(self):
        v = self.netnode.supval(tag="S", index=0x7000)

        # stored as:
        #
        #   first chunk:
        #     effective addr
        #     length
        #   second chunk:
        #     delta from first.ea + first.length
        #     length
        #   third chunk:
        #     delta from second.ea + second.length
        #     length
        #   ...

        last_ea = 0
        last_length = 0

        if self.idb.wordsize == 4:
            unpacker = unpack_dds
        elif self.idb.wordsize == 8:
            unpacker = unpack_dqs
        else:
            raise RuntimeError("unexpected wordsize")

        for delta, length in pairs(unpacker(v)):
            ea = last_ea + last_length + delta
            yield Chunk(ea, length)
            last_ea = ea
            last_length = length

    # S-0x1000: sp change points
    # S-0x4000: register variables
    # S-0x5000: local labels
    # S-0x7000: function tails

    def get_stack_change_points(self):
        # ref: ida.wll@0x100793d0
        try:
            v = self.netnode.supval(tag="S", index=0x1000)
        except KeyError:
            return
        offset = self.nodeid

        if self.idb.wordsize == 4:
            unpacker = unpack_dds
        elif self.idb.wordsize == 8:
            unpacker = unpack_dqs
        else:
            raise RuntimeError("unexpected wordsize")
        for (delta, change) in pairs(unpacker(v)):
            offset += delta
            if change & 1:
                change = change >> 1
            else:
                change = -(change >> 1)

            yield StackChangePoint(offset, change)


Xref = namedtuple("Xref", ["frm", "to", "type"])


def _get_xrefs(db, tag, src=None, dst=None, types=None):
    if src is None and dst is None:
        raise ValueError("one of src or dst must be provided")

    nn = idb.netnode.Netnode(db, src if dst is None else dst)
    try:
        for entry in nn.charentries(tag=tag):
            if (types and entry.value in types) or (not types):
                if src is not None:
                    yield Xref(src, entry.parsed_key.index, entry.value)
                else:  # have dst
                    yield Xref(entry.parsed_key.index, dst, entry.value)
    except KeyError:
        return


def get_crefs_to(db, ea, types=None):
    """
    fetches the code references to the given address.

    Args:
      db (idb.IDB): the database.
      ea (int): the effective address from which to fetch xrefs.
      types (collection of int): if provided, a whitelist collection of xref types to include.

    Yields:
      int: xref address.
    """
    return _get_xrefs(db, dst=ea, tag="X", types=types)


def get_crefs_from(db, ea, types=None):
    """
    fetches the code references from the given address.

    Args:
      db (idb.IDB): the database.
      ea (int): the effective address from which to fetch xrefs.
      types (collection of int): if provided, a whitelist collection of xref types to include.

    Yields:
      int: xref address.
    """
    return _get_xrefs(db, src=ea, tag="x", types=types)


def get_drefs_to(db, ea, types=None):
    """
    fetches the data references to the given address.

    Args:
      db (idb.IDB): the database.
      ea (int): the effective address from which to fetch xrefs.
      types (collection of int): if provided, a whitelist collection of xref types to include.

    Yields:
      int: xref address.
    """
    return _get_xrefs(db, dst=ea, tag="D", types=types)


def get_drefs_from(db, ea, types=None):
    """
    fetches the data references from the given address.

    Args:
      db (idb.IDB): the database.
      ea (int): the effective address from which to fetch xrefs.
      types (collection of int): if provided, a whitelist collection of xref types to include.

    Yields:
      int: xref address.
    """
    return _get_xrefs(db, src=ea, tag="d", types=types)


# under v6.95, this works.
class Fixup(vstruct.VStruct):
    def __init__(self, wordsize):
        vstruct.VStruct.__init__(self)
        # sizeof() == 0xB (fixed)
        # possible values: 0x0 - 0xC. top bit has some meaning.
        self.type = v_uint8()
        self.unk01 = v_uint16()  # this might be the segment index + 1?
        if wordsize == 4:
            self.offset = v_uint32()
            self.unk07 = v_uint32()
        elif wordsize == 8:
            self.unk03 = v_uint32()
            self.unk07 = v_uint16()
            self.offset = v_uint64()
        else:
            raise ValueError("unexpected wordsize")

    def pcb_type(self):
        if self.type != 0x04:
            raise NotImplementedError("fixup type %x not yet supported" % (self.type))

    def get_fixup_length(self):
        if self.type == 0x4:
            return 0x4
        else:
            raise NotImplementedError("fixup type %x not yet supported" % (self.type))


class FixupV70:
    def __init__(self, buf, wordsize):
        self.buf = buf
        u = Unpacker(buf, wordsize=wordsize)

        # tbh, don't really know what these fields are...
        self.type = u.dw()
        self.unk1 = u.dd()
        self.unk2 = u.addr()
        self.offset = u.dd()  # strange this is not an offset

        if self.type != 0x8:
            raise NotImplementedError("fixup type %x not yet supported" % (self.type))

    def get_fixup_length(self):
        if self.type == 0x8:
            return 0x4
        else:
            raise NotImplementedError("fixup type %x not yet supported" % (self.type))


# '$ fixups' maps from fixup start address to details about it.
Fixups = Analysis(
    "$ fixups",
    [
        Field("fixups", "S", ADDRESSES, as_cast(Fixup)),
        Field("fixups", "S", ADDRESSES, FixupV70, minver=700),
    ],
)


def parse_seg_strings(buf, wordsize=None):
    strings = []
    offset = 0x0

    while offset < len(buf):
        if buf[offset] == 0x0:
            break

        string = PString(length_is_total=False)
        string.vsParse(buf, offset=offset)
        offset += len(string)
        strings.append(string.s)

    return strings


SegStrings = Analysis("$ segstrings", [Field("strings", "S", 0, parse_seg_strings),])


class Seg:
    def __init__(self, buf, wordsize):
        self.buf = buf
        u = Unpacker(buf, wordsize=wordsize)

        self.startEA = u.addr()
        self.endEA = self.startEA + u.addr()
        # index into `$ segstrings` array of strings.
        self.name_index = u.addr()

        # via: https://www.hex-rays.com/products/ida/support/sdkdoc/classsegment__t.html
        # use get/set_segm_class() functions
        self.sclass = u.addr()
        # this field is IDP dependent.
        # TODO: needs non-zero test
        self.orgbase = u.addr()
        # Segment flags
        self.flags = u.dd()
        # Segment alignment codes
        self.align = u.dd()
        # Segment combination codes
        self.comb = u.dd()
        # Segment permissions (0 means no information)
        self.perm = u.dd()
        # Number of bits in the segment addressing.
        # if 0: 16 bits
        # if 1: 32 bits
        # if 2: 64 bits
        # see: https://github.com/fireeye/flare-ida/blob/master/python/flare/jayutils.py#L94
        self.bitness = u.dd()
        # segment type (see Segment types). More...
        self.type = u.dd()
        # segment selector - should be unique.
        self.sel = u.dd()
        # default segment register values.
        self.defsr = NotImplementedError()
        # the segment color
        self.color = (u.dd() - 1) & 0xFFFFFFFF


# '$ segs' maps from segment start address to details about it.
#
# supvals:
#   format1:
#     index: start effective address
#     value: pack_dd data.
#         1: startEA
#         2: size
#         3: name index
#         ...
Segments = Analysis(
    "$ segs",
    [
        # we use `ALL` for the index type because `_is_address` above does not recognize
        #  addresses not backed by flags/bytes in the IDB.
        # there may be segments for the `.bss`, `extern`, etc sections here, and these
        #  do not have associated flags/bytes.
        # therefore, until we fix `is_address`, being slightly imprecise here works better.
        # note: all indexes in the `$ segs` netnode are addresses, so this assumption works ok.
        Field("segments", "S", ALL, Seg),
    ],
)

Imports = Analysis(
    "$ imports",
    [
        # index: entry number, value: node id
        Field("lib_netnodes", "A", NUMBERS, idb.netnode.as_uint),
        # index: entry number, value: dll name
        Field("lib_names", "S", NUMBERS, idb.netnode.as_string),
    ],
)

Import = namedtuple("Import", ["library", "function_name", "function_address"])


def enumerate_imports(db):
    """
    enumerate the functions imported by the module in the given database.

    yields:
      Tuple[str, str, int]: library name, function name, function address
    """
    imps = Imports(db)
    for index, libname in imps.lib_names.items():
        if index == 0xFFFFFFFF:
            continue

        # dereference the node id stored in the A val
        nnref = imps.lib_netnodes[index]
        nn = idb.netnode.Netnode(db, nnref)

        for funcaddr in nn.sups():
            try:
                funcname = nn.supstr(funcaddr)
                yield Import(libname, funcname, funcaddr)
            except KeyError:
                logger.warning("failed to find import supval: %x", funcaddr)
                continue


EntryPoints = Analysis(
    "$ entry points",
    [
        # index: ordinal, value: address, terminated by index: uint(-1)
        Field("functions", "A", NUMBERS, idb.netnode.as_uint),
        # index: address, value: address, should be only one?
        Field("main_entry", "A", ADDRESSES, idb.netnode.as_uint),
        # index: ordinal, value: ordinal
        Field("ordinals", "I", NUMBERS, idb.netnode.as_uint),
        # index: ordinal, value: string like (NTDLL!Rtl...)
        Field("forwarded_symbols", "F", NUMBERS, idb.netnode.as_string),
        # index: ordinal, value: string like (Rtl...)
        Field("function_names", "S", NUMBERS, idb.netnode.as_string),
        # index: address, value: string like (Rtl...), should be only one?
        Field("main_entry_name", "S", ADDRESSES, idb.netnode.as_string),
    ],
)

EntryPoint = namedtuple(
    "EntryPoint", ["name", "address", "ordinal", "forwarded_symbol"]
)


def enumerate_entrypoints(db):
    """
    enumerate the entry point functions in the given database.

    yields:
      Tuple[str, int, int, str]: function name, address, ordinal (optional), and forwarded symbol (optional)
    """
    ents = EntryPoints(db)

    ordinals = ents.ordinals
    forwarded_symbols = ents.forwarded_symbols
    names = ents.function_names
    names.update(ents.main_entry_name)

    for index, addr in ents.functions.items():
        if index == db.uint(-1):
            break
        yield EntryPoint(
            names.get(index), addr, ordinals.get(index), forwarded_symbols.get(index)
        )

    for index, addr in ents.main_entry.items():
        yield EntryPoint(
            names.get(index), addr, ordinals.get(index), forwarded_symbols.get(index)
        )


ScriptSnippets = Analysis(
    "$ scriptsnippets",
    [
        # number of spaces per tab
        Field("tabsize", "Y", 0x0, idb.netnode.as_uint),
        # netnode references
        Field("scripts", "A", NUMBERS, idb.netnode.as_uint),
    ],
)

ScriptSnippet = namedtuple("ScriptSnippet", ["name", "language", "code"])


def enumerate_script_snippets(db):
    """
    enumerate script snippets stored in the given database.

    yields:
      Tuple[str, str, str]: filename, language (Python or IDC), and source code
    """
    scripts = ScriptSnippets(db)

    for nnid in scripts.scripts.values():
        nn = idb.netnode.Netnode(db, nnid - 1)
        name = nn.supstr(0x0, tag="S")
        language = nn.supstr(0x1, tag="S")
        code = nn.supstr(0x0, tag="X")
        yield ScriptSnippet(name, language, code)
