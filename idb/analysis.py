import types
import struct
import logging
import binascii
import datetime
import itertools
from collections import namedtuple

import six
import vstruct
from vstruct.primitives import v_str
from vstruct.primitives import v_bytes
from vstruct.primitives import v_uint8
from vstruct.primitives import v_uint16
from vstruct.primitives import v_uint32
from vstruct.primitives import v_uint64

import idb
import idb.netnode


logger = logging.getLogger(__name__)


def is_flag_set(flags, flag):
    return flags & flag == flag


def as_unix_timestamp(buf, wordsize=None):
    '''
    parse unix timestamp bytes into a timestamp.
    '''
    q = struct.unpack_from("<I", buf, 0x0)[0]
    return datetime.datetime.utcfromtimestamp(q)


def as_md5(buf, wordsize=None):
    '''
    parse raw md5 bytes into a hex-formatted string.
    '''
    return binascii.hexlify(buf).decode('ascii')


def cast(buf, V, wordsize=None):
    '''
    apply a vstruct class to a sequence of bytes.

    Args:
        buf (bytes): the bytes to parse.
        V (type[vstruct.VStruct]): the vstruct class.

    Returns:
        V: the parsed instance of V.

    Example::

        s = cast(buf, Stat)
        assert s.gid == 0x1000
    '''
    v = V(wordsize=wordsize)
    v.vsParse(buf)
    return v


def as_cast(V):
    '''
    create a partial function that casts buffers to the given vstruct.

    Args:
        V (type[vstruct.VStruct]): the vstruct class.

    Returns:
        callable[bytes]->V: the function that parses buffers into V instances.

    Example::

        S = as_cast(Stat)
        s = S(buf)
        assert s.gid == 0x1000
    '''
    def inner(buf, wordsize=None):
        return cast(buf, V, wordsize=wordsize)
    setattr(inner, 'V', V.__name__)
    return inner


def unpack_dd(buf, offset=0):
    '''
    unpack up to 32-bits using the IDA-specific data packing format.

    Args:
      buf (bytes): the region to parse.
      offset (int): the offset into the region from which to unpack. default: 0.

    Returns:
      (int, int): the parsed dword, and the number of bytes consumed.

    Raises:
      KeyError: if the bounds of the region are exceeded.
    '''
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
            hi = (((header & 0x3F) << 8) + six.indexbytes(buf, 0x1))
            low = (six.indexbytes(buf, 0x2) << 8) + six.indexbytes(buf, 0x3)
            size = 4
        return (hi << 16) + low, size


def unpack_dw(buf, offset=0):
    '''
    unpack word.
    '''
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
    '''
    unpack qword.
    '''
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
            logger.debug('%s at %x: %x', unpack_fn.__name__, self.offset, v)
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
            raise RuntimeError('unexpected wordsize')


Field = namedtuple('Field', ['name', 'tag', 'index', 'cast', 'minver'])
# namedtuple default args.
# via: https://stackoverflow.com/a/18348004/87207
Field.__new__.__defaults__ = (None,) * len(Field._fields)


class IndexType:
    def __init__(self, name):
        self.name = name

    def str(self):
        return self.name.upper()


ALL = IndexType('all')
ADDRESSES = IndexType('addresses')
NUMBERS = IndexType('numbers')
NODES = IndexType('nodes')

VARIABLE_INDEXES = (ALL, ADDRESSES, NUMBERS, NODES)


class _Analysis(object):
    '''
    this is basically a metaclass for analyzers of IDA Pro netnode namespaces (named nodeid).
    provide set of fields, and parse them from netnodes (nodeid, tag, and optional index)
     when accessed.
    '''

    def __init__(self, db, nodeid, fields):
        self.idb = db
        self.nodeid = nodeid
        self.netnode = idb.netnode.Netnode(db, nodeid)
        self.fields = fields

        idb_version = idb.netnode.Netnode(db, 'Root Node').altval(index=-1)

        # note that order of fields is important:
        #   fields with matching minvers override previously defined fields of the same name
        self._fields_by_name = {f.name: f for f in self.fields
                                if (not f.minver) or
                                   (f.minver and
                                    idb_version >= f.minver)}

    def _is_address(self, index):
        '''
        does the given index fall within a segment?
        '''
        try:
            self.idb.id1.get_segment(index)
            return True
        except KeyError:
            return False

    def _is_node(self, index):
        '''
        does the index look like a raw nodeid?
        '''
        if self.idb.wordsize == 4:
            return index & 0xFF000000 == 0xFF000000
        elif self.idb.wordsize == 8:
            return index & 0xFF00000000000000 == 0xFF00000000000000
        else:
            raise RuntimeError('unexpected wordsize')

    def _is_number(self, index):
        '''
        does the index look like not (address or node)?
        '''
        return (not self._is_address(index)) and (not self._is_node(index))

    def __getattr__(self, key):
        '''
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
        '''
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
                raise ValueError('unexpected index')

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
                return field.cast(bytes(v),
                                  wordsize=self.idb.wordsize)

    def get_field_tag(self, name):
        '''
        get the tag associated with the given field name.

        Example::

            assert root.get_field_tag('version') == 'A'

        Args:
          key (str): the name of the field to fetch.

        Returns:
          str: a single character string tag.
        '''
        return self._fields_by_name[name].tag

    def get_field_index(self, name):
        '''
        get the index associated with the given field name.
        Example::

            assert root.get_field_index('version') == root.db.uint(-1)

        Args:
          key (str): the name of the field to fetch.

        Returns:
          int or IndexType: the index, if its specified.
            otherwise, this will be an `IndexType` that indicates what indices are expected.
        '''
        return self._fields_by_name[name].index


def Analysis(nodeid, fields):
    '''
    build a partial constructor for _Analysis with the given nodeid and fields.

    Example::

        Root = Analysis('Root Node', [Field(...), ...])
        root = Root(some_idb)
        assert root.version == 695
    '''
    def inner(db):
        return _Analysis(db, nodeid, fields)
    return inner


class IdaInfo(vstruct.VStruct):
    # ref: https://www.hex-rays.com/products/ida/support/sdkdoc/structidainfo.html

    def __init__(self, wordsize):
        vstruct.VStruct.__init__(self)

        if wordsize == 4:
            v_word = v_uint32
        elif wordsize == 8:
            v_word = v_uint64
        else:
            raise ValueError('unexpected wordsize')

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

        self.tag = v_str(size=0x3)  # 'IDA' below 7.0, 'ida' in 7.0
        self.zero = v_bytes(size=0x0)
        self.version = v_uint16()
        self.procname_size = v_bytes(size=0x0)
        self.procname = v_str(size=0x10)
        # TODO: the exact layout, particularly across versions, of the below is unknown.
        #self.s_genflags = v_uint16()
        #self.lflags = v_uint32()
        #self.database_change_count = v_uint32()
        #self.filetype = v_uint16()
        #self.ostype = v_uint16()
        #self.apptype = v_uint16()
        #self.asmtype = v_uint8()
        #self.specsegs = v_uint8()
        #self.af = v_uint32()
        #self.af2 = v_uint32()
        #self.baseaddr = v_word()
        #self.start_ss = v_uint32()
        #self.start_cs = v_uint32()
        #self.start_ip = v_uint32()
        #self.start_ea = v_uint32()
        #self.start_sp = v_uint32()
        #self.main = v_uint32()
        #self.min_ea = v_uint32()
        #self.max_ea = v_uint32()
        #self.omin_ea = v_uint32()
        #self.omax_ea = v_uint32()
        #self.lowoff = v_uint32()
        #self.highoff = v_uint32()
        #self.maxref = v_word()
        # ... and a bunch of other stuff

    def pcb_tag(self):
        if self.tag == 'IDA':
            # under 7.0
            pass
        elif self.tag == 'ida':
            # 7.0
            self['zero'].vsSetLength(0x1)
        else:
            raise NotImplementedError('raise unknown database tag: ' + self.tag)

    def pcb_version(self):
        # 6.95 database upgraded to v7.0b
        # we have a single byte that describes how long the procname is.
        if self.tag == 'IDA' and self.version == 700:
            self['procname_size'].vsSetLength(0x1)

    def pcb_procname_size(self):
        # 6.95 database upgraded to v7.0b
        # we have a single byte that describes how long the procname is.
        if self.procname_size:
            size = six.indexbytes(self.procname_size, 0x0)
            self['procname'].vsSetLength(size)

    @property
    def procName(self):
        return self.procname


Root = Analysis('Root Node', [
    Field('imagebase',      'A', -6,       idb.netnode.as_int),
    Field('crc',            'A', -5,       idb.netnode.as_int),
    Field('open_count',     'A', -4,       idb.netnode.as_int),
    Field('created',        'A', -2,       as_unix_timestamp),
    Field('version',        'A', -1,       idb.netnode.as_int),
    Field('md5',            'S', 1302,     as_md5),
    Field('version_string', 'S', 1303,     idb.netnode.as_string),
    Field('idainfo',        'S', 0x41b994, as_cast(IdaInfo)),
    Field('input_file_path','V', None,     idb.netnode.as_string)
])


Loader = Analysis('$ loader name', [
    Field('plugin', 'S', 0, idb.netnode.as_string),
    Field('format', 'S', 1, idb.netnode.as_string),
])


# see `scripts/dump_user.py` for intepretation.
OriginalUser = Analysis('$ original user', [
    Field('data', 'S', 0, bytes),
])


# see `scripts/dump_user.py` for intepretation.
User = Analysis('$ user1', [
    Field('data', 'S', 0, bytes),
])


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
            raise ValueError('unexpected wordsize')

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
FileRegions = Analysis('$ fileregions', [
    Field('regions',  'S', ADDRESSES, as_cast(FileRegion)),
    Field('regions',  'S', ADDRESSES, FileRegionV70, minver=700),
])


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
            try:
                self.owner = self.startEA - u.addr()
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
Functions = Analysis('$ funcs', [
    Field('functions', 'S', ADDRESSES, func_t),
    Field('comments', 'C', ADDRESSES, idb.netnode.as_string),
    Field('repeatable_comments', 'R', ADDRESSES, idb.netnode.as_string),
])


class PString(vstruct.VStruct):
    '''
    short pascal string, prefixed with single byte length.
    '''

    def __init__(self, length_is_total=True):
        vstruct.VStruct.__init__(self)
        self.length = v_uint8()
        self.s = v_str()
        self.length_is_total = length_is_total

    def pcb_length(self):
        length = self.length
        if self.length_is_total:
            length = length - 1
        self['s'].vsSetLength(length)


class TypeString(vstruct.VStruct):
    def __init__(self):
        vstruct.VStruct.__init__(self)
        self.header = v_uint8()
        self.length = v_uint8()
        self.s = v_str()

    def pcb_header(self):
        if self.header != 0x3D:
            raise RuntimeError('unexpected type header')

    def pcb_length(self):
        length = self.length
        self['s'].vsSetLength(length - 1)


class StructMember:
    def __init__(self, db, nodeid):
        self.idb = db

        self.nodeid = nodeid
        self.netnode = idb.netnode.Netnode(db, self.nodeid)

    def get_name(self):
        return self.netnode.name().partition('.')[2]

    def get_type(self):
        # nodeid: ff000078 tag: S index: 0x3000
        # 00000000: 3D 0A 48 49 4E 53 54 41  4E 43 45 00              =.HINSTANCE.

        v = self.netnode.supval(tag='S', index=0x3000)
        s = TypeString()
        s.vsParse(v)
        return s.s

    def get_enum_id(self):
        return self.altval(tag='A', index=0xB)

    def get_struct_id(self):
        return self.altval(tag='A', index=0x3)

    def get_member_comment(self):
        return self.supstr(tag='S', index=0x0)

    def get_repeatable_member_comment(self):
        return self.supstr(tag='S', index=0x1)

    # TODO: tag='A', index=0x10
    # TODO: tag='S', index=0x9, "ptrseg"

    def __str__(self):
        try:
            typ = self.get_type()
        except KeyError:
            return 'StructMember(name: %s)' % (self.get_name())
        else:
            return 'StructMember(name: %s, type: %s)' % (self.get_name(), typ)


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
    '''
    Example::

        struc = Struct(idb, 0xFF000075)
        assert struc.get_name() == 'EXCEPTION_INFO'
        assert len(struc.get_members()) == 5
        assert list(struc.get_members())[0].get_type() == 'DWORD'
    '''
    def __init__(self, db, structid):
        self.idb = db

        # if structid doesn't start with 0xFF0000..., add it.
        nodebase = idb.netnode.Netnode.get_nodebase(db)
        if structid < nodebase:
            structid += nodebase

        self.nodeid = structid
        self.netnode = idb.netnode.Netnode(db, self.nodeid)

    def get_members(self):
        v = self.netnode.supval(tag='M', index=0)
        u = Unpacker(v, wordsize=self.idb.wordsize)
        flags = u.dd()
        count = u.dd()

        if not flags & STRUCT_FLAGS.SF_FRAME:
            raise RuntimeError('unexpected frame header')

        for i in range(count):
            nodeid_offset = u.addr()
            _ = u.addr()
            _ = u.addr()
            _ = u.dd()
            _ = u.dd()

            member_nodeid = self.netnode.nodebase + nodeid_offset
            yield StructMember(self.idb, member_nodeid)


def chunks(l, n):
    '''
    Yield successive n-sized chunks from l.
    via: https://stackoverflow.com/a/312464/87207
    '''
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
                v = l[i:i + n]
                yield v
            except IndexError:
                return
            i += n


def pairs(l):
    return chunks(l, 2)


Chunk = namedtuple('Chunk', ['effective_address', 'length'])
FunctionParameter = namedtuple('FunctionParameter', ['type', 'name'])
FunctionSignature = namedtuple('FunctionSignature', ['calling_convention', 'rtype', 'unk', 'parameters'])
StackChangePoint = namedtuple('StackChangePoint', ['effective_address', 'change'])


class Function:
    '''
    Example::

        func = Function(idb, 0x401000)
        assert func.get_name() == 'DllEntryPoint'
        assert func.get_signature() == '... DllEntryPoint(...)'
    '''

    def __init__(self, db, fva):
        self.idb = db
        self.nodeid = fva
        self.netnode = idb.netnode.Netnode(db, self.nodeid)

    def get_name(self):
        try:
            return self.netnode.name()
        except KeyError:
            return 'sub_%X' % (self.nodeid)

    def get_signature(self):
        typebuf = self.netnode.supval(tag='S', index=0x3000)
        namebuf = self.netnode.supval(tag='S', index=0x3001)

        if six.indexbytes(typebuf, 0x0) != 0xC:
            raise RuntimeError('unexpected signature header')

        if six.indexbytes(typebuf, 0x1) == ord('S'):
            # this is just a guess...
            conv = '__stdcall'
        else:
            raise NotImplementedError()

        rtype = TypeString()
        rtype.vsParse(typebuf, offset=2)

        # this is a guess???
        sp_delta = typebuf[2 + len(rtype)]

        params = []
        typeoffset = 0x2 + len(rtype) + 0x1
        nameoffset = 0x0
        while typeoffset < len(typebuf):
            if six.indexbytes(typebuf, typeoffset) == 0x0:
                break
            typename = TypeString()
            typename.vsParse(typebuf, offset=typeoffset)
            typeoffset += len(typename)

            paramname = PString()
            paramname.vsParse(namebuf, offset=nameoffset)
            nameoffset += len(paramname)

            params.append(FunctionParameter(typename.s, paramname.s))

        return FunctionSignature(conv, rtype.s, sp_delta, params)

    def get_chunks(self):
        v = self.netnode.supval(tag='S', index=0x7000)

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
            raise RuntimeError('unexpected wordsize')

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
            v = self.netnode.supval(tag='S', index=0x1000)
        except KeyError:
            return
        offset = self.nodeid

        if self.idb.wordsize == 4:
            unpacker = unpack_dds
        elif self.idb.wordsize == 8:
            unpacker = unpack_dqs
        else:
            raise RuntimeError('unexpected wordsize')
        for (delta, change) in pairs(unpacker(v)):
            offset += delta
            if change & 1:
                change = change >> 1
            else:
                change = -(change >> 1)

            yield StackChangePoint(offset, change)


Xref = namedtuple('Xref', ['src', 'dst', 'type'])


def _get_xrefs(db, tag, src=None, dst=None, types=None):
    if src is None and dst is None:
        raise ValueError('one of src or dst must be provided')

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
    '''
    fetches the code references to the given address.

    Args:
      db (idb.IDB): the database.
      ea (int): the effective address from which to fetch xrefs.
      types (collection of int): if provided, a whitelist collection of xref types to include.

    Yields:
      int: xref address.
    '''
    return _get_xrefs(db, dst=ea, tag='X', types=types)


def get_crefs_from(db, ea, types=None):
    '''
    fetches the code references from the given address.

    Args:
      db (idb.IDB): the database.
      ea (int): the effective address from which to fetch xrefs.
      types (collection of int): if provided, a whitelist collection of xref types to include.

    Yields:
      int: xref address.
    '''
    return _get_xrefs(db, src=ea, tag='x', types=types)


def get_drefs_to(db, ea, types=None):
    '''
    fetches the data references to the given address.

    Args:
      db (idb.IDB): the database.
      ea (int): the effective address from which to fetch xrefs.
      types (collection of int): if provided, a whitelist collection of xref types to include.

    Yields:
      int: xref address.
    '''
    return _get_xrefs(db, dst=ea, tag='D', types=types)


def get_drefs_from(db, ea, types=None):
    '''
    fetches the data references from the given address.

    Args:
      db (idb.IDB): the database.
      ea (int): the effective address from which to fetch xrefs.
      types (collection of int): if provided, a whitelist collection of xref types to include.

    Yields:
      int: xref address.
    '''
    return _get_xrefs(db, src=ea, tag='d', types=types)


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
            raise ValueError('unexpected wordsize')

    def pcb_type(self):
        if self.type != 0x04:
            raise NotImplementedError(
                'fixup type %x not yet supported' %
                (self.type))

    def get_fixup_length(self):
        if self.type == 0x4:
            return 0x4
        else:
            raise NotImplementedError(
                'fixup type %x not yet supported' %
                (self.type))


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
            raise NotImplementedError(
                'fixup type %x not yet supported' %
                (self.type))

    def get_fixup_length(self):
        if self.type == 0x8:
            return 0x4
        else:
            raise NotImplementedError(
                'fixup type %x not yet supported' %
                (self.type))


# '$ fixups' maps from fixup start address to details about it.
Fixups = Analysis('$ fixups', [
    Field('fixups', 'S', ADDRESSES, as_cast(Fixup)),
    Field('fixups', 'S', ADDRESSES, FixupV70, minver=700),
])


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


SegStrings = Analysis('$ segstrings', [
    Field('strings', 'S', 0, parse_seg_strings),
])


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
Segments = Analysis('$ segs', [
    # we use `ALL` for the index type because `_is_address` above does not recognize
    #  addresses not backed by flags/bytes in the IDB.
    # there may be segments for the `.bss`, `extern`, etc sections here, and these
    #  do not have associated flags/bytes.
    # therefore, until we fix `is_address`, being slightly imprecise here works better.
    # note: all indexes in the `$ segs` netnode are addresses, so this assumption works ok.
    Field('segments', 'S', ALL, Seg),
])


Imports = Analysis('$ imports', [
    # index: entry number, value: node id
    Field('lib_netnodes', 'A', NUMBERS, idb.netnode.as_uint),
    # index: entry number, value: dll name
    Field('lib_names', 'S', NUMBERS, idb.netnode.as_string),
])


Import = namedtuple('Import', ['library', 'function_name', 'function_address'])


def enumerate_imports(db):
    '''
    enumerate the functions imported by the module in the given database.

    yields:
      Tuple[str, str, int]: library name, function name, function address
    '''
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
                logger.warning('failed to find import supval: %x', funcaddr)
                continue


EntryPoints = Analysis('$ entry points', [
    # index: ordinal, value: address, terminated by index: uint(-1)
    Field('functions', 'A', NUMBERS, idb.netnode.as_uint),
    # index: address, value: address, should be only one?
    Field('main_entry', 'A', ADDRESSES, idb.netnode.as_uint),
    # index: ordinal, value: ordinal
    Field('ordinals', 'I', NUMBERS, idb.netnode.as_uint),
    # index: ordinal, value: string like (NTDLL!Rtl...)
    Field('forwarded_symbols', 'F', NUMBERS, idb.netnode.as_string),
    # index: ordinal, value: string like (Rtl...)
    Field('function_names', 'S', NUMBERS, idb.netnode.as_string),
    # index: address, value: string like (Rtl...), should be only one?
    Field('main_entry_name', 'S', ADDRESSES, idb.netnode.as_string),
])


EntryPoint = namedtuple('EntryPoint', ['name', 'address', 'ordinal', 'forwarded_symbol'])


def enumerate_entrypoints(db):
    '''
    enumerate the entry point functions in the given database.

    yields:
      Tuple[str, int, int, str]: function name, address, ordinal (optional), and forwarded symbol (optional)
    '''
    ents = EntryPoints(db)

    ordinals = ents.ordinals
    forwarded_symbols = ents.forwarded_symbols
    names = ents.function_names
    names.update(ents.main_entry_name)

    for index, addr in ents.functions.items():
        if index == db.uint(-1):
            break
        yield EntryPoint(names.get(index), addr, ordinals.get(index), forwarded_symbols.get(index))

    for index, addr in ents.main_entry.items():
        yield EntryPoint(names.get(index), addr, ordinals.get(index), forwarded_symbols.get(index))
