import struct
import logging
import binascii
import datetime
from collections import namedtuple

import vstruct
from vstruct.primitives import v_bytes
from vstruct.primitives import v_uint8
from vstruct.primitives import v_uint32

import idb
import idb.netnode


logger = logging.getLogger(__name__)


def as_unix_timestamp(buf):
    '''
    parse unix timestamp bytes into a timestamp.
    '''
    q = struct.unpack_from("<I", buf, 0x0)[0]
    return datetime.datetime.utcfromtimestamp(q)


def as_md5(buf):
    '''
    parse raw md5 bytes into a hex-formatted string.
    '''
    return binascii.hexlify(buf).decode('ascii')


def cast(buf, V):
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
    v = V()
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
    def inner(buf):
        return cast(buf, V)
    return inner


Field = namedtuple('Field', ['name', 'tag', 'index', 'cast'])
# namedtuple default args.
# via: https://stackoverflow.com/a/18348004/87207
Field.__new__.__defaults__ = (None,) * len(Field._fields)


class Unique(): pass

ALL = Unique()
ADDRESSES = Unique()
NUMBERS = Unique()
NODES = Unique()

VARIABLE_INDEXES = (ALL, ADDRESSES, NUMBERS, NODES)


class _Analysis(object):
    def __init__(self, db, nodeid, fields):
        self.idb = db
        self.nodeid = nodeid
        self.netnode = self.idb.netnode(self.nodeid)
        self.fields = fields

        self._fields_by_name = {f.name: f for f in self.fields}

    def _is_address(self, index):
        try:
            self.idb.id1.get_segment(index)
            return True
        except KeyError:
            return False

    def _is_node(self, index):
        if self.idb.wordsize == 4:
            return index & 0xFF000000 == 0xFF000000
        elif self.idb.wordsize == 8:
            return index & 0xFF00000000000000 == 0xFF00000000000000
        else:
            raise RuntimeError('unexpected wordsize')

    def _is_number(self, index):
        return (not self._is_address(index)) and (not self._is_node(index))

    def __getattr__(self, key):
        '''
        Example::

            assert root.version == 695

        Example::

            assert 0x401000 in entrypoints.ordinals

        Example::

            assert entrypoints.ordinals[0] == 'DllMain'
        '''
        if key not in self._fields_by_name:
            return super(Analysis, self).__getattr__(key)

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
                    ret[sup.parsed_key.index] = field.cast(bytes(sup.value))
            return ret
        else:
            # normal field with an explicit index
            v = self.netnode.supval(field.index, tag=field.tag)
            if field.cast is None:
                return bytes(v)
            else:
                return field.cast(bytes(v))

    def get_field_tag(self, name):
        '''
        Example::

            assert root.get_field_tag('version') == 'A'
        '''
        return self._fields_by_name[name].tag

    def get_field_index(self, name):
        '''
        Example::

            assert root.get_field_index('version') == -1
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


ROOT_NODEID = 'Root Node'
class ROOT_INDEX:
    '''
    via: https://github.com/williballenthin/pyidbutil/blob/master/idbtool.py#L182
    '''
    VERSION = -1           # altval
    VERSION_STRING = 1303  # supval
    PARAM = 0x41b994       # supval
    OPEN_COUNT = -4        # altval
    CREATED = -2           # altval
    CRC = -5               # altval
    MD5 = 1302             # supval


Root = Analysis('Root Node', [
    Field('crc',            'A', -5,    idb.netnode.as_int),
    Field('open_count',     'A', -4,    idb.netnode.as_int),
    Field('created',        'A', -2,    as_unix_timestamp),
    Field('version',        'A', -1,    idb.netnode.as_int),
    Field('md5',            'S', 1302,  as_md5),
    Field('version_string', 'S', 1303,  idb.netnode.as_string),
    Field('param',          'S', 0x41b94, bytes),
])


LOADER_NODEID = '$ loader name'
class LOADER_INDEX:
    PLUGIN = 0x0  # supval
    FORMAT = 0x1  # supval


Loader = Analysis('$ loader name', [
    Field('plugin', 'S', 0, idb.netnode.as_string),
    Field('format', 'S', 1, idb.netnode.as_string),
])


User = Analysis('$ user1', [
    Field('data', 'S', 0, bytes),
])


# '$ entry points' maps from ordinal/address to function name.
#
# supvals:
#   format1
#     index: export ordinal
#     value: function name
#   format2
#     index: EA
#     value: function name
EntryPoints = Analysis('$ entry points', [
    Field('ordinals',  'S', NUMBERS, idb.netnode.as_string),
    Field('addresses', 'S', ADDRESSES, idb.netnode.as_string),
    Field('all',       'S', ALL, idb.netnode.as_string),
])


class FileRegion(vstruct.VStruct):
    def __init__(self):
        vstruct.VStruct.__init__(self)
        self.start = v_uint32()
        self.end = v_uint32()
        self.rva = v_uint32()


# '$ fileregions' maps from segment start address to details about it.
#
# supvals:
#   format1:
#     index: start effective address
#     value:
#       0x0: start effective address
#       0x4: end effective address
#       0x8: rva start?
FileRegions = Analysis('$ fileregions', [
    Field('regions',  'S', ADDRESSES, as_cast(FileRegion))
])



# nodeid: ff000022 tag: S index: 0x689bd410
# FF 68 9B D4 10 81 5A FF  44 10 99 CE 20 04 00 10 00 00 00 00 00 00
# [] [addr be  ] [] [   ]
#                flags, if 0x80 set, then next is 2 bytes
#
# nodeid: ff000022 tag: S index: 0x689bd56a
# FF 68 9B D5 6A 2D FF     80  00 C0 0A 48 05 01
# [] [addr be  ] [] []     []
#                flags, if 0x80 set, then next 2 bytes

class Function(vstruct.VStruct):
    def __init__(self):
        vstruct.VStruct.__init__(self)
        self.unk0  = v_uint8()
        self.start = v_uint32(bigend=True)
        self.flags = v_uint8()
        self.unk05 = v_bytes()

    def pcb_flags(self):
        if self.flags & 0x80:
            self['unk05'].vsSetLength(1)
        else:
            self['unk05'].vsSetLength(0)



# '$ funcs' maps from function effective address to details about it.
#
# supvals:
#   format1:
#     index: effective address
#     value:
#       0x0:
#       0x1: start effective address (big endian)
#       0x4:
#       0x8:
#       0xC:
Functions = Analysis('$ funcs', [
    Field('functions',  'S', ADDRESSES, as_cast(Function)),
])
