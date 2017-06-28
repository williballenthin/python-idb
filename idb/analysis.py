import struct
import binascii
import datetime
from collections import namedtuple

import vstruct
from vstruct.primitives import v_uint32

import idb
import idb.netnode


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


class _Analysis(object):
    def __init__(self, db, nodeid, fields):
        self.idb = db
        self.nodeid = nodeid
        self.netnode = self.idb.netnode(self.nodeid)
        self.fields = fields

        self._fields_by_name = {f.name: f for f in self.fields}

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
        if field.index == '*':
            # indexes are variable, so map them to the values
            ret = {}
            for sup in self.netnode.sups(tag=field.tag):
                v = self.netnode.supval(sup, tag=field.tag)
                if field.cast is None:
                    ret[sup] = bytes(v)
                else:
                    ret[sup] = field.cast(bytes(v))
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


# supvals:
#   format1
#     index: export ordinal
#     value: function name
#   format2
#     index: EA
#     value: function name
EntryPoints = Analysis('$ entrypoints', [
    Field('ordinals',  'S', '*', idb.netnode.as_string),
    Field('addresses', 'S', '*', idb.netnode.as_string),
])


class FileRegion(vstruct.VStruct):
    def __init__(self):
        vstruct.VStruct.__init__(self)
        self.start = v_uint32()
        self.end = v_uint32()
        self.rva = v_uint32()


# supvals:
#   format1:
#     index: start effective address
#     value:
#       0x0: start effective address
#       0x4: end effective address
#       0x8: rva start?
FileRegions = Analysis('$ fileregions', [
    Field('start',  'S', '*', as_cast(FileRegion))
])


FUNCS_NODEID = '$ funcs'
# supvals:
#   format1:
#     index: effective address
#     value:
#       0x0:
#       0x4:
#       0x8:
#       0xC:
Functions = Analysis('$ funcs', [
    Field('address',  'S', '*', bytes)
])
