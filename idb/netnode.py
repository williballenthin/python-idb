import struct
import logging
from collections import namedtuple

import vstruct
from vstruct.primitives import v_zstr
from vstruct.primitives import v_bytes
from vstruct.primitives import v_uint8
from vstruct.primitives import v_uint16
from vstruct.primitives import v_uint32
from vstruct.primitives import v_uint64


logger = logging.getLogger(__name__)

class TAGS:
    '''
    via: https://www.hex-rays.com/products/ida/support/sdkdoc/group__nn__res.html#gaedcc558fe55e19ebc6e304ba7ad8c4d6
    '''
    ALTVAL = 'A'
    SUPVAL = 'S'
    CHARVAL = 'C'  # this is just a guess...
    HASHVAL = 'H'
    VALUE = 'V'
    NAME = 'N'
    LINK = 'L'


def make_key(nodeid, tag=None, index=None, wordsize=4):
    '''

    Example::

        k = make_key('Root Node')


    Example::

        k = make_key(0x401000, 'X')

    Example::

        k = make_key(0x401000, 'X', 0x4010A24)
    '''
    if wordsize == 4:
        wordformat = 'I'
    elif wordsize == 8:
        wordformat = 'Q'
    else:
        raise ValueError('unexpected wordsize')

    if isinstance(nodeid, str):
        return b'N' + nodeid.encode('utf-8')

    elif isinstance(nodeid, int):
        if tag is None:
            raise ValueError('tag required')
        if isinstance(tag, str):
            if len(tag) != 1:
                raise ValueError('tag must be a single character string')
            tag = tag.encode('ascii')
        else:
            raise ValueError('tag must be a string')

        if index is None:
            return b'.' + struct.pack('>' + wordformat + 'c', nodeid, tag)
        else:
            return b'.' + struct.pack('>' + wordformat + 'ci', nodeid, tag, index)
    else:
        raise ValueError('unexpected type of nodeid')


ComplexKey = namedtuple('ComplexKey', ['nodeid', 'tag', 'index'])


def parse_key(buf, wordsize=4):
    if wordsize == 4:
        wordformat = 'I'
    elif wordsize == 8:
        wordformat = 'Q'
    else:
        raise ValueError('unexpected wordsize')

    if buf[0] != 0x2E:
        raise ValueError('buf is not a complex key')

    nodeid, tag = struct.unpack_from('>' + wordformat + 'c', buf, 1)
    tag = tag.decode('ascii')
    if len(buf) > 1 + 4 + 1:
        index = struct.unpack_from('>' + wordformat.lower(), buf, 6)[0]
    else:
        index = None

    return ComplexKey(nodeid, tag, index)


def deref(db, name, wordsize=4):
    key = make_key(name, wordsize=wordsize)
    cursor = db.id0.find(key)
    if wordsize == 4:
        return struct.unpack('<I', cursor.value)[0]
    elif wordsize == 8:
        return struct.unpack('<Q', cursor.value)[0]
    else:
        raise ValueError('unexpected wordsize')


def as_int(buf):
    if buf is None:
        raise KeyError((nodeid, tag, index))

    if len(buf) == 1:
        return struct.unpack('<B', buf)[0]
    elif len(buf) == 2:
        return struct.unpack('<H', buf)[0]
    elif len(buf) == 4:
        return struct.unpack('<L', buf)[0]
    elif len(buf) == 8:
        return struct.unpack('<Q', buf)[0]
    else:
        return RuntimeError('unexpected buf size')


def as_string(buf):
    if buf is None:
        raise KeyError((nodeid, tag, index))
    return bytes(buf).rstrip(b'\x00').decode('utf-8').rstrip('\x00')


def as_bytes(buf):
    if buf is None:
        raise KeyError((nodeid, tag, index))
    return bytes(buf)


class ROOT_INDEX:
    '''
    via: https://github.com/williballenthin/pyidbutil/blob/master/idbtool.py#L182
    '''
    VERSION = -1
    VERSION_STRING = 1303
    PARAM = 0x41b994
    OPEN_COUNT = -4
    CREATED = -2
    CRC = -5
    MD5 = 1302


# try to implement the methods here:
#
#   https://www.hex-rays.com/products/ida/support/sdkdoc/netnode_8hpp.html
#   https://www.hex-rays.com/products/ida/support/sdkdoc/classnetnode.html


class Netnode(object):
    def __init__(self, db, nodeid):
        '''
        Args:
          db (idb.IDB): the IDA Pro database.
          nodeid (Union[str, int]): the node id used to identify the netnode.


        Example::

            nn = Netnode("Root Node")
            print(nn.supval(1303))  # --> "6.95"

        Example::

            nn = Netnode(0x401000)
            TODO


        TODO: how to address the following keys:
          - $ MAX LINK
          - $ MAX NODE
          - $ MAX DESC

        these are unaddressable via IDA Pro netnodes, too.
        '''
        self.idb = db
        self.nodeid = nodeid
        self.wordsize = self.idb.wordsize

    def name(self):
        if isinstance(self.nodeid, str):
            return self.nodeid
        else:
            return ''

    def valobj(self):
        if not isinstance(self.nodeid, str):
            raise KeyError(self.nodeid)

        key = make_key(self.nodeid, wordsize=self.wordsize)
        cursor = self.idb.id0.find(key)
        return bytes(cursor.value)

    def valstr(self):
        return self.valobj().decode('utf-8').rstrip('\x00')

    def value_exists(self):
        try:
            return self.valobj() is not None
        except KeyError:
            return False

    def long_value(self):
        v = self.valobj()
        return struct.unpack('<I', v)[0]

    def deref(self):
        ptr = self.long_value()
        return Netnode(self.idb, ptr)

    def keys(self, tag=TAGS.SUPVAL):
        '''
        this replaces:
          - *1st
          - *nxt
          - *last
          - *prev
        '''
        if not isinstance(self.nodeid, int):
            raise KeyError((self.nodeid, index, tag))

        key = make_key(self.nodeid, tag, wordsize=self.wordsize)

        # this probably doesn't work...
        # need prefix matching
        cursor = db.id0.find(key)
        while cursor.key.startswith(key):
            yield cursor.key
            try:
                cursor.next()
            except IndexError:
                break

    def get_val(self, index, tag=TAGS.SUPVAL):
        '''
        fetch a sup/alt/hash/etc value from the netnode.
        the nodeid for this netnode must be an integer/effective address.
        '''
        if not isinstance(self.nodeid, int):
            raise KeyError((self.nodeid, index, tag))

        key = make_key(self.nodeid, tag, index, wordsize=self.wordsize)
        cursor = self.idb.id0.find(key)
        return bytes(cursor.value)

    def supval(self, index, tag=TAGS.SUPVAL):
        return self.get_val(index, tag)

    def supstr(self, index, tag=TAGS.SUPVAL):
        return self.supval(index, tag).decode('utf-8').rstrip('\x00')

    def sups(self, tag=TAGS.SUPVAL):
        '''
        this replaces:
          - sup1st
          - supnxt
          - suplast
          - supprev
        '''
        return self.keys(tag=tag)

    def altval(self, index, tag=TAGS.ALTVAL):
        return struct.unpack('<I', self.get_val(index, tag))[0]

    def alts(self, tag=TAGS.ALTVAL):
        '''
        this replaces:
          - alt1st
          - altnxt
          - altlast
          - altprev
        '''
        return self.keys(tag=tag)

    def charval(self, index, tag=TAGS.CHARVAL):
        return struct.unpack('<C', self.get_val(index, tag))[0]

    def chars(self, tag=TAGS.ALTVAL):
        '''
        this replaces:
          - char1st
          - charnxt
          - charlast
          - charprev
        '''
        return self.keys(tag=tag)

    def hashval(self, index, tag=TAGS.HASHVAL):
        '''
        TODO: how is this different from a supval?
        '''
        return self.get_val(index, tag)

    def hashes(self, tag=TAGS.HASHVAL):
        '''
        this replaces:
          - hash1st
          - hashnxt
          - hashlast
          - hashprev
        '''
        return self.keys(tag=tag)

    def blobsize(self):
        '''
        TODO: how is this arbitrary data stored?
        '''
        raise NotImplementedError()

    def getblob(self):
        raise NotImplementedError()
