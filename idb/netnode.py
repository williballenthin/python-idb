import struct
import logging
from collections import namedtuple

import six


logger = logging.getLogger(__name__)


def uint32(i):
    '''
    Convert the given signed number into its 32-bit little endian unsigned number value.

    Example::

        assert uint32(-1) == 0xFFFFFFFF


    Example::

        assert uint32(1) == 1
    '''
    return struct.unpack('>I', struct.pack('>i', i))[0]


def uint64(i):
    '''
    Convert the given signed number into its 64-bit little endian unsigned number value.

    Example::

        assert uint64(-1) == 0xFFFFFFFFFFFFFFFF


    Example::

        assert uint64(1) == 1
    '''
    return struct.unpack('>Q', struct.pack('>q', i))[0]


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

    if isinstance(nodeid, six.string_types):
        return b'N' + nodeid.encode('utf-8')

    elif isinstance(nodeid, six.integer_types):
        if tag is None:
            raise ValueError('tag required')
        if not isinstance(tag, str):
            raise ValueError('tag must be a string')
        if len(tag) != 1:
            raise ValueError('tag must be a single character string')

        tag = tag.encode('ascii')

        if index is None:
            return b'.' + struct.pack('>' + wordformat + 'c', nodeid, tag)
        elif index < 0:
            return b'.' + struct.pack('>' + wordformat + 'c' + wordformat.lower(), nodeid, tag, index)
        else:
            return b'.' + struct.pack('>' + wordformat + 'c' + wordformat, nodeid, tag, index)
    else:
        raise ValueError('unexpected type of nodeid: ' + str(type(nodeid)))


ComplexKey = namedtuple('ComplexKey', ['nodeid', 'tag', 'index'])

TAG_LENGTH = 1
KEY_HEADER_LENGTH = 1


def parse_key(buf, wordsize=4):
    if six.indexbytes(buf, 0x0) != 0x2E:
        raise ValueError('buf is not a complex key')

    if wordsize == 4:
        wordformat = 'I'
    elif wordsize == 8:
        wordformat = 'Q'
    else:
        raise ValueError('unexpected wordsize')

    nodeid, tag = struct.unpack_from('>' + wordformat + 'c', buf, 1)
    tag = tag.decode('ascii')
    if len(buf) >= TAG_LENGTH + 2 * wordsize + KEY_HEADER_LENGTH:
        offset = TAG_LENGTH + KEY_HEADER_LENGTH + wordsize
        index = struct.unpack_from('>' + wordformat, buf, offset)[0]
    else:
        index = None

    return ComplexKey(nodeid, tag, index)


def as_uint(buf, wordsize=None):
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


def as_int(buf, wordsize=None):
    if len(buf) == 1:
        return struct.unpack('<b', buf)[0]
    elif len(buf) == 2:
        return struct.unpack('<h', buf)[0]
    elif len(buf) == 4:
        return struct.unpack('<l', buf)[0]
    elif len(buf) == 8:
        return struct.unpack('<q', buf)[0]
    else:
        return RuntimeError('unexpected buf size')


def as_string(buf, wordsize=None):
    return bytes(buf).rstrip(b'\x00').decode('utf-8').rstrip('\x00')


# try to implement the methods here:
#
#   https://www.hex-rays.com/products/ida/support/sdkdoc/classnetnode.html


Entry = namedtuple('Entry', ['key', 'parsed_key', 'value'])


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
            for xref in nn.alts(tag='X'):
                print(xref)

        TODO: how to address the following keys:
          - $ MAX LINK
          - $ MAX NODE
          - $ MAX DESC

        these are unaddressable via IDA Pro netnodes, too.
        '''
        self.idb = db
        self.wordsize = self.idb.wordsize
        if self.wordsize == 4:
            self.nodebase = 0xFF000000
        elif self.wordsize == 8:
            self.nodebase = 0xFF00000000000000
        else:
            raise RuntimeError('unexpected wordsize')

        if isinstance(nodeid, six.string_types):
            key = make_key(nodeid, wordsize=self.wordsize)
            cursor = self.idb.id0.find(key)
            self.nodeid = as_uint(cursor.value)
            logger.info('resolved string netnode %s to %x', nodeid, self.nodeid)
        elif isinstance(nodeid, six.integer_types):
            self.nodeid = nodeid
        else:
            raise ValueError('unexpected type for nodeid')

    @staticmethod
    def get_nodebase(db):
        if db.wordsize == 4:
            return 0xFF000000
        elif db.wordsize == 8:
            return 0xFF00000000000000

    def name(self):
        '''
        fetch the name associated with the netnode.
        basically supval(tag='N')

        Returns:
          str: the name stored in the netnode.

        Raises:
          KeyError: if the name for the netnode does not exist.
        '''
        key = make_key(self.nodeid, TAGS.NAME, wordsize=self.wordsize)
        cursor = self.idb.id0.find(key)
        return as_string(cursor.value)

    def get_tag_entries(self, tag=TAGS.SUPVAL):
        '''
        generate the entries for the given tag in this netnode.

        this replaces:
          - *1st
          - *nxt
          - *last
          - *prev

        Yields:
          Entry: an entry (with key and value) under the given tag in this netnode.
        '''
        key = make_key(self.nodeid, tag, wordsize=self.wordsize)
        try:
            cursor = self.idb.id0.find_prefix(key)
        except KeyError:
            return
        while bytes(cursor.key).startswith(key):
            parsed_key = parse_key(cursor.key, wordsize=self.idb.wordsize)
            yield Entry(cursor.key, parsed_key, cursor.value)
            try:
                cursor.next()
            except IndexError:
                break

    def get_val(self, index, tag=TAGS.SUPVAL):
        '''
        fetch a sup/alt/hash/etc value from the netnode.
        the nodeid for this netnode must be an integer/effective address.

        Args:
          index (int): the index of the data to fetch.
          tag (str): single character tag.

        Returns:
          bytes: the raw data.
        '''
        key = make_key(self.nodeid, tag, index, wordsize=self.wordsize)
        cursor = self.idb.id0.find(key)
        return bytes(cursor.value)

    def supval(self, index, tag=TAGS.SUPVAL):
        return self.get_val(index, tag)

    def supstr(self, index, tag=TAGS.SUPVAL):
        return as_string(self.supval(index, tag))

    def sups(self, tag=TAGS.SUPVAL):
        '''
        this replaces:
          - sup1st
          - supnxt
          - suplast
          - supprev
        '''
        for entry in self.get_tag_entries(tag=tag):
            yield entry.parsed_key.index

    def supentries(self, tag=TAGS.SUPVAL):
        for entry in self.get_tag_entries(tag=tag):
            yield entry

    def altval(self, index, tag=TAGS.ALTVAL):
        return as_int(self.get_val(index, tag))

    def alts(self, tag=TAGS.ALTVAL):
        '''
        this replaces:
          - alt1st
          - altnxt
          - altlast
          - altprev
        '''
        for entry in self.get_tag_entries(tag=tag):
            yield entry.parsed_key.index

    def altentries(self, tag=TAGS.ALTVAL):
        for entry in self.get_tag_entries(tag=tag):
            # TODO: cast the value?
            yield entry

    def charval(self, index, tag=TAGS.CHARVAL):
        return as_int(self.get_val(index, tag))

    def chars(self, tag=TAGS.ALTVAL):
        '''
        this replaces:
          - char1st
          - charnxt
          - charlast
          - charprev
        '''
        for entry in self.get_tag_entries(tag=tag):
            yield entry.parsed_key.index

    def charentries(self, tag=TAGS.CHARVAL):
        for entry in self.get_tag_entries(tag=tag):
            yield Entry(entry.key, entry.parsed_key, as_int(entry.value))

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
        for entry in self.get_tag_entries(tag=tag):
            yield entry.parsed_key.index

    def hashentries(self, tag=TAGS.HASHVAL):
        for entry in self.get_tag_entries(tag=tag):
            yield entry

    def valobj(self):
        '''
        fetch the default netnode value.
        this is basically supval(tag='V').
        '''
        key = make_key(self.nodeid, TAGS.VALUE, wordsize=self.wordsize)
        cursor = self.idb.id0.find(key)
        return bytes(cursor.value)

    def valstr(self):
        return as_string(self.valobj())

    def value_exists(self):
        try:
            return self.valobj() is not None
        except KeyError:
            return False

    def long_value(self):
        return as_uint(self.valobj())

    def blobsize(self):
        '''
        TODO: how is this arbitrary data stored?
        '''
        raise NotImplementedError()

    def getblob(self):
        raise NotImplementedError()
