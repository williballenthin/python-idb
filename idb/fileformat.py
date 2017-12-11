'''
lots of inspiration from: https://github.com/nlitsme/pyidbutil
'''
import abc
import zlib
import struct
import logging
import functools
from collections import namedtuple

import vstruct
from vstruct.primitives import v_bytes
from vstruct.primitives import v_uint8
from vstruct.primitives import v_uint16
from vstruct.primitives import v_uint32
from vstruct.primitives import v_uint64

import idb
import idb.netnode


logger = logging.getLogger(__name__)


class FileHeader(vstruct.VStruct):
    def __init__(self):
        vstruct.VStruct.__init__(self)
        # list of offsets to section headers.
        # order should line up with the SECTIONS definition (see below).
        self.offsets = []
        # list of checksums of sections.
        # order should line up with the SECTIONS definition.
        self.checksums = []

        self.signature = v_bytes(size=0x4)  # IDA1 | IDA2
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
        if self.signature not in (b'IDA1', b'IDA2'):
            raise ValueError('bad signature')
        if self.sig2 != 0xAABBCCDD:
            raise ValueError('bad sig2')
        if self.version != 0x6:
            raise ValueError('unsupported version')
        return True


class COMPRESSION_METHOD:
    NONE = 0
    ZLIB = 2


class SectionHeader(vstruct.VStruct):
    def __init__(self):
        vstruct.VStruct.__init__(self)
        self.compression_method = v_uint8()
        self.length = v_uint64()
        self.is_compressed = False

    def pcb_compression_method(self):
        if self.compression_method == COMPRESSION_METHOD.NONE:
            self.is_compressed = False
        else:
            self.is_compressed = True


class Section(vstruct.VStruct):
    def __init__(self):
        vstruct.VStruct.__init__(self)
        self.header = SectionHeader()
        self._contents = v_bytes()
        self.contents = b''

    def vsEmit(self, **kwargs):
        if self.header.is_compressed:
            raise NotImplementedError('Section may not be serialized because it was compressed')

        vstruct.VStruct.vsEmit(self, **kwargs)

    def pcb_header(self):
        self['_contents'].vsSetLength(self.header.length)

    def pcb__contents(self):
        if not self.header.is_compressed:
            self.contents = self._contents
        else:
            self.contents = zlib.decompress(self._contents)
            logger.debug('decompressed parsed section.')

    def validate(self):
        if self.header.length == 0:
            raise ValueError('zero size')
        return True


# sizeof(BranchEntryPointer)
# sizeof(BranchEntry)
# sizeof(LeafEntry)
# sizeof(LeafEntryPointer)
SIZEOF_ENTRY = 0x6


class BranchEntryPointer(vstruct.VStruct):
    def __init__(self):
        vstruct.VStruct.__init__(self)
        self.page = v_uint32()
        self.offset = v_uint16()


class BranchEntry(vstruct.VStruct):
    def __init__(self, page):
        vstruct.VStruct.__init__(self)
        self.page = page
        self.key_length = v_uint16()
        self.key = v_bytes()
        self.value_length = v_uint16()
        self.value = v_bytes()

    def pcb_key_length(self):
        self['key'].vsSetLength(self.key_length)

    def pcb_value_length(self):
        self['value'].vsSetLength(self.value_length)


class LeafEntryPointer(vstruct.VStruct):
    def __init__(self):
        vstruct.VStruct.__init__(self)
        self.common_prefix = v_uint16()
        self.unk02 = v_uint16()
        self.offset = v_uint16()


class LeafEntry(vstruct.VStruct):
    def __init__(self, key, common_prefix):
        vstruct.VStruct.__init__(self)
        self.pkey = key
        self.common_prefix = common_prefix

        self.key_length = v_uint16()
        self._key = v_bytes()
        self.value_length = v_uint16()
        self.value = v_bytes()

        self.key = None

    def pcb_key_length(self):
        self['_key'].vsSetLength(self.key_length)

    def pcb_value_length(self):
        self['value'].vsSetLength(self.value_length)

    def pcb__key(self):
        self.key = self.pkey[:self.common_prefix] + self._key


class Page(vstruct.VStruct):
    '''
    single node in the b-tree.
    has a bunch of key-value entries that may point to other pages.
    binary search these keys and traverse pointers to efficienty query the index.

    branch node::

                                      +-------------+
        +-----------------------------+ ppointer    |  ----> [ node with keys less than entry1.key]
        | entry1.key | entry1.value   |-------------+
        +-----------------------------+ entry1.page |  ----> [ node with entry1.key < X < entry2.key]
        | entry2.key | entry2.value   |-------------+
        +-----------------------------+ entry2.page |  ----> [ node with entry2.key < X < entry3.key]
        | ...        | ...            |-------------+
        +-----------------------------+ ...         |
        | entryN.key | entryN.value   |-------------+
        +-----------------------------+ entryN.key  |  ----> [ node with keys greater than entryN.key]
                                      +-------------+

    leaf node::

        +-----------------------------+
        | entry1.key | entry1.value   |
        +-----------------------------+
        | entry2.key | entry2.value   |
        +-----------------------------+
        | ...        | ...            |
        +-----------------------------+
        | entryN.key | entryN.value   |
        +-----------------------------+

    '''

    def __init__(self, page_size, page_number):
        vstruct.VStruct.__init__(self)
        self.page_number = page_number
        self.ppointer = v_uint32()
        self.entry_count = v_uint16()
        self.contents = v_bytes(page_size)
        # ordered cache of entries, once loaded.
        self._entries = []

    def is_leaf(self):
        '''
        return True if this is a leaf node.

        Returns:
          bool: True if this is a leaf node.
        '''
        return self.ppointer == 0

    def _load_entries(self):
        if not self._entries:
            key = b''
            for i in range(self.entry_count):
                if self.is_leaf():
                    ptr = LeafEntryPointer()
                    ptr.vsParse(self.contents, offset=i * SIZEOF_ENTRY)

                    entry = LeafEntry(key, ptr.common_prefix)
                    entry.vsParse(self.contents, offset=ptr.offset - SIZEOF_ENTRY)
                else:
                    ptr = BranchEntryPointer()
                    ptr.vsParse(self.contents, offset=i * SIZEOF_ENTRY)

                    entry = BranchEntry(int(ptr.page))
                    entry.vsParse(self.contents, offset=ptr.offset - SIZEOF_ENTRY)
                self._entries.append(entry)
                key = entry.key

    def get_entries(self):
        '''
        generate the entries from this page in order.
        each entry is guaranteed to have the following fields:
          - key
          - value

        Yields:
          Union[BranchEntry, LeafEntry]: the b-tree entries from this page.
        '''
        self._load_entries()
        for entry in self._entries:
            yield entry

    def find_index(self, key):
        '''
        find the index of the exact match, or in the case of a branch node,
         the index of the least-greater entry.
        '''
        # implementation note:
        #  suprisingly, using a binary search here does not substantially improve performance.
        #  this is probably the the dominating operations are parsing and allocating entries.
        #  the linear scan below is simpler to read, so we'll use that until it becomes an issue.
        if self.is_leaf():
            for i, entry in enumerate(self.get_entries()):
                if key == bytes(entry.key):
                    return i
        else:
            for i, entry in enumerate(self.get_entries()):
                entry_key = bytes(entry.key)
                if key == entry_key:
                    return i
                elif key < entry_key:
                    # this is the least-greater entry
                    return i
                else:
                    continue
        raise KeyError(key)

    def get_entry(self, entry_number):
        '''
        get the entry at the given index.

        Arguments:
          entry_number (int): the entry index.

        Returns:
          Union[BranchEntry, LeafEntry]: the b-tree entry.

        Raises:
          KeyError: if the entry number is not in the range of entries.
        '''
        self._load_entries()
        if entry_number >= len(self._entries):
            raise KeyError(entry_number)
        return self._entries[entry_number]

    def validate(self):
        last = None
        for entry in self.get_entries():
            if last is None:
                continue

            if last.key >= entry.key:
                raise ValueError('bad page entry sort order')

            last = entry
        return True


class FindStrategy(object):
    '''
    defines the interface for strategies of searching the btree.

    implementors will provide a `.find()` method that operates on a `Cursor` instance.
    the method will update the cursor as it navigates the btree.
    '''
    __meta__ = abc.ABCMeta

    @abc.abstractmethod
    def find(self, cursor, key):
        raise NotImplementedError()


class ExactMatchStrategy(FindStrategy):
    '''
    strategy used to find the entry with exactly the key provided.
    if the exact key is not found, `KeyError` is raised.
    '''

    def _find(self, cursor, page_number, key):
        page = cursor.index.get_page(page_number)
        cursor.path.append(page)

        is_largest = False
        try:
            entry_number = page.find_index(key)
        except KeyError:
            # an entry larger than the given key is not found.
            # but we know we should be searching this node,
            #  so we must have to recurse into the final page pointer.
            is_largest = True
            entry_number = page.entry_count - 1

        entry = page.get_entry(entry_number)

        if bytes(entry.key) == key:
            cursor.entry = entry
            cursor.entry_number = entry_number
            return
        elif page.is_leaf():
            # no matches!
            raise KeyError(key)
        else:
            if is_largest:
                next_page_number = page.get_entry(page.entry_count - 1).page
            elif entry_number == 0:
                next_page_number = page.ppointer
            else:
                next_page_number = page.get_entry(entry_number - 1).page
            self._find(cursor, next_page_number, key)
            return

    def find(self, cursor, key):
        self._find(cursor, cursor.index.root_page, key)


class PrefixMatchStrategy(FindStrategy):
    '''
    strategy used to find the first entry that begins with the given key.
    it may be an exact match, or an exact match does not exist, and the result starts with the given key.
    if no entries start with the given key, `KeyError` is raised.
    '''

    def _find(self, cursor, page_number, key):
        page = cursor.index.get_page(page_number)
        cursor.path.append(page)

        if page.is_leaf():
            for i, entry in enumerate(page.get_entries()):
                entry_key = bytes(entry.key)
                if entry_key.startswith(key):
                    cursor.entry = entry
                    cursor.entry_number = i
                    return
                elif entry_key > key:
                    # as soon as we reach greater entries, we'll never match
                    break

            # pop the final path entry, cause we know its not here
            cursor.path = cursor.path[:-1]
            raise KeyError(key)
        else:  # is branch node
            next_page = page.ppointer
            for i, entry in enumerate(page.get_entries()):
                entry_key = bytes(entry.key)
                if entry_key == key:
                    cursor.entry = entry
                    cursor.entry_number = i
                    return
                elif entry_key.startswith(key):
                    # this is obviously a good match; however,
                    # there may have been an exact match in the sub-page just prior,
                    # so we need to first check that first.
                    try:
                        return self._find(cursor, next_page, key)
                    except KeyError:
                        cursor.entry = entry
                        cursor.entry_number = i
                        return
                elif entry_key > key:
                    # as soon as we reach greater entries, we'll never match.
                    # so we need to check the sub-page just prior.
                    return self._find(cursor, next_page, key)
                else:
                    next_page = entry.page

            # since we haven't found a matching entry, but we know our matches must be somewhere,
            # we need to search the final sub-page, which contains the greatest entries.
            last_entry = page.get_entry(page.entry_count - 1)
            return self._find(cursor, last_entry.page, key)

    def find(self, cursor, key):
        self._find(cursor, cursor.index.root_page, key)


class RoundDownMatchStrategy(FindStrategy):
    '''
    strategy used to find the matching key, or the key just less than the given key.
    it may be an exact match, or an exact match does not exist,
     and the result is less than the given key.
    if no entries are less than the given key, `KeyError` is raised.
    '''

    def _find(self, cursor, page_number, key):
        page = cursor.index.get_page(page_number)
        cursor.path.append(page)

        if page.is_leaf():
            for i, entry in enumerate(page.get_entries()):
                entry_key = bytes(entry.key)

                if entry_key == key:
                    cursor.entry = entry
                    cursor.entry_number = i
                    return
                elif entry_key > key:
                    if i == 0:
                        # need to handle this at the branch node, or
                        #  if this is the only node, bubbles up.
                        raise KeyError(key)
                    else:
                        cursor.entry = page.get_entry(i - 1)
                        cursor.entry_number = i - 1
            entry_number = page.entry_count - 1
            cursor.entry = page.get_entry(entry_number)
            cursor.entry_number = entry_number
        else:  # is branch node
            for i, entry in enumerate(page.get_entries()):
                entry_key = bytes(entry.key)
                if entry_key == key:
                    cursor.entry = entry
                    cursor.entry_number = i
                    return
                elif entry_key > key:
                    if i == 0:
                        # may raise KeyError, and its meant to bubble all the
                        # way up.
                        return self._find(cursor, page.ppointer, key)
                    else:
                        try:
                            entry = page.get_entry(i - 1)
                            return self._find(cursor, entry.page, key)
                        except KeyError:
                            cursor.entry = entry
                            cursor.entry_number = i - 1
                            return
                else:
                    continue

            try:
                entry = page.get_entry(page.entry_count - 1)
                return self._find(cursor, entry.page, key)
            except KeyError:
                cursor.entry = entry
                cursor.entry_number = page.entry_count - 1
                return

    def find(self, cursor, key):
        self._find(cursor, cursor.index.root_page, key)


class MinKeyStrategy(FindStrategy):
    '''
    strategy used to find the minimum key in the index.
    note: this completely ignores the provided key.
    '''

    def _find(self, cursor, page_number):
        page = cursor.index.get_page(page_number)
        cursor.path.append(page)

        if page.is_leaf():
            entry = page.get_entry(0)
            cursor.entry = entry
            cursor.entry_number = 0
        else:  # is branch node
            return self._find(cursor, page.ppointer)

    def find(self, cursor, _):
        self._find(cursor, cursor.index.root_page)


class MaxKeyStrategy(FindStrategy):
    '''
    strategy used to find the maximum key in the index.
    note: this completely ignores the provided key.
    '''

    def _find(self, cursor, page_number):
        page = cursor.index.get_page(page_number)
        cursor.path.append(page)

        if page.is_leaf():
            entry_number = page.entry_count - 1
            entry = page.get_entry(entry_number)
            cursor.entry = entry
            cursor.entry_number = entry_number
        else:  # is branch node
            entry_number = page.entry_count - 1
            entry = page.get_entry(entry_number)
            return self._find(cursor, entry.page)

    def find(self, cursor, _):
        self._find(cursor, cursor.index.root_page)


EXACT_MATCH = ExactMatchStrategy
PREFIX_MATCH = PrefixMatchStrategy
ROUND_DOWN_MATCH = RoundDownMatchStrategy
MIN_KEY = MinKeyStrategy
MAX_KEY = MaxKeyStrategy


class Cursor(object):
    '''
    represents a particular location in the b-tree.
    can be navigated "forward" and "backwards".
    '''

    def __init__(self, index):
        super(Cursor, self).__init__()
        self.index = index

        # ordered list of pages from root to leaf that we traversed to get to
        # this point
        self.path = []

        # populated once found
        self.entry = None

        self.entry_number = None

    def next(self):
        '''
        traverse to the next entry.
        updates this current cursor instance.

        Raises:
          IndexError: if the entry does not exist. the cursor is in an unknown state afterwards.
        '''
        current_page = self.path[-1]
        if current_page.is_leaf():
            if self.entry_number == current_page.entry_count - 1:
                # complex case: have to traverse up and then around.
                # we are at the end of a leaf node. so we need to go to the parent and find the next entry.
                # we may have to go up multiple parents.
                start_key = self.entry.key

                while True:
                    # pop the current node off the path
                    if len(self.path) <= 1:
                        raise IndexError()
                    self.path = self.path[:-1]

                    current_page = self.path[-1]
                    try:
                        entry_number = current_page.find_index(start_key)
                    except KeyError:
                        # not found, becaues its too big for this node.
                        # so we need to go higher.
                        continue
                    else:
                        # found a valid entry, so lets process it.
                        break

                # entry_number now points to the least-greater entry relative to start key.
                # this should be the entry that points to the page from which we just came.
                # we'll want to return the key from this entry.

                self.entry = current_page.get_entry(entry_number)
                self.entry_number = entry_number
                return

            else:  # is inner entry.
                # simple case: simply increment the entry number in the current node.
                next_entry_number = self.entry_number + 1
                next_entry = current_page.get_entry(next_entry_number)

                self.entry = next_entry
                self.entry_number = next_entry_number
                return
        else:  # is branch node.

            # follow the min-edge down to a leaf, and take the min entry.
            next_page = self.index.get_page(self.entry.page)
            while not next_page.is_leaf():
                self.path.append(next_page)
                next_page = self.index.get_page(next_page.ppointer)

            self.path.append(next_page)
            self.entry = next_page.get_entry(0)
            self.entry_number = 0
            return

    def prev(self):
        '''
        traverse to the previous entry.
        updates this current cursor instance.

        Raises:
          IndexError: if the entry does not exist. the cursor is in an unknown state afterwards.
        '''
        current_page = self.path[-1]
        if current_page.is_leaf():
            if self.entry_number == 0:
                # complex case: have to traverse up and then around.
                # we are at the beginning of a leaf node.
                # so we need to go to the parent and find the prev entry.
                # we may have to go up multiple parents.
                start_key = self.entry.key

                while True:
                    # pop the current node off the path
                    if len(self.path) <= 1:
                        raise IndexError()
                    self.path = self.path[:-1]

                    current_page = self.path[-1]
                    try:
                        entry_number = current_page.find_index(start_key)
                    except KeyError:
                        entry_number = current_page.entry_count

                    if entry_number == 0:
                        # not found, becaues its too small for this node.
                        # so we need to go higher.
                        continue
                    else:
                        break

                # entry_number now points to the least-greater entry relative to start key.
                # this should be the entry that points to the page from which we just came.
                # we'll want to return the key from the entry that is just
                # smaller than this one.

                self.entry = current_page.get_entry(entry_number - 1)
                self.entry_number = entry_number - 1
                return

            else:  # is inner entry.
                # simple case: simply decrement the entry number in the current
                # node.
                next_entry_number = self.entry_number - 1
                next_entry = current_page.get_entry(next_entry_number)

                self.entry = next_entry
                self.entry_number = next_entry_number
                return
        else:  # is branch node.

            # follow the max-edge down to a leaf, and take the max entry.
            current_page = self.path[-1]
            if self.entry_number == 0:
                next_page_number = current_page.ppointer
            else:
                next_page_number = current_page.get_entry(self.entry_number - 1).page

            next_page = self.index.get_page(next_page_number)
            while not next_page.is_leaf():
                self.path.append(next_page)
                next_page = self.index.get_page(next_page.get_entry(next_page.entry_count - 1).page)

            self.path.append(next_page)
            self.entry = next_page.get_entry(next_page.entry_count - 1)
            self.entry_number = next_page.entry_count - 1
            return

    @property
    def key(self):
        return self.entry.key

    @property
    def value(self):
        return self.entry.value


class ID0(vstruct.VStruct):
    '''
    a b-tree index.
    keys and values are arbitrary byte strings.

    use `.find()` to identify a matching entry, and use the resulting cursor
     instance to access the value, or traverse to less/greater entries.
    '''

    def __init__(self, buf, wordsize):
        vstruct.VStruct.__init__(self)
        self.buf = idb.memview(buf)
        self.wordsize = wordsize

        self.next_free_offset = v_uint32()
        self.page_size = v_uint16()
        self.root_page = v_uint32()
        self.record_count = v_uint32()
        self.page_count = v_uint32()
        self.unk12 = v_uint8()
        self.signature = v_bytes(size=0x09)

        self._page_cache = {}

    def get_page_buffer(self, page_number):
        if page_number < 1:
            logger.warning('unexpected page number requested: %d', page_number)

        offset = self.page_size * page_number
        return self.buf[offset:offset + self.page_size]

    def get_page(self, page_number):
        page = self._page_cache.get(page_number, None)
        if page is not None:
            return page

        buf = self.get_page_buffer(page_number)
        page = Page(self.page_size, page_number)
        page.vsParse(buf)

        self._page_cache[page_number] = page
        return page

    def find(self, key, strategy=EXACT_MATCH):
        '''
        Args:
          key (bytes): the index key for which to search.
          strategy (Type[MatchStrategy]): the strategy to use to do the search.
            some possible strategies:
              - EXACT_MATCH (default)
              - PREFIX_MATCH

        Returns:
          cursor: the cursor that points to the match.

        Raises:
          KeyError: if the match failes to find a result.
        '''
        c = Cursor(self)
        s = strategy()
        s.find(c, key)
        return c

    def find_prefix(self, key):
        '''
        convenience shortcut for prefix match search.
        '''
        return self.find(key, strategy=PREFIX_MATCH)

    def get_min(self):
        '''
        find the minimum entry in the index.

        Returns:
          cursor: the cursor that points to the match.
        '''
        return self.find(None, strategy=MIN_KEY)

    def get_max(self):
        '''
        find the maximum entry in the index.

        Returns:
          cursor: the cursor that points to the match.
        '''
        return self.find(None, strategy=MAX_KEY)

    def validate(self):
        if self.signature != b'B-tree v2':
            raise ValueError('bad signature')
        return True


class SegmentBounds(vstruct.VStruct):
    '''
    specifies the range of a segment.
    '''

    def __init__(self, wordsize):
        vstruct.VStruct.__init__(self)

        self.wordsize = wordsize
        if wordsize == 4:
            self.v_word = v_uint32
        elif wordsize == 8:
            self.v_word = v_uint64
        else:
            raise RuntimeError('unexpected wordsize')

        self.start = self.v_word()
        self.end = self.v_word()


class ID1(vstruct.VStruct):
    '''
    contains flags for each byte.
    '''
    PAGE_SIZE = 0x2000

    def __init__(self, wordsize, buf=None):
        vstruct.VStruct.__init__(self)

        self.wordsize = wordsize
        if wordsize == 4:
            self.v_word = v_uint32
        elif wordsize == 8:
            self.v_word = v_uint64
        else:
            raise RuntimeError('unexpected wordsize')

        self.signature = v_bytes(size=0x04)
        self.unk04 = v_uint32()     # 0x3
        self.segment_count = v_uint32()
        self.unk0C = v_uint32()     # 0x800
        self.page_count = v_uint32()
        # varrays are not actually very list-like,
        #  so the struct field will be ._segments
        #  and the property will be .segments.
        self._segments = vstruct.VArray()
        self.segments = []
        self.padding = v_bytes()
        self.buffer = v_bytes()

    SegmentDescriptor = namedtuple('SegmentDescriptor', ['bounds', 'offset'])

    def pcb_segment_count(self):
        self['_segments'].vsAddElements(self.segment_count,
                                        functools.partial(
                                            SegmentBounds,
                                            self.wordsize))

    def pcb__segments(self):
        offset = 0
        for i in range(self.segment_count):
            segment = self._segments[i]
            segment_byte_count = segment.end - segment.start
            segment_length = 4 * segment_byte_count  # each flag entry is a uint32 on all platforms
            self.segments.append(ID1.SegmentDescriptor(segment, offset))
            offset += segment_length
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

    def __init__(self, wordsize, buf=None):
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
        # this appears to actually be the number of dwords used by the names.
        # so for an .i64, this is 2x the name count.
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
        count = self.name_count
        if self.wordsize == 8:
            count //= 2

        fmt = "<{count:d}{word_fmt:s}".format(count=count, word_fmt=self.word_fmt)
        size = struct.calcsize(fmt)
        if size > len(self.buffer):
            raise ValueError('buffer too small')
        return struct.unpack(fmt, self.buffer[:size])


class TIL(vstruct.VStruct):
    def __init__(self, buf=None, wordsize=4):
        vstruct.VStruct.__init__(self)
        self.wordsize = wordsize
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
        # we use a memoryview since we'll take a bunch of read-only subslices.
        self.buf = idb.memview(buf)

        # list of parsed Section instances or None.
        # the entries should line up with the SECTIONS definition.
        self.sections = []

        # these fields will be parsed from self.buf once the header is parsed.
        # they are *not* linearly parsed during .vsParse().
        self.id0 = None  # type: ID0
        self.id1 = None  # type: ID1
        self.nam = None  # type: NAM
        self.seg = None  # type: NotImplemented
        self.til = None  # type: TIL
        self.id2 = None  # type: NotImplemented

        # these are the only true vstruct fields for this struct.
        self.header = FileHeader()

        # updated once header is parsed.
        self.wordsize = 0
        self.uint = ValueError

    def pcb_header(self):
        if self.header.signature == b'IDA1':
            self.wordsize = 4
            self.uint = idb.netnode.uint32
        elif self.header.signature == b'IDA2':
            self.wordsize = 8
            self.uint = idb.netnode.uint64
        else:
            raise RuntimeError('unexpected file signature: %s' % (self.header.signature))

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

            s = sectiondef.cls(buf=section.contents, wordsize=self.wordsize)
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
