from fixtures import *

import sys
import struct
import logging
import datetime
import binascii


#logging.basicConfig(level=logging.DEBUG)


def make_string_name_key(name):
    return b'N' + name.encode('utf-8')


def make_int_name_key(name, wordsize=4):
    if wordsize == 4:
        return b'N' + struct.pack('<BI', 0, name)
    elif wordsize == 8:
        return b'N' + struct.pack('<BQ', 0, name)
    else:
        raise RuntimeError('unexpected wordsize')


def make_name_key(name, wordsize=4):
    if isinstance(name, str):
        return make_string_name_key(name)
    else:
        return make_int_name_key(name, wordsize=wordsize)


def get_nodeid(idb, name, wordsize=4):
    # TODO: 64bit
    key = make_name_key(name)
    cursor = idb.id0.find(key)
    if wordsize == 4:
        return struct.unpack('<I', cursor.value)[0]
    elif wordsize == 8:
        return struct.unpack('<Q', cursor.value)[0]
    else:
        raise RuntimeError('unexpected wordsize')


def make_complex_key(nodeid, tag, index, wordsize=4):
    if wordsize == 4:
        wordformat = 'I'
    elif wordsize == 8:
        wordformat = 'Q'
    else:
        raise RuntimeError('unexpected wordsize')

    fmt = '>s' + wordformat + 's' + wordformat
    tag = tag.encode('utf-8')
    if isinstance(index, str):
        index = index.encode('utf-8')
    elif isinstance(index, int) and index < 0:
        fmt = '>s' + wordformat + 's' + wordformat.lower()

    return struct.pack(fmt, b'.', nodeid, tag, index)


def get_int(idb, nodeid, tag, index):
    key = make_complex_key(nodeid, tag, index)
    cursor = idb.id0.find(key)
    data = cursor.value

    if data is None:
        raise KeyError((nodeid, tag, index))

    if len(data) == 1:
        return struct.unpack('<B', data)[0]
    elif len(data) == 2:
        return struct.unpack('<H', data)[0]
    elif len(data) == 4:
        return struct.unpack('<L', data)[0]
    elif len(data) == 8:
        return struct.unpack('<Q', data)[0]
    else:
        return RuntimeError('unexpected data size')


def get_string(idb, nodeid, tag, index):
    key = make_complex_key(nodeid, tag, index)
    cursor = idb.id0.find(key)
    data = cursor.value

    if data is None:
        raise KeyError((nodeid, tag, index))

    return bytes(data).rstrip(b'\x00').decode('utf-8')


def get_bytes(idb, nodeid, tag, index):
    key = make_complex_key(nodeid, tag, index)
    cursor = idb.id0.find(key)
    data = cursor.value

    if data is None:
        raise KeyError((nodeid, tag, index))
    return bytes(data)


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


def test_root(kernel32_idb):
    root = get_nodeid(kernel32_idb, 'Root Node')
    assert get_int(kernel32_idb, root, 'A', ROOT_INDEX.VERSION) == 695
    assert get_string(kernel32_idb, root, 'S', ROOT_INDEX.VERSION_STRING) == '6.95'
    assert get_int(kernel32_idb, root, 'A', ROOT_INDEX.OPEN_COUNT) == 1
    ts = get_int(kernel32_idb, root, 'A', ROOT_INDEX.CREATED)
    ts = datetime.datetime.utcfromtimestamp(ts)
    assert ts.isoformat() == '2017-06-20T22:31:34'
    assert get_int(kernel32_idb, root, 'A', ROOT_INDEX.CRC) == 0xdf9bdf12
    md5 = get_bytes(kernel32_idb, root, 'S', ROOT_INDEX.MD5)
    md5 = binascii.hexlify(md5).decode('ascii')
    assert md5 == '00bf1bf1b779ce1af41371426821e0c2'
