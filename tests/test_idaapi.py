import pytest
from fixtures import *

import idb


import logging
logging.basicConfig(level=logging.DEBUG)


def test_bytes(kernel32_idb):
    first_ea = 0x68901010
    flags = kernel32_idb.GetFlags(first_ea)
    assert kernel32_idb.hasValue(flags) == True
    byte = kernel32_idb.IdbByte(first_ea)
    assert byte == 0x8B

    with pytest.raises(KeyError):
        # this effective address does not exist
        kernel32_idb.GetFlags(0x88888888)
        assert kernel32_idb.hasValue(kernel32_idb.GetFlags(0x88888888)) == True


def test_state(kernel32_idb):
    # .text:68901010 8B FF                                   mov     edi, edi
    # .text:68901012 55                                      push    ebp
    first_ea = 0x68901010
    flags = kernel32_idb.GetFlags(first_ea)
    assert kernel32_idb.isCode(flags) == True
    assert kernel32_idb.isData(flags) == False
    assert kernel32_idb.isTail(flags) == False
    assert kernel32_idb.isNotTail(flags) == True
    assert kernel32_idb.isUnknown(flags) == False
    assert kernel32_idb.isHead(flags) == True

    flags = kernel32_idb.GetFlags(first_ea + 1)
    assert kernel32_idb.isCode(flags) == False
    assert kernel32_idb.isData(flags) == False
    assert kernel32_idb.isTail(flags) == True
    assert kernel32_idb.isNotTail(flags) == False
    assert kernel32_idb.isUnknown(flags) == False
    assert kernel32_idb.isHead(flags) == False



def test_code(kernel32_idb):
    first_ea = 0x68901010
    flags = kernel32_idb.GetFlags(first_ea)

    assert kernel32_idb.isFunc(flags) == True
    assert kernel32_idb.isImmd(flags) == False

    second_ea = 0x68901012
    flags = kernel32_idb.GetFlags(second_ea)
    assert kernel32_idb.isFunc(flags) == False
    assert kernel32_idb.isImmd(flags) == False

