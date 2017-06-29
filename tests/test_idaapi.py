import pytest
from fixtures import *

import idb


import logging
logging.basicConfig(level=logging.DEBUG)


def test_heads(kernel32_idb):
    # .text:68901010 8B FF                                   mov     edi, edi
    # .text:68901012 55                                      push    ebp
    first_ea = 0x68901010
    assert kernel32_idb.Head(first_ea) == 0x68901010
    assert kernel32_idb.Head(first_ea + 1) == 0x68901010
    assert kernel32_idb.NextHead(first_ea) == 0x68901012
    assert kernel32_idb.PrevHead(first_ea + 2) == first_ea


def test_bytes(kernel32_idb):
    # .text:68901010 8B FF                                   mov     edi, edi
    # .text:68901012 55                                      push    ebp

    first_ea = 0x68901010
    flags = kernel32_idb.GetFlags(first_ea)
    assert kernel32_idb.hasValue(flags) == True
    byte = kernel32_idb.IdbByte(first_ea)
    assert byte == 0x8B

    with pytest.raises(KeyError):
        # this effective address does not exist
        kernel32_idb.GetFlags(0x88888888)
        assert kernel32_idb.hasValue(kernel32_idb.GetFlags(0x88888888)) == True

    assert kernel32_idb.GetManyBytes(0x68901010, 0x3) == b'\x8B\xFF\x55'


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


def test_specific_state(kernel32_idb):
    # .text:68901010 8B FF                                   mov     edi, edi
    # .text:68901012 55                                      push    ebp
    first_ea = 0x68901010
    flags = kernel32_idb.GetFlags(first_ea)

    assert kernel32_idb.isFlow(flags) == False
    assert kernel32_idb.isVar(flags) == False
    assert kernel32_idb.hasExtra(flags) == True
    assert kernel32_idb.has_cmt(flags) == False
    assert kernel32_idb.hasRef(flags) == True
    assert kernel32_idb.has_name(flags) == True
    assert kernel32_idb.has_dummy_name(flags) == False

    # .text:68901044 FF 70 18                                push    dword ptr [eax+18h] ; HeapHandle
    first_ea = 0x68901044
    flags = kernel32_idb.GetFlags(first_ea)
    assert kernel32_idb.isFlow(flags) == True
    assert kernel32_idb.has_cmt(flags) == True



def test_code(kernel32_idb):
    # .text:68901010 8B FF                                   mov     edi, edi
    # .text:68901012 55                                      push    ebp
    first_ea = 0x68901010
    flags = kernel32_idb.GetFlags(first_ea)

    assert kernel32_idb.isFunc(flags) == True
    assert kernel32_idb.isImmd(flags) == False

    second_ea = 0x68901012
    flags = kernel32_idb.GetFlags(second_ea)
    assert kernel32_idb.isFunc(flags) == False
    assert kernel32_idb.isImmd(flags) == False


def test_data(kernel32_idb):
    # text:689011EB 90 90 90 90 90 90 90 90+                align 20h
    flags = kernel32_idb.GetFlags(0x689011eb)
    assert kernel32_idb.isByte(flags) == False
    assert kernel32_idb.isWord(flags) == False
    assert kernel32_idb.isDwrd(flags) == False
    assert kernel32_idb.isQwrd(flags) == False
    assert kernel32_idb.isOwrd(flags) == False
    assert kernel32_idb.isYwrd(flags) == False
    assert kernel32_idb.isTbyt(flags) == False
    assert kernel32_idb.isFloat(flags) == False
    assert kernel32_idb.isDouble(flags) == False
    assert kernel32_idb.isPackReal(flags) == False
    assert kernel32_idb.isASCII(flags) == False
    assert kernel32_idb.isStruct(flags) == False
    assert kernel32_idb.isAlign(flags) == True
    assert kernel32_idb.is3byte(flags) == False
    assert kernel32_idb.isCustom(flags) == False

    # .text:68901497 90 90 90 90 90                          db 5 dup(90h)
    flags = kernel32_idb.GetFlags(0x68901497)
    assert kernel32_idb.isByte(flags) == True
    assert kernel32_idb.isWord(flags) == False
    assert kernel32_idb.isDwrd(flags) == False
    assert kernel32_idb.isQwrd(flags) == False
    assert kernel32_idb.isOwrd(flags) == False
    assert kernel32_idb.isYwrd(flags) == False
    assert kernel32_idb.isTbyt(flags) == False
    assert kernel32_idb.isFloat(flags) == False
    assert kernel32_idb.isDouble(flags) == False
    assert kernel32_idb.isPackReal(flags) == False
    assert kernel32_idb.isASCII(flags) == False
    assert kernel32_idb.isStruct(flags) == False
    assert kernel32_idb.isAlign(flags) == False
    assert kernel32_idb.is3byte(flags) == False
    assert kernel32_idb.isCustom(flags) == False

    # .text:6893A7BC 24 83 98 68                             dd offset sub_68988324
    flags = kernel32_idb.GetFlags(0x6893a7bc)
    assert kernel32_idb.isByte(flags) == False
    assert kernel32_idb.isWord(flags) == False
    assert kernel32_idb.isDwrd(flags) == True
    assert kernel32_idb.isQwrd(flags) == False
    assert kernel32_idb.isOwrd(flags) == False
    assert kernel32_idb.isYwrd(flags) == False
    assert kernel32_idb.isTbyt(flags) == False
    assert kernel32_idb.isFloat(flags) == False
    assert kernel32_idb.isDouble(flags) == False
    assert kernel32_idb.isPackReal(flags) == False
    assert kernel32_idb.isASCII(flags) == False
    assert kernel32_idb.isStruct(flags) == False
    assert kernel32_idb.isAlign(flags) == False
    assert kernel32_idb.is3byte(flags) == False
    assert kernel32_idb.isCustom(flags) == False

    # .text:6893A840 42 69 41 63 74 69 76 61+aBiactivatework db 'BiActivateWorkItem',0
    flags = kernel32_idb.GetFlags(0x6893a840)
    assert kernel32_idb.isByte(flags) == False
    assert kernel32_idb.isWord(flags) == False
    assert kernel32_idb.isDwrd(flags) == False
    assert kernel32_idb.isQwrd(flags) == False
    assert kernel32_idb.isOwrd(flags) == False
    assert kernel32_idb.isYwrd(flags) == False
    assert kernel32_idb.isTbyt(flags) == False
    assert kernel32_idb.isFloat(flags) == False
    assert kernel32_idb.isDouble(flags) == False
    assert kernel32_idb.isPackReal(flags) == False
    assert kernel32_idb.isASCII(flags) == True
    assert kernel32_idb.isStruct(flags) == False
    assert kernel32_idb.isAlign(flags) == False
    assert kernel32_idb.is3byte(flags) == False
    assert kernel32_idb.isCustom(flags) == False



