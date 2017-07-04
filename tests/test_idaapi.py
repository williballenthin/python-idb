import pytest
from fixtures import *

import idb


import logging
logging.basicConfig(level=logging.DEBUG)


def test_heads(kernel32_idb):
    idc = idb.IDAPython(kernel32_idb).idc

    # .text:68901010 8B FF                                   mov     edi, edi
    # .text:68901012 55                                      push    ebp
    first_ea = 0x68901010
    assert idc.Head(first_ea) == 0x68901010
    assert idc.Head(first_ea + 1) == 0x68901010
    assert idc.NextHead(first_ea) == 0x68901012
    assert idc.PrevHead(first_ea + 2) == first_ea


def test_bytes(kernel32_idb):
    idc = idb.IDAPython(kernel32_idb).idc
    ida_bytes = idb.IDAPython(kernel32_idb).ida_bytes

    # .text:68901010 8B FF                                   mov     edi, edi
    # .text:68901012 55                                      push    ebp
    flags = idc.GetFlags(0x68901010)
    assert idc.hasValue(flags) == True

    byte = idc.IdbByte(0x68901010)
    assert byte == 0x8B

    with pytest.raises(KeyError):
        # this effective address does not exist
        idc.GetFlags(0x88888888)
        assert idc.hasValue(idc.GetFlags(0x88888888)) == True

    assert idc.ItemSize(0x68901010) == 2
    with pytest.raises(ValueError):
        idc.ItemSize(0x68901011)
    assert idc.ItemSize(0x68901012) == 1

    assert idc.GetManyBytes(0x68901010, 0x3) == b'\x8B\xFF\x55'


def test_state(kernel32_idb):
    idc = idb.IDAPython(kernel32_idb).idc
    ida_bytes = idb.IDAPython(kernel32_idb).ida_bytes

    # .text:68901010 8B FF                                   mov     edi, edi
    # .text:68901012 55                                      push    ebp
    flags = idc.GetFlags(0x68901010)
    assert ida_bytes.isCode(flags) == True
    assert ida_bytes.isData(flags) == False
    assert ida_bytes.isTail(flags) == False
    assert ida_bytes.isNotTail(flags) == True
    assert ida_bytes.isUnknown(flags) == False
    assert ida_bytes.isHead(flags) == True

    flags = idc.GetFlags(0x68901011)
    assert ida_bytes.isCode(flags) == False
    assert ida_bytes.isData(flags) == False
    assert ida_bytes.isTail(flags) == True
    assert ida_bytes.isNotTail(flags) == False
    assert ida_bytes.isUnknown(flags) == False
    assert ida_bytes.isHead(flags) == False


def test_specific_state(kernel32_idb):
    idc = idb.IDAPython(kernel32_idb).idc
    ida_bytes = idb.IDAPython(kernel32_idb).ida_bytes

    # .text:68901010 8B FF                                   mov     edi, edi
    # .text:68901012 55                                      push    ebp
    flags = idc.GetFlags(0x68901010)
    assert ida_bytes.isFlow(flags) == False
    assert ida_bytes.isVar(flags) == False
    assert ida_bytes.hasExtra(flags) == True
    assert ida_bytes.has_cmt(flags) == False
    assert ida_bytes.hasRef(flags) == True
    assert ida_bytes.has_name(flags) == True
    assert ida_bytes.has_dummy_name(flags) == False

    # .text:68901044 FF 70 18                                push    dword ptr [eax+18h] ; HeapHandle
    flags = idc.GetFlags(0x68901044)
    assert ida_bytes.isFlow(flags) == True
    assert ida_bytes.has_cmt(flags) == True


def test_code(kernel32_idb):
    idc = idb.IDAPython(kernel32_idb).idc
    ida_bytes = idb.IDAPython(kernel32_idb).ida_bytes

    # .text:68901010 8B FF                                   mov     edi, edi
    # .text:68901012 55                                      push    ebp
    flags = idc.GetFlags(0x68901010)
    assert ida_bytes.isFunc(flags) == True
    assert ida_bytes.isImmd(flags) == False

    flags = idc.GetFlags(0x68901012)
    assert ida_bytes.isFunc(flags) == False
    assert ida_bytes.isImmd(flags) == False


def test_data(kernel32_idb):
    idc = idb.IDAPython(kernel32_idb).idc
    ida_bytes = idb.IDAPython(kernel32_idb).ida_bytes

    # text:689011EB 90 90 90 90 90 90 90 90+                align 20h
    flags = idc.GetFlags(0x689011eb)
    assert ida_bytes.isByte(flags) == False
    assert ida_bytes.isWord(flags) == False
    assert ida_bytes.isDwrd(flags) == False
    assert ida_bytes.isQwrd(flags) == False
    assert ida_bytes.isOwrd(flags) == False
    assert ida_bytes.isYwrd(flags) == False
    assert ida_bytes.isTbyt(flags) == False
    assert ida_bytes.isFloat(flags) == False
    assert ida_bytes.isDouble(flags) == False
    assert ida_bytes.isPackReal(flags) == False
    assert ida_bytes.isASCII(flags) == False
    assert ida_bytes.isStruct(flags) == False
    assert ida_bytes.isAlign(flags) == True
    assert ida_bytes.is3byte(flags) == False
    assert ida_bytes.isCustom(flags) == False

    # .text:68901497 90 90 90 90 90                          db 5 dup(90h)
    flags = idc.GetFlags(0x68901497)
    assert ida_bytes.isByte(flags) == True
    assert ida_bytes.isWord(flags) == False
    assert ida_bytes.isDwrd(flags) == False
    assert ida_bytes.isQwrd(flags) == False
    assert ida_bytes.isOwrd(flags) == False
    assert ida_bytes.isYwrd(flags) == False
    assert ida_bytes.isTbyt(flags) == False
    assert ida_bytes.isFloat(flags) == False
    assert ida_bytes.isDouble(flags) == False
    assert ida_bytes.isPackReal(flags) == False
    assert ida_bytes.isASCII(flags) == False
    assert ida_bytes.isStruct(flags) == False
    assert ida_bytes.isAlign(flags) == False
    assert ida_bytes.is3byte(flags) == False
    assert ida_bytes.isCustom(flags) == False

    # .text:6893A7BC 24 83 98 68                             dd offset sub_68988324
    flags = idc.GetFlags(0x6893a7bc)
    assert ida_bytes.isByte(flags) == False
    assert ida_bytes.isWord(flags) == False
    assert ida_bytes.isDwrd(flags) == True
    assert ida_bytes.isQwrd(flags) == False
    assert ida_bytes.isOwrd(flags) == False
    assert ida_bytes.isYwrd(flags) == False
    assert ida_bytes.isTbyt(flags) == False
    assert ida_bytes.isFloat(flags) == False
    assert ida_bytes.isDouble(flags) == False
    assert ida_bytes.isPackReal(flags) == False
    assert ida_bytes.isASCII(flags) == False
    assert ida_bytes.isStruct(flags) == False
    assert ida_bytes.isAlign(flags) == False
    assert ida_bytes.is3byte(flags) == False
    assert ida_bytes.isCustom(flags) == False

    # .text:6893A840 42 69 41 63 74 69 76 61+aBiactivatework db 'BiActivateWorkItem',0
    flags = idc.GetFlags(0x6893a840)
    assert ida_bytes.isByte(flags) == False
    assert ida_bytes.isWord(flags) == False
    assert ida_bytes.isDwrd(flags) == False
    assert ida_bytes.isQwrd(flags) == False
    assert ida_bytes.isOwrd(flags) == False
    assert ida_bytes.isYwrd(flags) == False
    assert ida_bytes.isTbyt(flags) == False
    assert ida_bytes.isFloat(flags) == False
    assert ida_bytes.isDouble(flags) == False
    assert ida_bytes.isPackReal(flags) == False
    assert ida_bytes.isASCII(flags) == True
    assert ida_bytes.isStruct(flags) == False
    assert ida_bytes.isAlign(flags) == False
    assert ida_bytes.is3byte(flags) == False
    assert ida_bytes.isCustom(flags) == False


def test_operand_types(kernel32_idb):
    idc = idb.IDAPython(kernel32_idb).idc

    # .text:68901010 8B FF                                   mov     edi, edi
    # .text:68901012 55                                      push    ebp
    flags = idc.GetFlags(0x68901012)
    assert idc.isDefArg0(flags) == False  # there is an operand, but its not a number, so...
    assert idc.isDefArg1(flags) == False
    assert idc.isOff0(flags) == False
    assert idc.isChar0(flags) == False
    assert idc.isSeg0(flags) == False
    assert idc.isEnum0(flags) == False
    assert idc.isStroff0(flags) == False
    assert idc.isStkvar0(flags) == False
    assert idc.isFloat0(flags) == False
    assert idc.isCustFmt0(flags) == False
    assert idc.isNum0(flags) == False

    # .text:68901015 64 A1 30 00 00 00                       mov     eax, large fs:30h
    # .text:6890101B 83 EC 18                                sub     esp, 18h
    flags = idc.GetFlags(0x6890101B)
    assert idc.isDefArg0(flags) == False
    assert idc.isDefArg1(flags) == True
    assert idc.isOff1(flags) == False
    assert idc.isChar1(flags) == False
    assert idc.isSeg1(flags) == False
    assert idc.isEnum1(flags) == False
    assert idc.isStroff1(flags) == False
    assert idc.isStkvar1(flags) == False
    assert idc.isFloat1(flags) == False
    assert idc.isCustFmt1(flags) == False
    assert idc.isNum1(flags) == True

    # .text:68901964 FF 75 24                                push    [ebp+lpOverlapped] ; lpOverlapped
    flags = idc.GetFlags(0x68901964)
    assert idc.isDefArg0(flags) == True
    assert idc.isDefArg1(flags) == False
    assert idc.isOff0(flags) == False
    assert idc.isChar0(flags) == False
    assert idc.isSeg0(flags) == False
    assert idc.isEnum0(flags) == False
    assert idc.isStroff0(flags) == False
    assert idc.isStkvar0(flags) == True
    assert idc.isFloat0(flags) == False
    assert idc.isCustFmt0(flags) == False
    assert idc.isNum0(flags) == False
