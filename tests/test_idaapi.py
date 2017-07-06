import pytest
from fixtures import *

import idb
import idb.idapython


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


def test_colors(small_idb):
    api = idb.IDAPython(small_idb)

    assert api.ida_nalt.is_colored_item(0) == True

    # this is what i set it to via IDAPython when creating the idb.
    assert api.idc.GetColor(0, api.idc.CIC_ITEM) == 0x888888


def test_func_t(kernel32_idb):
    api = idb.IDAPython(kernel32_idb)

    DllEntryPoint = api.ida_funcs.get_func(0x68901695)
    assert DllEntryPoint.startEA == 0x68901695
    assert DllEntryPoint.endEA == 0x689016B0
    # the netnode id of the frame structure
    # go look at netnode | FF 00 00 00 00 75 |
    assert DllEntryPoint.frame == 0x75
    # size of local variables
    assert DllEntryPoint.frsize == 0x0
    # size of saved registers.
    # i presume this is for saved ebp.
    # in the IDA functions view, the "Locals" column may be (frsize + frregs).
    assert DllEntryPoint.frregs == 0x4
    # size on stack of arguments
    assert DllEntryPoint.argsize == 0xC
    # frame pointer delta. not clear on how this is computed.
    # in fact, a value of 0x9 doesn't make much sense. so this might be wrong.
    # more likely to be the stack change point count.
    assert DllEntryPoint.fpd == 0x9

    flags = DllEntryPoint.flags
    # collected empirically
    assert idb.idapython.is_flag_set(flags, api.ida_funcs.FUNC_NORET) == False
    assert idb.idapython.is_flag_set(flags, api.ida_funcs.FUNC_FAR) == False
    assert idb.idapython.is_flag_set(flags, api.ida_funcs.FUNC_LIB) == False
    assert idb.idapython.is_flag_set(flags, api.ida_funcs.FUNC_STATICDEF) == False
    assert idb.idapython.is_flag_set(flags, api.ida_funcs.FUNC_FRAME) == True
    assert idb.idapython.is_flag_set(flags, api.ida_funcs.FUNC_USERFAR) == False
    assert idb.idapython.is_flag_set(flags, api.ida_funcs.FUNC_HIDDEN) == False
    assert idb.idapython.is_flag_set(flags, api.ida_funcs.FUNC_THUNK) == False
    assert idb.idapython.is_flag_set(flags, api.ida_funcs.FUNC_BOTTOMBP) == False
    assert idb.idapython.is_flag_set(flags, api.ida_funcs.FUNC_NORET_PENDING) == False
    assert idb.idapython.is_flag_set(flags, api.ida_funcs.FUNC_SP_READY) == True
    assert idb.idapython.is_flag_set(flags, api.ida_funcs.FUNC_PURGED_OK) == True
    assert idb.idapython.is_flag_set(flags, api.ida_funcs.FUNC_TAIL) == False
    # also demonstrate finding the func from an address it may contain.
    # note: this can be a pretty slow search, since we do everything on demand with no caching.
    assert api.ida_funcs.get_func(0x68901695 + 1).startEA == 0x68901695

    # this is the function chunk for DllEntryPoint, but gets resolved to the non-tail func.
    assert api.ida_funcs.get_func(0x68906156).startEA == 0x68901695
    assert api.ida_funcs.get_func(0x68906156 + 1).startEA == 0x68901695


def test_find_bb_end(kernel32_idb):
    # .text:68901695 000 8B FF                                   mov     edi, edi
    # .text:68901697 000 55                                      push    ebp
    # .text:68901698 004 8B EC                                   mov     ebp, esp
    # .text:6890169A 004 83 7D 0C 01                             cmp     [ebp+fdwReason], 1
    # .text:6890169E 004 0F 84 B2 4A 00 00                       jz      loc_68906156

    api = idb.IDAPython(kernel32_idb)
    assert api.idaapi._find_bb_end(0x68901695) == 0x6890169E
    assert api.idaapi._find_bb_end(0x68901697) == 0x6890169E
    assert api.idaapi._find_bb_end(0x68901698) == 0x6890169E
    assert api.idaapi._find_bb_end(0x6890169A) == 0x6890169E
    assert api.idaapi._find_bb_end(0x6890169E) == 0x6890169E

    # single insn in the bb:
    # .text:68906227 220 A3 44 B0 9D 68                          mov     dword_689DB044, eax
    assert api.idaapi._find_bb_end(0x68906227) == 0x68906227


def test_find_bb_start(kernel32_idb):
    # .text:68901695 000 8B FF                                   mov     edi, edi
    # .text:68901697 000 55                                      push    ebp
    # .text:68901698 004 8B EC                                   mov     ebp, esp
    # .text:6890169A 004 83 7D 0C 01                             cmp     [ebp+fdwReason], 1
    # .text:6890169E 004 0F 84 B2 4A 00 00                       jz      loc_68906156

    api = idb.IDAPython(kernel32_idb)
    assert api.idaapi._find_bb_start(0x68901695) == 0x68901695
    assert api.idaapi._find_bb_start(0x68901697) == 0x68901695
    assert api.idaapi._find_bb_start(0x68901698) == 0x68901695
    assert api.idaapi._find_bb_start(0x6890169A) == 0x68901695
    assert api.idaapi._find_bb_start(0x6890169E) == 0x68901695

    # single insn in the bb:
    # .text:68906227 220 A3 44 B0 9D 68                          mov     dword_689DB044, eax
    assert api.idaapi._find_bb_start(0x68906227) == 0x68906227


def pluck(prop, s):
    '''
    generate the values from the given attribute with name `prop` from the given sequence of items `s`.

    Args:
      prop (str): the name of an attribute.
      s (sequnce): a bunch of objects.

    Yields:
      any: the values of the requested field across the sequence
    '''
    for x in s:
        yield getattr(x, prop)


def lpluck(prop, s):
    '''
    like `pluck`, but returns the result in a single list.
    '''
    return list(pluck(prop, s))


def test_flow_preds(kernel32_idb):
    api = idb.IDAPython(kernel32_idb)

    assert lpluck('src', api.idaapi._get_flow_preds(0x68901695)) == []
    assert lpluck('src', api.idaapi._get_flow_preds(0x68901697)) == [0x68901695]
    assert lpluck('src', api.idaapi._get_flow_preds(0x68901698)) == [0x68901697]

    assert lpluck('src', api.idaapi._get_flow_preds(0x68906156)) == [0x6890169E]
    assert lpluck('type', api.idaapi._get_flow_preds(0x68906156)) == [api.idaapi.fl_JN]


def test_flow_succs(kernel32_idb):
    api = idb.IDAPython(kernel32_idb)

    assert lpluck('dst', api.idaapi._get_flow_succs(0x68901695)) == [0x68901697]
    assert lpluck('dst', api.idaapi._get_flow_succs(0x68901697)) == [0x68901698]
    assert lpluck('dst', api.idaapi._get_flow_succs(0x68901698)) == [0x6890169A]

    assert lpluck('dst', api.idaapi._get_flow_succs(0x6890169E)) == [0x689016A4, 0x68906156]
    assert lpluck('type', api.idaapi._get_flow_succs(0x6890169E)) == [api.idaapi.fl_F, api.idaapi.fl_JN]

