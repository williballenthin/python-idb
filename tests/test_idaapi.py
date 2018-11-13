import os
import pytest

import idb

from fixtures import *


slow = pytest.mark.skipif(
    not pytest.config.getoption("--runslow"),
    reason="need --runslow option to run"
)


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


@kern32_test()
def test_heads(kernel32_idb, version, bitness, expected):
    idc = idb.IDAPython(kernel32_idb).idc

    # .text:68901010 8B FF                                   mov     edi, edi
    # .text:68901012 55                                      push    ebp
    first_ea = 0x68901010
    assert idc.Head(first_ea) == 0x68901010
    assert idc.Head(first_ea + 1) == 0x68901010
    assert idc.NextHead(first_ea) == 0x68901012
    assert idc.PrevHead(first_ea + 2) == first_ea


@kern32_test()
def test_bytes(kernel32_idb, version, bitness, expected):
    idc = idb.IDAPython(kernel32_idb).idc

    # .text:68901010 8B FF                                   mov     edi, edi
    # .text:68901012 55                                      push    ebp
    flags = idc.GetFlags(0x68901010)
    assert idc.hasValue(flags) is True

    byte = idc.IdbByte(0x68901010)
    assert byte == 0x8B

    # this effective address does not exist
    assert not idc.GetFlags(0x88888888) # FIXME:our idc.GetFlags return None, but it should return 0 when running in ida.
    # assert idc.hasValue(idc.GetFlags(0x88888888)) is False

    assert idc.ItemSize(0x68901010) == 2
    with pytest.raises(ValueError):
        idc.ItemSize(0x68901011)
    assert idc.ItemSize(0x68901012) == 1

    assert idc.GetManyBytes(0x68901010, 0x3) == b'\x8B\xFF\x55'


def test_bytes_2(elf_idb):
    '''
    Demonstrate issue reported as #12.
    Thanks to @binoopang.

    This exercises fetching of flags/bytes from a segment that is not the first.
    '''
    api = idb.IDAPython(elf_idb)
    assert api.idc.GetManyBytes(0x8049df0, 0x10) == b'\x8D\x4C\x24\x04\x83\xE4\xF0\xFF\x71\xFC\x55\x89\xE5\x57\x56\x53'


@kern32_test()
def test_state(kernel32_idb, version, bitness, expected):
    idc = idb.IDAPython(kernel32_idb).idc
    ida_bytes = idb.IDAPython(kernel32_idb).ida_bytes

    # .text:68901010 8B FF                                   mov     edi, edi
    # .text:68901012 55                                      push    ebp
    flags = idc.GetFlags(0x68901010)
    assert ida_bytes.is_code(flags) is True
    assert ida_bytes.is_data(flags) is False
    assert ida_bytes.is_tail(flags) is False
    assert ida_bytes.is_not_tail(flags) is True
    assert ida_bytes.is_unknown(flags) is False
    assert ida_bytes.is_head(flags) is True

    flags = idc.GetFlags(0x68901011)
    assert ida_bytes.is_code(flags) is False
    assert ida_bytes.is_data(flags) is False
    assert ida_bytes.is_tail(flags) is True
    assert ida_bytes.is_not_tail(flags) is False
    assert ida_bytes.is_unknown(flags) is False
    assert ida_bytes.is_head(flags) is False


@kern32_test()
def test_specific_state(kernel32_idb, version, bitness, expected):
    idc = idb.IDAPython(kernel32_idb).idc
    ida_bytes = idb.IDAPython(kernel32_idb).ida_bytes

    # .text:68901010 8B FF                                   mov     edi, edi
    # .text:68901012 55                                      push    ebp
    flags = idc.GetFlags(0x68901010)
    assert ida_bytes.is_flow(flags) is False
    assert ida_bytes.is_var(flags) is False
    assert ida_bytes.has_extra_cmts(flags) is True
    assert ida_bytes.has_cmt(flags) is False
    assert ida_bytes.has_ref(flags) is True
    assert ida_bytes.has_name(flags) is True
    assert ida_bytes.has_dummy_name(flags) is False

    # .text:68901044 FF 70 18                                push    dword ptr [eax+18h] ; HeapHandle
    flags = idc.GetFlags(0x68901044)
    assert ida_bytes.is_flow(flags) is True
    assert ida_bytes.has_cmt(flags) is True


@kern32_test()
def test_code(kernel32_idb, version, bitness, expected):
    idc = idb.IDAPython(kernel32_idb).idc
    ida_bytes = idb.IDAPython(kernel32_idb).ida_bytes

    # .text:68901010 8B FF                                   mov     edi, edi
    # .text:68901012 55                                      push    ebp
    flags = idc.GetFlags(0x68901010)
    assert ida_bytes.is_func(flags) is True
    assert ida_bytes.has_immd(flags) is False

    flags = idc.GetFlags(0x68901012)
    assert ida_bytes.is_func(flags) is False
    assert ida_bytes.has_immd(flags) is False


@kern32_test()
def test_data(kernel32_idb, version, bitness, expected):
    idc = idb.IDAPython(kernel32_idb).idc
    ida_bytes = idb.IDAPython(kernel32_idb).ida_bytes

    # text:689011EB 90 90 90 90 90 90 90 90+                align 20h
    flags = idc.GetFlags(0x689011eb)
    assert ida_bytes.is_byte(flags) is False
    assert ida_bytes.is_word(flags) is False
    assert ida_bytes.is_dword(flags) is False
    assert ida_bytes.is_qword(flags) is False
    assert ida_bytes.is_oword(flags) is False
    assert ida_bytes.is_yword(flags) is False
    assert ida_bytes.is_tbyte(flags) is False
    assert ida_bytes.is_float(flags) is False
    assert ida_bytes.is_double(flags) is False
    assert ida_bytes.is_pack_real(flags) is False
    assert ida_bytes.is_strlit(flags) is False
    assert ida_bytes.is_struct(flags) is False
    assert ida_bytes.is_align(flags) is True
    assert ida_bytes.is_custom(flags) is False

    # .text:68901497 90 90 90 90 90                          db 5 dup(90h)
    flags = idc.GetFlags(0x68901497)
    assert ida_bytes.is_byte(flags) is True
    assert ida_bytes.is_word(flags) is False
    assert ida_bytes.is_dword(flags) is False
    assert ida_bytes.is_qword(flags) is False
    assert ida_bytes.is_oword(flags) is False
    assert ida_bytes.is_yword(flags) is False
    assert ida_bytes.is_tbyte(flags) is False
    assert ida_bytes.is_float(flags) is False
    assert ida_bytes.is_double(flags) is False
    assert ida_bytes.is_pack_real(flags) is False
    assert ida_bytes.is_strlit(flags) is False
    assert ida_bytes.is_struct(flags) is False
    assert ida_bytes.is_align(flags) is False
    assert ida_bytes.is_custom(flags) is False

    # .text:6893A7BC 24 83 98 68                             dd offset sub_68988324
    flags = idc.GetFlags(0x6893a7bc)
    assert ida_bytes.is_byte(flags) is False
    assert ida_bytes.is_word(flags) is False
    assert ida_bytes.is_dword(flags) is True
    assert ida_bytes.is_qword(flags) is False
    assert ida_bytes.is_oword(flags) is False
    assert ida_bytes.is_yword(flags) is False
    assert ida_bytes.is_tbyte(flags) is False
    assert ida_bytes.is_float(flags) is False
    assert ida_bytes.is_double(flags) is False
    assert ida_bytes.is_pack_real(flags) is False
    assert ida_bytes.is_strlit(flags) is False
    assert ida_bytes.is_struct(flags) is False
    assert ida_bytes.is_align(flags) is False
    assert ida_bytes.is_custom(flags) is False

    # .text:6893A840 42 69 41 63 74 69 76 61+aBiactivatework db 'BiActivateWorkItem',0
    flags = idc.GetFlags(0x6893a840)
    assert ida_bytes.is_byte(flags) is False
    assert ida_bytes.is_word(flags) is False
    assert ida_bytes.is_dword(flags) is False
    assert ida_bytes.is_qword(flags) is False
    assert ida_bytes.is_oword(flags) is False
    assert ida_bytes.is_yword(flags) is False
    assert ida_bytes.is_tbyte(flags) is False
    assert ida_bytes.is_float(flags) is False
    assert ida_bytes.is_double(flags) is False
    assert ida_bytes.is_pack_real(flags) is False
    assert ida_bytes.is_strlit(flags) is True
    assert ida_bytes.is_struct(flags) is False
    assert ida_bytes.is_align(flags) is False
    assert ida_bytes.is_custom(flags) is False


@kern32_test()
def test_function_name(kernel32_idb, version, bitness, expected):
    api = idb.IDAPython(kernel32_idb)
    assert api.idc.GetFunctionName(0x68901695) == 'DllEntryPoint'


@kern32_test()
def test_operand_types(kernel32_idb, version, bitness, expected):
    idc = idb.IDAPython(kernel32_idb).idc

    # .text:68901010 8B FF                                   mov     edi, edi
    # .text:68901012 55                                      push    ebp
    flags = idc.GetFlags(0x68901012)
    # there is an operand, but its not a number, so...
    assert idc.isDefArg0(flags) is False
    assert idc.isDefArg1(flags) is False
    assert idc.isOff0(flags) is False
    assert idc.isChar0(flags) is False
    assert idc.isSeg0(flags) is False
    assert idc.isEnum0(flags) is False
    assert idc.isStroff0(flags) is False
    assert idc.isStkvar0(flags) is False
    assert idc.isFloat0(flags) is False
    assert idc.isCustFmt0(flags) is False
    assert idc.isNum0(flags) is False

    # .text:68901015 64 A1 30 00 00 00                       mov     eax, large fs:30h
    # .text:6890101B 83 EC 18                                sub     esp, 18h
    flags = idc.GetFlags(0x6890101B)
    assert idc.isDefArg0(flags) is False
    assert idc.isDefArg1(flags) is True
    assert idc.isOff1(flags) is False
    assert idc.isChar1(flags) is False
    assert idc.isSeg1(flags) is False
    assert idc.isEnum1(flags) is False
    assert idc.isStroff1(flags) is False
    assert idc.isStkvar1(flags) is False
    assert idc.isFloat1(flags) is False
    assert idc.isCustFmt1(flags) is False
    assert idc.isNum1(flags) is True

    # .text:68901964 FF 75 24                                push    [ebp+lpOverlapped] ; lpOverlapped
    flags = idc.GetFlags(0x68901964)
    assert idc.isDefArg0(flags) is True
    assert idc.isDefArg1(flags) is False
    assert idc.isOff0(flags) is False
    assert idc.isChar0(flags) is False
    assert idc.isSeg0(flags) is False
    assert idc.isEnum0(flags) is False
    assert idc.isStroff0(flags) is False
    assert idc.isStkvar0(flags) is True
    assert idc.isFloat0(flags) is False
    assert idc.isCustFmt0(flags) is False
    assert idc.isNum0(flags) is False


def test_colors(small_idb):
    api = idb.IDAPython(small_idb)

    assert api.ida_nalt.is_colored_item(0) is True

    # this is what i set it to via IDAPython when creating the idb.
    assert api.idc.GetColor(0, api.idc.CIC_ITEM) == 0x888888


@kern32_test()
def test_func_t(kernel32_idb, version, bitness, expected):
    api = idb.IDAPython(kernel32_idb)

    DllEntryPoint = api.ida_funcs.get_func(0x68901695)
    assert DllEntryPoint.startEA == 0x68901695
    assert DllEntryPoint.endEA == 0x689016B0
    # the netnode id of the frame structure
    # go look at netnode | FF 00 00 00 00 75 |
    # this is specific to the .idb
    # assert DllEntryPoint.frame == 0x75

    # size of local variables
    assert DllEntryPoint.frsize == 0x0
    # size of saved registers.
    # i presume this is for saved ebp.
    # in the IDA functions view, the "Locals" column may be (frsize + frregs).
    assert DllEntryPoint.frregs == 0x4
    # size on stack of arguments
    assert DllEntryPoint.argsize == 0xC

    flags = DllEntryPoint.flags
    # collected empirically
    assert idb.idapython.is_flag_set(flags, api.ida_funcs.FUNC_NORET) is False
    assert idb.idapython.is_flag_set(flags, api.ida_funcs.FUNC_FAR) is False
    assert idb.idapython.is_flag_set(flags, api.ida_funcs.FUNC_LIB) is False
    assert idb.idapython.is_flag_set(
        flags, api.ida_funcs.FUNC_STATICDEF) is False
    assert idb.idapython.is_flag_set(flags, api.ida_funcs.FUNC_FRAME) is True
    assert idb.idapython.is_flag_set(
        flags, api.ida_funcs.FUNC_USERFAR) is False
    assert idb.idapython.is_flag_set(flags, api.ida_funcs.FUNC_HIDDEN) is False
    assert idb.idapython.is_flag_set(flags, api.ida_funcs.FUNC_THUNK) is False
    assert idb.idapython.is_flag_set(
        flags, api.ida_funcs.FUNC_BOTTOMBP) is False
    assert idb.idapython.is_flag_set(
        flags, api.ida_funcs.FUNC_NORET_PENDING) is False
    assert idb.idapython.is_flag_set(
        flags, api.ida_funcs.FUNC_SP_READY) is True
    assert idb.idapython.is_flag_set(
        flags, api.ida_funcs.FUNC_PURGED_OK) is True
    assert idb.idapython.is_flag_set(flags, api.ida_funcs.FUNC_TAIL) is False
    # also demonstrate finding the func from an address it may contain.
    # note: this can be a pretty slow search, since we do everything on demand
    # with no caching.
    assert api.ida_funcs.get_func(0x68901695 + 1).startEA == 0x68901695

    # this is the function chunk for DllEntryPoint, but gets resolved to the
    # non-tail func.
    assert api.ida_funcs.get_func(0x68906156).startEA == 0x68901695
    assert api.ida_funcs.get_func(0x68906156 + 1).startEA == 0x68901695


@kern32_test()
def test_find_bb_end(kernel32_idb, version, bitness, expected):
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

    # regression test
    assert api.idaapi._find_bb_end(0x689016A4) == 0x689016AD


@kern32_test()
def test_find_bb_start(kernel32_idb, version, bitness, expected):
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


@kern32_test()
def test_flow_preds(kernel32_idb, version, bitness, expected):
    api = idb.IDAPython(kernel32_idb)

    assert lpluck('src', api.idaapi._get_flow_preds(0x68901695)) == []
    assert lpluck('src', api.idaapi._get_flow_preds(0x68901697)) == [0x68901695]
    assert lpluck('src', api.idaapi._get_flow_preds(0x68901698)) == [0x68901697]

    assert lpluck('src', api.idaapi._get_flow_preds(0x68906156)) == [0x6890169E]
    assert lpluck('type', api.idaapi._get_flow_preds(0x68906156)) == [api.idaapi.fl_JN]


@kern32_test()
def test_flow_succs(kernel32_idb, version, bitness, expected):
    api = idb.IDAPython(kernel32_idb)

    assert lpluck('dst', api.idaapi._get_flow_succs(0x68901695)) == [0x68901697]
    assert lpluck('dst', api.idaapi._get_flow_succs(0x68901697)) == [0x68901698]
    assert lpluck('dst', api.idaapi._get_flow_succs(0x68901698)) == [0x6890169A]

    assert lpluck('dst', api.idaapi._get_flow_succs(0x6890169E)) == [0x689016A4, 0x68906156]
    assert lpluck('type', api.idaapi._get_flow_succs(0x6890169E)) == [api.idaapi.fl_F, api.idaapi.fl_JN]


@kern32_test()
def test_flow_chart(kernel32_idb, version, bitness, expected):
    api = idb.IDAPython(kernel32_idb)

    DllEntryPoint = api.ida_funcs.get_func(0x68901695)
    bbs = list(api.idaapi.FlowChart(DllEntryPoint))
    assert list(sorted(lpluck('startEA', bbs))) == [
        0x68901695, 0x689016A4, 0x68906156]

    for bb in bbs:
        if bb.startEA == 0x68901695:
            assert list(
                sorted(
                    lpluck(
                        'startEA',
                        bb.succs()))) == [
                0x689016A4,
                0x68906156]
        elif bb.startEA == 0x689016A4:
            assert lpluck('startEA', bb.succs()) == []
        elif bb.startEA == 0x68906156:
            assert lpluck('startEA', bb.succs()) == [0x689016A4]

    for bb in bbs:
        if bb.startEA == 0x68901695:
            assert lpluck('startEA', bb.preds()) == []
        elif bb.startEA == 0x689016A4:
            assert list(sorted(lpluck('startEA', bb.preds()))) == [0x68901695, 0x68906156]
        elif bb.startEA == 0x68906156:
            assert lpluck('startEA', bb.preds()) == [0x68901695]


@kern32_test()
def test_fixups(kernel32_idb, version, bitness, expected):
    api = idb.IDAPython(kernel32_idb)

    # .text:6890101E 01C 53                                      push    ebx
    # .text:6890101F 020 8B 58 10                                mov     ebx, [eax+10h]
    # .text:68901022 020 57                                      push    edi
    # .text:68901023 024 8B 3D 98 B1 9D 68                       mov     edi, dword_689DB198
    # .text:68901029 024 85 FF                                   test    edi, edi
    assert api.idaapi.contains_fixups(0x6890101E, 1) is False
    assert api.idaapi.contains_fixups(0x6890101E, 2) is False
    assert api.idaapi.contains_fixups(0x6890101E, 5) is False
    assert api.idaapi.contains_fixups(0x6890101E, 7) is False
    assert api.idaapi.contains_fixups(0x6890101E, 8) is True
    assert api.idaapi.contains_fixups(0x6890101E, 9) is True
    assert api.idaapi.contains_fixups(0x68901023 + 2, 1) is True
    assert api.idaapi.contains_fixups(0x68901023 + 2, 0x10) is True

    assert api.idaapi.get_next_fixup_ea(0x6890101E) == 0x68901025
    assert api.idaapi.get_next_fixup_ea(0x68901023) == 0x68901025
    assert api.idaapi.get_next_fixup_ea(0x68901025) == 0x68901025
    assert api.idaapi.get_next_fixup_ea(0x68901025 + 1) == 0x68901034


@kern32_test()
def test_input_md5(kernel32_idb, version, bitness, expected):
    api = idb.IDAPython(kernel32_idb)
    assert api.idc.GetInputMD5() == '00bf1bf1b779ce1af41371426821e0c2'
    assert api.idautils.GetInputFileMD5() == '00bf1bf1b779ce1af41371426821e0c2'
    assert api.ida_nalt.retrieve_input_file_md5() == '00bf1bf1b779ce1af41371426821e0c2'


@kern32_test()
def test_input_sha256(kernel32_idb, version, bitness, expected):
    api = idb.IDAPython(kernel32_idb)
    assert api.idc.GetInputSHA256() == 'ba1bc09b7bb290656582b4e4d896105caf00825b557ce45621e76741cd5dc262'
    assert api.ida_nalt.retrieve_input_file_sha256() == 'ba1bc09b7bb290656582b4e4d896105caf00825b557ce45621e76741cd5dc262'


@kern32_test()
def test_segments(kernel32_idb, version, bitness, expected):
    api = idb.IDAPython(kernel32_idb)

    assert api.idc.FirstSeg() == 0x68901000
    assert api.idc.NextSeg(0x68901000) == 0x689db000
    assert api.idc.NextSeg(0x689db000) == 0x689dd000

    assert api.idc.SegName(0x68901000) == '.text'
    assert api.idc.SegName(0x689db000) == '.data'
    assert api.idc.SegName(0x689dd000) == '.idata'

    assert api.idc.SegStart(0x68901000) == 0x68901000
    assert api.idc.SegStart(0x68901000 + 1) == 0x68901000
    assert api.idc.SegStart(0x689db000 - 1) == 0x68901000
    assert api.idc.SegStart(0x689db000) == 0x689db000

    assert api.idc.SegEnd(0x68901000) == 0x689db000
    assert api.idc.SegEnd(0x689db000) == 0x689dd000
    assert api.idc.SegEnd(0x689dd000) == 0x689de230

    seg = api.idaapi.getseg(0x68901000)
    assert seg.startEA == 0x68901000
    assert seg.endEA == 0x689db000


@kern32_test()
@requires_capstone
def test_get_mnem(kernel32_idb, version, bitness, expected):
    api = idb.IDAPython(kernel32_idb)

    # .text:68901695 000 8B FF                                   mov     edi, edi
    # .text:68901697 000 55                                      push    ebp
    # .text:68901698 004 8B EC                                   mov     ebp, esp
    # .text:6890169A 004 83 7D 0C 01                             cmp     [ebp+fdwReason], 1
    # .text:6890169E 004 0F 84 B2 4A 00 00                       jz      loc_68906156
    assert api.idc.GetMnem(0x68901695) == 'mov'


@kern32_test()
def test_functions(kernel32_idb, version, bitness, expected):
    api = idb.IDAPython(kernel32_idb)

    funcs = api.idautils.Functions()
    # exact number of detected functions varies by IDA version,
    # but the first and last addresses should remain constant.
    assert funcs[0] == 0x68901010
    assert funcs[-1] == 0x689bd410

    # this is a function chunk. should not be reported.
    assert 0x689018e5 not in funcs


@kern32_test()
def test_function_names(kernel32_idb, version, bitness, expected):
    api = idb.IDAPython(kernel32_idb)

    assert api.idc.GetFunctionName(0x68901695) == 'DllEntryPoint'
    assert api.idc.GetFunctionName(0x689016b5) == 'sub_689016b5'

    with pytest.raises(KeyError):
        # this is issue #7.
        _ = api.idc.GetFunctionName(0x689018e5)


@slow
@kern32_test()
def test_all_function_names(kernel32_idb, version, bitness, expected):
    api = idb.IDAPython(kernel32_idb)

    # should not raise any exceptions
    funcs = api.idautils.Functions()
    for func in funcs:
        _ = api.idc.GetFunctionName(func)


@kern32_test()
def test_comments(kernel32_idb, version, bitness, expected):
    api = idb.IDAPython(kernel32_idb)

    assert api.ida_bytes.get_cmt(0x6890103c, False) == 'Flags'
    assert api.ida_bytes.get_cmt(0x689023b4, True) == 'jumptable 6892FF97 default case'

    assert api.idc.Comment(0x6890103c) == 'Flags'
    assert api.idc.RptCmt(0x6890103c) == ''

    assert api.idc.RptCmt(0x689023b4) == 'jumptable 6892FF97 default case'
    assert api.idc.Comment(0x689023b4) == ''

    assert api.idc.GetCommentEx(0x6890103c, False) == 'Flags'
    assert api.idc.GetCommentEx(0x689023b4, True) == 'jumptable 6892FF97 default case'


@slow
@kern32_test([
    (695, 32, (13369, 283)),
    (695, 64, (13369, 283)),
    (700, 32, (13368, 283)),
    (700, 64, (13368, 283)),
])
def test_all_comments(kernel32_idb, version, bitness, expected):
    api = idb.IDAPython(kernel32_idb)

    regcmts = []
    repcmts = []

    textseg = 0x68901000
    for ea in range(textseg, api.idc.SegEnd(textseg)):
        flags = api.idc.GetFlags(ea)
        if not api.ida_bytes.has_cmt(flags):
            continue

        regcmts.append(api.ida_bytes.get_cmt(ea, False))
        repcmts.append(api.ida_bytes.get_cmt(ea, True))

    assert len(regcmts), len(repcmnts) == expected


@kern32_test()
def test_LocByName(kernel32_idb, version, bitness, expected):
    api = idb.IDAPython(kernel32_idb)

    assert api.idc.LocByName('CancelIo') == 0x6892e70a
    assert api.idc.GetFunctionName(api.idc.LocByName('CancelIo')) == 'CancelIo'

    assert api.idc.LocByName('__does not exist__') == -1


@kern32_test()
def test_MinMaxEA(kernel32_idb, version, bitness, expected):
    api = idb.IDAPython(kernel32_idb)

    assert api.idc.MinEA() == 0x68901000
    assert api.idc.MaxEA() == 0x689de230


@kern32_test()
def test_CodeRefsTo(kernel32_idb, version, bitness, expected):
    api = idb.IDAPython(kernel32_idb)

    # this is the start of a function.
    # calls are not code refs.
    assert set(api.idautils.CodeRefsTo(0x689AD974, True)) == set([])

    # this is the start of a basic block with one incoming edge, from a taken conditional jump.
    assert set(api.idautils.CodeRefsTo(0x68901031, True)) == set([0x6890102b])

    # this is an instruction at the middle of a basic block.
    assert set(api.idautils.CodeRefsTo(0x68901012, True)) == set([0x68901010])
    assert set(api.idautils.CodeRefsTo(0x68901012, False)) == set([])


@kern32_test()
def test_CodeRefsFrom(kernel32_idb, version, bitness, expected):
    api = idb.IDAPython(kernel32_idb)

    # this is an instruction at the middle of a basic block.
    assert set(api.idautils.CodeRefsFrom(0x68901010, True)) == set([0x68901012])
    assert set(api.idautils.CodeRefsFrom(0x68901010, False)) == set([])

    # this is the end of a function.
    assert set(api.idautils.CodeRefsFrom(0x689011B2, True)) == set([])

    # this is a conditional jump.
    assert set(api.idautils.CodeRefsFrom(0x6890102B, True)) == set([0x6890113B, 0x68901031])
    assert set(api.idautils.CodeRefsFrom(0x6890102B, False)) == set([0x6890113B])


@kern32_test()
def test_DataRefsFrom(kernel32_idb, version, bitness, expected):
    api = idb.IDAPython(kernel32_idb)

    # .text:6890618E cmp     ___security_cookie, 0
    assert set(api.idautils.DataRefsFrom(0x6890618E)) == set([0x689db370])

    # .text:689061AB mov     eax, ___security_cookie
    assert set(api.idautils.DataRefsFrom(0x689061AB)) == set([0x689db370])

    # .text:689061B2 mov     dword_689DB05
    assert set(api.idautils.DataRefsFrom(0x689061B2)) == set([0x689DB054])


@kern32_test()
def test_imports(kernel32_idb, version, bitness, expected):
    api = idb.IDAPython(kernel32_idb)
    assert api.ida_nalt.get_import_module_qty() == 47
    assert api.ida_nalt.get_import_module_name(0) == 'api-ms-win-core-rtlsupport-l1-2-0'
    assert api.ida_nalt.get_import_module_name(1) == 'ntdll'

    names = []
    def cb(addr, name, ordinal):
        names.append((addr, name, ordinal))
        return True

    api.ida_nalt.enum_import_names(1, cb)
    assert len(names) == 388
    assert names[0] == (0x689dd014, 'NtMapUserPhysicalPagesScatter', None)


@kern32_test()
def test_exports(kernel32_idb, version, bitness, expected):
    api = idb.IDAPython(kernel32_idb)
    assert api.ida_entry.get_entry_qty() == 1572
    assert api.ida_entry.get_entry_ordinal(0x0) == 1
    assert api.ida_entry.get_entry(api.ida_entry.get_entry_ordinal(0x0)) == 0x6890172d
    assert api.ida_entry.get_entry_name(api.ida_entry.get_entry_ordinal(0x0)) == 'BaseThreadInitThunk'
    assert api.ida_entry.get_entry_forwarder(api.ida_entry.get_entry_ordinal(0x10)) is None

    assert api.ida_entry.get_entry_ordinal(1572) == 0x68901695
    assert api.ida_entry.get_entry_name(0x68901695) == 'DllEntryPoint'


@kern32_test()
def test_GetType(kernel32_idb, version, bitness, expected):
    api = idb.IDAPython(kernel32_idb)
    assert api.idc.GetType(0x68901695) == 'BOOL __stdcall DllEntryPoint(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)'

    # valid function, but no type data associated...

    #     .text:6899AE01                         ; Attributes: bp-based frame
    #     .text:6899AE01
    #     .text:6899AE01                         sub_6899AE01 proc near
    assert api.idc.GetType(0x6899AE01) == None


@kern32_test()
def test_inf_structure(kernel32_idb, version, bitness, expected):
    api = idb.IDAPython(kernel32_idb)
    inf_structure = api.idaapi.get_inf_structure()
    assert inf_structure.procname == 'metapc'


@requires_capstone
def test_multi_bitness():
    cd = os.path.dirname(__file__)
    idbpath = os.path.join(cd, 'data', 'multibitness', 'multibitness.idb')

    with idb.from_file(idbpath) as db:
        api = idb.IDAPython(db)
        assert api.idc.GetDisasm(0x0)    == 'xor\tdx, dx'    # 16-bit
        assert api.idc.GetDisasm(0x1000) == 'xor\tedx, edx'  # 32-bit


@kern32_test()
def test_name(kernel32_idb, version, bitness, expected):
    api = idb.IDAPython(kernel32_idb)
    assert api.ida_bytes.has_name(api.ida_bytes.get_flags(0x689DB190)) == True
    assert api.ida_name.get_name(0x689DB190) == 'FinestResolution'


@kern32_test()
def test_names(kernel32_idb, version, bitness, expected):
    api = idb.IDAPython(kernel32_idb)
    if version == 700:
        assert len(list(api.idautils.Names())) == 14247
    elif version == 695:
        assert len(list(api.idautils.Names())) == 14252
    else:
        raise ValueError('unexpected version')


def test_anterior_lines():
    cd = os.path.dirname(__file__)
    idbpath = os.path.join(cd, 'data', 'ant-post-comments', 'small.idb')

    with idb.from_file(idbpath) as db:
        api = idb.IDAPython(db)
        assert api.idc.LineA(1, 0) == 'anterior line 1'
        assert api.idc.LineA(1, 1) == 'anterior line 2'
        assert api.idc.LineA(1, 2) == ''


def test_posterior_lines():
    cd = os.path.dirname(__file__)
    idbpath = os.path.join(cd, 'data', 'ant-post-comments', 'small.idb')

    with idb.from_file(idbpath) as db:
        api = idb.IDAPython(db)
        assert api.idc.LineB(1, 0) == 'posterior line 1'
        assert api.idc.LineB(1, 1) == 'posterior line 2'
        assert api.idc.LineB(1, 2) == ''


def test_function_comment():
    cd = os.path.dirname(__file__)
    idbpath = os.path.join(cd, 'data', 'func-comment', 'small.idb')

    with idb.from_file(idbpath) as db:
        api = idb.IDAPython(db)
        assert api.ida_funcs.get_func_cmt(3, False) == 'function comment'
        assert api.ida_funcs.get_func_cmt(3, True) == 'repeatable function comment'

