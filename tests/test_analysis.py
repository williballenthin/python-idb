from fixtures import *

import idb.analysis


import logging
logging.basicConfig(level=logging.DEBUG)


def test_root(kernel32_idb):
    root = idb.analysis.Root(kernel32_idb)

    assert root.version == 695
    assert root.get_field_tag('version') == 'A'
    assert root.get_field_index('version') == -1

    assert root.version_string == '6.95'
    assert root.open_count == 1
    assert root.created.isoformat() == '2017-06-20T22:31:34'
    assert root.crc == 0xdf9bdf12
    assert root.md5 == '00bf1bf1b779ce1af41371426821e0c2'


def test_loader(kernel32_idb):
    loader = idb.analysis.Loader(kernel32_idb)

    assert loader.plugin == 'pe.ldw'
    assert loader.format.startswith('Portable executable') == True


def test_entrypoints(kernel32_idb):
    entrypoints = idb.analysis.EntryPoints(kernel32_idb)

    addresses = entrypoints.addresses
    assert len(addresses) == 1
    assert 0x68901695 in addresses
    assert addresses[0x68901695] == 'DllEntryPoint'

    ordinals = entrypoints.ordinals
    assert len(ordinals) == 0x623
    assert 0x1 in ordinals
    assert 0x623 in ordinals
    assert ordinals[0x1] == 'BaseThreadInitThunk'

    allofthem = entrypoints.all
    assert len(allofthem) == 0x624


def test_fileregions(kernel32_idb):
    fileregions = idb.analysis.FileRegions(kernel32_idb)

    regions = fileregions.regions
    assert len(regions) == 3
    assert list(regions.keys()) == [0x68901000, 0x689db000, 0x689dd000]


    assert regions[0x68901000].start == 0x68901000
    assert regions[0x68901000].end == 0x689db000
    assert regions[0x68901000].rva == 0x1000


def test_functions(kernel32_idb):
    functions = idb.analysis.Functions(kernel32_idb)

    funcs = functions.functions
    assert len(funcs) == 0x12a8

    for addr, func in funcs.items():
        assert addr == func.startEA


def test_struct(kernel32_idb):
    # ; BOOL __stdcall DllEntryPoint(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
    # .text:68901695                                         public DllEntryPoint
    # .text:68901695                         DllEntryPoint   proc near
    # .text:68901695
    # .text:68901695                         hinstDLL        = dword ptr  8
    # .text:68901695                         fdwReason       = dword ptr  0Ch
    # .text:68901695                         lpReserved      = dword ptr  10h
    struc = idb.analysis.Struct(kernel32_idb, 0xFF000075)
    members = list(struc.get_members())

    assert list(map(lambda m: m.get_name(), members)) == [' s',
                                                          ' r',
                                                          'hinstDLL',
                                                          'fdwReason',
                                                          'lpReserved',]

    assert members[2].get_type() == 'HINSTANCE'


def test_function(kernel32_idb):
    # .text:689016B5                         sub_689016B5    proc near
    # .text:689016B5
    # .text:689016B5                         var_214         = dword ptr -214h
    # .text:689016B5                         var_210         = dword ptr -210h
    # .text:689016B5                         var_20C         = dword ptr -20Ch
    # .text:689016B5                         var_205         = byte ptr -205h
    # .text:689016B5                         var_204         = word ptr -204h
    # .text:689016B5                         var_4           = dword ptr -4
    # .text:689016B5                         arg_0           = dword ptr  8
    # .text:689016B5
    # .text:689016B5                         ; FUNCTION CHUNK AT .text:689033D9 SIZE 00000017 BYTES
    # .text:689016B5                         ; FUNCTION CHUNK AT .text:68904247 SIZE 000000A3 BYTES
    # .text:689016B5                         ; FUNCTION CHUNK AT .text:689061B9 SIZE 0000025E BYTES
    # .text:689016B5                         ; FUNCTION CHUNK AT .text:689138B4 SIZE 0000001F BYTES
    # .text:689016B5                         ; FUNCTION CHUNK AT .text:6892BC20 SIZE 00000021 BYTES
    # .text:689016B5                         ; FUNCTION CHUNK AT .text:6892F138 SIZE 00000015 BYTES
    # .text:689016B5                         ; FUNCTION CHUNK AT .text:6892F267 SIZE 00000029 BYTES
    # .text:689016B5                         ; FUNCTION CHUNK AT .text:68934D65 SIZE 0000003D BYTES
    # .text:689016B5                         ; FUNCTION CHUNK AT .text:68937707 SIZE 00000084 BYTES
    # .text:689016B5
    # .text:689016B5 8B FF                                   mov     edi, edi
    # .text:689016B7 55                                      push    ebp
    # .text:689016B8 8B EC                                   mov     ebp, esp
    # .text:689016BA 81 EC 14 02 00 00                       sub     esp, 214h
    sub_689016B5 = idb.analysis.Function(kernel32_idb, 0x689016B5)
    assert sub_689016B5.get_name() == 'sub_689016B5'

    chunks = list(sub_689016B5.get_chunks())
    assert chunks == [(0x689033D9, 0x17),
                      (0x68904247, 0xA3),
                      (0x689061B9, 0x25E),
                      (0x689138B4, 0x1F),
                      (0x6892BC20, 0x21),
                      (0x6892F138, 0x15),
                      (0x6892F267, 0x29),
                      (0x68934D65, 0x3D),
                      (0x68937707, 0x84)]

    #sub_689016B5.get_unk()


    # ; BOOL __stdcall DllEntryPoint(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
    # .text:68901695                                         public DllEntryPoint
    # .text:68901695                         DllEntryPoint   proc near
    # .text:68901695
    # .text:68901695                         hinstDLL        = dword ptr  8
    # .text:68901695                         fdwReason       = dword ptr  0Ch
    # .text:68901695                         lpReserved      = dword ptr  10h
    DllEntryPoint = idb.analysis.Function(kernel32_idb, 0x68901695)

    sig = DllEntryPoint.get_signature()
    assert sig.calling_convention == 'stdcall'
    assert sig.rtype == 'BOOL'
    assert len(sig.parameters) == 3
    assert list(map(lambda p: p.type, sig.parameters)) == ['HINSTANCE', 'DWORD', 'LPVOID']
    assert list(map(lambda p: p.name, sig.parameters)) == ['hinstDLL', 'fdwReason', 'lpReserved']


def test_stack_change_points(kernel32_idb):
    # .text:68901AEA                         CreateThread    proc near
    # .text:68901AEA
    # .text:68901AEA                         lpThreadAttributes= dword ptr  8
    # .text:68901AEA                         dwStackSize     = dword ptr  0Ch
    # .text:68901AEA                         lpStartAddress  = dword ptr  10h
    # .text:68901AEA                         lpParameter     = dword ptr  14h
    # .text:68901AEA                         dwCreationFlags = dword ptr  18h
    # .text:68901AEA                         lpThreadId      = dword ptr  1Ch
    # .text:68901AEA
    # .text:68901AEA 8B FF                                   mov     edi, edi
    # .text:68901AEC 55                                      push    ebp
    # .text:68901AED 8B EC                                   mov     ebp, esp
    # .text:68901AEF FF 75 1C                                push    [ebp+lpThreadId]
    # .text:68901AF2 8B 45 18                                mov     eax, [ebp+dwCreationFlags]
    # .text:68901AF5 6A 00                                   push    0
    # .text:68901AF7 25 04 00 01 00                          and     eax, 10004h
    # .text:68901AFC 50                                      push    eax
    # .text:68901AFD FF 75 14                                push    [ebp+lpParameter]
    # .text:68901B00 FF 75 10                                push    [ebp+lpStartAddress]
    # .text:68901B03 FF 75 0C                                push    [ebp+dwStackSize]
    # .text:68901B06 FF 75 08                                push    [ebp+lpThreadAttributes]
    # .text:68901B09 6A FF                                   push    0FFFFFFFFh
    # .text:68901B0B FF 15 00 D8 9D 68                       call    ds:CreateRemoteThreadEx_0
    # .text:68901B11 5D                                      pop     ebp
    # .text:68901B12 C2 18 00                                retn    18h
    # .text:68901B12                         CreateThread    endp
    CreateThread = idb.analysis.Function(kernel32_idb, 0x68901aea)
    change_points = list(CreateThread.get_stack_change_points())
    assert change_points == [(0x68901aed, -4),
                             (0x68901af2, -4),
                             (0x68901af7, -4),
                             (0x68901afd, -4),
                             (0x68901b00, -4),
                             (0x68901b03, -4),
                             (0x68901b06, -4),
                             (0x68901b09, -4),
                             (0x68901b0b, -4),
                             (0x68901b11, 32),
                             (0x68901b12, 4)]

    # .text:68901493                         ; HANDLE __stdcall GetCurrentProcess()
    # .text:68901493                                         public GetCurrentProcess
    # .text:68901493                         GetCurrentProcess proc near
    # .text:68901493 83 C8 FF                                or      eax, 0FFFFFFFFh
    # .text:68901496 C3                                      retn
    # .text:68901496                         GetCurrentProcess endp
    GetCurrentProcess = idb.analysis.Function(kernel32_idb, 0x68901493)
    with pytest.raises(KeyError):
        # there are no stack change points in this function
        assert list(GetCurrentProcess.get_stack_change_points()) == []



def test_xrefs(kernel32_idb):
    assert list(idb.analysis.crefs_from(kernel32_idb, 0x68901695)) == []
    assert list(idb.analysis.crefs_from(kernel32_idb, 0x6890169E)) == [0x68906156]

    assert list(idb.analysis.crefs_to(kernel32_idb, 0x6890169E)) == []
    assert list(idb.analysis.crefs_to(kernel32_idb, 0x68906156)) == [0x6890169E]
