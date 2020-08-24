import functools
import re

import idb.analysis
from fixtures import *
from idb.typeinf_flags import *

try:
    from re import fullmatch
except ImportError:

    def fullmatch(regex, string, flags=0):
        """Emulate python-3.4 re.fullmatch()."""
        return re.match("(?:" + regex + r")\Z", string, flags=flags)


def pluck(prop, s):
    """
    generate the values from the given attribute with name `prop` from the given sequence of items `s`.

    Args:
      prop (str): the name of an attribute.
      s (sequnce): a bunch of objects.

    Yields:
      any: the values of the requested field across the sequence
    """
    for x in s:
        yield getattr(x, prop)


def lpluck(prop, s):
    """
    like `pluck`, but returns the result in a single list.
    """
    return list(pluck(prop, s))


@kern32_test()
def test_root(kernel32_idb, version, bitness, expected):
    root = idb.analysis.Root(kernel32_idb)

    assert root.version in (480, 610, 640, 650, 670, 680, 695, 700)
    assert root.get_field_tag("version") == "A"
    assert root.get_field_index("version") == -1

    vs = str(version / 100)
    assert root.version_string == vs if len(vs) == 4 else vs + "0"
    assert root.open_count in (1, 2)
    assert root.md5 == "00bf1bf1b779ce1af41371426821e0c2"


@kern32_test()
def test_root_timestamp(kernel32_idb, version, bitness, expected):
    root = idb.analysis.Root(kernel32_idb)
    actual = root.created.isoformat()
    pattern = r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"
    assert fullmatch(pattern, actual) is not None


@kern32_test()
def test_root_open_count(kernel32_idb, version, bitness, expected):
    root = idb.analysis.Root(kernel32_idb)
    assert root.open_count in (2, 1)


@kern32_test(
    [
        (695, 32, "pe.ldw"),
        (695, 64, "pe64.l64"),
        (700, 32, "pe.dll"),
        (700, 64, "pe64.dll"),
    ]
)
def test_loader(kernel32_idb, version, bitness, expected):
    loader = idb.analysis.Loader(kernel32_idb)

    assert loader.format.startswith("Portable executable") is True
    assert loader.plugin == expected


@kern32_test(
    [
        (695, 32, 0x75),
        (695, 64, 0x75),
        (700, 32, 0x7A),  # not supported.
        (700, 64, 0x7A),  # not supported.
    ]
)
def test_fileregions(kernel32_idb, version, bitness, expected):
    fileregions = idb.analysis.FileRegions(kernel32_idb)

    regions = fileregions.regions
    assert len(regions) == 3
    assert list(regions.keys()) == [0x68901000, 0x689DB000, 0x689DD000]

    assert regions[0x68901000].start == 0x68901000
    assert regions[0x68901000].end == 0x689DB000
    assert regions[0x68901000].rva == 0x1000


@kern32_test(
    [(695, 32, 0x12A8), (695, 64, 0x12A8), (700, 32, 0x1290), (700, 64, 0x1290),]
)
def test_functions(kernel32_idb, version, bitness, expected):
    functions = idb.analysis.Functions(kernel32_idb)
    funcs = functions.functions
    for addr, func in funcs.items():
        assert addr == func.startEA
    assert len(funcs) == expected


@kern32_test(
    [(695, 32, 0x75), (695, 64, 0x75), (700, 32, 0x7A), (700, 64, 0x7A),]
)
def test_function_frame(kernel32_idb, version, bitness, expected):
    DllEntryPoint = idb.analysis.Functions(kernel32_idb).functions[0x68901695]
    assert DllEntryPoint.startEA == 0x68901695
    assert DllEntryPoint.endEA == 0x689016B0
    assert DllEntryPoint.frame == expected


@kern32_test()
def test_struct(kernel32_idb, version, bitness, expected):
    # ; BOOL __stdcall DllEntryPoint(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
    # .text:68901695                                         public DllEntryPoint
    # .text:68901695                         DllEntryPoint   proc near
    # .text:68901695
    # .text:68901695                         hinstDLL        = dword ptr  8
    # .text:68901695                         fdwReason       = dword ptr  0Ch
    # .text:68901695                         lpReserved      = dword ptr  10h
    DllEntryPoint = idb.analysis.Functions(kernel32_idb).functions[0x68901695]
    struc = idb.analysis.Struct(kernel32_idb, DllEntryPoint.frame)

    members = list(struc.get_members())

    assert list(map(lambda m: m.get_name(), members)) == [
        " s",
        " r",
        "hinstDLL",
        "fdwReason",
        "lpReserved",
    ]

    assert members[2].get_type() == ("HINSTANCE" if version > 500 else None)


def _check_functype(db, fva, _type):
    return idb.analysis.Function(db, fva).get_signature().get_typestr() == _type


@kern32_test()
def test_function(kernel32_idb, version, bitness, expected):
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
    if 500 < version <= 700:
        assert sub_689016B5.get_name() == "sub_689016B5"
    else:
        assert sub_689016B5.get_name() == "__BaseDllInitialize@12"

    chunks = list(sub_689016B5.get_chunks())
    assert chunks == [
        (0x689033D9, 0x17),
        (0x68904247, 0xA3),
        (0x689061B9, 0x25E),
        (0x689138B4, 0x1F),
        (0x6892BC20, 0x21),
        (0x6892F138, 0x15),
        (0x6892F267, 0x29),
        (0x68934D65, 0x3D),
        (0x68937707, 0x84),
    ]

    # sub_689016B5.get_unk()

    # ; BOOL __stdcall DllEntryPoint(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
    # .text:68901695                                         public DllEntryPoint
    # .text:68901695                         DllEntryPoint   proc near
    # .text:68901695
    # .text:68901695                         hinstDLL        = dword ptr  8
    # .text:68901695                         fdwReason       = dword ptr  0Ch
    # .text:68901695                         lpReserved      = dword ptr  10h
    DllEntryPoint = idb.analysis.Function(kernel32_idb, 0x68901695)

    sig = DllEntryPoint.get_signature()
    if version <= 700:
        assert (
            sig.get_typestr()
            == "BOOL (__stdcall DllEntryPoint)(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)"
        )
    else:
        assert (
            sig.get_typestr()
            == "BOOL (__stdcall _BaseDllInitialize@12)(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)"
        )

    assert sig.get_cc() == CM_CC_STDCALL
    assert sig.get_rettype().get_typename() == "BOOL"
    assert len(sig.type_details.args) == 3

    check_functype = functools.partial(_check_functype, kernel32_idb)

    if version >= 730:
        assert check_functype(
            0x68901551,
            "void (__fastcall @__security_check_cookie@4)(uintptr_t StackCookie)",
        )
        assert check_functype(
            0x68901637, "void* (__cdecl _memset)(void*, int Val, size_t Size)"
        )
        assert check_functype(
            0x689031AE,
            "int (__thiscall ?NotifyLoadStringResource@CMessageMapper@FSPErrorMessages@@QAEJPAUHINSTANCE__@@IPBGKPAPAX@Z)(FSPErrorMessages::CMessageMapper* this, HINSTANCE CriticalSection, unsigned int, unsigned int16*, unsigned int, void**)",
        )
    elif version >= 720:
        assert check_functype(
            0x68936AEC,
            "int (__stdcall _BasepProcessInvalidImage@84)(NTSTATUS Status, int, int, int, int, int, int, int, int, int, int, int, int, int, PUNICODE_STRING, int, int, int, int, int, int)",
        )
        assert check_functype(
            0x68901637, "void* (__cdecl _memset)(void* Dst, int Val, size_t Size)"
        )
        assert check_functype(
            0x689031AE,
            "int (__thiscall ?NotifyLoadStringResource@CMessageMapper@FSPErrorMessages@@QAEJPAUHINSTANCE__@@IPBGKPAPAX@Z)(FSPErrorMessages::CMessageMapper* this, HINSTANCE CriticalSection, unsigned int, unsigned int16*, unsigned int, void**)",
        )
    elif version >= 700:
        assert check_functype(
            0x68936AEC,
            "int (__cdecl BasepProcessInvalidImage)(NTSTATUS NtStatus, int, int, int, int, int, int, int, int, int, int, int, int, int, PUNICODE_STRING, int, int, int, int, int, int)",
        )
        assert check_functype(
            0x68904AED, "int (__thiscall sub_68904AED)(HANDLE FileHandle, int, int)"
        )
    elif version > 630:
        assert check_functype(
            0x68915529, "int (__cdecl sub_68915529)(LPCWSTR lpString1, int, int)"
        )
        assert check_functype(
            0x68904AED, "int (__thiscall sub_68904AED)(HANDLE FileHandle, int, int)"
        )
    elif 630 == version:
        assert check_functype(
            0x68915529, "int (__cdecl sub_68915529)(PCNZWCH Buf1, int, int)"
        )
        assert check_functype(
            0x689172CF, "int (__thiscall sub_689172CF)(DWORD Size, int, int, int, int)"
        )
    elif version == 500:
        assert check_functype(
            0x68903158,
            "int (__fastcall _BasepNotifyLoadStringResource@16)(int, int, int, int, int, int)",
        )
        assert check_functype(
            0x68906511, "int (__cdecl _StringCbPrintfW)(wchar_t*, int, wchar_t*, int8)"
        )


def test_function_usercall():
    _db = load_idb(os.path.join(CD, "data", "thumb", "ls.idb"))
    check_functype = functools.partial(_check_functype, _db)

    # unsigned __int8 *__usercall human_readable@<R0>(
    #   uintmax_t n@<0:R0, 4:R1>,
    #   unsigned __int8 *buf@<R2>,
    #   int opts@<R3>,
    #   uintmax_t from_block_size,
    #   uintmax_t to_block_size
    # )
    assert check_functype(
        0x181F8,
        "unsigned int8* (__usercall human_readable@<R0>)(uintmax_t n@<0:R0, 4:R1>, unsigned int8* buf@<R2>, int opts@<R3>, uintmax_t from_block_size, uintmax_t to_block_size)",
    )

    # unsigned __int8 *__usercall imaxtostr@<R0>(intmax_t i@<0:R0, 4:R1>, unsigned __int8 *buf@<R2>)
    assert check_functype(
        0x18D94,
        "unsigned int8* (__usercall imaxtostr@<R0>)(intmax_t i@<0:R0, 4:R1>, unsigned int8* buf@<R2>)",
    )

    # unsigned __int8 *__usercall umaxtostr@<R0>(uintmax_t i@<0:R0, 4:R1>, unsigned __int8 *buf@<R2>)
    assert check_functype(
        0x18E00,
        "unsigned int8* (__usercall umaxtostr@<R0>)(uintmax_t i@<0:R0, 4:R1>, unsigned int8* buf@<R2>)",
    )

    # uintmax_t __usercall xnumtoumax@<R1:R0>(
    #   const unsigned __int8 *n_str@<R0>,
    #   int base@<R1>,
    #   uintmax_t min@<0:R2, 4:R3>,
    #   uintmax_t max,
    #   const unsigned __int8 *suffixes,
    #   const unsigned __int8 *err,
    #   int err_exit
    # )
    assert check_functype(
        0x1B944,
        "uintmax_t (__usercall xnumtoumax@<R1:R0>)(unsigned int8* n_str@<R0>, int base@<R1>, uintmax_t min@<0:R2, 4:R3>, uintmax_t max, unsigned int8* suffixes, unsigned int8* err, int err_exit)",
    )

    # uintmax_t __usercall xdectoumax@<R1:R0>(
    #   const unsigned __int8 *n_str@<R0>,
    #   uintmax_t min@<0:R2, 4:R3>,
    #   uintmax_t max,
    #   const unsigned __int8 *suffixes,
    #   const unsigned __int8 *err,
    #   int err_exit
    # )
    assert check_functype(
        0x1BA54,
        "uintmax_t (__usercall xdectoumax@<R1:R0>)(unsigned int8* n_str@<R0>, uintmax_t min@<0:R2, 4:R3>, uintmax_t max, unsigned int8* suffixes, unsigned int8* err, int err_exit)",
    )


@kern32_test()
def test_stack_change_points(kernel32_idb, version, bitness, expected):
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
    CreateThread = idb.analysis.Function(kernel32_idb, 0x68901AEA)
    change_points = list(CreateThread.get_stack_change_points())
    assert change_points == [
        (0x68901AED, -4),
        (0x68901AF2, -4),
        (0x68901AF7, -4),
        (0x68901AFD, -4),
        (0x68901B00, -4),
        (0x68901B03, -4),
        (0x68901B06, -4),
        (0x68901B09, -4),
        (0x68901B0B, -4),
        (0x68901B11, 32),
        (0x68901B12, 4),
    ]

    # .text:68901493                         ; HANDLE __stdcall GetCurrentProcess()
    # .text:68901493                                         public GetCurrentProcess
    # .text:68901493                         GetCurrentProcess proc near
    # .text:68901493 83 C8 FF                                or      eax, 0FFFFFFFFh
    # .text:68901496 C3                                      retn
    # .text:68901496                         GetCurrentProcess endp
    GetCurrentProcess = idb.analysis.Function(kernel32_idb, 0x68901493)
    # there are no stack change points in this function
    assert list(GetCurrentProcess.get_stack_change_points()) == []


@kern32_test()
def test_xrefs(kernel32_idb, version, bitness, expected):
    assert lpluck("to", idb.analysis.get_crefs_from(kernel32_idb, 0x68901695)) == []
    assert lpluck("to", idb.analysis.get_crefs_from(kernel32_idb, 0x6890169E)) == [
        0x68906156
    ]

    assert lpluck("frm", idb.analysis.get_crefs_to(kernel32_idb, 0x6890169E)) == []
    assert lpluck("frm", idb.analysis.get_crefs_to(kernel32_idb, 0x68906156)) == [
        0x6890169E
    ]

    # .text:689016BA 004 81 EC 14 02 00 00                       sub     esp, 214h
    # .text:689016C0 218 A1 70 B3 9D 68                          mov     eax, ___security_cookie
    # .text:689016C5 218 33 C5                                   xor     eax, ebp
    security_cookie = 0x689DB370
    assert lpluck("to", idb.analysis.get_drefs_from(kernel32_idb, 0x689016C0)) == [
        security_cookie
    ]
    assert lpluck("frm", idb.analysis.get_drefs_to(kernel32_idb, 0x689016C0)) == []

    assert 0x689016C0 in pluck(
        "frm", idb.analysis.get_drefs_to(kernel32_idb, security_cookie)
    )
    assert (
        lpluck("to", idb.analysis.get_drefs_from(kernel32_idb, security_cookie)) == []
    )


@pytest.mark.skipif(six.PY2, reason="it consumes too much memory")
@kern32_test()
def test_fixups(kernel32_idb, version, bitness, expected):
    fixups = idb.analysis.Fixups(kernel32_idb).fixups
    assert len(fixups) == 31608

    # .text:68901022 020 57                                      push    edi
    # .text:68901023 024 8B 3D 98 B1 9D 68                       mov     edi, dword_689DB198
    # .text:68901029 024 85 FF                                   test    edi, edi
    assert fixups[0x68901023 + 2].offset == 0x689DB198
    assert fixups[0x68901023 + 2].get_fixup_length() == 0x4


@kern32_test()
def test_segments(kernel32_idb, version, bitness, expected):
    segs = idb.analysis.Segments(kernel32_idb).segments
    assert list(sorted(map(lambda s: s.startEA, segs.values()))) == [
        0x68901000,
        0x689DB000,
        0x689DD000,
    ]
    end_ea = list(sorted(map(lambda s: s.endEA, segs.values())))
    if version > 500:
        assert end_ea == [
            0x689DB000,
            0x689DD000,
            0x689DE230,
        ]
    else:
        assert end_ea == [1755164672, 1755169504, 1755177520]


@kern32_test(
    [
        (680, 32, None),
        (680, 64, None),
        (695, 32, None),
        (695, 64, None),
        (700, 32, None),
        (700, 64, None),
        (720, 32, None),
        (720, 64, None),
        (730, 32, None),
        (730, 64, None),
    ]
)
def test_segstrings(kernel32_idb, version, bitness, expected):
    strs = idb.analysis.SegStrings(kernel32_idb).strings

    # the first string is some binary data.
    assert strs[1:] == [".text", "CODE", ".data", "DATA", ".idata"]


def test_segments2(elf_idb):
    EXPECTED = {
        ".init": {
            "startEA": 0x80496AC,
            "sclass": 0x2,
            "orgbase": 0x0,
            "align": 0x5,
            "comb": 0x2,
            "perm": 0x5,
            "bitness": 0x1,
            "flags": 0x10,
            "sel": 0x1,
            "type": 0x2,
            "color": 0xFFFFFFFF,
        },
        ".plt": {
            "startEA": 0x80496D0,
            "sclass": 0x2,
            "orgbase": 0x0,
            "align": 0x3,
            "comb": 0x2,
            "perm": 0x5,
            "bitness": 0x1,
            "flags": 0x10,
            "sel": 0x2,
            "type": 0x2,
            "color": 0xFFFFFFFF,
        },
        ".plt.got": {
            "startEA": 0x8049DE0,
            "sclass": 0x2,
            "orgbase": 0x0,
            "align": 0xA,
            "comb": 0x2,
            "perm": 0x5,
            "bitness": 0x1,
            "flags": 0x10,
            "sel": 0x3,
            "type": 0x2,
            "color": 0xFFFFFFFF,
        },
        ".text": {
            "startEA": 0x8049DF0,
            "sclass": 0x2,
            "orgbase": 0x0,
            "align": 0x3,
            "comb": 0x2,
            "perm": 0x5,
            "bitness": 0x1,
            "flags": 0x10,
            "sel": 0x4,
            "type": 0x2,
            "color": 0xFFFFFFFF,
        },
        ".fini": {
            "startEA": 0x805B634,
            "sclass": 0x2,
            "orgbase": 0x0,
            "align": 0x5,
            "comb": 0x2,
            "perm": 0x5,
            "bitness": 0x1,
            "flags": 0x10,
            "sel": 0x5,
            "type": 0x2,
            "color": 0xFFFFFFFF,
        },
        ".rodata": {
            "startEA": 0x805B660,
            "sclass": 0x8,
            "orgbase": 0x0,
            "align": 0x8,
            "comb": 0x2,
            "perm": 0x4,
            "bitness": 0x1,
            "flags": 0x10,
            "sel": 0x6,
            "type": 0x3,
            "color": 0xFFFFFFFF,
        },
        ".eh_frame_hdr": {
            "startEA": 0x8060C14,
            "sclass": 0x8,
            "orgbase": 0x0,
            "align": 0x5,
            "comb": 0x2,
            "perm": 0x4,
            "bitness": 0x1,
            "flags": 0x10,
            "sel": 0x7,
            "type": 0x3,
            "color": 0xFFFFFFFF,
        },
        ".eh_frame": {
            "startEA": 0x8061430,
            "sclass": 0x8,
            "orgbase": 0x0,
            "align": 0x5,
            "comb": 0x2,
            "perm": 0x4,
            "bitness": 0x1,
            "flags": 0x10,
            "sel": 0x8,
            "type": 0x3,
            "color": 0xFFFFFFFF,
        },
        ".init_array": {
            "startEA": 0x8067F00,
            "sclass": 0xC,
            "orgbase": 0x0,
            "align": 0x5,
            "comb": 0x2,
            "perm": 0x6,
            "bitness": 0x1,
            "flags": 0x10,
            "sel": 0x9,
            "type": 0x3,
            "color": 0xFFFFFFFF,
        },
        ".fini_array": {
            "startEA": 0x8067F04,
            "sclass": 0xC,
            "orgbase": 0x0,
            "align": 0x5,
            "comb": 0x2,
            "perm": 0x6,
            "bitness": 0x1,
            "flags": 0x10,
            "sel": 0xA,
            "type": 0x3,
            "color": 0xFFFFFFFF,
        },
        ".jcr": {
            "startEA": 0x8067F08,
            "sclass": 0xC,
            "orgbase": 0x0,
            "align": 0x5,
            "comb": 0x2,
            "perm": 0x6,
            "bitness": 0x1,
            "flags": 0x10,
            "sel": 0xB,
            "type": 0x3,
            "color": 0xFFFFFFFF,
        },
        ".got": {
            "startEA": 0x8067FFC,
            "sclass": 0xC,
            "orgbase": 0x0,
            "align": 0x5,
            "comb": 0x2,
            "perm": 0x6,
            "bitness": 0x1,
            "flags": 0x10,
            "sel": 0xC,
            "type": 0x3,
            "color": 0xFFFFFFFF,
        },
        ".got.plt": {
            "startEA": 0x8068000,
            "sclass": 0xC,
            "orgbase": 0x0,
            "align": 0x5,
            "comb": 0x2,
            "perm": 0x6,
            "bitness": 0x1,
            "flags": 0x10,
            "sel": 0xD,
            "type": 0x3,
            "color": 0xFFFFFFFF,
        },
        ".data": {
            "startEA": 0x80681E0,
            "sclass": 0xC,
            "orgbase": 0x0,
            "align": 0x8,
            "comb": 0x2,
            "perm": 0x6,
            "bitness": 0x1,
            "flags": 0x10,
            "sel": 0xE,
            "type": 0x3,
            "color": 0xFFFFFFFF,
        },
        ".bss": {
            "startEA": 0x8068380,
            "sclass": 0x13,
            "orgbase": 0x0,
            "align": 0x9,
            "comb": 0x2,
            "perm": 0x6,
            "bitness": 0x1,
            "flags": 0x10,
            "sel": 0xF,
            "type": 0x9,
            "color": 0xFFFFFFFF,
        },
        "extern": {
            "startEA": 0x8068FB8,
            "sclass": 0x0,
            "orgbase": 0x0,
            "align": 0x3,
            "comb": 0x2,
            "perm": 0x0,
            "bitness": 0x1,
            "flags": 0x10,
            "sel": 0x10,
            "type": 0x1,
            "color": 0xFFFFFFFF,
        },
    }

    segs = idb.analysis.Segments(elf_idb).segments
    strs = idb.analysis.SegStrings(elf_idb).strings

    for seg in segs.values():
        segname = strs[seg.name_index]
        expected_seg = EXPECTED[segname]
        for k, v in expected_seg.items():
            assert v == getattr(seg, k)


@kern32_test()
def test_imports(kernel32_idb, version, bitness, expected):
    imports = list(idb.analysis.enumerate_imports(kernel32_idb))
    assert len(imports) == 1116
    assert (
        "api-ms-win-core-rtlsupport-l1-2-0",
        "RtlCaptureContext",
        0x689DD000,
    ) in imports

    libs = set([])
    for imp in imports:
        libs.add(imp.library)

    assert "KERNELBASE" in libs
    assert "ntdll" in libs


@kern32_test()
def test_entrypoints2(kernel32_idb, version, bitness, expected):
    entrypoints = list(idb.analysis.enumerate_entrypoints(kernel32_idb))

    assert len(entrypoints) == 1572
    assert entrypoints[0] == ("BaseThreadInitThunk", 0x6890172D, 1, None)
    if version > 680:
        assert entrypoints[-100] == (
            "WaitForThreadpoolWorkCallbacks",
            0x689DAB51,
            1473,
            "NTDLL.TpWaitForWork",
        )
    else:
        assert entrypoints[-100] == (
            "WaitForThreadpoolWorkCallbacks",
            0x689DAB51,
            1473,
            None,
        )
    if version <= 700:
        assert entrypoints[-1] == ("DllEntryPoint", 0x68901696, None, None)
    else:
        assert entrypoints[-1] == ("_BaseDllInitialize@12", 0x68901696, None, None)


@kern32_test()
def test_idainfo(kernel32_idb, version, bitness, expected):
    idainfo = idb.analysis.Root(kernel32_idb).idainfo

    if version == 695:
        assert idainfo.tag == "IDA"
    elif version == 700:
        assert idainfo.tag == "ida"
    assert 480 <= idainfo.version <= 700
    assert idainfo.procname == "metapc"

    # Portable Executable (PE)
    assert idainfo.filetype == 11
    if version <= 695:
        assert idainfo.af == 0xFFFF
        assert idainfo.ascii_break == ord("\n")
        if version == 630:
            assert idainfo.compiler == 129
        else:
            assert idainfo.compiler == 0x01
        assert idainfo.sizeof_int == 4
        assert idainfo.sizeof_bool in (1, 4)
        assert idainfo.sizeof_long == 4
        assert idainfo.sizeof_llong == 8
        if version > 500:
            assert idainfo.sizeof_ldbl == 8
    elif version >= 700:
        assert idainfo.af == 0xDFFFFFF7
        assert idainfo.strlit_break == ord("\n")

        assert idainfo.maxref == 16
        assert idainfo.netdelta == 0
        assert idainfo.xrefnum == 0
        assert idainfo.xrefflag == 0xF
        # Visual C++
        assert idainfo.cc_id == 0x01
        assert idainfo.cc_size_i == 4
        assert idainfo.cc_size_b == 1
        assert idainfo.cc_size_l == 4
        assert idainfo.cc_size_ll == 8
        assert idainfo.cc_size_ldbl == 8


def test_idainfo_multibitness():
    # this was a 6.95 file upgraded to 7.0b
    cd = os.path.dirname(__file__)
    idbpath = os.path.join(cd, "data", "multibitness", "multibitness.idb")
    with idb.from_file(idbpath) as db:
        idainfo = idb.analysis.Root(db).idainfo
        assert idainfo.tag == "IDA"  # like from 6.95
        assert idainfo.version == 700  # like from 7.00
        assert idainfo.procname == "metapc"  # actually stored as `| 0x06 m e t a p c |`
