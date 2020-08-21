# -*- coding: utf-8 -*-
import collections
import logging
import os
import re
import struct
import weakref

import six

from idb.analysis import StructMember, Struct
from idb.netnode import Netnode
from idb.typeinf import TIL

if six.PY2:
    import functools32 as functools
else:
    import functools

import idb.netnode
import idb.analysis

logger = logging.getLogger(__name__)


# via: https://stackoverflow.com/a/33672499/87207
def memoized_method(*lru_args, **lru_kwargs):
    def decorator(func):
        @functools.wraps(func)
        def wrapped_func(self, *args, **kwargs):
            # We're storing the wrapped method inside the instance. If we had
            # a strong reference to self the instance would never die.
            self_weak = weakref.ref(self)

            @functools.wraps(func)
            @functools.lru_cache(*lru_args, **lru_kwargs)
            def cached_method(*args, **kwargs):
                return func(self_weak(), *args, **kwargs)

            setattr(self, func.__name__, cached_method)
            return cached_method(*args, **kwargs)

        return wrapped_func

    return decorator


# This decorator is meant to wrap a module in another one like IDA does with
# ida_* wrapped in idaapi and/or idc.
# We could use __getattr__ in idaapi to act as a proxy but that will break
# statements like "from idaapi import *" or "from idc import *", a quite common
# pattern in IDAPython scripts.
# We do it here instead of shim.py:HookedImporter to get the same wraps in
# situations where the shim is not needed
# Use it on ida_* __init__()
# XXX: This is mostly a prototype. Needs further considerations.
def wrap_module(into, full=True):
    def decorator(func):
        @functools.wraps(func)
        def wrapped_func(self, *args, **kwargs):
            func(self, *args, **kwargs)
            mod = self.api.__dict__[into]
            for attr in dir(self):
                # Do not set private fields and api/idb objs already present in
                # every module
                if attr.startswith("_") or attr == "api" or attr == "idb":
                    continue
                obj = getattr(self, attr)
                # If full is False, only set "constants"
                if not full and callable(obj):
                    continue
                setattr(mod, attr, obj)

        return wrapped_func

    return decorator


def is_flag_set(flags, flag):
    return flags & flag == flag


class FLAGS:
    # instruction/data operands
    # via:
    # https://www.hex-rays.com/products/ida/support/sdkdoc/group___f_f__op.html

    # outer offset base (combined with operand number). More...
    OPND_OUTER = 0x80

    # mask for operand number
    OPND_MASK = 0x07

    # all operands
    OPND_ALL = OPND_MASK

    # byte states bits
    # via:
    # https://www.hex-rays.com/products/ida/support/sdkdoc/group___f_f__statebits.html

    # Mask for typing.
    MS_CLS = 0x00000600

    # Code ?
    FF_CODE = 0x00000600

    # Data ?
    FF_DATA = 0x00000400

    # Tail ?
    FF_TAIL = 0x00000200

    # Unknown ?
    FF_UNK = 0x00000000

    # specific state information bits
    # via:
    # https://www.hex-rays.com/products/ida/support/sdkdoc/group___f_f__statespecb.html

    # Mask of common bits.
    MS_COMM = 0x000FF800

    # Has comment ?
    FF_COMM = 0x00000800

    # has references
    FF_REF = 0x00001000

    # Has next or prev lines ?
    FF_LINE = 0x00002000

    # Has name ?
    FF_NAME = 0x00004000

    # Has dummy name?
    FF_LABL = 0x00008000

    # Exec flow from prev instruction.
    FF_FLOW = 0x00010000

    # Inverted sign of operands.
    FF_SIGN = 0x00020000

    # Bitwise negation of operands.
    FF_BNOT = 0x00040000

    # is variable byte?
    FF_VAR = 0x00080000

    # instruction operand types bites
    # via:
    # https://www.hex-rays.com/products/ida/support/sdkdoc/group___f_f__opbits.html

    # Mask for 1st arg typing.
    MS_0TYPE = 0x00F00000

    # Void (unknown)?
    FF_0VOID = 0x00000000

    # Hexadecimal number?
    FF_0NUMH = 0x00100000

    # Decimal number?
    FF_0NUMD = 0x00200000

    # Char ('x')?
    FF_0CHAR = 0x00300000

    # Segment?
    FF_0SEG = 0x00400000

    # Offset?
    FF_0OFF = 0x00500000

    # Binary number?
    FF_0NUMB = 0x00600000

    # Octal number?
    FF_0NUMO = 0x00700000

    # Enumeration?
    FF_0ENUM = 0x00800000

    # Forced operand?
    FF_0FOP = 0x00900000

    # Struct offset?
    FF_0STRO = 0x00A00000

    # Stack variable?
    FF_0STK = 0x00B00000

    # Floating point number?
    FF_0FLT = 0x00C00000

    # Custom representation?
    FF_0CUST = 0x00D00000

    # Mask for the type of other operands.
    MS_1TYPE = 0x0F000000

    # Void (unknown)?
    FF_1VOID = 0x00000000

    # Hexadecimal number?
    FF_1NUMH = 0x01000000

    # Decimal number?
    FF_1NUMD = 0x02000000

    # Char ('x')?
    FF_1CHAR = 0x03000000

    # Segment?
    FF_1SEG = 0x04000000

    # Offset?
    FF_1OFF = 0x05000000

    # Binary number?
    FF_1NUMB = 0x06000000

    # Octal number?
    FF_1NUMO = 0x07000000

    # Enumeration?
    FF_1ENUM = 0x08000000

    # Forced operand?
    FF_1FOP = 0x09000000

    # Struct offset?
    FF_1STRO = 0x0A000000

    # Stack variable?
    FF_1STK = 0x0B000000

    # Floating point number?
    FF_1FLT = 0x0C000000

    # Custom representation?
    FF_1CUST = 0x0D000000

    # code byte bits
    # via: https://www.hex-rays.com/products/ida/support/sdkdoc/group___f_f__codebits.html
    # Mask for code bits.
    MS_CODE = 0xF0000000

    # function start?
    FF_FUNC = 0x10000000

    # Has Immediate value?
    FF_IMMD = 0x40000000

    # Has jump table or switch_info?
    FF_JUMP = 0x80000000

    # data bytes bits
    # via:
    # https://www.hex-rays.com/products/ida/support/sdkdoc/group___f_f__databits.html

    # Mask for DATA typing.
    DT_TYPE = 0xF0000000

    # byte
    FF_BYTE = 0x00000000

    # word
    FF_WORD = 0x10000000

    # double word
    FF_DWRD = 0x20000000

    # quadro word
    FF_QWRD = 0x30000000

    # tbyte
    FF_TBYT = 0x40000000

    # ASCII ?
    FF_ASCI = 0x50000000

    # Struct ?
    FF_STRU = 0x60000000

    # octaword/xmm word (16 bytes/128 bits)
    FF_OWRD = 0x70000000

    # float
    FF_FLOAT = 0x80000000

    # double
    FF_DOUBLE = 0x90000000

    # packed decimal real
    FF_PACKREAL = 0xA0000000

    # alignment directive
    FF_ALIGN = 0xB0000000

    # 3-byte data (only with support from the processor module)
    FF_3BYTE = 0xC0000000

    # custom data type
    FF_CUSTOM = 0xD0000000

    # ymm word (32 bytes/256 bits)
    FF_YWRD = 0xE0000000

    # bytes
    # via:
    # https://www.hex-rays.com/products/ida/support/sdkdoc/group___f_f__.html

    # Mask for byte value.
    MS_VAL = 0x000000FF

    # Byte has value?
    FF_IVL = 0x00000100


class AFLAGS:
    # additional flags
    # via:
    # https://www.hex-rays.com/products/ida/support/sdkdoc/group___a_f_l__.html

    # has line number info
    AFL_LINNUM = 0x00000001

    # user-defined SP value
    AFL_USERSP = 0x00000002

    # name is public (inter-file linkage)
    AFL_PUBNAM = 0x00000004

    # name is weak
    AFL_WEAKNAM = 0x00000008

    # the item is hidden completely
    AFL_HIDDEN = 0x00000010

    # the instruction/data is specified by the user
    AFL_MANUAL = 0x00000020

    # the code/data border is hidden
    AFL_NOBRD = 0x00000040

    # display struct field name at 0 offset when displaying an offset. More...
    AFL_ZSTROFF = 0x00000080

    # the 1st operand is bitwise negated
    AFL_BNOT0 = 0x00000100

    # the 2nd operand is bitwise negated
    AFL_BNOT1 = 0x00000200

    # item from the standard library. More...
    AFL_LIB = 0x00000400

    # has typeinfo? (NSUP_TYPEINFO)
    AFL_TI = 0x00000800

    # has typeinfo for operand 0? (NSUP_OPTYPES)
    AFL_TI0 = 0x00001000

    # has typeinfo for operand 1? (NSUP_OPTYPES+1)
    AFL_TI1 = 0x00002000

    # has local name too (FF_NAME should be set)
    AFL_LNAME = 0x00004000

    # has type comment? (such a comment may be changed by IDA)
    AFL_TILCMT = 0x00008000

    # toggle leading zeroes for the 1st operand
    AFL_LZERO0 = 0x00010000

    # toggle leading zeroes for the 2nd operand
    AFL_LZERO1 = 0x00020000

    # has user defined instruction color?
    AFL_COLORED = 0x00040000

    # terse structure variable display?
    AFL_TERSESTR = 0x00080000

    # code: toggle sign of the 1st operand
    AFL_SIGN0 = 0x00100000

    # code: toggle sign of the 2nd operand
    AFL_SIGN1 = 0x00200000

    # for imported function pointers: doesn't return. More...
    AFL_NORET = 0x00400000

    # sp delta value is fixed by analysis. More...
    AFL_FIXEDSPD = 0x00800000

    # the previous insn was created for alignment purposes only
    AFL_ALIGNFLOW = 0x01000000

    # the type information is definitive. More...
    AFL_USERTI = 0x02000000

    # function returns a floating point value
    AFL_RETFP = 0x04000000

    # insn modifes SP and uses the modified value More...
    AFL_USEMODSP = 0x08000000

    # autoanalysis should not create code here
    AFL_NOTCODE = 0x10000000


class ida_netnode:
    @wrap_module("idaapi")
    def __init__(self, db, api):
        self.idb = db
        self.api = api

    def netnode(self, *args, **kwargs):
        return idb.netnode.Netnode(self.idb, *args, **kwargs)


class ida_ida:
    @wrap_module("idaapi")
    @wrap_module("idc", full=False)
    def __init__(self, db, api):
        self.idb = db
        self.api = api

        # via: https://www.hex-rays.com/products/ida/support/idapython_docs/ida_ida-module.html

        # filetype_t
        # from: https://www.hex-rays.com/products/ida/support/sdkdoc/ida_8hpp.html
        self.f_EXE_old = 0
        self.f_COM_old = 1
        self.f_BIN = 2
        self.f_DRV = 3
        self.f_WIN = 4
        self.f_HEX = 5
        self.f_MEX = 6
        self.f_LX = 7
        self.f_LE = 8
        self.f_NLM = 9
        self.f_COFF = 10
        self.f_PE = 11
        self.f_OMF = 12
        self.f_SREC = 13
        self.f_ZIP = 14
        self.f_OMFLIB = 15
        self.f_AR = 16
        self.f_LOADER = 17
        self.f_ELF = 18
        self.f_W32RUN = 19
        self.f_AOUT = 20
        self.f_PRC = 21
        self.f_EXE = 22
        self.f_COM = 23
        self.f_AIXAR = 24
        self.f_MACHO = 25
        # storage_type_t
        # from: https://www.hex-rays.com/products/ida/support/sdkdoc/ida_8hpp.html
        self.STT_CUR = -1
        self.STT_VA = 0
        self.STT_MM = 1
        self.STT_DBG = 2
        # Autoanalysis is enabled?
        self.INFFL_AUTO = 1
        # the target assembler
        self.INFFL_ALLASM = 2
        # loading an idc file that contains database info
        self.INFFL_LOADIDC = 4
        # do not store user info in the database
        self.INFFL_NOUSER = 8
        # (internal) temporary interdiction to modify the database
        self.INFFL_READONLY = 16
        # check manual operands? (unused)
        self.INFFL_CHKOPS = 32
        # allow non-matched operands? (unused)
        self.INFFL_NMOPS = 64
        # currently using graph options ({graph})
        self.INFFL_GRAPH_VIEW = 128
        # decode floating point processor instructions?
        self.LFLG_PC_FPP = 1
        # 32-bit program?
        self.LFLG_PC_FLAT = 2
        # 64-bit program?
        self.LFLG_64BIT = 4
        # Is dynamic library?
        self.LFLG_IS_DLL = 8
        # treat 'REF_OFF32' as 32-bit offset for 16bit segments (otherwise try SEG16:OFF16)
        self.LFLG_FLAT_OFF32 = 16
        # Byte order: is MSB first?
        self.LFLG_MSF = 32
        # (wide bytes: {dnbits} > 8)
        self.LFLG_WIDE_HBF = 64
        # do not store input full path in debugger process options
        self.LFLG_DBG_NOPATH = 128
        # memory snapshot was taken?
        self.LFLG_SNAPSHOT = 256
        # pack the database?
        self.LFLG_PACK = 512
        # compress the database?
        self.LFLG_COMPRESS = 1024
        # is kernel mode binary?
        self.LFLG_KERNMODE = 2048
        # leave database components unpacked
        self.IDB_UNPACKED = 0
        # pack database components into .idb
        self.IDB_PACKED = 1
        # compress & pack database components
        self.IDB_COMPRESSED = 2
        # Trace execution flow.
        self.AF_CODE = 1
        # Mark typical code sequences as code.
        self.AF_MARKCODE = 2
        # Locate and create jump tables.
        self.AF_JUMPTBL = 4
        # Control flow to data segment is ignored.
        self.AF_PURDAT = 8
        # Analyze and create all xrefs.
        self.AF_USED = 16
        # Delete instructions with no xrefs.
        self.AF_UNK = 32
        # Create function if data xref data->code32 exists.
        self.AF_PROCPTR = 64
        # Create functions if call is present.
        self.AF_PROC = 128
        # Create function tails.
        self.AF_FTAIL = 256
        # Create stack variables.
        self.AF_LVAR = 512
        # Propagate stack argument information.
        self.AF_STKARG = 1024
        # Propagate register argument information.
        self.AF_REGARG = 2048
        # Trace stack pointer.
        self.AF_TRACE = 4096
        # Perform full SP-analysis.
        self.AF_VERSP = 8192
        # Perform 'no-return' analysis.
        self.AF_ANORET = 16384
        # Try to guess member function types.
        self.AF_MEMFUNC = 32768
        # Truncate functions upon code deletion.
        self.AF_TRFUNC = 65536
        # Create string literal if data xref exists.
        self.AF_STRLIT = 131072
        # Check for unicode strings.
        self.AF_CHKUNI = 262144
        # Create offsets and segments using fixup info.
        self.AF_FIXUP = 524288
        # Create offset if data xref to seg32 exists.
        self.AF_DREFOFF = 1048576
        # Convert 32bit instruction operand to offset.
        self.AF_IMMOFF = 2097152
        # Automatically convert data to offsets.
        self.AF_DATOFF = 4194304
        # Use flirt signatures.
        self.AF_FLIRT = 8388608
        # Append a signature name comment for recognized anonymous library functions.
        self.AF_SIGCMT = 16777216
        # Allow recognition of several copies of the same function.
        self.AF_SIGMLT = 33554432
        # Automatically hide library functions.
        self.AF_HFLIRT = 67108864
        # Rename jump functions as j_...
        self.AF_JFUNC = 134217728
        # Rename empty functions as nullsub_...
        self.AF_NULLSUB = 268435456
        # Coagulate data segs at the final pass.
        self.AF_DODATA = 536870912
        # Coagulate code segs at the final pass.
        self.AF_DOCODE = 1073741824
        # Final pass of analysis.
        self.AF_FINAL = -2147483648
        # Handle EH information.
        self.AF2_DOEH = 1
        # Handle RTTI information
        self.AF2_DORTTI = 2
        self.NM_REL_OFF = 0
        self.NM_PTR_OFF = 1
        self.NM_NAM_OFF = 2
        self.NM_REL_EA = 3
        self.NM_PTR_EA = 4
        self.NM_NAM_EA = 5
        self.NM_EA = 6
        self.NM_EA4 = 7
        self.NM_EA8 = 8
        self.NM_SHORT = 9
        self.NM_SERIAL = 10
        # 4 byte alignment for 8byte scalars (__int64/double) inside structures?
        self.ABI_8ALIGN4 = 1
        # do not align stack arguments to stack slots
        self.ABI_PACK_STKARGS = 2
        self.ABI_BIGARG_ALIGN = 4
        # long double areuments are passed on stack
        self.ABI_STACK_LDBL = 8
        # varargs are always passed on stack (even when there are free registers)
        self.ABI_STACK_VARARGS = 16
        # use the floating-point register set
        self.ABI_HARD_FLOAT = 32
        # compiler/abi were set by user flag and require SETCOMP_BY_USER flag to be changed
        self.ABI_SET_BY_USER = 64
        # use gcc layout for udts (used for mingw)
        self.ABI_GCC_LAYOUT = 128
        # max number of operands allowed for an instruction
        self.UA_MAXOP = 8
        self.MAXADDR = 4278190080
        self.IDB_EXT32 = "idb"
        self.IDB_EXT64 = "i64"
        self.IDB_EXT = "idb"


class ida_ua:
    # op_t
    # via: https://www.hex-rays.com/products/ida/support/sdkdoc/group__o__.html

    o_void = 0  # No operand
    o_reg = 1  # General register
    o_mem = 2  # Direct memory reference
    o_phrase = 3  # Memory reference using registers
    o_displ = 4  # Memory reference using registers and displacement
    o_imm = 5  # Immediate value
    o_far = 6  # Immediate far address
    o_near = 7  # Immediate near  address
    o_idpspec0 = 8  # Processor specific
    o_idpspec1 = 9
    o_idpspec2 = 10
    o_idpspec3 = 11
    o_idpspec4 = 12
    o_idpspec5 = 13

    @wrap_module("idaapi")
    @wrap_module("idc", full=False)
    def __init__(self, db, api):
        self.idb = db
        self.api = api


class idc:
    SEGPERM_EXEC = 1  # Execute
    SEGPERM_WRITE = 2  # Write
    SEGPERM_READ = 4  # Read
    SEGPERM_MAXVAL = 7  # (SEGPERM_EXEC + SEGPERM_WRITE + SEGPERM_READ)

    SFL_COMORG = (
        0x01  # IDP dependent field (IBM PC: if set, ORG directive is not commented out)
    )
    SFL_OBOK = 0x02  # orgbase is present? (IDP dependent field)
    SFL_HIDDEN = 0x04  # is the segment hidden?
    SFL_DEBUG = 0x08  # is the segment created for the debugger?
    SFL_LOADER = 0x10  # is the segment created by the loader?
    SFL_HIDETYPE = 0x20  # hide segment type (do not print it in the listing)

    def __init__(self, db, api):
        self.idb = db
        self.api = api
        # these will be the capstone disassemblers, lazily loaded.
        # map from bitness (numbers 16, 32, and 64) to capstone disassembler instance
        self.bit_dis = None
        # map from tuple (segment start, end address) to capstone disassembler instance
        self.seg_dis = None

        # apparently this enum changes with bitness.
        # this is annoying.
        # so, be sure to reference these via an `idc` *instance*.
        # yes:
        #
        #    idc(some_idb).FUNCATTR_START
        #
        # no:
        #
        #    idc.FUNCATTR_START
        #
        # via:
        # https://github.com/zachriggle/idapython/blob/37d2fd13b31fec8e6e53fbb9704fa3cd0cbd5b07/python/idc.py#L4149
        if self.idb.wordsize == 4:
            # function start address
            self.FUNCATTR_START = 0
            # function end address
            self.FUNCATTR_END = 4
            # function flags
            self.FUNCATTR_FLAGS = 8
            # function frame id
            self.FUNCATTR_FRAME = 10
            # size of local variables
            self.FUNCATTR_FRSIZE = 14
            # size of saved registers area
            self.FUNCATTR_FRREGS = 18
            # number of bytes purged from the stack
            self.FUNCATTR_ARGSIZE = 20
            # frame pointer delta
            self.FUNCATTR_FPD = 24
            # function color code
            self.FUNCATTR_COLOR = 28

            # starting address
            self.SEGATTR_START = 0
            # ending address
            self.SEGATTR_END = 4
            self.SEGATTR_ORGBASE = 16
            # alignment
            self.SEGATTR_ALIGN = 20
            # combination
            self.SEGATTR_COMB = 21
            # permissions
            self.SEGATTR_PERM = 22
            # bitness (0: 16, 1: 32, 2: 64 bit segment)
            self.SEGATTR_BITNESS = 23
            # segment flags
            self.SEGATTR_FLAGS = 24
            # segment selector
            self.SEGATTR_SEL = 28
            # default ES value
            self.SEGATTR_ES = 32
            # default CS value
            self.SEGATTR_CS = 36
            # default SS value
            self.SEGATTR_SS = 40
            # default DS value
            self.SEGATTR_DS = 44
            # default FS value
            self.SEGATTR_FS = 48
            # default GS value
            self.SEGATTR_GS = 52
            # segment type
            self.SEGATTR_TYPE = 96
            # segment color
            self.SEGATTR_COLOR = 100

            self.BADADDR = 0xFFFFFFFF
            self.__EA64__ = False

        elif self.idb.wordsize == 8:
            self.FUNCATTR_START = 0
            self.FUNCATTR_END = 8
            self.FUNCATTR_FLAGS = 16
            self.FUNCATTR_FRAME = 18
            self.FUNCATTR_FRSIZE = 26
            self.FUNCATTR_FRREGS = 34
            self.FUNCATTR_ARGSIZE = 36
            self.FUNCATTR_FPD = 44
            self.FUNCATTR_COLOR = 52
            self.FUNCATTR_OWNER = 18
            self.FUNCATTR_REFQTY = 26

            self.SEGATTR_START = 0
            self.SEGATTR_END = 8
            self.SEGATTR_ORGBASE = 32
            self.SEGATTR_ALIGN = 40
            self.SEGATTR_COMB = 41
            self.SEGATTR_PERM = 42
            self.SEGATTR_BITNESS = 43
            self.SEGATTR_FLAGS = 44
            self.SEGATTR_SEL = 48
            self.SEGATTR_ES = 56
            self.SEGATTR_CS = 64
            self.SEGATTR_SS = 72
            self.SEGATTR_DS = 80
            self.SEGATTR_FS = 88
            self.SEGATTR_GS = 96
            self.SEGATTR_TYPE = 184
            self.SEGATTR_COLOR = 188

            self.BADADDR = 0xFFFFFFFFFFFFFFFF
            self.__EA64__ = True
        else:
            raise RuntimeError("unexpected wordsize")

        # Command line arguments passed to idapython scripts. Args passed via -S
        # switch in IDA
        self.ARGV = []

        ## Mantain API compatibility for API < 7
        self.GetMnem = self.print_insn_mnem
        self.GetOpnd = self.print_operand
        self.GetOpType = self.get_operand_type
        self.FindFuncEnd = self.find_func_end

    def ScreenEA(self):
        return self.api.ScreenEA

    def _get_segment(self, ea):
        segs = idb.analysis.Segments(self.idb).segments
        for seg in segs.values():
            if seg.startEA <= ea < seg.endEA:
                return seg

    def SegStart(self, ea):
        seg = self._get_segment(ea)
        if seg is None:
            return None
        return seg.startEA

    def SegEnd(self, ea):
        seg = self._get_segment(ea)
        if seg is None:
            return None
        return seg.endEA

    def FirstSeg(self):
        segs = idb.analysis.Segments(self.idb).segments
        for startEA in sorted(segs.keys()):
            return startEA

    def NextSeg(self, ea):
        segs = idb.analysis.Segments(self.idb).segments.values()
        segs = sorted(segs, key=lambda s: s.startEA)

        for i, seg in enumerate(segs):
            if seg.startEA <= ea < seg.endEA:
                if i < len(segs) - 1:
                    return segs[i + 1].startEA
                else:
                    return self.BADADDR

    def SegName(self, ea):
        # if segment doesn't have explicit name, then...
        # its unclear what this data will be.
        # we *want* something like `seg000`.
        segstrings = idb.analysis.SegStrings(self.idb).strings
        return segstrings[self._get_segment(ea).name_index]

    def GetSegmentAttr(self, ea, attr):
        if attr == self.SEGATTR_START:
            return self.SegStart(ea)
        elif attr == self.SEGATTR_END:
            return self.SegEnd(ea)
        elif attr == self.SEGATTR_ORGBASE:
            return self._get_segment(ea).orgbase
        elif attr == self.SEGATTR_ALIGN:
            return self._get_segment(ea).align
        elif attr == self.SEGATTR_COMB:
            return self._get_segment(ea).comb
        elif attr == self.SEGATTR_PERM:
            return self._get_segment(ea).perm
        elif attr == self.SEGATTR_BITNESS:
            return self._get_segment(ea).bitness
        elif attr == self.SEGATTR_FLAGS:
            return self._get_segment(ea).flags
        elif attr == self.SEGATTR_TYPE:
            return self._get_segment(ea).type
        elif attr == self.SEGATTR_COLOR:
            return self._get_segment(ea).color
        else:
            raise NotImplementedError(
                "segment attribute %d not yet implemented" % (attr)
            )

    def MinEA(self):
        segs = idb.analysis.Segments(self.idb).segments.values()
        segs = list(sorted(segs, key=lambda s: s.startEA))
        return segs[0].startEA

    def MaxEA(self):
        segs = idb.analysis.Segments(self.idb).segments.values()
        segs = list(sorted(segs, key=lambda s: s.startEA))
        return segs[-1].endEA

    def GetFlags(self, ea):
        try:
            return self.idb.id1.get_flags(ea)
        except KeyError:
            return 0

    def IdbByte(self, ea):
        flags = self.GetFlags(ea)
        if self.hasValue(flags):
            return flags & FLAGS.MS_VAL
        else:
            raise KeyError(ea)

    def Head(self, ea):
        flags = self.GetFlags(ea)
        while not self.api.ida_bytes.is_head(flags):
            ea -= 1
            # TODO: handle Index/KeyError here when we overrun a segment
            flags = self.GetFlags(ea)
        return ea

    def ItemSize(self, ea):
        return self.api.ida_bytes.get_item_end(ea) - ea

    def NextHead(self, ea):
        ea += 1
        flags = self.GetFlags(ea)
        while (
            flags is not None and flags != 0 and not self.api.ida_bytes.is_head(flags)
        ):
            ea += 1
            # TODO: handle Index/KeyError here when we overrun a segment
            flags = self.GetFlags(ea)
        return ea

    def PrevHead(self, ea):
        ea = self.Head(ea)
        ea -= 1
        return self.Head(ea)

    def GetManyBytes(self, ea, size, use_dbg=False):
        """
        Raises:
          IndexError: if the range extends beyond a segment.
          KeyError: if a byte is not defined.
        """
        if use_dbg:
            raise NotImplementedError()

        # can only read from one segment at a time
        if self.SegStart(ea) != self.SegStart(ea + size):
            # edge case: when reading exactly to the end of the segment.
            if ea + size == self.SegEnd(ea):
                pass
            else:
                raise IndexError((ea, ea + size))

        ret = []
        try:
            for i in range(ea, ea + size):
                ret.append(self.IdbByte(i))
        except KeyError:
            # we have already verified that that the requested range falls within a Segment.
            # however, the underlying ID1 section may be smaller than the Segment.
            # so, we pad the Segment with NULL bytes.
            # this is consistent with the IDAPython behavior.
            # see github issue #29.
            ret.extend([0x0 for _ in range(size - len(ret))])

        if six.PY2:
            return "".join(map(chr, ret))
        else:
            return bytes(ret)

    def _load_dis(self, arch, mode):
        import capstone

        if self.bit_dis is None:
            self.bit_dis = {}
        if self.bit_dis.get((arch, mode)) is None:
            r = capstone.Cs(arch, mode)
            self.bit_dis[(arch, mode)] = r
        return self.bit_dis[(arch, mode)]

    def _disassemble(self, ea):
        import capstone

        size = self.ItemSize(ea)
        inst_buf = self.GetManyBytes(ea, size)
        segment = self._get_segment(ea)
        bitness = 16 << segment.bitness  # 16, 32, 64
        procname = self.api.idaapi.get_inf_structure().procname.lower()

        dis = None
        if procname == "arm" and bitness == 64:
            dis = self._load_dis(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
        elif procname == "arm" and bitness == 32:
            if size == 2:
                dis = self._load_dis(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)
            else:
                dis = self._load_dis(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
        elif procname in [
            "metapc",
            "8086",
            "80286r",
            "80286p",
            "80386r",
            "80386p",
            "80486r",
            "80486p",
            "80586r",
            "80586p",
            "80686p",
            "k62",
            "p2",
            "p3",
            "athlon",
            "p4",
            "8085",
        ]:
            if bitness == 16:
                dis = self._load_dis(capstone.CS_ARCH_X86, capstone.CS_MODE_16)
            elif bitness == 32:
                dis = self._load_dis(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
            elif bitness == 64:
                dis = self._load_dis(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        elif procname == "mipsb":
            if bitness == 32:
                dis = self._load_dis(
                    capstone.CS_ARCH_MIPS,
                    capstone.CS_MODE_MIPS32 | capstone.CS_MODE_BIG_ENDIAN,
                )
            elif bitness == 64:
                dis = self._load_dis(
                    capstone.CS_ARCH_MIPS,
                    capstone.CS_MODE_MIPS64 | capstone.CS_MODE_BIG_ENDIAN,
                )
        elif procname == "mipsl":
            if bitness == 32:
                dis = self._load_dis(
                    capstone.CS_ARCH_MIPS,
                    capstone.CS_MODE_MIPS32 | capstone.CS_MODE_LITTLE_ENDIAN,
                )
            elif bitness == 64:
                dis = self._load_dis(
                    capstone.CS_ARCH_MIPS,
                    capstone.CS_MODE_MIPS64 | capstone.CS_MODE_LITTLE_ENDIAN,
                )
        elif procname == "ppc":
            if bitness == 32:
                dis = self._load_dis(
                    capstone.CS_ARCH_PPC,
                    capstone.CS_MODE_32 | capstone.CS_MODE_BIG_ENDIAN,
                )
            elif bitness == 64:
                dis = self._load_dis(
                    capstone.CS_ARCH_PPC,
                    capstone.CS_MODE_64 | capstone.CS_MODE_BIG_ENDIAN,
                )
        elif procname == "ppcl":
            if bitness == 32:
                dis = self._load_dis(
                    capstone.CS_ARCH_PPC,
                    capstone.CS_MODE_32 | capstone.CS_MODE_LITTLE_ENDIAN,
                )
            elif bitness == 64:
                dis = self._load_dis(
                    capstone.CS_ARCH_PPC,
                    capstone.CS_MODE_64 | capstone.CS_MODE_LITTLE_ENDIAN,
                )
        elif procname == "sparcb":
            if bitness == 32:
                dis = self._load_dis(
                    capstone.CS_ARCH_SPARC, capstone.CS_MODE_BIG_ENDIAN
                )
        elif procname == "sparcl":
            if bitness == 32:
                dis = self._load_dis(
                    capstone.CS_ARCH_SPARC, capstone.CS_MODE_LITTLE_ENDIAN
                )

        if dis is None:
            raise NotImplementedError(
                "unknown arch %s bit:%s inst_len:%d"
                % (procname, bitness, len(inst_buf))
            )
        dis.detail = True

        try:
            op = next(dis.disasm(inst_buf, ea))
        except StopIteration:
            raise RuntimeError("failed to disassemble %s" % (hex(ea)))
        else:
            return op

    def print_insn_mnem(self, ea):
        op = self._disassemble(ea)
        return op.mnemonic

    def GetDisasm(self, ea):
        op = self._disassemble(ea)
        return "%s\t%s" % (op.mnemonic, op.op_str)

    def print_operand(self, ea, n):
        op = self._disassemble(ea)
        opnds = op.op_str.split(", ")
        n_opnds = len(opnds)

        if 0 <= n < n_opnds:
            return opnds[n]
        else:
            return ""

    def get_operand_type(self, ea, n):
        from capstone import CS_OP_INVALID, CS_OP_REG, CS_OP_MEM, CS_OP_IMM

        op = self._disassemble(ea)
        opnds = op.operands
        n_opnds = len(opnds)

        # capstone produces 2 operands for immediate far jmp/call, IDA only 1
        # TODO: we need better handling of o_far recognition
        is_far = False
        if op.mnemonic in ["ljmp", "lcall"]:
            n_opnds = 1
            is_far = True
        # continue normal operand type check
        if 0 <= n < n_opnds:
            op_n = opnds[n]
            if op_n.type == CS_OP_INVALID:
                return -1
            elif op_n.type == CS_OP_REG:
                return self.api.ida_ua.o_reg
            elif op_n.type == CS_OP_MEM:
                op_mem = op_n.value.mem
                if op_mem.base == 0:
                    return self.api.ida_ua.o_mem
                if op_mem.base != 0 and op_mem.disp == 0:
                    return self.api.ida_ua.o_phrase
                if op_mem.base != 0 and op_mem.disp != 0:
                    return self.api.ida_ua.o_displ
            elif op_n.type == CS_OP_IMM:
                if is_far:
                    return self.api.ida_ua.o_far
                elif self.api.ida_bytes.is_code(self.GetFlags(op_n.value.imm)):
                    return self.api.ida_ua.o_near
                else:
                    return self.api.ida_ua.o_imm
        else:
            return self.api.ida_ua.o_void

    # one instruction or data
    CIC_ITEM = 1
    # function
    CIC_FUNC = 2
    # segment
    CIC_SEGM = 3
    # default color
    DEFCOLOR = 0xFFFFFFFF

    def GetColor(self, ea, what):
        """
        Args:
          ea (int): effective address of thing.
          what (int): one of:
            - idc.CIC_ITEM
            - idc.CIC_FUNC
            - idc.CIC_SEGM

        Returns:
          int: the color in RGB. possibly idc.DEFCOLOR if not set.
        """
        if what != idc.CIC_ITEM:
            raise NotImplementedError()

        if not self.api.ida_nalt.is_colored_item(ea):
            return idc.DEFCOLOR

        nn = self.api.ida_netnode.netnode(ea)
        try:
            return nn.altval(tag="A", index=0x14) - 1
        except KeyError:
            return idc.DEFCOLOR

    def GetFunctionFlags(self, ea):
        func = self.api.ida_funcs.get_func(ea)
        return func.flags

    def GetFunctionAttr(self, ea, attr):
        func = self.api.ida_funcs.get_func(ea)

        if attr == self.FUNCATTR_START:
            return func.startEA
        elif attr == self.FUNCATTR_END:
            return func.endEA
        elif attr == self.FUNCATTR_FLAGS:
            return func.flags
        elif attr == self.FUNCATTR_FRAME:
            return func.frame
        elif attr == self.FUNCATTR_FRSIZE:
            return func.frsize
        elif attr == self.FUNCATTR_FRREGS:
            return func.frregs
        elif attr == self.FUNCATTR_ARGSIZE:
            return func.argsize
        elif attr == self.FUNCATTR_FPD:
            return func.fpd
        elif attr == self.FUNCATTR_COLOR:
            return func.color
        else:
            raise ValueError("unknown attr: %x" % (attr))

    def GetFunctionName(self, ea):
        return self.api.ida_funcs.get_func_name(ea)

    def find_func_end(self, ea):
        func = self.api.ida_funcs.get_func(ea)
        if not func:
            return self.BADADDR
        else:
            return func.endEA

    def LocByName(self, name):
        try:
            key = ("N" + name).encode("utf-8")
            cursor = self.idb.id0.find(key)
            return idb.netnode.as_uint(cursor.value)
        except KeyError:
            return -1

    def GetInputMD5(self):
        return self.api.ida_nalt.retrieve_input_file_md5()

    def GetInputSHA256(self):
        return self.api.ida_nalt.retrieve_input_file_sha256()

    def GetInputFile(self):
        return os.path.basename(self.api.ida_nalt.get_input_file_path())

    def Comment(self, ea):
        return self.api.ida_bytes.get_cmt(ea, False)

    def RptCmt(self, ea):
        return self.api.ida_bytes.get_cmt(ea, True)

    def GetCommentEx(self, ea, repeatable):
        return self.api.ida_bytes.get_cmt(ea, repeatable)

    def GetType(self, ea):
        try:
            f = idb.analysis.Function(self.idb, ea)
        except Exception as e:
            logger.warning("failed to fetch function for GetType: %s", e)
            return None
        sig = f.get_signature()
        return sig.get_typestr() if sig is not None else None

    @staticmethod
    def hasValue(flags):
        return flags & FLAGS.FF_IVL > 0

    @staticmethod
    def isDefArg0(flags):
        return flags & FLAGS.MS_0TYPE > 0

    @staticmethod
    def isDefArg1(flags):
        return flags & FLAGS.MS_1TYPE > 0

    @staticmethod
    def isOff0(flags):
        return flags & FLAGS.MS_0TYPE == FLAGS.FF_0CUST

    @staticmethod
    def isOff1(flags):
        return flags & FLAGS.MS_1TYPE == FLAGS.FF_1CUST

    @staticmethod
    def isChar0(flags):
        return flags & FLAGS.MS_0TYPE == FLAGS.FF_0CHAR

    @staticmethod
    def isChar1(flags):
        return flags & FLAGS.MS_1TYPE == FLAGS.FF_1CHAR

    @staticmethod
    def isSeg0(flags):
        return flags & FLAGS.MS_0TYPE == FLAGS.FF_0SEG

    @staticmethod
    def isSeg1(flags):
        return flags & FLAGS.MS_1TYPE == FLAGS.FF_1SEG

    @staticmethod
    def isEnum0(flags):
        return flags & FLAGS.MS_0TYPE == FLAGS.FF_0ENUM

    @staticmethod
    def isEnum1(flags):
        return flags & FLAGS.MS_1TYPE == FLAGS.FF_1ENUM

    @staticmethod
    def isStroff0(flags):
        return flags & FLAGS.MS_0TYPE == FLAGS.FF_0STRO

    @staticmethod
    def isStroff1(flags):
        return flags & FLAGS.MS_1TYPE == FLAGS.FF_1STRO

    @staticmethod
    def isStkvar0(flags):
        return flags & FLAGS.MS_0TYPE == FLAGS.FF_0STK

    @staticmethod
    def isStkvar1(flags):
        return flags & FLAGS.MS_1TYPE == FLAGS.FF_1STK

    @staticmethod
    def isFloat0(flags):
        return flags & FLAGS.MS_0TYPE == FLAGS.FF_0FLT

    @staticmethod
    def isFloat1(flags):
        return flags & FLAGS.MS_1TYPE == FLAGS.FF_1FLT

    @staticmethod
    def isCustFmt0(flags):
        return flags & FLAGS.MS_0TYPE == FLAGS.FF_0CUST

    @staticmethod
    def isCustFmt1(flags):
        return flags & FLAGS.MS_1TYPE == FLAGS.FF_1CUST

    @staticmethod
    def isNum0(flags):
        t = flags & FLAGS.MS_0TYPE
        return (
            t == FLAGS.FF_0NUMB
            or t == FLAGS.FF_0NUMO
            or t == FLAGS.FF_0NUMD
            or t == FLAGS.FF_0NUMH
        )

    @staticmethod
    def isNum1(flags):
        t = flags & FLAGS.MS_1TYPE
        return (
            t == FLAGS.FF_1NUMB
            or t == FLAGS.FF_1NUMO
            or t == FLAGS.FF_1NUMD
            or t == FLAGS.FF_1NUMH
        )

    @staticmethod
    def get_optype_flags0(flags):
        return flags & FLAGS.MS_0TYPE

    @staticmethod
    def get_optype_flags1(flags):
        return flags & FLAGS.MS_1TYPE

    def LineA(self, ea, num):
        nn = self.api.ida_netnode.netnode(ea)
        # 1000 looks like a magic number, and it sorta is.
        # S-1000, 1001, 1002, ... are where anterior lines are
        try:
            return nn.supstr(tag="S", index=1000 + num)
        except KeyError:
            return ""

    def LineB(self, ea, num):
        nn = self.api.ida_netnode.netnode(ea)
        try:
            return nn.supstr(tag="S", index=2000 + num)
        except KeyError:
            return ""


class ida_bytes:
    @wrap_module("idaapi")
    def __init__(self, db, api):
        self.idb = db
        self.api = api

        ## Mantain API compatibility for API < 7
        self.get_long = self.get_dword

    def get_cmt(self, ea, repeatable):
        flags = self.api.idc.GetFlags(ea)
        if not self.has_cmt(flags):
            return ""

        try:
            nn = self.api.ida_netnode.netnode(ea)
            if repeatable:
                return nn.supstr(tag="S", index=1)
            else:
                return nn.supstr(tag="S", index=0)
        except KeyError:
            return ""

    def get_flags(self, ea):
        return self.api.idc.GetFlags(ea)

    @staticmethod
    def is_func(flags):
        return flags & FLAGS.MS_CODE == FLAGS.FF_FUNC

    @staticmethod
    def has_immd(flags):
        return flags & FLAGS.MS_CODE == FLAGS.FF_IMMD

    @staticmethod
    def is_code(flags):
        return flags & FLAGS.MS_CLS == FLAGS.FF_CODE

    @staticmethod
    def is_data(flags):
        return flags & FLAGS.MS_CLS == FLAGS.FF_DATA

    @staticmethod
    def is_tail(flags):
        return flags & FLAGS.MS_CLS == FLAGS.FF_TAIL

    @staticmethod
    def is_not_tail(flags):
        return not ida_bytes.is_tail(flags)

    @staticmethod
    def is_unknown(flags):
        return flags & FLAGS.MS_CLS == FLAGS.FF_UNK

    @staticmethod
    def is_head(flags):
        return ida_bytes.is_code(flags) or ida_bytes.is_data(flags)

    @staticmethod
    def is_flow(flags):
        return flags & FLAGS.MS_COMM & FLAGS.FF_FLOW > 0

    @staticmethod
    def is_var(flags):
        return flags & FLAGS.MS_COMM & FLAGS.FF_VAR > 0

    @staticmethod
    def has_extra_cmts(flags):
        return flags & FLAGS.MS_COMM & FLAGS.FF_LINE > 0

    @staticmethod
    def has_cmt(flags):
        return flags & FLAGS.MS_COMM & FLAGS.FF_COMM > 0

    @staticmethod
    def has_ref(flags):
        return flags & FLAGS.MS_COMM & FLAGS.FF_REF > 0

    @staticmethod
    def has_name(flags):
        return flags & FLAGS.MS_COMM & FLAGS.FF_NAME > 0

    @staticmethod
    def has_dummy_name(flags):
        return flags & FLAGS.MS_COMM & FLAGS.FF_LABL > 0

    @staticmethod
    def has_auto_name(flags):
        # unknown how to compute this
        raise NotImplementedError()

    @staticmethod
    def has_any_name(flags):
        # unknown how to compute this
        raise NotImplementedError()

    @staticmethod
    def has_user_name(flags):
        # unknown how to compute this
        raise NotImplementedError()

    @staticmethod
    def is_invsign(flags):
        return flags & FLAGS.MS_COMM & FLAGS.FF_SIGN > 0

    @staticmethod
    def is_bnot(flags):
        return flags & FLAGS.MS_COMM & FLAGS.FF_BNOT > 0

    @staticmethod
    def has_value(flags):
        return (flags & FLAGS.FF_IVL) > 0

    @staticmethod
    def is_byte(flags):
        return flags & FLAGS.DT_TYPE == FLAGS.FF_BYTE

    @staticmethod
    def is_word(flags):
        return flags & FLAGS.DT_TYPE == FLAGS.FF_WORD

    @staticmethod
    def is_dword(flags):
        return flags & FLAGS.DT_TYPE == FLAGS.FF_DWRD

    @staticmethod
    def is_qword(flags):
        return flags & FLAGS.DT_TYPE == FLAGS.FF_QWRD

    @staticmethod
    def is_oword(flags):
        return flags & FLAGS.DT_TYPE == FLAGS.FF_OWRD

    @staticmethod
    def is_yword(flags):
        return flags & FLAGS.DT_TYPE == FLAGS.FF_YWRD

    @staticmethod
    def is_tbyte(flags):
        return flags & FLAGS.DT_TYPE == FLAGS.FF_TBYT

    @staticmethod
    def is_float(flags):
        return flags & FLAGS.DT_TYPE == FLAGS.FF_FLOAT

    @staticmethod
    def is_double(flags):
        return flags & FLAGS.DT_TYPE == FLAGS.FF_DOUBLE

    @staticmethod
    def is_pack_real(flags):
        return flags & FLAGS.DT_TYPE == FLAGS.FF_PACKREAL

    @staticmethod
    def is_strlit(flags):
        return flags & FLAGS.DT_TYPE == FLAGS.FF_ASCI

    @staticmethod
    def is_struct(flags):
        return flags & FLAGS.DT_TYPE == FLAGS.FF_STRU

    @staticmethod
    def is_align(flags):
        return flags & FLAGS.DT_TYPE == FLAGS.FF_ALIGN

    @staticmethod
    def is_custom(flags):
        return flags & FLAGS.DT_TYPE == FLAGS.FF_CUSTOM

    def get_bytes(self, ea, count):
        return self.api.idc.GetManyBytes(ea, count)

    def next_that(self, ea, maxea, testf):
        for i in range(ea + 1, maxea):
            flags = self.get_flags(i)
            if testf(flags):
                return i
        return self.api.idc.BADADDR

    def next_not_tail(self, ea):
        while True:
            ea += 1
            flags = self.get_flags(ea)
            if not self.is_tail(flags):
                break
        return ea

    def next_inited(self, ea, maxea):
        return self.next_that(ea, maxea, lambda flags: ida_bytes.has_value(flags))

    def get_item_end(self, ea):
        ea += 1
        flags = self.api.idc.GetFlags(ea)
        while (
            flags is not None
            and not self.api.ida_bytes.is_head(flags)
            and self.api.idc.SegEnd(ea)
        ):
            ea += 1
            flags = self.api.idc.GetFlags(ea)
        return ea

    def get_byte(self, ea):
        return ord(self.get_bytes(ea, 1))

    def get_word(self, ea):
        if self.api.idaapi.get_inf_structure().is_be:
            fmt = ">H"
        else:
            fmt = "<H"
        return struct.unpack(fmt, self.get_bytes(ea, 2))[0]

    def get_dword(self, ea):
        if self.api.idaapi.get_inf_structure().is_be:
            fmt = ">I"
        else:
            fmt = "<I"
        return struct.unpack(fmt, self.get_bytes(ea, 4))[0]

    def get_qword(self, ea):
        if self.api.idaapi.get_inf_structure().is_be:
            fmt = ">Q"
        else:
            fmt = "<Q"
        return struct.unpack(fmt, self.get_bytes(ea, 8))[0]


class ida_nalt:
    @wrap_module("idaapi")
    def __init__(self, db, api):
        self.idb = db
        self.api = api

    def get_aflags(self, ea):
        nn = self.api.ida_netnode.netnode(ea)
        try:
            return nn.altval(tag="A", index=0x8)
        except KeyError:
            return 0

    def is_hidden_item(self, ea):
        return is_flag_set(self.get_aflags(ea), AFLAGS.AFL_HIDDEN)

    def is_hidden_border(self, ea):
        return is_flag_set(self.get_aflags(ea), AFLAGS.AFL_NOBRD)

    def uses_modsp(self, ea):
        return is_flag_set(self.get_aflags(ea), AFLAGS.AFL_USEMODSP)

    def is_zstroff(self, ea):
        return is_flag_set(self.get_aflags(ea), AFLAGS.AFL_ZSTROFF)

    def is__bnot0(self, ea):
        return is_flag_set(self.get_aflags(ea), AFLAGS.AFL_BNOT0)

    def is__bnot1(self, ea):
        return is_flag_set(self.get_aflags(ea), AFLAGS.AFL_BNOT1)

    def is_libitem(self, ea):
        return is_flag_set(self.get_aflags(ea), AFLAGS.AFL_LIB)

    def has_ti(self, ea):
        return is_flag_set(self.get_aflags(ea), AFLAGS.AFL_TI)

    def has_ti0(self, ea):
        return is_flag_set(self.get_aflags(ea), AFLAGS.AFL_TI0)

    def has_ti1(self, ea):
        return is_flag_set(self.get_aflags(ea), AFLAGS.AFL_TI1)

    def has_lname(self, ea):
        return is_flag_set(self.get_aflags(ea), AFLAGS.AFL_LNAME)

    def is_tilcmt(self, ea):
        return is_flag_set(self.get_aflags(ea), AFLAGS.AFL_TILCMT)

    def is_usersp(self, ea):
        return is_flag_set(self.get_aflags(ea), AFLAGS.AFL_USERSP)

    def is_lzero0(self, ea):
        return is_flag_set(self.get_aflags(ea), AFLAGS.AFL_LZERO0)

    def is_lzero1(self, ea):
        return is_flag_set(self.get_aflags(ea), AFLAGS.AFL_LZERO1)

    def is_colored_item(self, ea):
        return is_flag_set(self.get_aflags(ea), AFLAGS.AFL_COLORED)

    def is_terse_struc(self, ea):
        return is_flag_set(self.get_aflags(ea), AFLAGS.AFL_TERSESTR)

    def is__invsign0(self, ea):
        return is_flag_set(self.get_aflags(ea), AFLAGS.AFL_SIGN0)

    def is__invsign1(self, ea):
        return is_flag_set(self.get_aflags(ea), AFLAGS.AFL_SIGN1)

    def is_noret(self, ea):
        return is_flag_set(self.get_aflags(ea), AFLAGS.AFL_NORET)

    def is_fixed_spd(self, ea):
        return is_flag_set(self.get_aflags(ea), AFLAGS.AFL_FIXEDSPD)

    def is_align_flow(self, ea):
        return is_flag_set(self.get_aflags(ea), AFLAGS.AFL_ALIGNFLOW)

    def is_userti(self, ea):
        return is_flag_set(self.get_aflags(ea), AFLAGS.AFL_USERTI)

    def is_retfp(self, ea):
        return is_flag_set(self.get_aflags(ea), AFLAGS.AFL_RETFP)

    def is_notcode(self, ea):
        return is_flag_set(self.get_aflags(ea), AFLAGS.AFL_NOTCODE)

    def get_import_module_qty(self):
        return max(idb.analysis.Imports(self.idb).lib_names.keys())

    def get_import_module_name(self, mod_index):
        return idb.analysis.Imports(self.idb).lib_names[mod_index]

    def enum_import_names(self, mod_index, py_cb):
        imps = idb.analysis.Imports(self.idb)

        # dereference the node id stored in the A val
        nnref = imps.lib_netnodes[mod_index]
        nn = idb.netnode.Netnode(self.idb, nnref)

        for funcaddr in nn.sups():
            funcname = nn.supstr(funcaddr)
            if not py_cb(funcaddr, funcname, None):
                return

    def get_imagebase(self):
        try:
            return idb.analysis.Root(self.idb).imagebase
        except KeyError:
            # seems that the key is not present in all databases,
            # particularly those with an imagebase of 0x0.
            return 0x0

        # TODO: where to fetch ordinal?

    def retrieve_input_file_sha256(self):
        return idb.analysis.Root(self.idb).sha256

    def retrieve_input_file_md5(self):
        return idb.analysis.Root(self.idb).md5

    def get_input_file_path(self):
        return idb.analysis.Root(self.idb).input_file_path


class ida_funcs:
    # via: https://www.hex-rays.com/products/ida/support/sdkdoc/group___f_u_n_c__.html
    # Function doesn't return.
    FUNC_NORET = 0x00000001

    # Far function.
    FUNC_FAR = 0x00000002

    # Library function.
    FUNC_LIB = 0x00000004

    # Static function.
    FUNC_STATICDEF = 0x00000008

    # Function uses frame pointer (BP)
    FUNC_FRAME = 0x00000010

    # User has specified far-ness. More...
    FUNC_USERFAR = 0x00000020

    # A hidden function chunk.
    FUNC_HIDDEN = 0x00000040

    # Thunk (jump) function.
    FUNC_THUNK = 0x00000080

    # BP points to the bottom of the stack frame.
    FUNC_BOTTOMBP = 0x00000100

    # Function 'non-return' analysis must be performed. More...
    FUNC_NORET_PENDING = 0x00200

    # SP-analysis has been performed. More...
    FUNC_SP_READY = 0x00000400

    # 'argsize' field has been validated. More...
    FUNC_PURGED_OK = 0x00004000

    # This is a function tail. More...
    FUNC_TAIL = 0x00008000

    @wrap_module("idaapi")
    @wrap_module("idc", full=False)
    def __init__(self, db, api):
        self.idb = db
        self.api = api

    def get_func(self, ea):
        """
        get the func_t associated with the given address.
        if the address is not the start of a function (or function tail), then searches
         for a function that contains the given address.
        note: the range search is pretty slow, since we parse everything on-demand.
        """
        nn = self.api.ida_netnode.netnode("$ funcs")
        try:
            v = nn.supval(tag="S", index=ea)
        except KeyError:
            # search for the given effective address in the function regions.
            # according to [1], `get_func` only searches the primary region, and not all chunks?
            #
            # [1]: http://www.openrce.org/reference_library/ida_sdk_lookup/get_func
            for func in idb.analysis.Functions(self.idb).functions.values():
                if not (func.startEA <= ea < func.endEA):
                    continue

                if is_flag_set(func.flags, self.FUNC_TAIL):
                    return self.get_func(func.owner)
                else:
                    return func

            return None
        else:
            func = idb.analysis.func_t(v, wordsize=self.idb.wordsize)
            if is_flag_set(func.flags, self.FUNC_TAIL):
                return self.get_func(func.owner)
            else:
                return func

    def get_func_cmt(self, ea, repeatable):
        # function comments are stored on the `$ funcs` netnode
        # tag is either `R` or `C`.
        # index is effective address of the function.
        # for example::
        #
        #     nodeid: ff00000000000027 tag: C index: 0x401598
        #     00000000: 72 65 70 20 63 6D 74 00                           rep cmt.
        #     --
        #     nodeid: ff00000000000027 tag: N index: None
        #     00000000: 24 20 66 75 6E 63 73                              $ funcs
        #     --
        #     nodeid: ff00000000000027 tag: R index: 0x401598
        #     00000000: 72 65 70 20 63 6D 74 00                           rep cmt.
        #
        # i think its a bug that when you set a repeatable function via the IDA UI,
        # it also sets a local function comment.

        func = self.get_func(ea)
        if func is None:
            return ""

        nn = self.api.ida_netnode.netnode("$ funcs")
        try:
            if repeatable:
                tag = "R"
            else:
                tag = "C"
            return nn.supstr(tag=tag, index=func.startEA)
        except KeyError:
            return ""

    def get_func_name(self, ea):
        func = self.get_func(ea)
        if func is None:
            return ""

        # shouldn't be a chunk
        if is_flag_set(func.flags, func.FUNC_TAIL) or ea != func.startEA:
            raise KeyError(ea)

        ea = func.startEA
        nn = self.api.ida_netnode.netnode(ea)
        try:
            return nn.name()
        except:
            if self.idb.wordsize == 4:
                return "sub_%04x" % (ea)
            elif self.idb.wordsize == 8:
                return "sub_%08x" % (ea)
            else:
                raise RuntimeError("unexpected wordsize")

    def get_func_qty(self):
        return len(idb.analysis.Functions(self.idb).functions)

    def getn_func(self, n):
        return idb.analysis.Functions(self.idb).functions.values()[n]


class BasicBlock(object):
    """
    interface extracted from: https://raw.githubusercontent.com/gabtremblay/idabearclean/master/idaapi.py
    """

    def __init__(self, flowchart, startEA, lastInstEA, endEA):
        self.fc = flowchart
        self.id = startEA
        self.startEA = startEA
        self.lastInstEA = lastInstEA
        self.endEA = endEA
        # types are declared here:
        #  https://www.hex-rays.com/products/ida/support/sdkdoc/gdl_8hpp.html#afa6fb2b53981d849d63273abbb1624bd
        # not sure if they are stored in the idb. seems like probably not.
        self.type = NotImplementedError()

    def preds(self):
        for pred in self.fc.preds[self.startEA]:
            yield self.fc.bbs[pred]

    def succs(self):
        for succ in self.fc.succs[self.startEA]:
            yield self.fc.bbs[succ]

    def __str__(self):
        return "BasicBlock(startEA: 0x%x, endEA: 0x%x)" % (self.startEA, self.endEA)


def is_empty(s):
    for c in s:
        return False
    return True


class idaapi:
    # xref flags
    # via:
    # https://www.hex-rays.com/products/ida/support/sdkdoc/group__xref__type.html#ga78aab6d0d6bd9cb4904bbdbb5ac4fa71

    # unknown – for compatibility with old versions.
    # Should not be used anymore.
    fl_U = 0
    # Call Far
    fl_CF = 0x10
    # Call Near
    fl_CN = 0x11
    # Jump Far.
    fl_JF = 0x12
    # Jump Near.
    fl_JN = 0x13
    # User specified (obsolete)
    fl_USobsolete = 0x14
    # Ordinary flow: used to specify execution flow to the next instruction.
    fl_F = 0x15
    # unknown – for compatibility with old versions.
    # Should not be used anymore.
    dr_U = 0
    # Offset
    # The reference uses 'offset' of data rather than its value OR
    # The reference appeared because the "OFFSET" flag of instruction is set.
    # The meaning of this type is IDP dependent.
    dr_O = 1
    # Write access.
    dr_W = 2
    # Read access.
    dr_R = 3
    # Text (for forced operands only) Name of data is used in manual operand.
    dr_T = 4
    # Informational (a derived java class references its base class informationally)
    dr_I = 5
    # return all references
    XREF_ALL = 0
    # don't return ordinary flow xrefs
    XREF_FAR = 1
    # return data references only
    XREF_DATA = 2

    def __init__(self, db, api):
        self.idb = db
        self.api = api

        self.BADADDR = self.api.idc.BADADDR

    def _find_bb_end(self, ea):
        """
        Args:
          ea (int): address at which a basic block begins. behavior undefined if its not a block start.

        Returns:
          int: the address of the final instruction in the basic block. it may be the same as the start.
        """
        if not is_empty(
            idb.analysis.get_crefs_from(
                self.idb, ea, types=[idaapi.fl_JN, idaapi.fl_JF, idaapi.fl_F]
            )
        ):
            return ea

        if not self.api.idc.GetFlags(ea):
            return ea

        while True:
            last_ea = ea
            ea = self.api.idc.NextHead(ea)

            flags = self.api.idc.GetFlags(ea)
            if flags == 0:
                return last_ea

            if self.api.ida_bytes.has_ref(flags):
                return last_ea

            if self.api.ida_bytes.is_func(flags):
                return last_ea

            if not self.api.ida_bytes.is_flow(flags):
                return last_ea

            if not is_empty(
                idb.analysis.get_crefs_from(
                    self.idb, ea, types=[idaapi.fl_JN, idaapi.fl_JF, idaapi.fl_F]
                )
            ):
                return ea

    def _find_bb_start(self, ea):
        """
        Args:
          ea (int): address at which a basic block ends. behavior undefined if its not a block end.

        Returns:
          int: the address of the first instruction in the basic block. it may be the same as the end.
        """
        while True:
            flags = self.api.idc.GetFlags(ea)
            if self.api.ida_bytes.has_ref(flags):
                return ea

            if self.api.ida_bytes.is_func(flags):
                return ea

            last_ea = ea
            ea = self.api.idc.PrevHead(ea)

            if not is_empty(
                idb.analysis.get_crefs_from(
                    self.idb, ea, types=[idaapi.fl_JN, idaapi.fl_JF, idaapi.fl_F]
                )
            ):
                return last_ea

            if not self.api.ida_bytes.is_flow(flags):
                return last_ea

    def _get_flow_preds(self, ea):
        # this is basically CodeRefsTo with flow=True.
        # need to fixup the return types, though.

        flags = self.api.idc.GetFlags(ea)
        if flags is not None and self.api.ida_bytes.is_flow(flags):
            # prev instruction fell through to this insn
            yield idb.analysis.Xref(self.api.idc.PrevHead(ea), ea, idaapi.fl_F)

        # get all the flow xrefs to this instruction.
        # a flow xref is like a fallthrough or jump, not like a call.
        for xref in idb.analysis.get_crefs_to(
            self.idb, ea, types=[idaapi.fl_JN, idaapi.fl_JF, idaapi.fl_F]
        ):
            yield xref

    def _get_flow_succs(self, ea):
        # this is basically CodeRefsFrom with flow=True.
        # need to fixup the return types, though.

        nextea = self.api.idc.NextHead(ea)
        nextflags = self.api.idc.GetFlags(nextea)
        if nextflags is not None and self.api.ida_bytes.is_flow(nextflags):
            # instruction falls through to next insn
            yield idb.analysis.Xref(ea, nextea, idaapi.fl_F)

        # get all the flow xrefs from this instruction.
        # a flow xref is like a fallthrough or jump, not like a call.
        for xref in idb.analysis.get_crefs_from(
            self.idb, ea, types=[idaapi.fl_JN, idaapi.fl_JF, idaapi.fl_F]
        ):
            yield xref

    def FlowChart(self, func):
        """
        Example::

            f = idaapi.FlowChart(idaapi.get_func(here()))
            for block in f:
                if p:
                    print "%x - %x [%d]:" % (block.startEA, block.endEA, block.id)
                for succ_block in block.succs():
                    if p:
                        print "  %x - %x [%d]:" % (succ_block.startEA, succ_block.endEA, succ_block.id)

                for pred_block in block.preds():
                    if p:
                        print "  %x - %x [%d]:" % (pred_block.startEA, pred_block.endEA, pred_block.id)

        via: https://github.com/EiNSTeiN-/idapython/blob/master/examples/ex_gdl_qflow_chart.py
        """

        # i have no idea how this data is indexed in the idb.
        # is it even indexed?
        # therefore, let's parse the basic blocks ourselves!

        class _FlowChart:
            def __init__(self, db, api, ea):
                self.idb = db
                logger.debug("creating flowchart for %x", ea)

                # set of startEA
                seen = set([])

                # map from startEA to BasicBlock instance
                bbs_by_start = {}
                # map from endEA to BasicBlock instance
                bbs_by_end = {}

                # map from startEA to set of startEA
                preds = collections.defaultdict(lambda: set([]))
                # map from startEA to set of startEA
                succs = collections.defaultdict(lambda: set([]))

                lastInstEA = api.idaapi._find_bb_end(ea)

                logger.debug("found end. %x -> %x", ea, lastInstEA)
                block = BasicBlock(self, ea, lastInstEA, api.idc.NextHead(lastInstEA))
                bbs_by_start[ea] = block
                bbs_by_end[lastInstEA] = block

                q = [block]

                while q:
                    logger.debug("iteration")
                    logger.debug("queue: [%s]", ", ".join(map(str, q)))

                    block = q[0]
                    q = q[1:]

                    logger.debug("exploring %s", block)

                    if block.startEA in seen:
                        logger.debug("already seen!")
                        continue
                    logger.debug("new!")
                    seen.add(block.startEA)

                    for xref in api.idaapi._get_flow_preds(block.startEA):
                        if xref.frm not in bbs_by_end:
                            pred_start = api.idaapi._find_bb_start(xref.frm)
                            pred = BasicBlock(
                                self, pred_start, xref.frm, api.idc.NextHead(xref.frm)
                            )
                            bbs_by_start[pred.startEA] = pred
                            bbs_by_end[pred.lastInstEA] = pred
                        else:
                            pred = bbs_by_end[xref.frm]

                        logger.debug("pred: %s", pred)

                        preds[block.startEA].add(pred.startEA)
                        succs[pred.startEA].add(block.startEA)
                        q.append(pred)

                    for xref in api.idaapi._get_flow_succs(block.lastInstEA):
                        if xref.to not in bbs_by_start:
                            succ_end = api.idaapi._find_bb_end(xref.to)
                            succ = BasicBlock(
                                self, xref.to, succ_end, api.idc.NextHead(succ_end)
                            )
                            bbs_by_start[succ.startEA] = succ
                            bbs_by_end[succ.lastInstEA] = succ
                        else:
                            succ = bbs_by_start[xref.to]

                        logger.debug("succ: %s", succ)

                        succs[block.startEA].add(succ.startEA)
                        preds[succ.startEA].add(block.startEA)
                        q.append(succ)

                self.preds = preds
                self.succs = succs
                self.bbs = bbs_by_start

            def __iter__(self):
                for bb in self.bbs.values():
                    yield bb

        return _FlowChart(self.idb, self.api, func.startEA)

    def get_next_fixup_ea(self, ea):
        nn = self.api.ida_netnode.netnode("$ fixups")
        # TODO: this is really bad algorithmically. we should cache.
        for index in nn.sups(tag="S"):
            if ea <= index:
                return index
        raise KeyError(ea)

    def contains_fixups(self, ea, size):
        try:
            next_fixup = self.get_next_fixup_ea(ea)
        except KeyError:
            return False
        else:
            if next_fixup < ea + size:
                return True
            else:
                return False

    def getseg(self, ea):
        segs = idb.analysis.Segments(self.idb).segments
        for seg in segs.values():
            if seg.startEA <= ea < seg.endEA:
                return seg

    def get_segm_name(self, ea):
        return self.api.idc.SegName(ea)

    def get_segm_end(self, ea):
        return self.api.idc.SegEnd(ea)

    class IdaInfo(object):
        def __init__(self, api, inf):
            self.api = api
            self.inf = inf

        @property
        def tag(self):
            return self.inf.tag

        @property
        def version(self):
            return self.inf.version

        @property
        def procname(self):
            return self.inf.procname

        @property
        def lflags(self):
            return self.inf.lflags

        @property
        def filetype(self):
            return self.inf.filetype

        def is_32bit(self):
            return self.lflags & self.api.ida_ida.LFLG_PC_FLAT > 0

        def is_64bit(self):
            return self.lflags & self.api.ida_ida.LFLG_64BIT > 0

        def is_snapshot(self):
            return self.lflags & self.api.ida_ida.LFLG_SNAPSHOT > 0

        def is_dll(self):
            return self.lflags & self.api.ida_ida.LFLG_IS_DLL > 0

        def is_flat_off32(self):
            return self.lflags & self.api.ida_ida.LFLG_FLAT_OFF32 > 0

        def is_be(self):
            return self.lflags & self.api.ida_ida.LFLG_MSF > 0

        def is_wide_high_byte_first(self):
            return self.lflags & self.api.ida_ida.LFLG_WIDE_HBF > 0

        def is_kernel_mode(self):
            return self.lflags & self.api.ida_ida.LFLG_KERNMODE > 0

    def get_inf_structure(self):
        return self.IdaInfo(self.api, idb.analysis.Root(self.idb).idainfo)

    def get_imagebase(self):
        return self.api.ida_nalt.get_imagebase()

    TYPE_NAMES = {
        0: "MS DOS EXE File",  # (obsolete)
        1: "MS DOS COM File",  # (obsolete)
        2: "Binary file",
        3: "MS DOS Driver",
        4: "New Executable (NE)",
        5: "Intel Hex Object File",
        6: "MOS Technology Hex Object File",
        7: "Linear Executable (LX)",
        8: "Linear Executable (LE)",
        9: "Netware Loadable Module (NLM)",
        10: "Common Object File Format (COFF)",
        11: "Portable Executable (PE)",
        12: "Object Module Format",
        13: "R-records",
        14: "ZIP file",  # (this file is never loaded to IDA database)
        15: "Library of OMF Modules",
        16: "ar library",
        17: "file is loaded using LOADER DLL",
        18: "Executable and Linkable Format (ELF)",
        19: "Watcom DOS32 Extender (W32RUN)",
        20: "Linux a.out (AOUT)",
        21: "PalmPilot program file",
        22: "MS DOS EXE File",
        23: "MS DOS COM File",
        24: "AIX ar library",
    }

    def get_file_type_name(self):
        return self.TYPE_NAMES[self.get_inf_structure().filetype]


class StringItem:
    def __init__(self, ea, length, strtype, s):
        self.ea = ea
        self.length = length
        self.strtype = strtype
        self.s = s

    def __str__(self):
        return self.s


class _Strings:
    C = 0x0
    C_16 = 0x1
    C_32 = 0x2
    PASCAL = 0x4
    PASCAL_16 = 0x5
    LEN2 = 0x8
    LEN2_16 = 0x9
    LEN4 = 0xC
    LEN4_16 = 0xD

    ASCII_BYTE = (
        b" !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[]^_`"
        b"abcdefghijklmnopqrstuvwxyz{|}\\~\t"
    )

    def __init__(self, db, api):
        self.db = db
        self.api = api

        self.cache = None

        self.strtypes = [0]
        self.minlen = 5
        self.only_7bit = True
        self.ignore_instructions = False
        self.display_only_existing_strings = False

    def clear_cache(self):
        self.cache = None

    @memoized_method()
    def get_seg_data(self, seg):
        start = self.api.idc.SegStart(seg)
        end = self.api.idc.SegEnd(start)

        IdbByte = self.api.idc.IdbByte
        get_flags = self.api.ida_bytes.get_flags
        has_value = self.api.ida_bytes.has_value

        data = []
        for i in range(start, end):
            try:
                b = IdbByte(i)
            except KeyError:
                break
            if b == 0:
                flags = get_flags(i)
                if not has_value(flags):
                    break
            data.append(b)

        if six.PY2:
            return "".join(map(chr, data))
        else:
            return bytes(data)

    def parse_C_strings(self, va, buf):
        reg = b"([%s]{%d,})" % (_Strings.ASCII_BYTE, self.minlen)
        ascii_re = re.compile(reg)
        for match in ascii_re.finditer(buf):
            s = match.group().decode("ascii")
            yield StringItem(va + match.start(), len(s), _Strings.C, s)

    def parse_C_16_strings(self, va, buf):
        reg = b"((?:[%s]\x00){%d,})" % (_Strings.ASCII_BYTE, self.minlen)
        uni_re = re.compile(reg)
        for match in uni_re.finditer(buf):
            try:
                s = match.group().decode("utf-16")
            except UnicodeDecodeError:
                continue
            else:
                yield StringItem(va + match.start(), len(s), _Strings.C_16, s)

    def parse_C_32_strings(self, va, buf):
        reg = b"((?:[%s]\x00\x00\x00){%d,})" % (_Strings.ASCII_BYTE, self.minlen)
        uni_re = re.compile(reg)
        for match in uni_re.finditer(buf):
            try:
                s = match.group().decode("utf-32")
            except UnicodeDecodeError:
                continue
            else:
                yield StringItem(va + match.start(), len(s), _Strings.C_32, s)

    def parse_PASCAL_strings(self, va, buf):
        raise NotImplementedError("parse PASCAL strings")

    def parse_PASCAL_16_strings(self, va, buf):
        raise NotImplementedError("parse PASCAL_16 strings")

    def parse_LEN2_strings(self, va, buf):
        raise NotImplementedError("parse LEN2 strings")

    def parse_LEN2_16_strings(self, va, buf):
        raise NotImplementedError("parse LEN2_16 strings")

    def parse_LEN4_strings(self, va, buf):
        raise NotImplementedError("parse LEN4 strings")

    def parse_LEN4_16_strings(self, va, buf):
        raise NotImplementedError("parse LEN4_16 strings")

    def refresh(self):
        ret = []
        for seg in self.api.idautils.Segments():
            buf = self.get_seg_data(seg)

            for parser in (
                self.parse_C_strings,
                self.parse_C_16_strings,
                self.parse_C_32_strings,
                self.parse_PASCAL_strings,
                self.parse_PASCAL_16_strings,
                self.parse_LEN2_strings,
                self.parse_LEN2_16_strings,
                self.parse_LEN4_strings,
                self.parse_LEN4_16_strings,
            ):
                try:
                    ret.extend(list(parser(seg, buf)))
                except NotImplementedError as e:
                    logger.warning("warning: %s", e)
        self.cache = ret[:]
        return ret

    def setup(
        self,
        strtypes=[0],
        minlen=5,
        only_7bit=True,
        ignore_instructions=False,
        display_only_existing_strings=False,
    ):
        self.strtypes = strtypes
        self.minlen = minlen
        self.only_7bit = only_7bit
        self.ignore_instructions = ignore_instructions
        self.display_only_existing_strings = display_only_existing_strings

    def __iter__(self):
        if self.cache is None:
            self.refresh()

        for s in self.cache:
            yield s

    def __getitem__(self, index):
        if self.cache is None:
            self.refresh()
        return self.cache[index]


class idautils:
    def __init__(self, db, api):
        self.idb = db
        self.api = api
        self.strings = _Strings(db, api)

    def GetInputFileMD5(self):
        return self.api.idc.GetInputMD5()

    def Segments(self):
        return sorted(idb.analysis.Segments(self.idb).segments.keys())

    def Functions(self, start=None, end=None):
        ret = []
        for ea, func in idb.analysis.Functions(self.idb).functions.items():
            if start and start > ea:
                continue
            if end and end <= ea:
                continue
            # we won't report chunks
            if is_flag_set(func.flags, func.FUNC_TAIL):
                continue
            ret.append(func.startEA)
        return list(sorted(ret))

    def Chunks(self, fva):
        try:
            func_t = idb.analysis.Functions(self.idb).functions[fva]
        except KeyError:
            logger.debug("failed to fetch func_t: 0x%x", fva)
            return

        yield (func_t.startEA, func_t.endEA)

        try:
            f = idb.analysis.Function(self.idb, fva)
        except KeyError:
            logger.debug("failed to fetch Function: 0x%x", fva)
            return

        try:
            for start, size in f.get_chunks():
                yield (start, start + size)
        except KeyError:
            return

    def Heads(self, start, end):
        ea = start

        while not self.api.ida_bytes.is_head(self.api.idc.GetFlags(ea)):
            ea = self.api.idc.NextHead(ea)
            if ea >= end:
                return

        while ea != self.api.idc.BADADDR:
            yield ea
            ea = self.api.idc.NextHead(ea)
            if ea >= end:
                return

    def _get_fallthrough_xref_to(self, ea):
        # fallthrough flow is not explicitly encoded
        flags = self.api.idc.GetFlags(ea)
        if flags is None:
            return None

        if not self.api.ida_bytes.is_flow(flags):
            return None

        return idb.analysis.Xref(self.api.idc.PrevHead(ea), ea, 0x15)

    def CodeRefsTo(self, ea, flow):
        if flow:
            ftf = self._get_fallthrough_xref_to(ea)
            if ftf is not None:
                yield ftf.frm

        # get all the code xrefs to this instruction.
        # a code xref is like a fallthrough or jump, not like a call.
        for xref in idb.analysis.get_crefs_to(
            self.idb, ea, types=[idaapi.fl_JN, idaapi.fl_JF, idaapi.fl_F]
        ):
            yield xref.frm

    def _get_fallthrough_xref_from(self, ea):
        nextea = self.api.idc.NextHead(ea)
        nextflags = self.api.idc.GetFlags(nextea)
        if nextflags is None:
            return None

        if not self.api.ida_bytes.is_flow(nextflags):
            return None

        return idb.analysis.Xref(ea, nextea, 0x15)

    def CodeRefsFrom(self, ea, flow):
        if flow:
            ftf = self._get_fallthrough_xref_from(ea)
            if ftf is not None:
                yield ftf.to

        # get all the code xrefs from this instruction.
        # a code xref is like a fallthrough or jump, not like a call.
        for xref in idb.analysis.get_crefs_from(
            self.idb, ea, types=[idaapi.fl_JN, idaapi.fl_JF, idaapi.fl_F]
        ):
            yield xref.to

    ALL_DREF_TYPES = (
        idaapi.dr_U,
        idaapi.dr_O,
        idaapi.dr_W,
        idaapi.dr_R,
        idaapi.dr_T,
        idaapi.dr_I,
    )
    ALL_CREF_TYPES = (
        idaapi.fl_JN,
        idaapi.fl_JF,
        idaapi.fl_F,
        idaapi.fl_CN,
        idaapi.fl_CF,
    )

    def DataRefsFrom(self, ea):
        # IDAPython docstring says this returns a list,
        # but its actually a generator.

        # calls are not data references.
        # global variables are data references.
        for xref in idb.analysis.get_drefs_from(
            self.idb, ea, types=self.ALL_DREF_TYPES
        ):
            yield xref.to

    def DataRefsTo(self, ea):
        for xref in idb.analysis.get_drefs_to(self.idb, ea, types=self.ALL_DREF_TYPES):
            yield xref.frm

    def XrefsTo(self, ea, flags=idaapi.XREF_ALL):
        # return all references
        if flags == idaapi.XREF_ALL:
            typef = self.ALL_CREF_TYPES
            typed = self.ALL_DREF_TYPES

        # don't return ordinary flow xrefs
        elif flags == idaapi.XREF_FAR:
            # Call Far
            # Call Near
            # Jump Far.
            # Jump Near.
            typef = [idaapi.fl_CF, idaapi.fl_CN, idaapi.fl_JF, idaapi.fl_JN]
            # strange, but true: include drefs in XREF_FAR
            typed = self.ALL_DREF_TYPES

        # return data references only
        elif flags == idaapi.XREF_DATA:
            typef = None
            typed = self.ALL_DREF_TYPES

        else:
            raise ValueError("unexpected flags value")

        if typef:
            for xref in idb.analysis.get_crefs_to(self.idb, ea, typef):
                yield xref

            # fallthrough flow is not explicitly encoded
            if idaapi.fl_F in typef:
                ftf = self._get_fallthrough_xref_to(ea)
                if ftf is not None:
                    yield ftf

        if typed:
            for xref in idb.analysis.get_drefs_to(self.idb, ea, typed):
                yield xref

    def XrefsFrom(self, ea, flags=idaapi.XREF_ALL):
        # return all references
        if flags == idaapi.XREF_ALL:
            typef = self.ALL_CREF_TYPES
            typed = self.ALL_DREF_TYPES

        # don't return ordinary flow xrefs
        elif flags == idaapi.XREF_FAR:
            # Call Far
            # Call Near
            # Jump Far.
            # Jump Near.
            typef = [idaapi.fl_CF, idaapi.fl_CN, idaapi.fl_JF, idaapi.fl_JN]
            # strange, but true: include drefs in XREF_FAR
            typed = self.ALL_DREF_TYPES

        # return data references only
        elif flags == idaapi.XREF_DATA:
            typef = None
            typed = self.ALL_DREF_TYPES

        else:
            raise ValueError("unexpected flags value")

        if typef:
            for xref in idb.analysis.get_crefs_from(self.idb, ea, typef):
                yield xref

            # fallthrough flow is not explicitly encoded
            if idaapi.fl_F in typef:
                ftf = self._get_fallthrough_xref_from(ea)
                if ftf is not None:
                    yield ftf

        if typed:
            for xref in idb.analysis.get_drefs_from(self.idb, ea, typed):
                yield xref

    def Strings(self, default_setup=False):
        return self.strings

    def Names(self):
        for i in range(self.api.ida_name.get_nlist_size()):
            ea = self.api.ida_name.get_nlist_ea(i)
            name = self.api.ida_name.get_nlist_name(i)
            yield (ea, name)

    def Entries(self):
        for i in range(self.api.ida_entry.get_entry_qty()):
            ordinal = self.api.ida_entry.get_entry_ordinal(i)
            yield (
                i,
                ordinal,
                self.api.ida_entry.get_entry(ordinal),
                self.api.ida_entry.get_entry_name(ordinal),
            )


class ida_entry:
    @wrap_module("idaapi")
    def __init__(self, db, api):
        self.idb = db
        self.api = api

    def get_entry_qty(self):
        ents = idb.analysis.EntryPoints(self.idb)
        return len(ents.functions) + len(ents.main_entry)

    def get_entry_ordinal(self, index):
        ents = idb.analysis.EntryPoints(self.idb)
        try:
            return ents.ordinals[index + 1]
        except KeyError:
            # once we enumerate all the exports by ordinal,
            # then wrap into the "main entry".
            # not sure that there can be more than one, but we attempt to deal here.
            return sorted(ents.main_entry)[index - len(ents.functions) - 1]

    def get_entry(self, ordinal):
        # for the "main entry", ordinal is actually an address.
        ents = idb.analysis.EntryPoints(self.idb)
        return ents.functions[ordinal]

    def get_entry_name(self, ordinal):
        ents = idb.analysis.EntryPoints(self.idb)
        try:
            return ents.function_names[ordinal]
        except KeyError:
            # for the "main entry", ordinal is actually an address.
            return ents.main_entry_name[ordinal]

    def get_entry_forwarder(self, ordinal):
        ents = idb.analysis.EntryPoints(self.idb)
        return ents.forwarded_symbols.get(ordinal)


class ida_name:
    @wrap_module("idaapi")
    def __init__(self, db, api):
        self.idb = db
        self.api = api

    def get_name(self, ea):
        flags = self.api.ida_bytes.get_flags(ea)
        if not self.api.ida_bytes.has_name(flags):
            func = self.api.ida_funcs.get_func(ea)
            if func and func.startEA == ea:
                return self.api.ida_funcs.get_func_name(ea)
            refs = self.api.idautils.CodeRefsTo(ea, 0)
            if next(refs, None):
                return "loc_%X" % (ea)
            return ""

        try:
            nn = self.api.ida_netnode.netnode(ea)
            return nn.name()
        except KeyError:
            return ""

    @memoized_method()
    def _get_name_ptrs(self):
        """
        a wrapper for the NAM section parser that caches the results on first access.
        """
        return self.idb.nam.names()

    def get_nlist_size(self):
        return self.idb.nam.name_count

    def get_nlist_ea(self, i):
        return self._get_name_ptrs()[i]

    def get_nlist_name(self, i):
        ea = self.get_nlist_ea(i)
        return self.get_name(ea)


class ida_struct:
    def __init__(self, db, api):
        self.idb = db
        self.api = api

        self._struct_ids = []
        self._load_structs()

    def _load_structs(self):
        node = Netnode(self.idb, "$ structs")
        for entry in node.altentries():
            self._struct_ids.append(idb.netnode.as_uint(entry.value) - 1)

    # def get_member(self, sptr, offset):
    #     """Get member at given offset."""
    #     raise NotImplementedError()

    def get_member_by_fullname(self, fullname):
        """Get a member by its fully qualified name, "struct.field"."""
        return StructMember(self.idb, fullname)

    def get_member_by_id(self, mid):
        """Check if the specified member id points to a struct member."""
        return StructMember(self.idb, mid)

    def get_member_by_name(self, sptr, membername):
        """Get a member by its name, like "field44"."""
        return sptr.find_member_by_name(membername)

    def get_member_cmt(self, mid, repeatable):
        """Get comment of structure member."""
        m = self.get_member_by_id(mid)
        if repeatable:
            return m.get_repeatable_member_comment()
        else:
            return m.get_member_comment()

    def get_member_fullname(self, mid):
        """Get a member's fully qualified name, "struct.field"."""
        m = self.get_member_by_id(mid)
        return m.get_fullname()

    # def get_member_id(self, sptr, offset):
    #     """Get member id at given offset."""
    #     raise NotImplementedError()

    def get_member_name(self, mid):
        """Get name of structure member."""
        return self.get_member_by_id(mid).get_name()

    def get_member_size(self, nonnul_mptr):
        """Get size of structure member."""
        tinfo = self.get_member_tinfo(nonnul_mptr)
        if not tinfo:
            return None
        else:
            return tinfo.get_size()

    def get_member_struc(self, fullname):
        """Get containing structure of member by its full name "struct.field"."""
        return Struct(self.idb, fullname)

    def get_member_tinfo(self, mptr):
        """Get tinfo for given member."""
        _type = mptr.get_typeinfo()
        if not _type:
            return None
        ordinal = self.api.ida_typeinf.get_ordinal_from_idb_type(mptr.get_name(), _type)
        if ordinal == -1:
            return None
        else:
            return self.api.ida_typeinf.get_numbered_type(ordinal)

    def get_struc_id(self, name):
        """Get struct id by name."""
        return Struct(self.idb, name).nodeid

    def get_first_struc_idx(self):
        return 0 if len(self._struct_ids) > 0 else self.api.idc.BADADDR

    def get_last_struc_idx(self):
        return (
            self._struct_ids[-1] if len(self._struct_ids) > 0 else self.api.idc.BADADDR
        )

    def get_struc(self, id):
        """Get pointer to struct type info."""
        return Struct(self.idb, id)

    def get_struc_by_idx(self, idx):
        return Struct(self.idb, self._struct_ids[idx])

    def get_struc_name(self, id, flags=0):
        """Get struct name by id"""
        return self.get_struc(id).get_name()

    def get_struc_idx(self, id):
        return self._struct_ids.index(id)

    def get_struc_id(self, name):
        return Netnode(self.idb, name).nodeid


class ida_typeinf:
    def __init__(self, db, api):
        self.idb = db
        self.api = api
        self.types = db.til.types

    def get_named_type(self, name, ntf_flags=None):
        """Get a type data by its name."""
        return self.types.find_by_name(name)

    def get_type_flags(self, t):
        """Get type flags ( 'TYPE_FLAGS_MASK' )"""
        return idb.typeinf.get_type_flags(t)

    def get_base_flags(self, t):
        return idb.typeinf.get_base_type(t)

    def get_numbered_type(self, ordinal):
        """Get type ordinal by its name."""
        if 0 < ordinal < len(self.types):
            return self.types[ordinal]
        else:
            return None

    def get_ordinal_from_idb_type(self, name, _type):
        """Get ordinal number of an idb type (struct/enum).
        The 'type' parameter is used only to determine the kind of the type (struct or enum).
        Use this function to find out the correspondence between idb types and til types"""
        if not _type or len(_type) == 0:
            return -1
        typ = self.get_named_type(name)
        if self.get_base_flags(typ.type.base_type) == self.get_base_flags(
            ord(_type[0])
        ):
            return typ.ordinal
        else:
            return -1


class IDAPython:
    def __init__(self, db, ScreenEA=None):
        self.idb = db
        self.ScreenEA = ScreenEA

        self.idc = idc(db, self)
        self.idaapi = idaapi(db, self)
        self.idautils = idautils(db, self)
        self.ida_ida = ida_ida(db, self)
        self.ida_funcs = ida_funcs(db, self)
        self.ida_bytes = ida_bytes(db, self)
        self.ida_netnode = ida_netnode(db, self)
        self.ida_nalt = ida_nalt(db, self)
        self.ida_entry = ida_entry(db, self)
        self.ida_name = ida_name(db, self)
        self.ida_struct = ida_struct(db, self)
        self.ida_typeinf = ida_typeinf(db, self)
        self.ida_ua = ida_ua(db, self)
