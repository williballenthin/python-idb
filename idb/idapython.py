# -*- coding: utf-8 -*-
import re
import logging
import weakref
import functools
import collections

import six

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
    def __init__(self, db, api):
        self.idb = db
        self.api = api

    def netnode(self, *args, **kwargs):
        return idb.netnode.Netnode(self.idb, *args, **kwargs)


class idc:

    SEGPERM_EXEC   = 1  # Execute
    SEGPERM_WRITE  = 2  # Write
    SEGPERM_READ   = 4  # Read
    SEGPERM_MAXVAL = 7  # (SEGPERM_EXEC + SEGPERM_WRITE + SEGPERM_READ)

    SFL_COMORG   = 0x01  # IDP dependent field (IBM PC: if set, ORG directive is not commented out)
    SFL_OBOK     = 0x02  # orgbase is present? (IDP dependent field)
    SFL_HIDDEN   = 0x04  # is the segment hidden?
    SFL_DEBUG    = 0x08  # is the segment created for the debugger?
    SFL_LOADER   = 0x10  # is the segment created by the loader?
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
            self.FUNCATTR_START   = 0
            # function end address
            self.FUNCATTR_END     = 4
            # function flags
            self.FUNCATTR_FLAGS   = 8
            # function frame id
            self.FUNCATTR_FRAME   = 10
            # size of local variables
            self.FUNCATTR_FRSIZE  = 14
            # size of saved registers area
            self.FUNCATTR_FRREGS  = 18
            # number of bytes purged from the stack
            self.FUNCATTR_ARGSIZE = 20
            # frame pointer delta
            self.FUNCATTR_FPD     = 24
            # function color code
            self.FUNCATTR_COLOR   = 28

            # starting address
            self.SEGATTR_START   =  0
            # ending address
            self.SEGATTR_END     =  4
            self.SEGATTR_ORGBASE = 16
            # alignment
            self.SEGATTR_ALIGN   = 20
            # combination
            self.SEGATTR_COMB    = 21
            # permissions
            self.SEGATTR_PERM    = 22
            # bitness (0: 16, 1: 32, 2: 64 bit segment)
            self.SEGATTR_BITNESS = 23
            # segment flags
            self.SEGATTR_FLAGS   = 24
            # segment selector
            self.SEGATTR_SEL     = 28
            # default ES value
            self.SEGATTR_ES      = 32
            # default CS value
            self.SEGATTR_CS      = 36
            # default SS value
            self.SEGATTR_SS      = 40
            # default DS value
            self.SEGATTR_DS      = 44
            # default FS value
            self.SEGATTR_FS      = 48
            # default GS value
            self.SEGATTR_GS      = 52
            # segment type
            self.SEGATTR_TYPE    = 96
            # segment color
            self.SEGATTR_COLOR   = 100

            self.BADADDR = 0xFFFFFFFF

        elif self.idb.wordsize == 8:
            self.FUNCATTR_START   = 0
            self.FUNCATTR_END     = 8
            self.FUNCATTR_FLAGS   = 16
            self.FUNCATTR_FRAME   = 18
            self.FUNCATTR_FRSIZE  = 26
            self.FUNCATTR_FRREGS  = 34
            self.FUNCATTR_ARGSIZE = 36
            self.FUNCATTR_FPD     = 44
            self.FUNCATTR_COLOR   = 52
            self.FUNCATTR_OWNER   = 18
            self.FUNCATTR_REFQTY  = 26

            self.SEGATTR_START   =  0
            self.SEGATTR_END     =  8
            self.SEGATTR_ORGBASE = 32
            self.SEGATTR_ALIGN   = 40
            self.SEGATTR_COMB    = 41
            self.SEGATTR_PERM    = 42
            self.SEGATTR_BITNESS = 43
            self.SEGATTR_FLAGS   = 44
            self.SEGATTR_SEL     = 48
            self.SEGATTR_ES      = 56
            self.SEGATTR_CS      = 64
            self.SEGATTR_SS      = 72
            self.SEGATTR_DS      = 80
            self.SEGATTR_FS      = 88
            self.SEGATTR_GS      = 96
            self.SEGATTR_TYPE    = 184
            self.SEGATTR_COLOR   = 188

            self.BADADDR = 0xFFFFFFFFFFFFFFFF
        else:
            raise RuntimeError('unexpected wordsize')

    def ScreenEA(self):
        return self.api.ScreenEA

    def _get_segment(self, ea):
        segs = idb.analysis.Segments(self.idb).segments
        for seg in segs.values():
            if seg.startEA <= ea < seg.endEA:
                return seg

    def SegStart(self, ea):
        return self._get_segment(ea).startEA

    def SegEnd(self, ea):
        return self._get_segment(ea).endEA

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
            raise NotImplementedError('segment attribute %d not yet implemented' % (attr))

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
        oea = ea
        flags = self.GetFlags(ea)
        if not self.api.ida_bytes.is_head(flags):
            raise ValueError('ItemSize must only be called on a head address.')

        ea += 1
        flags = self.GetFlags(ea)
        while flags is not None and not self.api.ida_bytes.is_head(flags):
            ea += 1
            # TODO: handle Index/KeyError here when we overrun a segment
            flags = self.GetFlags(ea)
        return ea - oea

    def NextHead(self, ea):
        ea += 1
        flags = self.GetFlags(ea)
        while flags is not None and not self.api.ida_bytes.is_head(flags):
            ea += 1
            # TODO: handle Index/KeyError here when we overrun a segment
            flags = self.GetFlags(ea)
        return ea

    def PrevHead(self, ea):
        ea = self.Head(ea)
        ea -= 1
        return self.Head(ea)

    def GetManyBytes(self, ea, size, use_dbg=False):
        '''
        Raises:
          IndexError: if the range extends beyond a segment.
          KeyError: if a byte is not defined.
        '''
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
            ret.extend([0x0 for _ in  range(size - len(ret))])

        if six.PY2:
            return ''.join(map(chr, ret))
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
        bitness = 16 << segment.bitness# 16, 32, 64
        procname = self.api.idaapi.get_inf_structure().procname.lower()

        dis = None
        if procname == "arm" and bitness == 64:
            dis = self._load_dis(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
        elif procname == "arm" and bitness == 32:
            if size == 2:
                dis = self._load_dis(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)
            else:
                dis = self._load_dis(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
        elif procname in ['metapc', '8086', '80286r', '80286p', '80386r', '80386p','80486r', '80486p', '80586r', '80586p', '80686p', 'k62', 'p2', 'p3', 'athlon', 'p4', '8085']:
            if bitness == 16:
                dis = self._load_dis(capstone.CS_ARCH_X86, capstone.CS_MODE_16)
            elif bitness == 32:
                dis = self._load_dis(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
            elif bitness == 64:
                dis = self._load_dis(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        elif procname == "mipsb":
            if bitness == 32:
                dis = self._load_dis(capstone.CS_ARCH_MIPS, capstone.CS_MODE_MIPS32 | capstone.CS_MODE_BIG_ENDIAN)
            elif bitness == 64:
                dis = self._load_dis(capstone.CS_ARCH_MIPS, capstone.CS_MODE_MIPS64 | capstone.CS_MODE_BIG_ENDIAN)
        elif procname == "mipsl":
            if bitness == 32:
                dis = self._load_dis(capstone.CS_ARCH_MIPS, capstone.CS_MODE_MIPS32 | capstone.CS_MODE_LITTLE_ENDIAN)
            elif bitness == 64:
                dis = self._load_dis(capstone.CS_ARCH_MIPS, capstone.CS_MODE_MIPS64 | capstone.CS_MODE_LITTLE_ENDIAN)

        if dis is None:
            raise NotImplementedError("unknown arch %s bit:%s inst_len:%d" % (procname, bitness, len(inst_buf)))
        dis.detail = True

        try:
            op = next(dis.disasm(inst_buf, ea))
        except StopIteration:
            raise RuntimeError('failed to disassemble %s' % (hex(ea)))
        else:
            return op

    def GetMnem(self, ea):
        op = self._disassemble(ea)
        return op.mnemonic

    def GetDisasm(self, ea):
        op = self._disassemble(ea)
        return '%s\t%s' % (op.mnemonic, op.op_str)

    # one instruction or data
    CIC_ITEM = 1
    # function
    CIC_FUNC = 2
    # segment
    CIC_SEGM = 3
    # default color
    DEFCOLOR = 0xFFFFFFFF

    def GetColor(self, ea, what):
        '''
        Args:
          ea (int): effective address of thing.
          what (int): one of:
            - idc.CIC_ITEM
            - idc.CIC_FUNC
            - idc.CIC_SEGM

        Returns:
          int: the color in RGB. possibly idc.DEFCOLOR if not set.
        '''
        if what != idc.CIC_ITEM:
            raise NotImplementedError()

        if not self.api.ida_nalt.is_colored_item(ea):
            return idc.DEFCOLOR

        nn = self.api.ida_netnode.netnode(ea)
        try:
            return nn.altval(tag='A', index=0x14) - 1
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
            raise ValueError('unknown attr: %x' % (attr))

    def GetFunctionName(self, ea):
        return self.api.ida_funcs.get_func_name(ea)

    def LocByName(self, name):
        try:
            key = ("N" + name).encode('utf-8')
            cursor = self.idb.id0.find(key)
            return idb.netnode.as_uint(cursor.value)
        except KeyError:
            return -1

    def GetInputMD5(self):
        return idb.analysis.Root(self.idb).md5

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
            logger.warning('failed to fetch function for GetType: %s', e)
            return None

        try:
            name = f.get_name()
            sig = f.get_signature()
        except KeyError:
            return None

        params = []
        for param in sig.parameters:
            params.append('%s %s' % (param.type, param.name))

        return '{rtype:s} {cc:s} {name:s}({params:s})'.format(
            rtype=sig.rtype,
            cc=sig.calling_convention,
            name=name,
            params=', '.join(params),
        )

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
        return t == FLAGS.FF_0NUMB or \
            t == FLAGS.FF_0NUMO or \
            t == FLAGS.FF_0NUMD or \
            t == FLAGS.FF_0NUMH

    @staticmethod
    def isNum1(flags):
        t = flags & FLAGS.MS_1TYPE
        return t == FLAGS.FF_1NUMB or \
            t == FLAGS.FF_1NUMO or \
            t == FLAGS.FF_1NUMD or \
            t == FLAGS.FF_1NUMH

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
            return nn.supstr(tag='S', index=1000 + num)
        except KeyError:
            return ''

    def LineB(self, ea, num):
        nn = self.api.ida_netnode.netnode(ea)
        try:
            return nn.supstr(tag='S', index=2000 + num)
        except KeyError:
            return ''


class ida_bytes:
    def __init__(self, db, api):
        self.idb = db
        self.api = api

    def get_cmt(self, ea, repeatable):
        flags = self.api.idc.GetFlags(ea)
        if not self.has_cmt(flags):
            return ''

        try:
            nn = self.api.ida_netnode.netnode(ea)
            if repeatable:
                return nn.supstr(tag='S', index=1)
            else:
                return nn.supstr(tag='S', index=0)
        except KeyError:
            return ''

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
        for i in range(ea+1, maxea):
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


class ida_nalt:
    def __init__(self, db, api):
        self.idb = db
        self.api = api

    def get_aflags(self, ea):
        nn = self.api.ida_netnode.netnode(ea)
        try:
            return nn.altval(tag='A', index=0x8)
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

    def __init__(self, db, api):
        self.idb = db
        self.api = api

    def get_func(self, ea):
        '''
        get the func_t associated with the given address.
        if the address is not the start of a function (or function tail), then searches
         for a function that contains the given address.
        note: the range search is pretty slow, since we parse everything on-demand.
        '''
        nn = self.api.ida_netnode.netnode('$ funcs')
        try:
            v = nn.supval(tag='S', index=ea)
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
            return ''

        nn = self.api.ida_netnode.netnode('$ funcs')
        try:
            if repeatable:
                tag = 'R'
            else:
                tag = 'C'
            return nn.supstr(tag=tag, index=func.startEA)
        except KeyError:
            return ''

    def get_func_name(self, ea):
        func = self.get_func(ea)
        # ensure this is a function
        if func.startEA != ea:
            raise KeyError(ea)

        # shouldn't be a chunk
        if is_flag_set(func.flags, func.FUNC_TAIL):
            raise KeyError(ea)

        nn = self.api.ida_netnode.netnode(ea)
        try:
            return nn.name()
        except:
            if self.idb.wordsize == 4:
                return 'sub_%04x' % (ea)
            elif self.idb.wordsize == 8:
                return 'sub_%08x' % (ea)
            else:
                raise RuntimeError('unexpected wordsize')


class BasicBlock(object):
    '''
    interface extracted from: https://raw.githubusercontent.com/gabtremblay/idabearclean/master/idaapi.py
    '''

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
        return 'BasicBlock(startEA: 0x%x, endEA: 0x%x)' % (self.startEA, self.endEA)


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

    def __init__(self, db, api):
        self.idb = db
        self.api = api

    def _find_bb_end(self, ea):
        '''
        Args:
          ea (int): address at which a basic block begins. behavior undefined if its not a block start.

        Returns:
          int: the address of the final instruction in the basic block. it may be the same as the start.
        '''
        if not is_empty(idb.analysis.get_crefs_from(self.idb, ea,
                                                    types=[idaapi.fl_JN, idaapi.fl_JF, idaapi.fl_F])):
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

            if not is_empty(idb.analysis.get_crefs_from(self.idb, ea,
                                                        types=[idaapi.fl_JN, idaapi.fl_JF, idaapi.fl_F])):
                return ea

    def _find_bb_start(self, ea):
        '''
        Args:
          ea (int): address at which a basic block ends. behavior undefined if its not a block end.

        Returns:
          int: the address of the first instruction in the basic block. it may be the same as the end.
        '''
        while True:
            flags = self.api.idc.GetFlags(ea)
            if self.api.ida_bytes.has_ref(flags):
                return ea

            if self.api.ida_bytes.is_func(flags):
                return ea

            last_ea = ea
            ea = self.api.idc.PrevHead(ea)

            if not is_empty(idb.analysis.get_crefs_from(self.idb, ea,
                                                        types=[idaapi.fl_JN, idaapi.fl_JF, idaapi.fl_F])):
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
        for xref in idb.analysis.get_crefs_to(self.idb, ea,
                                              types=[idaapi.fl_JN, idaapi.fl_JF, idaapi.fl_F]):
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
        for xref in idb.analysis.get_crefs_from(self.idb, ea,
                                                types=[idaapi.fl_JN, idaapi.fl_JF, idaapi.fl_F]):
            yield xref

    def FlowChart(self, func):
        '''
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
        '''

        # i have no idea how this data is indexed in the idb.
        # is it even indexed?
        # therefore, let's parse the basic blocks ourselves!

        class _FlowChart:
            def __init__(self, db, api, ea):
                self.idb = db
                logger.debug('creating flowchart for %x', ea)

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

                logger.debug('found end. %x -> %x', ea, lastInstEA)
                block = BasicBlock(self, ea, lastInstEA, api.idc.NextHead(lastInstEA))
                bbs_by_start[ea] = block
                bbs_by_end[lastInstEA] = block

                q = [block]

                while q:
                    logger.debug('iteration')
                    logger.debug('queue: [%s]', ', '.join(map(str, q)))

                    block = q[0]
                    q = q[1:]

                    logger.debug('exploring %s', block)

                    if block.startEA in seen:
                        logger.debug('already seen!')
                        continue
                    logger.debug('new!')
                    seen.add(block.startEA)

                    for xref in api.idaapi._get_flow_preds(block.startEA):
                        if xref.src not in bbs_by_end:
                            pred_start = api.idaapi._find_bb_start(xref.src)
                            pred = BasicBlock(self, pred_start, xref.src, api.idc.NextHead(xref.src))
                            bbs_by_start[pred.startEA] = pred
                            bbs_by_end[pred.lastInstEA] = pred
                        else:
                            pred = bbs_by_end[xref.src]

                        logger.debug('pred: %s', pred)

                        preds[block.startEA].add(pred.startEA)
                        succs[pred.startEA].add(block.startEA)
                        q.append(pred)

                    for xref in api.idaapi._get_flow_succs(block.lastInstEA):
                        if xref.dst not in bbs_by_start:
                            succ_end = api.idaapi._find_bb_end(xref.dst)
                            succ = BasicBlock(self, xref.dst, succ_end, api.idc.NextHead(succ_end))
                            bbs_by_start[succ.startEA] = succ
                            bbs_by_end[succ.lastInstEA] = succ
                        else:
                            succ = bbs_by_start[xref.dst]

                        logger.debug('succ: %s', succ)

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
        nn = self.api.ida_netnode.netnode('$ fixups')
        # TODO: this is really bad algorithmically. we should cache.
        for index in nn.sups(tag='S'):
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

    def get_inf_structure(self):
        return idb.analysis.Root(self.idb).idainfo

    def get_imagebase(self):
        return self.api.ida_nalt.get_imagebase()


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
    LEN4 =  0xC
    LEN4_16 = 0xD

    ASCII_BYTE = b" !\"#\$%&\'\(\)\*\+,-\./0123456789:;<=>\?@ABCDEFGHIJKLMNOPQRSTUVWXYZ\[\]\^_`abcdefghijklmnopqrstuvwxyz\{\|\}\\\~\t"

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
            b = IdbByte(i)
            if b == 0:
                flags = get_flags(i)
                if not has_value(flags):
                    break
            data.append(b)

        if six.PY2:
            return ''.join(map(chr, data))
        else:
            return bytes(data)

    def parse_C_strings(self, va, buf):
        reg = b"([%s]{%d,})" % (_Strings.ASCII_BYTE, self.minlen)
        ascii_re = re.compile(reg)
        for match in ascii_re.finditer(buf):
            s = match.group().decode('ascii')
            yield StringItem(va + match.start(), len(s), _Strings.C, s)

    def parse_C_16_strings(self, va, buf):
        reg = b"((?:[%s]\x00){%d,})" % (_Strings.ASCII_BYTE, self.minlen)
        uni_re = re.compile(reg)
        for match in uni_re.finditer(buf):
            try:
                s = match.group().decode('utf-16')
            except UnicodeDecodeError:
                continue
            else:
                yield StringItem(va + match.start(), len(s), _Strings.C_16, s)

    def parse_C_32_strings(self, va, buf):
        reg = b"((?:[%s]\x00\x00\x00){%d,})" % (_Strings.ASCII_BYTE, self.minlen)
        uni_re = re.compile(reg)
        for match in uni_re.finditer(buf):
            try:
                s = match.group().decode('utf-32')
            except UnicodeDecodeError:
                continue
            else:
                yield StringItem(va + match.start(), len(s), _Strings.C_32, s)

    def parse_PASCAL_strings(self, va, buf):
        raise NotImplementedError('parse PASCAL strings')

    def parse_PASCAL_16_strings(self, va, buf):
        raise NotImplementedError('parse PASCAL_16 strings')

    def parse_LEN2_strings(self, va, buf):
        raise NotImplementedError('parse LEN2 strings')

    def parse_LEN2_16_strings(self, va, buf):
        raise NotImplementedError('parse LEN2_16 strings')

    def parse_LEN4_strings(self, va, buf):
        raise NotImplementedError('parse LEN4 strings')

    def parse_LEN4_16_strings(self, va, buf):
        raise NotImplementedError('parse LEN4_16 strings')

    def refresh(self):
        ret = []
        for seg in self.api.idautils.Segments():
            buf = self.get_seg_data(seg)

            for parser in (self.parse_C_strings,
                           self.parse_C_16_strings,
                           self.parse_C_32_strings,
                           self.parse_PASCAL_strings,
                           self.parse_PASCAL_16_strings,
                           self.parse_LEN2_strings,
                           self.parse_LEN2_16_strings,
                           self.parse_LEN4_strings,
                           self.parse_LEN4_16_strings):
                try:
                    ret.extend(list(parser(seg, buf)))
                except NotImplementedError as e:
                    logger.warning('warning: %s', e)
        self.cache = ret[:]
        return ret

    def setup(self,
              strtypes=[0],
              minlen=5,
              only_7bit=True,
              ignore_instructions=False,
              display_only_existing_strings=False):
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

    def Functions(self):
        ret = []
        for ea, func in idb.analysis.Functions(self.idb).functions.items():
            # we won't report chunks
            if is_flag_set(func.flags, func.FUNC_TAIL):
                continue
            ret.append(func.startEA)
        return list(sorted(ret))

    def CodeRefsTo(self, ea, flow):
        if flow:
            flags = self.api.idc.GetFlags(ea)
            if flags is not None and self.api.ida_bytes.is_flow(flags):
                # prev instruction fell through to this insn
                yield self.api.idc.PrevHead(ea)

        # get all the code xrefs to this instruction.
        # a code xref is like a fallthrough or jump, not like a call.
        for xref in idb.analysis.get_crefs_to(self.idb, ea,
                                              types=[idaapi.fl_JN, idaapi.fl_JF, idaapi.fl_F]):
            yield xref.src

    def CodeRefsFrom(self, ea, flow):
        if flow:
            nextea = self.api.idc.NextHead(ea)
            nextflags = self.api.idc.GetFlags(nextea)
            if self.api.ida_bytes.is_flow(nextflags):
                # instruction falls through to next insn
                yield nextea

        # get all the code xrefs from this instruction.
        # a code xref is like a fallthrough or jump, not like a call.
        for xref in idb.analysis.get_crefs_from(self.idb, ea,
                                                types=[idaapi.fl_JN, idaapi.fl_JF, idaapi.fl_F]):
            yield xref.dst

    def Strings(self, default_setup=False):
        return self.strings


class ida_entry:
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
    def __init__(self, db, api):
        self.idb = db
        self.api = api

    def get_name(self, ea):
        flags = self.api.ida_bytes.get_flags(ea)
        if not self.api.ida_bytes.has_name(flags):
            return ''

        try:
            nn = self.api.ida_netnode.netnode(ea)
            return nn.name()
        except KeyError:
            return ''


class IDAPython:
    def __init__(self, db, ScreenEA=None):
        self.idb = db
        self.ScreenEA = ScreenEA

        self.idc = idc(db, self)
        self.idaapi = idaapi(db, self)
        self.idautils = idautils(db, self)
        self.ida_funcs = ida_funcs(db, self)
        self.ida_bytes = ida_bytes(db, self)
        self.ida_netnode = ida_netnode(db, self)
        self.ida_nalt = ida_nalt(db, self)
        self.ida_entry = ida_entry(db, self)
        self.ida_name = ida_name(db, self)
