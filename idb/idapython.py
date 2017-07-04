class FLAGS:
    # instruction/data operands
    # via: https://www.hex-rays.com/products/ida/support/sdkdoc/group___f_f__op.html

    # outer offset base (combined with operand number). More...
    OPND_OUTER = 0x80

    # mask for operand number
    OPND_MASK = 0x07

    # all operands
    OPND_ALL = OPND_MASK

    # byte states bits
    # via: https://www.hex-rays.com/products/ida/support/sdkdoc/group___f_f__statebits.html

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
    # via: https://www.hex-rays.com/products/ida/support/sdkdoc/group___f_f__statespecb.html

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
    # via: https://www.hex-rays.com/products/ida/support/sdkdoc/group___f_f__opbits.html

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
    # via: https://www.hex-rays.com/products/ida/support/sdkdoc/group___f_f__databits.html

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
    # via: https://www.hex-rays.com/products/ida/support/sdkdoc/group___f_f__.html

    # Mask for byte value.
    MS_VAL = 0x000000FF

    # Byte has value?
    FF_IVL = 0x00000100


class AFLAGS:
    # additional flags
    # via: https://www.hex-rays.com/products/ida/support/sdkdoc/group___a_f_l__.html

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
    def __init__(self, db):
        self.idb = db

    def netnode(self, *args, **kwargs):
        return idb.netnode.Netnode(self, *args, **kwargs)


class idc:
    def __init__(self, db):
        self.idb = db

    def SegStart(self, ea):
        # TODO: i think this should use '$ fileregions'
        return self.idb.id1.get_segment(ea).bounds.start

    def SegEnd(self, ea):
        # TODO: i think this should use '$ fileregions'
        return self.idb.id1.get_segment(ea).bounds.end

    def FirstSeg(self):
        # TODO: i think this should use '$ fileregions'
        return self.idb.id1.segments[0].bounds.start

    def NextSeg(self, ea):
        # TODO: i think this should use '$ fileregions'
        return self.idb.id1.get_next_segment(ea).bounds.start

    def GetFlags(self, ea):
        return self.idb.id1.get_flags(ea)

    def IdbByte(self, ea):
        flags = self.GetFlags(ea)
        if self.hasValue(flags):
            return flags & FLAGS.MS_VAL
        else:
            raise KeyError(ea)

    def Head(self, ea):
        flags = self.GetFlags(ea)
        while not ida_bytes.isHead(flags):
            ea -= 1
            # TODO: handle Index/KeyError here when we overrun a segment
            flags = self.GetFlags(ea)
        return ea

    def ItemSize(self, ea):
        oea = ea
        flags = self.GetFlags(ea)
        if not ida_bytes.isHead(flags):
            raise ValueError('ItemSize must only be called on a head address.')

        ea += 1
        flags = self.GetFlags(ea)
        while not ida_bytes.isHead(flags):
            ea += 1
            # TODO: handle Index/KeyError here when we overrun a segment
            flags = self.GetFlags(ea)
        return ea - oea

    def NextHead(self, ea):
        ea += 1
        flags = self.GetFlags(ea)
        while not ida_bytes.isHead(flags):
            ea += 1
            # TODO: handle Index/KeyError here when we overrun a segment
            flags = self.GetFlags(ea)
        return ea

    def PrevHead(self, ea):
        ea = self.Head(ea)
        ea -= 1
        return self.Head(ea)

    def GetManyBytes(self, ea, size, use_dbg= False):
        '''
        Raises:
          IndexError: if the range extends beyond a segment.
          KeyError: if a byte is not defined.
        '''
        if use_dbg:
            raise NotImplementedError()

        if self.SegStart(ea) != self.SegStart(ea + size):
            raise IndexError((ea, ea+size))

        ret = []
        for i in range(ea, ea + size):
            ret.append(self.IdbByte(i))
        return bytes(ret)

    def hasValue(self, flags):
        return flags & FLAGS.FF_IVL > 0

    def isDefArg0(self, flags):
        return flags & FLAGS.MS_0TYPE > 0

    def isDefArg1(self, flags):
        return flags & FLAGS.MS_1TYPE > 0

    def isOff0(self, flags):
        return flags & FLAGS.MS_0TYPE == FLAGS.FF_0CUST

    def isOff1(self, flags):
        return flags & FLAGS.MS_1TYPE == FLAGS.FF_1CUST

    def isChar0(self, flags):
        return flags & FLAGS.MS_0TYPE == FLAGS.FF_0CHAR

    def isChar1(self, flags):
        return flags & FLAGS.MS_1TYPE == FLAGS.FF_1CHAR

    def isSeg0(self, flags):
        return flags & FLAGS.MS_0TYPE == FLAGS.FF_0SEG

    def isSeg1(self, flags):
        return flags & FLAGS.MS_1TYPE == FLAGS.FF_1SEG

    def isEnum0(self, flags):
        return flags & FLAGS.MS_0TYPE == FLAGS.FF_0ENUM

    def isEnum1(self, flags):
        return flags & FLAGS.MS_1TYPE == FLAGS.FF_1ENUM

    def isStroff0(self, flags):
        return flags & FLAGS.MS_0TYPE == FLAGS.FF_0STRO

    def isStroff1(self, flags):
        return flags & FLAGS.MS_1TYPE == FLAGS.FF_1STRO

    def isStkvar0(self, flags):
        return flags & FLAGS.MS_0TYPE == FLAGS.FF_0STK

    def isStkvar1(self, flags):
        return flags & FLAGS.MS_1TYPE == FLAGS.FF_1STK

    def isFloat0(self, flags):
        return flags & FLAGS.MS_0TYPE == FLAGS.FF_0FLT

    def isFloat1(self, flags):
        return flags & FLAGS.MS_1TYPE == FLAGS.FF_1FLT

    def isCustFmt0(self, flags):
        return flags & FLAGS.MS_0TYPE == FLAGS.FF_0CUST

    def isCustFmt1(self, flags):
        return flags & FLAGS.MS_1TYPE == FLAGS.FF_1CUST

    def isNum0(self, flags):
        t = flags & FLAGS.MS_0TYPE
        return t == FLAGS.FF_0NUMB or \
               t == FLAGS.FF_0NUMO or \
               t == FLAGS.FF_0NUMD or \
               t == FLAGS.FF_0NUMH

    def isNum1(self, flags):
        t = flags & FLAGS.MS_1TYPE
        return t == FLAGS.FF_1NUMB or \
               t == FLAGS.FF_1NUMO or \
               t == FLAGS.FF_1NUMD or \
               t == FLAGS.FF_1NUMH

    def get_optype_flags0(self, flags):
        return flags & FLAGS.MS_0TYPE

    def get_optype_flags1(self, flags):
        return flags & FLAGS.MS_1TYPE


class ida_bytes:
    def __init__(self, db):
        self.idb = db

    @staticmethod
    def isFunc(flags):
        return flags & FLAGS.MS_CODE == FLAGS.FF_FUNC

    @staticmethod
    def isImmd(flags):
        return flags & FLAGS.MS_CODE == FLAGS.FF_IMMD

    @staticmethod
    def isCode(flags):
        return flags & FLAGS.MS_CLS == FLAGS.FF_CODE

    @staticmethod
    def isData(flags):
        return flags & FLAGS.MS_CLS == FLAGS.FF_DATA

    @staticmethod
    def isTail(flags):
        return flags & FLAGS.MS_CLS == FLAGS.FF_TAIL

    @staticmethod
    def isNotTail(flags):
        return not ida_bytes.isTail(flags)

    @staticmethod
    def isUnknown(flags):
        return flags & FLAGS.MS_CLS == FLAGS.FF_UNK

    @staticmethod
    def isHead(flags):
        return ida_bytes.isCode(flags) or ida_bytes.isData(flags)

    @staticmethod
    def isFlow(flags):
        return flags & FLAGS.MS_COMM & FLAGS.FF_FLOW > 0

    @staticmethod
    def isVar(flags):
        return flags & FLAGS.MS_COMM & FLAGS.FF_VAR > 0

    @staticmethod
    def hasExtra(flags):
        return flags & FLAGS.MS_COMM & FLAGS.FF_LINE > 0

    @staticmethod
    def has_cmt(flags):
        return flags & FLAGS.MS_COMM & FLAGS.FF_COMM > 0

    @staticmethod
    def hasRef(flags):
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
    def isByte(flags):
        return flags & FLAGS.DT_TYPE == FLAGS.FF_BYTE

    @staticmethod
    def isWord(flags):
       return flags & FLAGS.DT_TYPE == FLAGS.FF_WORD

    @staticmethod
    def isDwrd(flags):
       return flags & FLAGS.DT_TYPE == FLAGS.FF_DWRD

    @staticmethod
    def isQwrd(flags):
       return flags & FLAGS.DT_TYPE == FLAGS.FF_QWRD

    @staticmethod
    def isOwrd(flags):
       return flags & FLAGS.DT_TYPE == FLAGS.FF_OWRD

    @staticmethod
    def isYwrd(flags):
       return flags & FLAGS.DT_TYPE == FLAGS.FF_YWRD

    @staticmethod
    def isTbyt(flags):
       return flags & FLAGS.DT_TYPE == FLAGS.FF_TBYT

    @staticmethod
    def isFloat(flags):
       return flags & FLAGS.DT_TYPE == FLAGS.FF_FLOAT

    @staticmethod
    def isDouble(flags):
       return flags & FLAGS.DT_TYPE == FLAGS.FF_DOUBLE

    @staticmethod
    def isPackReal(flags):
       return flags & FLAGS.DT_TYPE == FLAGS.FF_PACKREAL

    @staticmethod
    def isASCII(flags):
       return flags & FLAGS.DT_TYPE == FLAGS.FF_ASCI

    @staticmethod
    def isStruct(flags):
       return flags & FLAGS.DT_TYPE == FLAGS.FF_STRU

    @staticmethod
    def isAlign(flags):
       return flags & FLAGS.DT_TYPE == FLAGS.FF_ALIGN

    @staticmethod
    def is3byte(flags):
       return flags & FLAGS.DT_TYPE == FLAGS.FF_3BYTE

    @staticmethod
    def isCustom(flags):
       return flags & FLAGS.DT_TYPE == FLAGS.FF_CUSTOM


class IDAPython:
    def __init__(self, db):
        self.idb = db
        self.idc = idc(db)
        self.ida_bytes = ida_bytes(db)
        self.ida_netnode = ida_netnode(db)
