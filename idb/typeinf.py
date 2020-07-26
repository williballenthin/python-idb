import zlib
from abc import ABCMeta, abstractmethod

from cached_property import cached_property
from vstruct import VStruct
from vstruct.primitives import *

# migrate from ida sdk and https://github.com/aerosoul94/tilutil/blob/c149641168/til/datatypes.py

RESERVED_BYTE = 0xFF

TYPE_BASE_MASK = 0x0F
TYPE_FLAGS_MASK = 0x30
TYPE_MODIF_MASK = 0xC0

TYPE_FULL_MASK = TYPE_BASE_MASK | TYPE_FLAGS_MASK

BT_UNK = 0x00
BT_VOID = 0x01
BTMT_SIZE0 = 0x00
BTMT_SIZE12 = 0x10
BTMT_SIZE48 = 0x20
BTMT_SIZE128 = 0x30

BT_INT8 = 0x02
BT_INT16 = 0x03
BT_INT32 = 0x04
BT_INT64 = 0x05
BT_INT128 = 0x06  # __int128 (for alpha & future use)
BT_INT = 0x07  # natural int. (size provided by idp module)
BTMT_UNKSIGN = 0x00
BTMT_SIGNED = 0x10
BTMT_USIGNED = 0x20
BTMT_UNSIGNED = BTMT_USIGNED
BTMT_CHAR = 0x30

BT_BOOL = 0x08
BTMT_DEFBOOL = 0x00
BTMT_BOOL1 = 0x10
BTMT_BOOL2 = 0x20
BTMT_BOOL4 = 0x30

BT_FLOAT = 0x09
BTMT_FLOAT = 0x00
BTMT_DOUBLE = 0x10
BTMT_LNGDBL = 0x20
BTMT_SPECFLT = 0x30

_BT_LAST_BASIC = BT_FLOAT

BT_PTR = 0x0A
BTMT_DEFPTR = 0x00
BTMT_NEAR = 0x10
BTMT_FAR = 0x20
BTMT_CLOSURE = 0x30

BT_ARRAY = 0x0B
BTMT_NONBASED = 0x10
BTMT_ARRESERV = 0x20

BT_FUNC = 0x0C
BTMT_DEFCALL = 0x00
BTMT_NEARCALL = 0x10
BTMT_FARCALL = 0x20
BTMT_INTCALL = 0x30

BT_COMPLEX = 0x0D
BTMT_STRUCT = 0x00
BTMT_UNION = 0x10
BTMT_ENUM = 0x20
BTMT_TYPEDEF = 0x30

BT_BITFIELD = 0x0E
BTMT_BFLDI8 = 0x00
BTMT_BFLDI16 = 0x10
BTMT_BFLDI32 = 0x20
BTMT_BFLDI64 = 0x30

BT_RESERVED = 0x0F

BTM_CONST = 0x40
BTM_VOLATILE = 0x80

BTE_SIZE_MASK = 0x07
# storage size.
#   - if == 0 ph.get_default_enum_size()
#   - else 1 << (n -1) = 1,2,4...64

BTE_RESERVED = 0x08
# must be 0, in order to distinguish
# from a tah-byte

BTE_BITFIELD = 0x10
# 'subarrays'. In this case ANY record
# has the following format:
#   - 'de' mask (has name)
#   - 'dt' cnt
#   - cnt records of 'de' values
#      (cnt CAN be 0)
# \note delta for ALL subsegment is ONE
BTE_OUT_MASK = 0x60  # output style mask
BTE_HEX = 0x00  # hex
BTE_CHAR = 0x20  # char or hex
BTE_SDEC = 0x40  # signed decimal
BTE_UDEC = 0x60  # unsigned decimal
BTE_ALWAYS = 0x80  # this bit MUST be present

BT_SEGREG = BT_INT | BTMT_CHAR  # segment register

BT_UNK_BYTE = BT_VOID | BTMT_SIZE12  # 1 byte
BT_UNK_WORD = BT_UNK | BTMT_SIZE12  # 2 bytes
BT_UNK_DWORD = BT_VOID | BTMT_SIZE48  # 4 bytes
BT_UNK_QWORD = BT_UNK | BTMT_SIZE48  # 8 bytes
BT_UNK_OWORD = BT_VOID | BTMT_SIZE128  # 16 bytes
BT_UNKNOWN = BT_UNK | BTMT_SIZE128  # unknown size - for parameters

BTF_BYTE = BT_UNK_BYTE  # byte
BTF_UNK = BT_UNKNOWN  # unknown
BTF_VOID = BT_VOID | BTMT_SIZE0  # void

BTF_INT8 = BT_INT8 | BTMT_SIGNED  # signed byte
BTF_CHAR = BT_INT8 | BTMT_CHAR  # signed char
BTF_UCHAR = BT_INT8 | BTMT_USIGNED  # unsigned char
BTF_UINT8 = BT_INT8 | BTMT_USIGNED  # unsigned byte

BTF_INT16 = BT_INT16 | BTMT_SIGNED  # signed short
BTF_UINT16 = BT_INT16 | BTMT_USIGNED  # unsigned short

BTF_INT32 = BT_INT32 | BTMT_SIGNED  # signed int
BTF_UINT32 = BT_INT32 | BTMT_USIGNED  # unsigned int

BTF_INT64 = BT_INT64 | BTMT_SIGNED  # signed long
BTF_UINT64 = BT_INT64 | BTMT_USIGNED  # unsigned long

BTF_INT128 = BT_INT128 | BTMT_SIGNED  # signed 128-bit value
BTF_UINT128 = BT_INT128 | BTMT_USIGNED  # unsigned 128-bit value

BTF_INT = BT_INT | BTMT_UNKSIGN  # int, unknown signedness
BTF_UINT = BT_INT | BTMT_USIGNED  # unsigned int
BTF_SINT = BT_INT | BTMT_SIGNED  # singed int

BTF_BOOL = BT_BOOL  # boolean

BTF_FLOAT = BT_FLOAT | BTMT_FLOAT  # float
BTF_DOUBLE = BT_FLOAT | BTMT_DOUBLE  # double
BTF_LDOUBLE = BT_FLOAT | BTMT_LNGDBL  # long double
BTF_TBYTE = BT_FLOAT | BTMT_SPECFLT  # see ::BTMT_SPECFLT

BTF_STRUCT = BT_COMPLEX | BTMT_STRUCT  # struct
BTF_UNION = BT_COMPLEX | BTMT_UNION  # union
BTF_ENUM = BT_COMPLEX | BTMT_ENUM  # enum
BTF_TYPEDEF = BT_COMPLEX | BTMT_TYPEDEF  # typedef

TAH_BYTE = 0xFE
FAH_BYTE = 0xFF

TAH_HASATTRS = 0x0010

CM_MASK = 0x03
CM_UNKNOWN = 0x00
CM_N8_F16 = 0x01
CM_N64 = 0x01
CM_N16_F32 = 0x02
CM_N32_F48 = 0x03

CM_M_MASK = 0x0C
CM_M_MN = 0x00
CM_M_FF = 0x04
CM_M_NF = 0x08
CM_M_FN = 0x0C

CM_CC_MASK = 0xF0
CM_CC_INVALID = 0x00
CM_CC_UNKNOWN = 0x10
CM_CC_VOIDARG = 0x20

CM_CC_CDECL = 0x30
CM_CC_ELLIPSIS = 0x40
CM_CC_STDCALL = 0x50
CM_CC_PASCAL = 0x60
CM_CC_FASTCALL = 0x70
CM_CC_THISCALL = 0x80
CM_CC_MANUAL = 0x90
CM_CC_SPOILED = 0xA0

CM_CC_RESERVE4 = 0xB0
CM_CC_RESERVE3 = 0xC0
CM_CC_SPECIALE = 0xD0
CM_CC_SPECIALP = 0xE0
CM_CC_SPECIAL = 0xF0


# convenience functions:


def is_type_const(t):
    return (t & BTM_CONST) != 0  # See ::BTM_CONST


def is_type_volatile(t):
    return (t & BTM_VOLATILE) != 0  # See ::BTM_VOLATILE


def get_base_type(t):
    return t & TYPE_BASE_MASK  # Get get basic type bits (::TYPE_BASE_MASK)


def get_type_flags(t):
    return t & TYPE_FLAGS_MASK  # Get type flags (::TYPE_FLAGS_MASK)


def get_full_type(t):
    return t & TYPE_FULL_MASK  # Get basic type bits + type flags (::TYPE_FULL_MASK)


# Is the type_t the last byte of type declaration?
# (there are no additional bytes after a basic type, see ::_BT_LAST_BASIC)
def is_typeid_last(t):
    return get_base_type(t) <= _BT_LAST_BASIC


# Identifies an unknown or void type with a known size (see \ref tf_unk)
def is_type_partial(t):
    return (get_base_type(t) <= BT_VOID) and get_type_flags(t) != 0


def is_type_void(t):
    return get_full_type(t) == BTF_VOID  # < See ::BTF_VOID


def is_type_unknown(t):
    return get_full_type(t) == BT_UNKNOWN  # < See ::BT_UNKNOWN


def is_type_ptr(t):
    return get_base_type(t) == BT_PTR  # < See ::BT_PTR


def is_type_complex(t):
    return get_base_type(t) == BT_COMPLEX  # < See ::BT_COMPLEX


def is_type_func(t):
    return get_base_type(t) == BT_FUNC  # < See ::BT_FUNC


def is_type_array(t):
    return get_base_type(t) == BT_ARRAY  # < See ::BT_ARRAY


def is_type_typedef(t):
    return get_full_type(t) == BTF_TYPEDEF  # < See ::BTF_TYPEDEF


def is_type_sue(t):
    return is_type_complex(t) and not is_type_typedef(
        t
    )  # < Is the type a struct/union/enum?


def is_type_struct(t):
    return get_full_type(t) == BTF_STRUCT  # < See ::BTF_STRUCT


def is_type_union(t):
    return get_full_type(t) == BTF_UNION  # < See ::BTF_UNION


def is_type_struni(t):
    return is_type_struct(t) or is_type_union(t)  # < Is the type a struct or union?


def is_type_enum(t):
    return get_full_type(t) == BTF_ENUM  # < See ::BTF_ENUM


def is_type_bitfld(t):
    return get_base_type(t) == BT_BITFIELD  # < See ::BT_BITFIELD

    # Does the type_t specify one of the basic types in \ref tf_int?


def is_type_int(bt):
    bt = get_base_type(bt)
    return BT_INT8 <= bt <= BT_INT


# Does the type specify a 128-bit value? (signed or unsigned, see \ref tf_int)
def is_type_int128(t):
    return get_full_type(t) == (BT_INT128 | BTMT_UNKSIGN) or get_full_type(t) == (
        BT_INT128 | BTMT_SIGNED
    )


# Does the type specify a 64-bit value? (signed or unsigned, see \ref tf_int)
def is_type_int64(t):
    return get_full_type(t) == (BT_INT64 | BTMT_UNKSIGN) or get_full_type(t) == (
        BT_INT64 | BTMT_SIGNED
    )


# Does the type specify a 32-bit value? (signed or unsigned, see \ref tf_int)
def is_type_int32(t):
    return get_full_type(t) == (BT_INT32 | BTMT_UNKSIGN) or get_full_type(t) == (
        BT_INT32 | BTMT_SIGNED
    )


# Does the type specify a 16-bit value? (signed or unsigned, see \ref tf_int)
def is_type_int16(t):
    return get_full_type(t) == (BT_INT16 | BTMT_UNKSIGN) or get_full_type(t) == (
        BT_INT16 | BTMT_SIGNED
    )


# Does the type specify a char value? (signed or unsigned, see \ref tf_int)
def is_type_char(t):
    return get_full_type(t) == (BT_INT8 | BTMT_CHAR) or get_full_type(t) == (
        BT_INT8 | BTMT_SIGNED
    )


# Is the type a pointer, array, or function type?
def is_type_paf(t):
    t = get_base_type(t)
    return BT_PTR <= t <= BT_FUNC


# Is the type a pointer or array type?
def is_type_ptr_or_array(t):
    t = get_base_type(t)
    return t == BT_PTR or t == BT_ARRAY


# Is the type a floating point type?
def is_type_floating(t):
    return get_base_type(t) == BT_FLOAT  # any floating type


# Is the type an integral type (char/short/int/long/bool)?
def is_type_integral(t):
    return get_full_type(t) > BT_VOID and get_base_type(t) <= BT_BOOL


# Is the type an extended integral type? (integral or enum)
def is_type_ext_integral(t):
    return is_type_integral(t) or is_type_enum(t)


# Is the type an arithmetic type? (floating or integral)
def is_type_arithmetic(t):
    return get_full_type(t) > BT_VOID and get_base_type(t) <= BT_FLOAT


# Is the type an extended arithmetic type? (arithmetic or enum)
def is_type_ext_arithmetic(t):
    return is_type_arithmetic(t) or is_type_enum(t)


def is_type_uint(t):
    return get_full_type(t) == BTF_UINT  # < See ::BTF_UINT


def is_type_uchar(t):
    return get_full_type(t) == BTF_UCHAR  # < See ::BTF_UCHAR


def is_type_uint16(t):
    return get_full_type(t) == BTF_UINT16  # < See ::BTF_UINT16


def is_type_uint32(t):
    return get_full_type(t) == BTF_UINT32  # < See ::BTF_UINT32


def is_type_uint64(t):
    return get_full_type(t) == BTF_UINT64  # < See ::BTF_UINT64


def is_type_uint128(t):
    return get_full_type(t) == BTF_UINT128  # < See ::BTF_UINT128


def is_type_ldouble(t):
    return get_full_type(t) == BTF_LDOUBLE  # < See ::BTF_LDOUBLE


def is_type_double(t):
    return get_full_type(t) == BTF_DOUBLE  # < See ::BTF_DOUBLE


def is_type_float(t):
    return get_full_type(t) == BTF_FLOAT  # < See ::BTF_FLOAT


def is_type_bool(t):
    return get_base_type(t) == BT_BOOL  # < See ::BTF_BOOL


def is_tah_byte(t):
    return t == TAH_BYTE


# Identify an sdacl byte.
# The first sdacl byte has the following format: 11xx000x.
# The sdacl bytes are appended to udt fields. They indicate the start of type
# attributes (as the tah-bytes do). The sdacl bytes are used in the udt
# headers instead of the tah-byte. This is done for compatibility with old
# databases, they were already using sdacl bytes in udt headers and as udt
# field postfixes.
# (see "sdacl-typeattrs" in the type bit definitions)


def is_sdacl_byte(t):
    return ((t & ~TYPE_FLAGS_MASK) ^ TYPE_MODIF_MASK) <= BT_VOID


def is_type_closure(t):
    return get_type_flags(t) == BTMT_CLOSURE


class TypeString:
    def __init__(self, buf, pos=0, parent=None):
        self.buf = buf
        self.pos = pos
        self.parent = parent

    def seek(self, n):
        self.pos += n
        if self.parent is not None:
            self.parent.seek(n)
        if self.pos > len(self.buf) or self.pos < 0:
            raise OverflowError

    def read(self, n):
        val = self.buf[self.pos : self.pos + n]
        self.seek(n)
        return val

    def unpack(self, unpack_fn, size=0):
        ret = unpack_fn(self.buf[self.pos :])
        if isinstance(ret, tuple):
            ret, _size = ret
            self.seek(_size if size == 0 else size)
        else:
            self.seek(size)
        return ret

    def peek_u8(self):
        return struct.unpack("<B", self.buf[self.pos : self.pos + 1])[0]

    def peek_u16(self):
        return struct.unpack("<H", self.buf[self.pos : self.pos + 2])[0]

    def u8(self):
        return struct.unpack("<B", self.read(1))[0]

    def u16(self):
        return struct.unpack("<H", self.read(2))[0]

    def dt(self):
        val = self.u8()
        if val & 0x80:
            val = val & 0x7F | self.u8() << 7
        return val - 1

    def de(self):
        val = 0
        while True:
            hi = val << 6
            b = self.u8()
            sign = b & 0x80
            if not sign:
                lo = b & 0x3F
                val = lo | hi
                break
            else:
                lo = 2 * hi
                hi = b & 0x7F
                val = lo | hi
        n = val & 0xFFFFFFFF
        return n | (-(n & 0x80000000))

    def da(self):
        # TODO: da
        raise Exception()
        # return 0, 0, 0

    def complex_n(self):
        n = self.dt()
        if n == 0x7FFE:
            n = self.de()
        return n

    def pstring(self):
        length = self.dt()
        buf = self.read(length)
        return buf.decode("ascii")

    def pbytes(self):
        length = self.dt()
        buf = self.read(length)
        return buf

    def type_attr(self):
        val = 0
        tah = self.u8()
        tmp = ((tah & 1) | ((tah >> 3) & 6)) + 1
        if is_tah_byte(tah) or tmp == 8:
            if tmp == 8:
                val = tmp
            shift = 0
            while True:
                next_byte = self.u8()
                if next_byte == 0:
                    raise ValueError("type_attr(): failed to parse")
                val |= (next_byte & 0x7F) << shift
                if next_byte & 0x80 == 0:
                    break
                shift += 7
        unk = []
        if val & TAH_HASATTRS:
            val = self.dt()
            for _ in range(val):
                string = self.pstring()
                self.seek(self.dt())
                unk.append(string)
        return val

    def tah_attr(self):
        if self.has_next() and is_tah_byte(self.peek_u8()):
            return self.type_attr()

    def sdacl_attr(self):
        if self.has_next() and is_sdacl_byte(self.peek_u8()):
            return self.type_attr()

    def get(self):
        return TypeString(self.rest())

    def ref(self):
        return TypeString(self.rest(), parent=self)

    def rest(self):
        return self.buf[self.pos :]

    def has_next(self):
        return self.pos < len(self.buf)


class TypeData:
    __metaclass__ = ABCMeta

    @abstractmethod
    def deserialize(self, til, type_string, fields, fieldcmts):
        pass


class TInfo:
    def __init__(self, base_type=BT_UNK, type_details=None):
        self.base_type = base_type
        self.flags = 0
        self.type_details = type_details

    def get_size(self):
        # TODO:
        raise NotImplementedError()

    def get_type_name(self):
        # TODO:
        raise NotImplementedError()


def create_tinfo(til, type_info, fields=None, fieldcmts=None):
    type_string = (
        type_info if isinstance(type_info, TypeString) else TypeString(type_info)
    )
    typ = type_string.peek_u8()
    if is_typeid_last(typ) or get_base_type(typ) == BT_RESERVED:
        type_string.seek(1)
        tinfo = TInfo(typ)
    else:
        type_data = None
        if is_type_ptr(typ):
            type_data = PointerTypeData()
        elif is_type_func(typ):
            type_data = FuncTypeData()
        elif is_type_array(typ):
            type_data = ArrayTypeData()
        elif is_type_typedef(typ):
            type_data = TypedefTypeData()
        elif is_type_struni(typ):
            type_data = UdtTypeData()
        elif is_type_enum(typ):
            type_data = EnumTypeData()
        elif is_type_bitfld(typ):
            type_data = BitfieldTypeData()
        tinfo = TInfo(typ, type_data.deserialize(til, type_string, fields, fieldcmts))
    return tinfo


class PointerTypeData(TypeData):
    """Representation of ptr_type_data_t"""

    def __init__(self):
        TypeData.__init__(self)
        self.obj_type = None
        self.closure = None
        self.based_ptr_size = 0
        self.taptr_bits = 0

    def deserialize(self, til, type_string, fields, fieldcmts):
        typ = type_string.u8()
        if is_type_closure(typ):
            ptr_size = type_string.u8()
            if ptr_size == RESERVED_BYTE:
                self.closure = create_tinfo(til, type_string.ref())
            else:
                self.based_ptr_size = type_string.u8()
        self.taptr_bits = type_string.tah_attr()
        self.obj_type = create_tinfo(til, type_string.ref(), fields, fieldcmts)
        return self


class ArrayTypeData(TypeData):
    def __init__(self):
        TypeData.__init__(self)
        self.elem_type = None  # tinfo_t
        self.base = None
        self.n_elems = 0

    def deserialize(self, til, type_string, fields, fieldcmts):
        typ = type_string.u8()
        if get_type_flags(typ) & BTMT_NONBASED:
            self.base = 0
            self.n_elems = type_string.dt()
        else:
            self.n_elems, self.base, _ = type_string.da()
            return self
        self.elem_type = create_tinfo(til, type_string.get(), fields, fieldcmts)
        return self


class FuncArg:
    def __init__(self):
        self.argloc = None  # argloc_t
        self.name = ""
        self.cmt = ""
        self.type = None  # tinfo_t
        self.flags = 0


class FuncTypeData(TypeData):
    def __init__(self):
        TypeData.__init__(self)
        self.args = []
        self.flags = 0
        self.rettype = None  # tinfo_t
        self.retloc = None  # argloc_t
        self.stkargs = None  # uval_t
        self.spoiled = None  # reginfovec_t
        self.cc = 0

    def deserialize(self, til, ts, fields, fieldcmts):
        typ = ts.u8()
        cm = ts.u8()
        if (cm & CM_CC_MASK) == CM_CC_SPOILED:
            num_of_spoiled_reg = cm & 0x0F  # low nibble is count
            if num_of_spoiled_reg == 15:
                bfa = ts.u8()  # function attribute byte (see BFA_*)
            else:  # spoiled_reg_info[num_of_spoiled_regs] see extract_spoiledreg
                pass
            cm = ts.u8()  # present real cm
        self.cc = cm & 0xF0
        self.flags |= 4 * get_type_flags(typ)
        if ts.peek_u8() == TAH_BYTE:
            ts.type_attr()
        self.rettype = create_tinfo(til, ts.ref(), fields, fieldcmts)
        if (
            self.cc == CM_CC_SPECIALE
            or self.cc == CM_CC_SPECIALP
            or self.cc == CM_CC_SPECIAL
        ):
            if (self.rettype.base_type & TYPE_FULL_MASK) == 1:
                self.retloc = self.deserialize_argloc(ts.get())

        # args
        if self.cc == CM_CC_VOIDARG:
            return self
        n = ts.dt()
        if n > 256:
            raise ValueError("invalid arg count!")
        for n in range(n):
            arg = FuncArg()
            if fields is not None:
                if n < len(fields):
                    arg.name = fields[n]
            if ts.peek_u8() == FAH_BYTE:
                ts.seek(1)
                arg.flags = ts.de()
            arg.type = create_tinfo(til, ts.ref(), fields, fieldcmts)
            if (
                self.cc == CM_CC_SPECIALE
                or self.cc == CM_CC_SPECIALP
                or self.cc == CM_CC_SPECIAL
            ):
                arg.argloc = self.deserialize_argloc(ts.get())
            self.args.append(arg)
        return self

    def deserialize_argloc(self, type_string):
        # TODO: deserialize_argloc
        raise NotImplementedError("deserialize_argloc() not implemented.")


class UdtMember:
    def __init__(self):
        self.offset = 0
        self.size = 0
        self.name = None  # qstring
        self.cmt = None  # qstring
        self.type = None  # tinfo_t
        self.effalign = 0
        self.tafld_bits = 0
        self.fda = 0


class UdtTypeData(TypeData):
    """An object to represent struct or union types"""

    def __init__(self):
        TypeData.__init__(self)
        self.members = []
        # total structure size in bytes
        self.total_size = 0
        # unpadded structure size in bytes
        self.unpadded_size = 0
        # effective structure alignment (in bytes)
        self.effalign = 0
        # TA... and TAUDT... bits.
        self.taudt_bits = 0
        # declared structure alignment (shift amount+1). 0 - unspecified
        self.sda = 0
        # pragma pack() alignment (shift amount)
        self.pack = 0
        self.is_union = False

    def deserialize(self, til, ts, fields, fieldcmts):
        typ = ts.u8()
        self.is_union = is_type_union(typ)
        n = ts.complex_n()
        if n == 0 and len(ts.rest()) >= 2 and ts.peek_u16() != 33009:
            buf = ts.pbytes()
            if buf.find(b"#") == 0:
                ordinal = TypeString(buf[1:]).de()
                _def = til.types.defs[ordinal - 1]
                if "type" in _def:
                    _type = _def.type
                else:
                    # may ref self
                    _type = ordinal
            else:
                name = buf.decode("ascii")
                _def = list(filter(lambda x: x.name == name, til.types.defs))
                if len(_def) > 0 and "type" in _def:
                    _type = _def[0].type
                else:
                    _type = name
            return _type
        else:
            alpow = n & 7
            member_cnt = n >> 3
            self.pack = alpow
            self.sda = ts.sdacl_attr()
            for i in range(member_cnt):
                member = UdtMember()
                member.type = create_tinfo(til, ts.ref(), fields, fieldcmts)
                if fields and len(fields) > i:
                    member.name = fields[i]
                self.members.append(member)
        return self


class EnumMember:
    def __init__(self, name, value=0, cmt=""):
        self.name = name  # qstring
        self.cmt = value  # qstring
        self.value = cmt


class EnumTypeData(TypeData):
    """Representation of enum_type_data_t"""

    def __init__(self):
        TypeData.__init__(self)
        self.group_sizes = []  # intvec_t
        # TAENUM_64BIT   0x0020
        #  	enum: store 64-bit values
        self.taenum_bits = 0
        self.bte = 0
        self.members = []

    def deserialize(self, til, type_string, fields, fieldcmts):
        typ = type_string.u8()
        n = type_string.complex_n()
        if n == 0:
            type_string.pstring()
            type_string.tah_attr()
        else:
            type_string.tah_attr()
            self.bte = type_string.u8()
            cur = 0
            for i in range(n):
                # TODO: subarrays
                # https://www.hex-rays.com/products/ida/support/sdkdoc/group__tf__enum.html#ga9ae7aa54dbc597ec17cbb17555306a02
                # In this case ANY record has the following format:
                #     'de' mask (has name)
                #     'dt' cnt
                #     cnt records of 'de' values (cnt CAN be 0)
                # Note
                #     delta for ALL subsegment is ONE
                if self.bte & BTE_BITFIELD:
                    # mask = type_string.de()
                    # cnt = type_string.dt()
                    # for j in range(cnt):
                    #     val = type_string.de()
                    pass
                else:
                    delta = type_string.de()
                    cur += delta
                    member = EnumMember(fields[i], value=cur)
                    self.members.append(member)
        return self


class TypedefTypeData(TypeData):
    """Representation of typedef_type_data_t"""

    def __init__(self):
        TypeData.__init__(self)
        self.til = None
        # union
        # {
        #    const char* name is_ordref=false: target type name. we do not own this pointer!
        #    uint32   ordinal is_ordref=true: type ordinal number
        # }
        self.name = None
        self.ordinal = 0
        self.is_ordref = False
        self.resolve = False

    def deserialize(self, til, type_string, fields, fieldcmts):
        self.til = til
        typ = type_string.u8()
        buf = type_string.pbytes()
        if len(buf) > 1 and buf.find(b"#") == 0:
            self.is_ordref = True
            self.ordinal = TypeString(buf[1:]).de()
        else:
            self.name = buf.decode("ascii")
        return self


class BitfieldTypeData(TypeData):
    """Representation of bitfield_type_data_t"""

    def __init__(self):
        TypeData.__init__(self)
        self.nbytes = 0
        self.width = 0
        self.is_unsigned = False

    def deserialize(self, til, type_string, fields, fieldcmts):
        typ = type_string.u8()
        dt = type_string.dt()
        self.nbytes = dt >> 1
        self.is_unsigned = bool(dt & 1)
        type_string.tah_attr()


class v_zbytes(v_zstr):
    """
    A v_zbytes placeholder class which will automatically return
    up to a null terminator bytes dynamically.
    """

    def vsGetValue(self):
        return self._vs_value[: -self._vs_align_pad]


class TILTypeInfo(VStruct):
    def __init__(self):
        VStruct.__init__(self)
        self.flags = v_uint32()
        self.name = v_zstr_utf8()
        self.ordinal = v_uint32()
        self.type_info = v_zbytes()
        self.cmt = v_zstr_utf8()
        self.fields_buf = v_zbytes()
        self.fieldcmts = v_zbytes()
        self.sclass = v_uint8()

    def pcb_flags(self):
        if self.flags >> 31:
            self.vsSetField("ordinal", v_uint64())
        if self.flags not in (0x7FFFFFFF, 0xFFFFFFFF):
            raise Exception("unsupported format {}".format(self.flags))

    def deserialize(self, til):
        _type = create_tinfo(til, self.type_info, self.fields, self.fieldcmts)
        object.__setattr__(self, "type", _type)

    @cached_property
    def fields(self):
        fields = []
        pos = 0
        while pos < len(self.fields_buf):
            length = struct.unpack("<B", self.fields_buf[pos : pos + 1])[0]
            fields.append(self.fields_buf[pos + 1 : pos + length].decode("ascii"))
            pos += length
        fields = list(filter(lambda x: x != "", fields))
        return fields


class TILBucket(VStruct):
    def __init__(self, flags):
        VStruct.__init__(self)

        self.flags = flags
        self.defs = None

        self.ndefs = v_uint32()
        self.size = v_uint32()

        if self.flags & TIL_ZIP:
            self.csize = v_uint32()
        else:
            self.csize = None

        self.buf = v_bytes()

    def pcb_size(self):
        self["buf"].vsSetLength(self.size)

    def pcb_csize(self):
        if self.csize is not None:
            self["buf"].vsSetLength(self.csize)

    def pcb_buf(self):
        if self.csize is not None:
            buf = zlib.decompress(self.buf)
            self.vsSetField("buf", buf)
        else:
            buf = self.buf.tobytes() if isinstance(self.buf, memoryview) else self.buf

        defs = []
        offset = 0
        for _ in range(self.ndefs):
            _def = TILTypeInfo()
            offset = _def.vsParse(buf, offset=offset)
            defs.append(_def)
        self.defs = defs

    def find_by_name(self, name):
        if not self.defs:
            return None
        _def = list(filter(lambda x: x.name == name, self.defs))
        if len(_def) == 0:
            return None
        return _def[0]


TIL_ZIP = 0x0001  # pack buckets using zip
TIL_MAC = 0x0002  # til has macro table
TIL_ESI = 0x0004  # extended sizeof info (short, long, longlong)
TIL_UNI = 0x0008  # universal til for any compiler
TIL_ORD = 0x0010  # type ordinal numbers are present
TIL_ALI = 0x0020  # type aliases are present (this bit is used only on the disk)
TIL_MOD = 0x0040  # til has been modified, should be saved
TIL_STM = 0x0080  # til has extra streams
TIL_SLD = 0x0100  # sizeof(long double)


class TIL(VStruct):
    def __init__(self, buf=None, wordsize=4):
        VStruct.__init__(self)
        self.wordsize = wordsize
        self.signature = v_str(size=0x06)

        # https://github.com/aerosoul94/tilutil/blob/master/distil.py#L545

        self.format = v_uint32()
        self.flags = v_uint32()

        self.title_len = v_uint8()
        self.title = v_str()

        self.base_len = v_uint8()
        self.base = v_str()

        self.id = v_uint8()
        self.cm = v_uint8()
        self.size_i = v_uint8()
        self.size_b = v_uint8()
        self.size_e = v_uint8()
        self.def_align = v_uint8()

        # self.size_s  uint8
        # self.size_l  uint8
        # self.size_ll  uint8
        # self.size_ldbl  uint8
        # self.syms  TILBucket
        # self.type_ordinal_numbers  uint32
        # self.types  TILBucket
        # self.macros  TILBucket

    def pcb_flags(self):
        if self.flags & TIL_ESI:
            self.vsAddField("size_s", v_uint8())
            self.vsAddField("size_l", v_uint8())
            self.vsAddField("size_ll", v_uint8())

        if self.flags & TIL_SLD:
            self.vsAddField("size_ldbl", v_uint8())

        self.vsAddField("syms", TILBucket(flags=self.flags))

        if self.flags & TIL_ORD:
            self.vsAddField("type_ordinal_numbers", v_uint32())

        self.vsAddField("types", TILBucket(flags=self.flags))
        self.vsAddField("macros", TILBucket(flags=self.flags))

    def pcb_title_len(self):
        self["title"].vsSetLength(self.title_len)

    def pcb_base_len(self):
        self["base"].vsSetLength(self.base_len)

    def vsParse(self, sbytes, offset=0, fast=False):
        sbytes = sbytes.tobytes() if isinstance(sbytes, memoryview) else sbytes
        result = VStruct.vsParse(self, sbytes, offset, fast)

        self.types.defs.sort(key=lambda x: x.ordinal)
        self.deserialize_bucket(self.syms)
        self.deserialize_bucket(self.types)
        return result

    def deserialize_bucket(self, bucket):
        for t in bucket.defs:
            t.deserialize(til=self)

    def validate(self):
        if self.signature != "IDATIL":
            raise ValueError("bad signature")
        return True
