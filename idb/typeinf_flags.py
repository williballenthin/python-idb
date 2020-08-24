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

# CM_CC_ Calling convention

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

ALOC_NONE = 0  # none
ALOC_STACK = 1  # stack offset
ALOC_DIST = 2  # distributed (scattered)
ALOC_REG1 = 3  # one register (and offset within it)
ALOC_REG2 = 4  # register pair
ALOC_RREL = 5  # register relative
ALOC_STATIC = 6  # global address
ALOC_CUSTOM = 7  # custom argloc (7 or higher)


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


def is_cm_cc_voidarg(t):
    return t & CM_CC_MASK == CM_CC_VOIDARG


def is_cm_cc_special(t):
    return t & CM_CC_MASK == CM_CC_SPECIAL


def is_cm_cc_special_pe(t):
    return t & CM_CC_MASK in (CM_CC_SPECIAL, CM_CC_SPECIALP, CM_CC_SPECIALE)


def is_cc_spoiled(t):
    return get_cc(t) == CM_CC_SPOILED


def get_cc(cm):
    return cm & CM_CC_MASK


def is_user_cc(cm):
    cc = get_cc(cm)
    return cc >= CM_CC_SPECIALE


# Does the calling convention use ellipsis?


def is_vararg_cc(cm):
    cc = get_cc(cm)
    return cc in (CM_CC_ELLIPSIS, CM_CC_SPECIALE)


# Does the calling convention clean the stack arguments upon return?.
# \note this function is valid only for x86 code


def is_purging_cc(cm):
    cc = get_cc(cm)
    return cc in (
        CM_CC_STDCALL,
        CM_CC_PASCAL,
        CM_CC_SPECIALP,
        CM_CC_FASTCALL,
        CM_CC_THISCALL,
    )
