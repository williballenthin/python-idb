from fixtures import *

import idb


import logging
logging.basicConfig(level=logging.DEBUG)


def test_code(kernel32_idb):
    first_ea = 0x68901010
    flags = kernel32_idb.GetFlags(first_ea)

    assert kernel32_idb.isFunc(flags) == True
    assert kernel32_idb.isImmd(flags) == False

    second_ea = 0x68901012
    flags = kernel32_idb.GetFlags(second_ea)
    assert kernel32_idb.isFunc(flags) == False
    assert kernel32_idb.isImmd(flags) == False

