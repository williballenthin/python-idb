#!/usr/bin/env python

import idaapi
import idautils
import idc


def print_section_list():
    for s in idautils.Segments():
        seg = idaapi.getseg(s)
        print("%s" % idc.SegName(s))
        print(" - start address: 0x%x" % seg.startEA)
        print(" - sclass: 0x%x" % seg.sclass)
        print(" - orgbase: 0x%x" % seg.orgbase)
        print(" - flags: 0x%x" % seg.flags)
        print(" - align: 0x%x" % seg.align)
        print(" - comb: 0x%x" % seg.comb)
        print(" - perm: 0x%x" % seg.perm)
        print(" - bitness: 0x%x" % seg.bitness)
        print(" - sel: 0x%x" % seg.sel)
        # print(' - defsr: 0x%x' % seg.defsr)
        print(" - type: 0x%x" % seg.type)
        print(" - color: 0x%x" % seg.color)


print_section_list()
