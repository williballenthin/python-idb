import os.path

import idb


def test_issue29():
    """
    demonstrate GetManyBytes can retrieve the entire .text section
    see github issue #29 for the backstory.
    """
    cd = os.path.dirname(__file__)
    idbpath = os.path.join(cd, "data", "issue29", "issue29.i64")

    with idb.from_file(idbpath) as db:
        api = idb.IDAPython(db)

        seg = api.idc.FirstSeg()
        while seg != api.idc.BADADDR:
            name = api.idc.SegName(seg)
            start = api.idc.SegStart(seg)
            end = api.idc.SegEnd(seg)

            if name == ".text":
                # should not fail at address 0x180072200
                textBytes = api.idc.GetManyBytes(start, end - start)
                assert len(textBytes) == end - start

            seg = api.idc.NextSeg(seg)
