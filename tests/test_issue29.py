import os.path

import idb


def test_issue29():
    '''
    demonstrate GetManyBytes can retrieve the entire .text section
    see github issue #29 for the backstory.
    '''
    cd = os.path.dirname(__file__)
    idbpath = os.path.join(cd, 'data', 'issue29', 'issue29.i64')

    with idb.from_file(idbpath) as db:
        api = idb.IDAPython(db)
        segments = idb.analysis.Segments(db).segments
        segStrings = idb.analysis.SegStrings(db).strings

        for seg in segments.values():
            name = segStrings[seg.name_index]
            segLen = seg.endEA - seg.startEA

            if name == '.text':
                # should not fail at address 0x180072200
                textBytes = api.idc.GetManyBytes(seg.startEA, segLen)
                assert len(textBytes) == segLen
                break
