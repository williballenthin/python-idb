import os.path

import idb


def test_issue28():
    """
    demonstrate parsing of section metadata.
    see github issue #28 for the backstory.
    """
    cd = os.path.dirname(__file__)
    idbpath = os.path.join(cd, "data", "elf", "cat.i64")

    with idb.from_file(idbpath) as db:
        api = idb.IDAPython(db)
        assert [
            2,
            2,
            2,
            2,
            2,
            2,
            2,
            2,
            2,
            2,
            2,
            2,
            2,
            2,
            2,
            2,
            2,
            2,
            2,
            2,
            2,
            2,
            2,
        ] == [
            api.idc.GetSegmentAttr(s, api.idc.SEGATTR_BITNESS)
            for s in api.idautils.Segments()
        ]
