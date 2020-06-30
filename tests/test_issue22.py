import os.path

import idb


def test_issue22():
    """
    demonstrate that functions found at addresses with the high bit set are no problem.
    see github issue #22 for the backstory.
    """
    cd = os.path.dirname(__file__)
    idbpath = os.path.join(cd, "data", "highaddr", "highaddr.idb")

    with idb.from_file(idbpath) as db:
        api = idb.IDAPython(db)
        assert len(api.idautils.Functions()) == 1
        assert api.idautils.Functions()[0] == 0xF7FFFFFF
