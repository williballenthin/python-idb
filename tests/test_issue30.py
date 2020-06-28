import os.path

import idb


def test_issue30():
    """
    demonstrate get_func_cmt().
    see github issue #30 for the backstory.
    """
    cd = os.path.dirname(__file__)
    idbpath = os.path.join(cd, "data", "issue30", "issue30.i64")

    with idb.from_file(idbpath) as db:
        api = idb.IDAPython(db)

        assert api.idc.GetCommentEx(0x401598, 0) == "local cmt"
        assert api.idc.GetCommentEx(0x401598, 1) == ""
        assert api.ida_funcs.get_func_cmt(0x401598, 0) == "rep cmt"
        assert api.ida_funcs.get_func_cmt(0x401598, 1) == "rep cmt"
