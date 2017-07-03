import contextlib


from idb.idapython import IDAPython


@contextlib.contextmanager
def from_file(path):
    # break import cycle
    import idb.fileformat

    with open(path, 'rb') as f:
        buf = memoryview(f.read())
        db = idb.fileformat.IDB(buf)
        db.vsParse(buf)
        yield db
