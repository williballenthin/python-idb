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


def from_buffer(buf):
    # break import cycle
    import idb.fileformat

    buf = memoryview(buf)
    db = idb.fileformat.IDB(buf)
    db.vsParse(buf)
    return db
