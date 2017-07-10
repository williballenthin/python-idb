import sys
import contextlib


from idb.idapython import IDAPython


if (sys.version_info > (3, 0)):
    def memview(buf):
        return memoryview(buf)
else:
    def memview(buf):
        # on py2.7, we get this madness::
        #
        #     bytes(memoryview('foo')) == <memoryview ...>
        return buf


@contextlib.contextmanager
def from_file(path):
    # break import cycle
    import idb.fileformat

    with open(path, 'rb') as f:
        buf = memview(f.read())
        db = idb.fileformat.IDB(buf)
        db.vsParse(buf)
        yield db


def from_buffer(buf):
    # break import cycle
    import idb.fileformat

    buf = memview(buf)
    db = idb.fileformat.IDB(buf)
    db.vsParse(buf)
    return db
