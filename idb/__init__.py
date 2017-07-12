import contextlib

import six

# keep this here, so that its exposed as::
#
#    import idb.IDAPython
from idb.idapython import IDAPython


if six.PY2:
    def memview(buf):
        # on py2.7, we get this madness::
        #
        #     bytes(memoryview('foo')) == "<memoryview ...>"
        return buf
else:
    def memview(buf):
        return memoryview(buf)


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
