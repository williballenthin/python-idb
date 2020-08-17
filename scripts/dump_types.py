import argparse
import json
import sys

from vstruct import VStruct
from vstruct.primitives import v_prim

import idb
from idb.typeinf import TILBucket, TILTypeInfo, TInfo


class TILEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, TILBucket):
            _dict = {k: v for k, v in obj if k != "buf"}
            _dict["defs"] = obj.defs
            return _dict
        elif isinstance(obj, TILTypeInfo):
            _dict = {k: v for k, v in obj if k != "fields_buf"}
            _dict["fields"] = obj.fields
            _dict["type"] = obj.type.get_typedeclare()
            return _dict
        elif isinstance(obj, TInfo):
            return obj.get_typestr()
        elif isinstance(obj, VStruct):
            return {k: v for k, v in obj}
        elif isinstance(obj, v_prim):
            return str(obj)
        elif isinstance(obj, memoryview):
            return obj.hex()

        return json.JSONEncoder.default(self, obj)


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]

    parser = argparse.ArgumentParser(
        description="Parse and display type information from an IDA Pro database."
    )
    parser.add_argument(
        "idb", type=argparse.FileType("rb"), help="Path to input idb file"
    )
    args = parser.parse_args(args=argv)

    til = idb.from_buffer(args.idb.read()).til
    # for _def in til.syms.defs:
    #     print(_def.type.get_typestr())
    for _def in til.types.defs:
        print(_def.type.get_typestr())
    return 0


if __name__ == "__main__":
    sys.exit(main())
