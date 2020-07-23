import argparse
import json
import sys

from vstruct import VStruct
from vstruct.primitives import v_prim

import idb
from idb.typeinf import TILBucket, TILTypeInfo


class TILEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, TILBucket):
            _dict = {k: v for k, v in obj if k != "buf"}
            _dict["defs"] = obj.sorted_defs_by_ordinal
            return _dict
        elif isinstance(obj, TILTypeInfo):
            _dict = {k: v for k, v in obj if k != "fields_buf"}
            _dict["fields"] = obj.fields
            return _dict
        elif isinstance(obj, VStruct):
            return {k: v for k, v in obj}
        elif isinstance(obj, v_prim):
            return str(obj)
        elif isinstance(obj, memoryview):
            return obj.hex()

        return json.JSONEncoder.default(self, obj)


def main():
    parser = argparse.ArgumentParser(
        description="Parse and display type information from an IDA Pro database."
    )
    parser.add_argument(
        "idb", type=argparse.FileType("rb"), help="Path to input idb file"
    )
    args = parser.parse_args()

    til = idb.from_buffer(args.idb.read()).til
    print(json.dumps(til, indent=2, cls=TILEncoder))
    return 0


if __name__ == "__main__":
    sys.exit(main())
