#!/usr/bin/env python3
"""
Extract the names of functions within the given IDA Pro database.

author: Willi Ballenthin
email: willi.ballenthin@gmail.com
"""
import argparse
import logging
import sys

import idb
import idb.analysis
import idb.netnode

logger = logging.getLogger(__name__)


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]

    parser = argparse.ArgumentParser(
        description="Extract the names of functions within the given IDA Pro database."
    )
    parser.add_argument("idbpath", type=str, help="Path to input idb file")
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable debug logging"
    )
    parser.add_argument(
        "-q", "--quiet", action="store_true", help="Disable all output but errors"
    )
    args = parser.parse_args(args=argv)

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
        logging.getLogger().setLevel(logging.DEBUG)
    elif args.quiet:
        logging.basicConfig(level=logging.ERROR)
        logging.getLogger().setLevel(logging.ERROR)
    else:
        logging.basicConfig(level=logging.INFO)
        logging.getLogger().setLevel(logging.INFO)

    with idb.from_file(args.idbpath) as db:
        root = idb.analysis.Root(db)
        api = idb.IDAPython(db)

        for fva in api.idautils.Functions():
            print("%s:0x%x:%s" % (root.md5, fva, api.idc.GetFunctionName(fva)))
            print(api.idc.GetType(fva))

    return 0


if __name__ == "__main__":
    sys.exit(main())
