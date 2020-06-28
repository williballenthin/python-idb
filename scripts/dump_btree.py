#!/usr/bin/env python3
"""
some documentation

author: Willi Ballenthin
email: willi.ballenthin@gmail.com
"""
import argparse
import logging
import sys

import hexdump

import idb
import idb.netnode

logger = logging.getLogger(__name__)


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]

    parser = argparse.ArgumentParser(
        description="Dump an IDB B-tree to a textual representation."
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
        cursor = db.id0.get_min()
        while True:
            if cursor.key[0] == 0x2E:
                try:
                    k = idb.netnode.parse_key(cursor.key, wordsize=db.wordsize)
                except UnicodeDecodeError:
                    hexdump.hexdump(cursor.key)
                else:
                    print(
                        "nodeid: %x tag: %s index: %s"
                        % (
                            k.nodeid,
                            k.tag,
                            hex(k.index) if k.index is not None else "None",
                        )
                    )
            else:
                hexdump.hexdump(cursor.key)

            hexdump.hexdump(bytes(cursor.value))
            print("--")

            try:
                cursor.next()
            except IndexError:
                break

    return 0


if __name__ == "__main__":
    sys.exit(main())
