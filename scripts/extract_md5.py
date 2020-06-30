#!/usr/bin/env python3
"""
Extract the original file MD5 from the IDA Pro database.

author: Willi Ballenthin
email: willi.ballenthin@gmail.com
"""
import argparse
import logging
import sys

import idb
import idb.netnode

logger = logging.getLogger(__name__)


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]

    parser = argparse.ArgumentParser(
        description="Extract the original file MD5 from an IDA Pro database."
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
        print(root.md5)

    return 0


if __name__ == "__main__":
    sys.exit(main())
