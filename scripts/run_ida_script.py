#!/usr/bin/env python3
"""
some documentation

author: Willi Ballenthin
email: willi.ballenthin@gmail.com
"""
import argparse
import logging
import os.path
import shlex
import sys

import idb
import idb.shim

logger = logging.getLogger(__name__)


def main(argv=None):
    # TODO: do version check for 3.x

    if argv is None:
        argv = sys.argv[1:]

    parser = argparse.ArgumentParser(
        description="Dump an IDB B-tree to a textual representation."
    )
    parser.add_argument(
        "script_path",
        type=str,
        help="""Path to script file.
                Command line arguments can be passed using quotes:
                "myscrypt.py arg1 arg2 "arg3 arg3""
        """,
    )
    parser.add_argument("idbpath", type=str, help="Path to input idb file")
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable debug logging"
    )
    parser.add_argument(
        "-q", "--quiet", action="store_true", help="Disable all output but errors"
    )
    parser.add_argument("--ScreenEA", type=str, help="Prepare value of ScreenEA()")
    args = parser.parse_args(args=argv)

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
        logging.getLogger().setLevel(logging.DEBUG)
    elif args.quiet:
        logging.basicConfig(level=logging.ERROR)
        logging.getLogger().setLevel(logging.ERROR)
        logging.getLogger("idb.netnode").setLevel(logging.ERROR)
        logging.getLogger("idb.fileformat").setLevel(logging.ERROR)
    else:
        logging.basicConfig(level=logging.INFO)
        logging.getLogger().setLevel(logging.INFO)
        logging.getLogger("idb.netnode").setLevel(logging.ERROR)
        logging.getLogger("idb.fileformat").setLevel(logging.ERROR)

    with idb.from_file(args.idbpath) as db:
        if args.ScreenEA:
            if args.ScreenEA.startswith("0x"):
                screenea = int(args.ScreenEA, 0x10)
            else:
                screenea = int(args.ScreenEA)
        else:
            screenea = list(sorted(idb.analysis.Segments(db).segments.keys()))[0]

        hooks = idb.shim.install(db, ScreenEA=screenea)

        script_args = shlex.split(args.script_path)
        # update sys.path to point to directory containing script.
        # so scripts can import .py files in the same directory.
        script_dir = os.path.dirname(script_args[0])
        sys.path.insert(0, script_dir)
        # update idc.ARGV
        hooks["idc"].ARGV = script_args

        with open(script_args[0], "rb") as f:
            g = {
                "__name__": "__main__",
            }
            g.update(hooks)
            exec(f.read(), g)

    return 0


if __name__ == "__main__":
    sys.exit(main())
