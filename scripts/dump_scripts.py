#!/usr/bin/env python3
"""
Extract scripts embedded within IDA Pro databases.

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
        description="Extract scripts embedded within IDA Pro databases."
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
        try:
            for script in idb.analysis.enumerate_script_snippets(db):
                logger.debug("script: %s", script.name)
                logger.debug("language: %s", script.language)
                logger.debug("code: \n%s", script.code)
                if script.language == "Python":
                    ext = ".py"
                elif script.language == "IDC":
                    ext = ".idc"
                else:
                    raise ValueError("unexpected script language: " + script.language)

                filename = script.name + ext
                logger.info(
                    "writing %s script %s to %s", script.language, script.name, filename
                )
                with open(filename, "wb") as f:
                    f.write(script.code.encode("utf-8"))
        except KeyError:
            logger.warning("not found script snippets")

    return 0


if __name__ == "__main__":
    sys.exit(main())
