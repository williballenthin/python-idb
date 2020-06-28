#!/usr/bin/env python
"""
Interactively explore an IDB B-Tree like a file system.

author: Willi Ballenthin
email: willi.ballenthin@gmail.com
"""
import argparse
import cmd
import logging
import sys

import hexdump
import tabulate

import idb
import idb.netnode

logger = logging.getLogger(__name__)


def h(i):
    return "%x" % (i)


def render_key(key, wordsize):
    if key[0] == 0x2E:
        k = idb.netnode.parse_key(key, wordsize)
        return "nodeid: %x tag: %s index: %s" % (
            k.nodeid,
            k.tag,
            hex(k.index) if k.index is not None else "None",
        )
    else:
        return bytes(key).decode("ascii")


class BTreeExplorer(cmd.Cmd):
    def __init__(self, db):
        super(BTreeExplorer, self).__init__()
        self.db = db
        self.path = [db.id0.root_page]

    @property
    def prompt(self):
        return "/".join(map(h, self.path)) + "/ > "

    @property
    def current_page(self):
        return self.db.id0.get_page(self.path[-1])

    def do_ls(self, line):
        """
        list the entries in the current B-tree page.
        """
        page = self.current_page

        rows = []

        if page.is_leaf():
            print("leaf: true")
            for i, entry in enumerate(page.get_entries()):
                rows.append((hex(i), render_key(entry.key, self.db.wordsize)))
        else:
            print("leaf: false")
            rows.append(("", "ppointer", hex(page.ppointer)))
            for i, entry in enumerate(page.get_entries()):
                rows.append(
                    (hex(i), render_key(entry.key, self.db.wordsize), hex(entry.page))
                )

        print(tabulate.tabulate(rows, headers=["entry", "key", "page number"]))

    def do_cd(self, line):
        """
        traverse the B-tree.

        you may only traverse to child nodes, or to the parent node.

        traverse to child node::

            > ls
            entry    key                                 page number
            -------  ----------------------------------  -------------
                     ppointer                            0x3

            > cd 0x3

        traverse to parent::

            > cd ..
        """
        if " " in line:
            part = line.partition(" ")[0]
        else:
            part = line

        if part == "..":
            if len(self.path) == 1:
                print("error: cannot go up, already at root node.")
                return
            self.path = self.path[:-1]
            return

        page = self.current_page

        target = int(part, 0x10)

        if not (
            target == page.ppointer
            or target in map(lambda e: e.page, page.get_entries())
        ):
            print("error: invalid page number.")
            return

        self.path.append(target)

    def do_cat(self, line):
        """
        display the contents of an entry.

        example::

            > ls
            leaf: true
            entry    key
            -------  -----------------------------------------
            0x0      b'$ MAX LINK'
            0x1      b'$ MAX NODE'
            0x2      b'$ NET DESC'
            0x3      nodeid: 0 tag: S index: 0x3e8
            0x4      nodeid: 0 tag: S index: 0x3e9
            ...
            ----  ------------------------------------------------------------------------------------------
            > cat 3
            00000000: 3B 20 46 69 6C 65 20 4E  61 6D 65 20 20 20 3A 20  ; File Name   :
            00000010: 5A 3A 5C 68 6F 6D 65 5C  75 73 65 72 5C 44 6F 63  Z:\\home\\user\\Doc
            00000020: 75 6D 65 6E 74 73 5C 63  6F 64 65 5C 70 79 74 68  uments\\code\\pyth
            00000030: 6F 6E 2D 69 64 62 5C 74  65 73 74 73 5C 64 61 74  on-idb\\tests\dat
            00000040: 61 5C 73 6D 61 6C 6C 5C  73 6D 61 6C 6C 2E 62 69  a\\small\\small.bi
            00000050: 6E 00
        """
        if " " in line:
            part = line.partition(" ")[0]
        else:
            part = line
        target = int(part, 0x10)

        entry = self.current_page.get_entry(target)
        hexdump.hexdump(entry.value)

    def do_exit(self, line):
        return True

    def do_quit(self, line):
        return True

    def do_EOF(self, line):
        return True


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]

    parser = argparse.ArgumentParser(
        description="Interactively explore an IDB B-tree like a file system."
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
        explorer = BTreeExplorer(db)
        explorer.cmdloop()

    return 0


if __name__ == "__main__":
    sys.exit(main())
