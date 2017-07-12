#!/usr/bin/env python3
'''
some documentation

author: Willi Ballenthin
email: willi.ballenthin@gmail.com
'''
import sys
import logging
import importlib.abc
import importlib.util

import argparse

import idb


logger = logging.getLogger(__name__)


class HookedImporter(importlib.abc.MetaPathFinder, importlib.abc.Loader):
    def __init__(self, hooks=None):
        self.hooks = hooks

    def find_spec(self, name, path, target=None):
        if name not in self.hooks:
            return None

        spec = importlib.util.spec_from_loader(name, importlib.util.LazyLoader(self))
        return spec

    def create_module(self, *args, **kwargs):
        # req'd in 3.6?
        return None

    def exec_module(self, module):
        mod = self.hooks[module.__spec__.name]
        for attr in dir(mod):
            if attr.startswith('__'):
                continue
            module.__dict__[attr] = getattr(mod, attr)
        return

    def install(self):
        sys.meta_path.insert(0, self)


def main(argv=None):
    # TODO: do version check for 3.x

    if argv is None:
        argv = sys.argv[1:]

    parser = argparse.ArgumentParser(description="Dump an IDB B-tree to a textual representation.")
    parser.add_argument("script_path", type=str,
                        help="Path to script file")
    parser.add_argument("idbpath", type=str,
                        help="Path to input idb file")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Enable debug logging")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="Disable all output but errors")
    parser.add_argument("--ScreenEA", type=str,
                        help="Prepare value of ScreenEA()")
    args = parser.parse_args(args=argv)

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
        logging.getLogger().setLevel(logging.DEBUG)
    elif args.quiet:
        logging.basicConfig(level=logging.ERROR)
        logging.getLogger().setLevel(logging.ERROR)
        logging.getLogger('idb.netnode').setLevel(logging.ERROR)
        logging.getLogger('idb.fileformat').setLevel(logging.ERROR)
    else:
        logging.basicConfig(level=logging.INFO)
        logging.getLogger().setLevel(logging.INFO)
        logging.getLogger('idb.netnode').setLevel(logging.ERROR)
        logging.getLogger('idb.fileformat').setLevel(logging.ERROR)

    with idb.from_file(args.idbpath) as db:
        if args.ScreenEA:
            if args.ScreenEA.startswith('0x'):
                screenea = int(args.ScreenEA, 0x10)
            else:
                screenea = int(args.ScreenEA)
        else:
            screenea = list(sorted(idb.analysis.Functions(db).functions.keys()))[0]

        api = idb.IDAPython(db, ScreenEA=screenea)

        hooks = {
            'idc': api.idc,
            'idaapi': api.idaapi,
            'idautils': api.idautils,
            'ida_funcs': api.ida_funcs,
            'ida_bytes': api.ida_bytes,
            'ida_netnode': api.ida_netnode,
            'ida_nalt': api.ida_nalt,
        }

        importer = HookedImporter(hooks=hooks)
        importer.install()

        with open(args.script_path, 'rb') as f:
            g = {
                '__name__': '__main__',
            }
            g.update(hooks)
            exec(f.read(), g)

    return 0


if __name__ == "__main__":
    sys.exit(main())
