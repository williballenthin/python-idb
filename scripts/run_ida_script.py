#!/usr/bin/env python3
'''
some documentation

author: Willi Ballenthin
email: willi.ballenthin@gmail.com
'''
import sys
import os.path
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
        logger.info('hooked importer: find-spec: %s', name)
        if name not in self.hooks:
            return None

        spec = importlib.util.spec_from_loader(name, self)
        return spec

    def create_module(self, spec):
        # req'd in 3.6
        logger.info('hooked importer: create-module: %s', spec.name)
        module = importlib.util._Module(spec.name)
        mod = self.hooks[spec.name]
        for attr in dir(mod):
            if attr.startswith('__'):
                continue
            module.__dict__[attr] = getattr(mod, attr)
        return module

    def exec_module(self, module):
        # module is already loaded (imported by line `import idb` above),
        # so no need to re-execute.
        #
        # req'd in 3.6.
        return

    def install(self):
        logger.info('install')
        sys.meta_path.insert(0, self)
        print(sys.meta_path)


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
            'ida_name': api.ida_name,
        }

        importer = HookedImporter(hooks=hooks)
        importer.install()

        # update sys.path to point to directory containing script.
        # so scripts can import .py files in the same directory.
        script_dir = os.path.dirname(args.script_path)
        sys.path.insert(0, script_dir)

        with open(args.script_path, 'rb') as f:
            g = {
                '__name__': '__main__',
            }
            g.update(hooks)
            exec(f.read(), g)

    return 0


if __name__ == "__main__":
    sys.exit(main())
