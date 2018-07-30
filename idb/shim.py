import sys
if sys.version_info[0] < 3:
    raise NotImplementedError('Python 3+ only for shimming the import system to work like IDA Pro.')

import types
import logging
import importlib.abc
import importlib.util

import idb


logger = logging.getLogger(__name__)



class HookedImporter(importlib.abc.MetaPathFinder, importlib.abc.Loader):
    def __init__(self, hooks=None):
        self.hooks = hooks

    def find_spec(self, name, path, target=None):
        if name not in self.hooks:
            return None

        spec = importlib.util.spec_from_loader(name, self)
        return spec

    def create_module(self, spec):
        # req'd in 3.6
        logger.info('hooking import: %s', spec.name)

        module = types.ModuleType(spec.name)
        module.__loader__ = self
        module.__package__ = ''

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
        sys.meta_path.insert(0, self)


def install(db, ScreenEA=None):
    if ScreenEA is None:
        ScreenEA = list(sorted(idb.analysis.Segments(db).segments.keys()))[0]

    api = idb.IDAPython(db, ScreenEA=ScreenEA)

    hooks = {
        'idc': api.idc,
        'idaapi': api.idaapi,
        'idautils': api.idautils,
        'ida_funcs': api.ida_funcs,
        'ida_bytes': api.ida_bytes,
        'ida_netnode': api.ida_netnode,
        'ida_nalt': api.ida_nalt,
        'ida_name': api.ida_name,
        'ida_entry': api.ida_entry,
    }

    importer = HookedImporter(hooks=hooks)
    importer.install()
    return hooks
