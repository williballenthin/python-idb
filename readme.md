![Python IDB](https://github.com/williballenthin/python-idb/workflows/Python%20IDB/badge.svg)

# python-idb

python-idb is a library for accessing the contents of [IDA Pro](https://www.hex-rays.com/products/ida/) databases (.idb files).
It provides read-only access to internal structures such as the B-tree (ID0 section), name address index (NAM section), flags index (ID2 section), and types (TIL section).
The library also provides analysis of B-tree entries to expose logical structures like functions, cross references, bytes, and disassembly (via [Capstone](http://www.capstone-engine.org/)).
An example use for python-idb might be to run IDA scripts in a pure-Python environment.

Willem Hengeveld (<mailto:itsme@xs4all.nl>) provided the initial research into the low-level structures in his projects [pyidbutil](https://github.com/nlitsme/pyidbutil) and [idbutil](https://github.com/nlitsme/idbutil).
Willem deserves substantial credit for reversing the .idb file format and publishing his results online.
This project heavily borrows from his knowledge, though there is little code overlap.


## example use:

### example: list function names

In this example, we list the effective addresses and names of functions:

```
In [4]: import idb
   ...: with idb.from_file('./data/kernel32/kernel32.idb') as db:
   ...:     api = idb.IDAPython(db)
   ...:     for ea in api.idautils.Functions():
   ...:         print('%x: %s' % (ea, api.idc.GetFunctionName(ea)))

Out [4]: 68901010: GetStartupInfoA
   ....: 689011df: Sleep
   ....: 68901200: MulDiv
   ....: 68901320: SwitchToFiber
   ....: 6890142c: GetTickCount
   ....: 6890143a: ReleaseMutex
   ....: 68901445: WaitForSingleObject
   ....: 68901450: GetCurrentThreadId
        ...
```

Note that we create an emulated instance of the IDAPython scripting interface, and use
this to invoke `idc` and `idautils` routines to fetch data.


### example: run an existing IDAPython script

In this example, we run the [yara_fn.py](https://gist.github.com/williballenthin/3abc9577bede0aeef25526b201732246) IDAPython script to generate a [YARA](https://virustotal.github.io/yara/) rule for the function at effective address 0x68901695 in kernel32.idb:

[![asciicast](https://asciinema.org/a/9n8qxpChjBTrF1tYAbp7ABIFW.png)](https://asciinema.org/a/9n8qxpChjBTrF1tYAbp7ABIFW?theme=monokai)

The target script `yara_fn.py` has only been slightly modified:
  - to make it Python 3.x compatible, and
  - to use the modern IDAPython modules, such as `ida_bytes.GetManyBytes` rather than `idc.GetManyBytes`.


## what works

  - ~250 unit tests that demonstrate functionality including file format, B-tree, analysis, and idaapi features.
  - read-only parsing of .idb and .i64 files from IDA Pro v5.0 to v7.5
    - extraction of file sections
    - B-tree lookups and queries (ID0 section)
    - flag enumeration (ID1 section)
    - named address listing (NAM section)
    - types parsing (TIL section)
  - analysis of artifacts that reconstructs logical elements, including:
    - root metadata
    - loader metadata
    - entry points
    - functions
    - structures
    - cross references
    - fixups
    - segments
  - partial implementation of the IDAPython API, including:
    - `Names`
    - `Heads`
    - `Segs`
    - `GetMnem` (via Capstone)
    - `Functions`
    - `FlowChart` (basic blocks)
    - lots and lots of flags
  - Python 2.7 & 3.x compatibility
  - zlib-packed idb/i64 files

## what will never work

  - write access


## getting started

python-idb is a pure-Python library, with the exception of Capstone (required only when calling disassembly APIs).
You can install it via pip or `setup.py install`, both of which should handle depedency resolution:

```
 $ cd ~/Downloads/python-idb/
 $ python setup.py install
 $ python scripts/run_ida_script.py  ~/tools/yara_fn.py  ~/Downloads/kernel32.idb
   ... profit! ...
```

While most python-idb function have meaningful docstrings, there is not yet a comprehensive documentation website.
However, the unit tests demonstrate functionality that you'll probably find useful.

Someone interested in learning the file format and contributing to the project should review the `idb.fileformat` module & tests.
Those that are looking to extract meaningful information from existing .idb files probably should look at the `idb.analysis` and `idb.idapython` modules & tests.

Please report issues or feature requests through Github's bug tracker associated with the project.


## license

python-idb is licensed under the Apache License, Version 2.0.
This means it is freely available for use and modification in a personal and professional capacity.
