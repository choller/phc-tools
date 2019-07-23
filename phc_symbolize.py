#!/usr/bin/env python3
# ***** BEGIN LICENSE BLOCK *****
# Version: MPL 2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# Contributors:
#  Christian Holler <choller@mozilla.com> (Original Developer)
#
# ***** END LICENSE BLOCK *****

import argparse
import json
import os
import sys

symbols = {}
filemap = {}

line_symbols_cache = {}


def load_symbols(module, symfile):
    if module not in symbols:
        symbols[module] = []

    if symfile not in line_symbols_cache:
        line_symbols_cache[symfile] = []

    with open(symfile, 'r') as symfile_fd:
        for line in symfile_fd:
            line = line.rstrip()
            if line.startswith("MODULE "):
                pass
            elif line.startswith("FILE "):
                # FILE 14574 hg:hg.mozilla.org/try:xpcom/io/nsLocalFileCommon.cpp:8ff5f360a1909a75f636e93860aa456625df25f7
                tmp = line.split(" ", maxsplit=2)
                if symfile not in filemap:
                    filemap[symfile] = {}
                # FILE definitions are *not* per module as one would expect,
                # but actually per symbols file (so the same FILE id can appear
                # multiple times per module, in distinct symbols files).
                filemap[symfile][tmp[1]] = tmp[2]
            elif line.startswith("PUBLIC "):
                # Not supported currently
                pass
            elif line.startswith("STACK "):
                pass
            elif line.startswith("INFO "):
                pass
            elif line.startswith("FUNC "):
                # FUNC 8e5440 14e 0 webrtc::AudioProcessingImpl::Initialize
                tmp = line.split(" ", maxsplit=4)
                comps = [int(tmp[1], 16), int(tmp[2], 16), tmp[4], symfile]
                symbols[module].append(comps)
            else:
                # This is a line entry:
                # address size line filenum
                # a51fd3 35 433 14574
                line_symbols_cache[symfile].append(line)


def retrieve_file_line_data_linear(symbol_entry, reladdr):
    # We reopen the symbols file and retrieve line data on the fly
    # because storing all of it in load_symbols is very memory intense.
    symfile = symbol_entry[3]
    with open(symfile, 'r') as symfile_fd:
        for line in symfile_fd:
            tmp = line.split(" ", maxsplit=3)
            try:
                start_addr = int(tmp[0], 16)
                if start_addr <= reladdr:
                    size = int(tmp[1], 16)
                    if (start_addr + size) > reladdr:

                        return (tmp[2], tmp[3].rstrip())
            except ValueError:
                # Ignore any non-line entries
                pass
    return (None, None)


def retrieve_file_line_data_binsearch(symbol_entry, reladdr):
    symfile = symbol_entry[3]
    lines = line_symbols_cache[symfile]

    if not lines:
        return (None, None)

    cmin = 0
    cmax = len(lines) - 1
    cidx = int(len(lines) / 2)

    while (cmax - cmin) >= 0 and cidx <= cmax:
        line = lines[cidx]
        tmp = line.split(" ", maxsplit=3)
        try:
            start_addr = int(tmp[0], 16)
            if start_addr <= reladdr:
                size = int(tmp[1], 16)
                if (start_addr + size) > reladdr:
                    return (tmp[2], tmp[3].rstrip())
                else:
                    cmin = cidx + 1
                    cidx = cmin + int((cmax - cmin) / 2)
            else:
                cmax = cidx - 1
                cidx = cmin + int((cmax - cmin) / 2)
        except ValueError:
            # Ignore any non-line entries
            cidx += 1

    return (None, None)


def retrieve_file_line_data(symbol_entry, reladdr):
    return retrieve_file_line_data_binsearch(symbol_entry, reladdr)


def read_extra_file(extra_file):
    def make_stack_array(line):
        return [int(x) for x in line.rstrip().split(sep="=")[1].split(",")]

    alloc_stack = None
    free_stack = None
    modules = None

    with open(extra_file, 'r') as extra_file_fd:
        for line in extra_file_fd:
            if line.startswith("PHCAllocStack"):
                alloc_stack = make_stack_array(line)
            elif line.startswith("PHCFreeStack"):
                free_stack = make_stack_array(line)
            elif line.startswith("StackTraces"):
                obj = json.loads(line.split(sep="=")[1])
                modules = obj["modules"]

    module_memory_map = {}

    for module in modules:
        module_memory_map[module["filename"]] = (int(module["base_addr"], 16), int(module["end_addr"], 16))

    return (alloc_stack, free_stack, module_memory_map)


def main(argv=None):
    '''Command line options.'''

    program_name = os.path.basename(sys.argv[0])

    if argv is None:
        argv = sys.argv[1:]

    # setup argparser
    parser = argparse.ArgumentParser(usage='%s EXTRA_FILE SYMBOLS_DIR' % program_name)
    parser.add_argument('rargs', nargs=argparse.REMAINDER)

    if not argv:
        parser.print_help()
        return 2

    opts = parser.parse_args(argv)

    if len(opts.rargs) < 2:
        parser.print_help()
        return 2

    extra_file = opts.rargs[0]
    symbols_dir = opts.rargs[1]

    if not os.path.isfile(extra_file):
        print("Invalid .extra file specified", file=sys.stderr)
        return 2

    if not os.path.isdir(symbols_dir):
        print("Invalid symbols directory specified", file=sys.stderr)
        return 2

    if not symbols_dir.endswith(os.sep):
        symbols_dir += os.sep

    print("Loading symbols...", file=sys.stderr)

    for (path, dirs, files) in os.walk(symbols_dir):
        for file in files:
            fp_file = os.path.join(path, file)

            if fp_file.endswith(".sym"):
                rel_file = fp_file.replace(symbols_dir, "", 1)
                comps = rel_file.split(os.sep)
                module = comps[0]

                load_symbols(module, fp_file)

    def print_stack(phc_stack, name, symbols, module_memory_map):
        stack_cnt = 0

        print("%s stack:" % name)
        print("")
        for addr in phc_stack:
            # Step 1: Figure out which module this address belongs to
            (module, reladdr) = (None, None)
            for module_cand in module_memory_map:
                base_addr = module_memory_map[module_cand][0]
                end_addr = module_memory_map[module_cand][1]

                if addr >= base_addr and addr < end_addr:
                    module = module_cand
                    reladdr = addr - base_addr
                    break

            if not module:
                print("#%s    (frame in unknown module)" % stack_cnt)
                stack_cnt += 1
                continue

            if module not in symbols:
                print("#%s    (missing symbols for module %s)" % (stack_cnt, module))
                stack_cnt += 1
                continue

            symbol_entry = None
            for sym in symbols[module]:
                if sym[0] <= reladdr and (sym[0] + sym[1]) > reladdr:
                    print("#%s    %s" % (stack_cnt, sym[2]))
                    symbol_entry = sym
                    break

            if not symbol_entry:
                print("#%s    ???" % stack_cnt)
            else:
                (line, filenum) = retrieve_file_line_data_binsearch(symbol_entry, reladdr)
                symfile = symbol_entry[3]
                if filenum and symfile in filemap:
                    print("    in file %s line %s" % (filemap[symfile][filenum], line))

            stack_cnt += 1

    (alloc_stack, free_stack, module_memory_map) = read_extra_file(extra_file)

    print_stack(free_stack, "Free", symbols, module_memory_map)
    print("")
    print_stack(alloc_stack, "Alloc", symbols, module_memory_map)


if __name__ == '__main__':
    main()
