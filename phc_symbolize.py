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
import requests
import sys

symbols = {}
filemap = {}

# Public symbols have a lower priority because they lack file/line information
symbols_public = {}

line_symbols_cache = {}

SOCORRO_AUTH_TOKEN = os.getenv("SOCORRO_AUTH_TOKEN")

# A mapping from filename to debug_file to save us from doing platform-specific
# conversions to get the debug_file name.
debugmap = {}

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
                # PUBLIC (m) 7f5c0 0 gdk_x11_get_server_time
                tmp = line.split(" ", maxsplit=3)

                # Support the optional "m" indicator for folded code
                base_idx = 0
                if tmp[1] == 'm':
                    base_idx = 1
                    tmp = line.split(" ", maxsplit=4)

                symbol_start = int(tmp[base_idx + 1], 16)

                if module not in symbols_public:
                    symbols_public[module] = []
                else:
                    # Set the end of the last symbol we parsed
                    symbols_public[module][-1][1] = symbol_start

                # Push new symbol with 0 as end, so we can fix it later
                symbols_public[module].append([symbol_start, 0, tmp[base_idx + 3]])
            elif line.startswith("STACK "):
                pass
            elif line.startswith("INFO "):
                pass
            elif line.startswith("FUNC "):
                # FUNC (m) 8e5440 14e 0 webrtc::AudioProcessingImpl::Initialize
                tmp = line.split(" ", maxsplit=4)

                # Support the optional "m" indicator for folded code
                base_idx = 0
                if tmp[1] == 'm':
                    base_idx = 1
                    tmp = line.split(" ", maxsplit=5)

                comps = [int(tmp[base_idx + 1], 16), int(tmp[base_idx + 2], 16), tmp[base_idx + 4], symfile]
                symbols[module].append(comps)
            else:
                # This is a line entry:
                # address size line filenum
                # a51fd3 35 433 14574
                line_symbols_cache[symfile].append(line)


def load_symbols_recursive(symbols_dir):
        for (path, dirs, files) in os.walk(symbols_dir):
            for file in files:
                fp_file = os.path.join(path, file)

                if fp_file.endswith(".sym"):
                    rel_file = fp_file.replace(symbols_dir, "", 1)
                    comps = rel_file.split(os.sep)
                    module = os.path.splitext(comps[-1])[0]

                    load_symbols(module, fp_file)


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
        return [int(x) for x in line.rstrip().split(",")]

    alloc_stack = None
    free_stack = None
    modules = None

    with open(extra_file, 'r') as extra_file_fd:
        data = json.load(extra_file_fd)
        if "PHCAllocStack" in data:
            alloc_stack = make_stack_array(data["PHCAllocStack"])
        elif "PHCFreeStack" in data:
            free_stack = make_stack_array(data["PHCFreeStack"])
        elif "StackTraces" in data:
            modules = json.loads(data["StackTraces"])["modules"]

    module_memory_map = {}

    for module in modules:
        module_memory_map[module["filename"]] = (int(module["base_addr"], 16), int(module["end_addr"], 16))

    return (alloc_stack, free_stack, module_memory_map)


def fetch_socorro_crash(crash_id):
    headers = {'Auth-Token': SOCORRO_AUTH_TOKEN}

    raw_url = 'https://crash-stats.mozilla.org/api/RawCrash/?crash_id=%s&format=meta' % crash_id
    processed_url = 'https://crash-stats.mozilla.org/api/ProcessedCrash/?crash_id=%s&datatype=processed' % crash_id

    response = requests.get(raw_url, headers=headers)

    if not response.ok:
        print("Error: Failed to fetch raw data from Socorro", file=sys.stderr)
        return (None, None, None, None, None)

    raw_data = response.json()

    if "PHCAllocStack" not in raw_data:
        print("Error: No PHCAllocStack in raw data, is this really a PHC crash?", file=sys.stderr)
        return (None, None, None, None, None)

    alloc_stack = [int(x) for x in raw_data["PHCAllocStack"].split(",")]
    if "PHCFreeStack" in raw_data:
        free_stack = [int(x) for x in raw_data["PHCFreeStack"].split(",")]
    else:
        free_stack = None

    response = requests.get(processed_url, headers=headers)

    if not response.ok:
        print("Error: Failed to fetch processed data from Socorro", file=sys.stderr)
        return (None, None, None, None, None)

    processed_data = response.json()

    module_memory_map = {}
    remote_symbols_files = set()

    # A list of pairs (debug_name/debug_id) for the symbol server remote API
    memory_map_remote = []
    for module in processed_data["json_dump"]["modules"]:
        module_memory_map[module["filename"]] = (int(module["base_addr"], 16), int(module["end_addr"], 16))
        if "symbol_url" in module:
            remote_symbols_files.add(module["symbol_url"])
            memory_map_remote.append([module["debug_file"], module["debug_id"]])
            debugmap[module["filename"]] = module["debug_file"]

    return (alloc_stack, free_stack, module_memory_map, remote_symbols_files, memory_map_remote)


def fetch_remote_symbols(url, symbols_dir):
    url_comps = url.split("/")
    dest_dir = os.path.join(symbols_dir, url_comps[-2])

    if not os.path.exists(dest_dir):
        os.makedirs(dest_dir)

    dest_file = os.path.join(dest_dir, url_comps[-1])

    sys.stderr.write("Fetching %s ... " % url)

    if os.path.exists(dest_file):
        print(" cached!", file=sys.stderr)
        return

    response = requests.get(url)
    print("done!", file=sys.stderr)

    with open(dest_file, 'w') as fd:
        fd.write(response.text)

    return


def find_module(addr, module_memory_map):
    # Figure out which module this address belongs to
    (module, reladdr) = (None, None)
    for module_cand in module_memory_map:
        base_addr = module_memory_map[module_cand][0]
        end_addr = module_memory_map[module_cand][1]

        if addr >= base_addr and addr < end_addr:
            module = module_cand
            reladdr = addr - base_addr
            break

    if not module:
        return (None, None)

    return (module, reladdr)


def main(argv=None):
    '''Command line options.'''

    program_name = os.path.basename(sys.argv[0])

    if argv is None:
        argv = sys.argv[1:]

    # setup argparser
    parser = argparse.ArgumentParser(usage='%s (EXTRA_FILE SYMBOLS_DIR | --remote CRASH_ID)' % program_name)
    parser.add_argument("--remote", dest="remote", help="Remote mode, fetch a crash from Socorro", metavar="CRASH_ID")
    parser.add_argument("--parse-local", dest="parse_local", help="Download symbol files and parse them locally", action="store_true")
    parser.add_argument('rargs', nargs=argparse.REMAINDER)

    if not argv:
        parser.print_help()
        return 2

    opts = parser.parse_args(argv)

    if not opts.remote and len(opts.rargs) < 2:
        parser.print_help()
        return 2

    # We need two stacks, the allocation stack and the free stack
    alloc_stack = None
    free_stack = None

    # The module memory map contains all the information about loaded
    # modules and their address ranges, required to resolve absolute
    # addresses to relative debug symbol addresses.
    module_memory_map = None

    # Directory where we either have local symbols or store remote symbols
    symbols_dir = None

    # Symbol server response, in case we use the remote API
    symbol_server_response = None

    if opts.remote:
        if SOCORRO_AUTH_TOKEN is None:
            print("Error: Must specify SOCORRO_AUTH_TOKEN in environment for remote actions.", file=sys.stderr)
            return 2

        (alloc_stack, free_stack, module_memory_map, remote_symbols_files, memory_map_remote) = fetch_socorro_crash(opts.remote)

        if not opts.parse_local:
            # We will query the symbol server to get the stacks symbolized.
            request = {
                "memoryMap": memory_map_remote,
                "stacks": []
            }
            for stack in [alloc_stack, free_stack]:
                if stack is not None:
                    stacks = []
                    for addr in stack:
                        (module, reladdr) = find_module(addr, module_memory_map)

                        if module is None:
                            stacks.append([0, 0])
                            continue

                        if module not in debugmap:
                            stacks.append([0, 0])
                            continue

                        idx = 0
                        found = False
                        for map_entry in memory_map_remote:
                            if map_entry[0] == debugmap[module]:
                                found = True
                                break
                            idx += 1

                        if not found:
                            print("Error: Module entry not found: %s" % module, file=sys.stderr)
                            return 2

                        stacks.append([idx, reladdr])

                    request["stacks"].append(stacks)

            symbol_server_response = requests.post("https://symbolication.services.mozilla.com/symbolicate/v5", json=request).json()
            if "results" not in symbol_server_response:
                print("Error in server response: %s" % symbol_server_response, file=sys.stderr)
                return 2
        else:
            # We will download the symbol files and parse them ourselves.
            symbols_dir = os.path.join(os.path.expanduser("~"), ".phc-symbols-cache")
            symbols_dir += os.sep

            if not os.path.exists(symbols_dir):
                os.mkdir(symbols_dir)

            for symbol_url in remote_symbols_files:
                if symbol_url != None:
                    fetch_remote_symbols(symbol_url, symbols_dir)

            sys.stderr.write("Loading downloaded symbols...")
            load_symbols_recursive(symbols_dir)
            print(" done!", file=sys.stderr)
    else:
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

        sys.stderr.write("Loading local symbols...")
        load_symbols_recursive(symbols_dir)
        print(" done!", file=sys.stderr)

        (alloc_stack, free_stack, module_memory_map) = read_extra_file(extra_file)

    def print_stack(phc_stack, name, symbols, module_memory_map):
        stack_cnt = 0

        print("%s stack:" % name)
        print("")
        for addr in phc_stack:
            (module, reladdr) = find_module(addr, module_memory_map)

            if not module:
                print("#%s    (frame in unknown module)" % stack_cnt)
                stack_cnt += 1
                continue

            if module not in symbols:
                # On Windows, the sym file is called xul.sym, *not* xul.dll.sym
                # unlike on Linux where it is called xul.so.sym.
                tmp = os.path.splitext(module)[0]
                if tmp in symbols:
                    module = tmp
                else:
                    print("#%s    (missing symbols for module %s %s)" % (stack_cnt, module, hex(reladdr)))
                    stack_cnt += 1
                    continue

            symbol_entry = None
            for sym in symbols[module]:
                if sym[0] <= reladdr and (sym[0] + sym[1]) > reladdr:
                    print("#%s    %s" % (stack_cnt, sym[2]))
                    symbol_entry = sym
                    break

            if not symbol_entry:
                # There is still a chance that we have a PUBLIC symbol without
                # file/line information available.
                if module in symbols_public:
                    for sym in symbols_public[module]:
                        if sym[0] <= reladdr and sym[1] > reladdr:
                            print("#%s    %s (%s +%s)" % (stack_cnt, sym[2], module, hex(reladdr)))
                            symbol_entry = sym
                            break

                if not symbol_entry:
                    print("#%s    ??? (unresolved symbol in %s +%s)" % (stack_cnt, module, hex(reladdr)))
            else:
                (line, filenum) = retrieve_file_line_data_binsearch(symbol_entry, reladdr)
                symfile = symbol_entry[3]
                if filenum and symfile in filemap:
                    print("    in file %s line %s" % (filemap[symfile][filenum], line))

            stack_cnt += 1

    def print_stack_remote(stack, name):
        print("%s stack:" % name)
        print("")

        for entry in stack:
            frame = "???"
            if "frame" in entry:
                frame = entry["frame"]
            function = "???"
            if "function" in entry:
                function = entry["function"]
            module = "???"
            if "module" in entry:
                module = entry["module"]

            print("#%s    %s (%s)" % (frame, function, module))

    if symbol_server_response:
        stacks = symbol_server_response["results"][0]["stacks"]
        if (len(stacks) > 1):
            print("")
            print_stack_remote(stacks[1], "Free")
        print("")
        print_stack_remote(stacks[0], "Alloc")
    else:
        if free_stack is not None:
            print("")
            print_stack(free_stack, "Free", symbols, module_memory_map)
        print("")
        print_stack(alloc_stack, "Alloc", symbols, module_memory_map)


if __name__ == '__main__':
    main()
