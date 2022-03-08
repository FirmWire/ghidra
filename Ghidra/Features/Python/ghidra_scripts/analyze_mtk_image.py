## ###
#  IP: Apache License 2.0
# 
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#  
#       http://www.apache.org/licenses/LICENSE-2.0
#  
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
##
# Analysis script for loading MediaTek firmware images
# @category: Examples.Python

#@category FirmWire

""" Load a MIPS-based MTK firmware image.
The script will work on a newly loaded image (which should not have undergone auto-analysis).

The script will perform a full auto-analysis using the following steps:
1. Remap file to BASE_ADDR
2. Based on given symbols file (md1_dbginfo.csv exported from md1_dbginfo)
    - Move 0-based symbols up to 0x9-based memory region
    - Map memory regions from emulating memory initialization functions (INT_InitRegions_C and different functions called from there)
3. Add entry points for known symbols
4. Disassemble at entry points and try to create functions in 3 stages:
4.1 Start at known symbols and function prologue mnemonics
4.2 Full auto analysis from these functions
4.3 m32 vs m16 mode detection from data references (0-alignment: m32, 1-alignment: m16)
4.4 Brute-force m16 + m32 disassembly
4.5 Fall-back label creation
5. Auto-analysis stale error Bookmark removal

Tested on two different a41 images:
- A415FXXU1ATE1
- A415FXXU1BUA1
"""

BASE_ADDR = 0x90000000

import struct, os, array

import ghidra
from ghidra.app.cmd.disassemble import MipsDisassembleCommand
from ghidra.app.emulator import EmulatorHelper
from ghidra.program.model.address import Address, AddressSet, AddressRangeImpl
from ghidra.program.model.listing import BookmarkType
from ghidra.program.model.symbol import RefType, SourceType

currentProgram = getCurrentProgram()
functionManager = currentProgram.getFunctionManager()
bookmarkManager = currentProgram.getBookmarkManager()
addr_factory = currentProgram.getAddressFactory()
md1rom_filebytes = currentProgram.getMemory().getAllFileBytes()[0]

FN_MODE_NONE = 0
FN_MODE_16 = 1
FN_MODE_32 = 2
MODE_32bit_mnems = [
    "SPECIAL2",
    "save"
]
MODE_32bit_mnems = [s.lower() for s in MODE_32bit_mnems]
MODE_16bit_mnems = [
    "save"
]
MODE_16bit_mnems = [s.lower() for s in MODE_16bit_mnems]
def get_mnem(addr):
    instr = getInstructionAt(toAddr(addr))
    if instr:
        return instr.getMnemonicString().lower()
    else:
        return None

def get_bytes(addr_long, length):
    vals = array.array('b', length*b"\0")
    currentProgram.getMemory().getBytes(toAddr(addr_long), vals)
    return vals.tostring()

def try_disassemble(start, end, mips16=False, do_analyze=True):
    start_address = toAddr(start)
    end_address   = toAddr(end-1)
    addresses = AddressSet(AddressRangeImpl(start_address, end_address))
    clearListing(start_address, end_address)
    cmd = MipsDisassembleCommand(start_address, addresses, mips16)
    if not do_analyze:
        cmd.enableCodeAnalysis(do_analyze)
    ret = cmd.applyTo(currentProgram)
    return cmd.getDisassembledAddressSet()

def disassemble_at(start, mips16=False):
    print("Starting disassembling at 0x{:08x}".format(start))
    start_address = toAddr(start)
    cmd = MipsDisassembleCommand(start_address, None, mips16)
    ret = cmd.applyTo(currentProgram)

function_count = 0
def try_function(start, end, name):
    global function_count
    address = toAddr(start)
    end_address = toAddr(end-1)
    func = functionManager.getFunctionAt(address)
    if func is not None:
        removeFunction(func)
    func = createFunction(address, name)
    if func is None:
        print("Failed function {} at address {}".format(name, address))
        return False
    addr_set = addr_factory.getAddressSet(address, end_address)
    func.body.add(addr_set)
    print("Created function {} at address {}".format(name, address))

    for bookmark in bookmarkManager.getBookmarksIterator(toAddr(start), True):
        print("removing bookmark {}".format(bookmark))
        bookmarkManager.removeBookmark(bookmark)

    function_count += 1
    if function_count % 200 == 0:
        print("[*] Added a bunch of functions, analyzing differences ({} now)...".format(function_count))
        analyzeChanges(currentProgram)

    return True

def detect_mode(start):
    # 1. disassemble single instruction in both modes
    # 2. compare opcode to candidate list of prologue opcode
    # 3. if not candidate, unchosen

    # 16 bit
    try_disassemble(start, start+4, True, do_analyze=False)
    mnem = get_mnem(start)

    if mnem:
        # print("16 bit: ", mnem)
        if mnem in MODE_16bit_mnems:
            clearListing(toAddr(start), toAddr(start+4))
            return FN_MODE_16

    # 32 bit
    try_disassemble(start, start+4, False, do_analyze=False)
    mnem = get_mnem(start)
    clearListing(toAddr(start), toAddr(start+4))
    if mnem:
        # print("32 bit: ", mnem)
        if mnem in MODE_32bit_mnems:
            return FN_MODE_32

    return FN_MODE_NONE

num_handled = 0
def handle_fn_disass(start, end, name, stage=0):
    global num_handled
    num_handled += 1
    if num_handled % 1000 == 0:
        print("Handled {} now...".format(num_handled))
    
    # First check whether the start address is actually mapped
    if not getMemoryBlock(toAddr(start)):
        # Not mapped, we are done here
        return True

    # Look for existing functions
    func = functionManager.getFunctionAt(toAddr(start))
    if func is not None:
        if func.getName() != name:
            print("Found existing function at 0x{:08x}, renaming to {}".format(start, name))
            try:
                func.setName(name, SourceType.USER_DEFINED)
            except ghidra.util.exception.DuplicateNameException:
                pass
        return True

    existing_sym = getSymbolAt(toAddr(start))
    if existing_sym and str(existing_sym)[:4] in ("SUB_", "LAB_"):
        # TODO: can we find a subroutine in another way?
        print("Found subroutine at 0x{:08x}".format(start))
        return try_function(start, end, name)

    existing_instr = getInstructionAt(toAddr(start))
    if existing_instr is not None:
        print("Found instruction at 0x{:08x}".format(start))
        return try_function(start, end, name)

    # Stage 0: heuristic via prologue opcodes
    mode = detect_mode(start)

    if mode == FN_MODE_16:
        disassemble_at(start, True)
        return try_function(start, end, name)
    elif mode == FN_MODE_32:
        disassemble_at(start, False)
        return try_function(start, end, name)

    if mode == FN_MODE_NONE and stage==0:
        # print("Skipping function for the moment")
        return False

    # Stage 1: look at data xrefs
    refs_m32 = [r for r in getReferencesTo(toAddr(start)) if r.getReferenceType() != RefType.EXTERNAL_REF]
    refs_m16 = [r for r in getReferencesTo(toAddr(start+1)) if r.getReferenceType() != RefType.EXTERNAL_REF]

    if stage == 1:
        if (not refs_m32) and refs_m16:
            # Has to be m16
            mode_16 = True

        elif (not refs_m16) and refs_m32:
            # Has to be m32
            mode_16 = False
        else:
            return False

        print("[+] disassemble because of references: 0x{:08x} ({})".format(start, name))
        disassemble_at(start, mode_16)
        return try_function(start, end, name)

    # Stage 2: Just try to disassemble without additional context
    elif stage == 2:
        print("handle last-ditch disassemble for: 0x{:08x} ({})".format(start, name))

        try:
            disas_set = try_disassemble(start, end, True)
            success = False
            if (disas_set is not None and not disas_set.isEmpty()) and (
                ((disas_set.getMaxAddress().getOffset() - disas_set.getMinAddress().getOffset()) >= (end-start) / 4 )):
                success = try_function(start, end, name)
            if success is False:
                print("Retrying as MIPS32...")
                disas_set = try_disassemble(start, end, False)
                if disas_set is not None and not disas_set.isEmpty():
                    success = try_function(start, end, name)
            if success:
                last_disass_addr = disas_set.getMaxAddress()
                if last_disass_addr is not None:
                    last_disass_addr = last_disass_addr.getOffset()
                    for bookmark in bookmarkManager.getBookmarksIterator(toAddr(start), True):
                        if bookmark.getAddress().getOffset() > last_disass_addr:
                            break
                        print("removing bookmark {}".format(bookmark))
                        bookmarkManager.removeBookmark(bookmark)
            return success
        except Exception as e:
            print(e)
            return False

    return False

def parse_debug_csv(filename):
    # [(start, end, name)]
    entries = []

    with open(filename, "r") as f:
        # Header
        f.readline()
        for line in f.readlines():
            # INT_Vectors 2096 16 UNKOWN FUNC
            if line.count(" ") != 4:
                continue
            name, start, length = line.split(" ")[:3]
            start, length = int(start), int(length)
            entries.append((start, start+length, name))

    return entries

def get_dword(addr):
    return struct.unpack("<I", struct.pack("<i", currentProgram.getMemory().getInt(toAddr(addr))))[0]

def emulate_custom_mk_ram_info(entry="custom_mk_ram_info", out_addr = 0x64000000, out_addr_mask=0xff000000, verbose=False):
    FAKE_RETURN = 0
    FAKE_SP = 0xff000000

    if isinstance(entry, str):
        fn_entry = getSymbol(entry, None).getAddress().getOffset()
    else:
        fn_entry = entry
    emu_helper = EmulatorHelper(currentProgram)
    emu_helper.enableMemoryWriteTracking(True)

    # Set controlled return location so we can identify return from emulated function
    ret_addr = toAddr(FAKE_RETURN)

    # Set initial PC
    emu_helper.writeRegister(emu_helper.getPCRegister(), fn_entry)

    # Set Register State
    emu_helper.writeRegister("ra", FAKE_RETURN)
    emu_helper.writeRegister("sp", FAKE_SP)

    print("Emulation starting at 0x{}".format(fn_entry))
    while monitor.isCancelled() is False:
        # Check the current address in the program counter, if it's
        # zero (our `FAKE_RETURN` value) stop emulation.
        # Set this to whatever end target you want.
        curr_pc = emu_helper.getExecutionAddress()
        if (curr_pc == ret_addr):
            print("Emulation complete.")
            break

        if verbose:
            # print current instruction and the registers we care about
            print("Address: 0x{} ({})".format(curr_pc, getInstructionAt(curr_pc)))
            for reg in ("s1", "a0", "v0", "v1"):
                print("  {} = {:#010x}".format(reg, emu_helper.readRegister(reg)))

        # single step emulation
        success = emu_helper.step(monitor)
        if (success == False):
            err = emu_helper.getLastError()
            printerr("Emulation Error: '{}'".format(err))
            break

    table_start = None
    for addr_range in emu_helper.getTrackedMemoryWriteSet():
        for addr in addr_range:
            addr = addr.getOffset()
            if addr & out_addr_mask == out_addr & out_addr_mask and addr & 3 == 0:
                print("Found first write at 0x{:08x}, scanning from here".format(addr))
                table_start = addr
                break

    regions = []
    if table_start is None:
        print("[-] Could not find table start")
    else:
        RESULT_SIZE = 0x400
        mapping_info_bytes = emu_helper.readMemory(toAddr(table_start), RESULT_SIZE)
        dws = struct.unpack("<"+(RESULT_SIZE//8)*"II", mapping_info_bytes)
        for i in range(0, len(dws), 2):
            addr, size = dws[i:i+2]
            if size > 0:
                regions.append((addr, addr+size))

        # Print sorted by start
        print("=== Address ranges ===")
        regions.sort(key=lambda r: r[0])
        for start, end in regions:
            print("0x{:08x} - 0x{:08x}".format(start, end))

    # Cleanup resources and release hold on currentProgram
    emu_helper.dispose()
    return regions

def map_uninitialized_holes(ranges):
    for new_start, new_end in ranges:
        colliding_block_ranges = []
        for block in getMemoryBlocks():
            # TODO: Skip overlay blocks
            # Python API seems broken here
            #if block.isOverlay():
            if block.getName().startswith("sys_mem_"):
                # We are loading from a dump, don't add uninitialized regions.
                return
            #if block.getType() == MemoryBlockType.OVERLAY:
            #    continue

            block_start = block.getStart().getOffset()
            block_end = block_start + block.getSize()
            if block_end <= new_start or block_start >= new_end:
                continue
            colliding_block_ranges.append((max(new_start, block_start), min(new_end, block_end)))

        if colliding_block_ranges:
            colliding_block_ranges.sort(key=lambda r: r[0])
            to_be_mapped_ranges = []

            print("Found collisions for region {:#08x} - {:#10x}".format(new_start, new_end))
            for i, (conflicting_start, conflicting_end) in enumerate(colliding_block_ranges):
                print("{:d}: {:#08x} - {:#010x}".format(i+1, conflicting_start,conflicting_end))
                if new_start != conflicting_start:
                    to_be_mapped_ranges.append((new_start, conflicting_start))
                new_start = conflicting_end
                if new_start >= new_end:
                    break

            if new_start + 1 < new_end:
                to_be_mapped_ranges.append((new_start, new_end))

            print("Left to be mapped:")
            for i, (start, end) in enumerate(to_be_mapped_ranges):
                print("{:d}: {:#08x} - {:#010x}".format(i+1, start, end))
                name = "uninit_block_{:08x}_{:08x}".format(start, end)
                try:
                    getCurrentProgram().getMemory().createUninitializedBlock(name, toAddr(start), end-start, False).setPermissions(True, True, False)
                except ghidra.program.model.mem.MemoryConflictException as e:
                    print("Cannot map uninitialized block: {}".format(e))

def add_map(name, addr, length, from_addr=None, contents=None, exec_perm=False, write_perm=True, read_perm=True):
    global md1rom_filebytes
    existing_block = getMemoryBlock(toAddr(addr))
    if existing_block is not None:
        print("Already mapped region at 0x{:08x}, skipping".format(addr))
        if existing_block.getStart().getOffset() == addr and existing_block.getName() != name:
            print("Renaming block to {}".format(name))
            existing_block.setName(name)
            existing_block.setPermissions(read_perm, write_perm, exec_perm)
        return
    elif length == 0:
        print("Skipping zero-sized region at 0x{:08x}, skipping".format(addr))
        return
    elif length < 0:
        print("Bug: negatively-sized ({}) region at 0x{:08x}, skipping".format(length, addr))
        assert(False)
    #elif (0x64000000 <= addr <= 0x66000000) or (0x64000000 <= addr+length <= 0x66000000):
    #    print("Skipping region at 0x{:08x} which would result in false-positive pointer assumptions".format(addr))
    #    return

    if contents is not None:
        assert(from_addr is None)
        assert(False)
        # TODO: map contents
        pass

    elif from_addr is not None:
        assert(contents is None)
        # Zero address aliases to higher segment
        print("Mapping 0x{:x} bytes from {:08x} - {:08x}".format(length, from_addr, addr))
        if from_addr < md1rom_filebytes.getSize():
            from_addr |= BASE_ADDR

        overlay = False
        block = currentProgram.getMemory().createInitializedBlock(name, toAddr(addr), length, 0, None, overlay)
        block.setPermissions(read_perm, write_perm, exec_perm)
        vals = array.array('b', length*b"\0")
        currentProgram.getMemory().getBytes(toAddr(from_addr), vals)
        block.putBytes(toAddr(addr), vals)

        # print(file_bytes_ref)
        pass

    else:
        # TODO: map uninitialized
        print("Mapping 0x{:x} uninitialized bytes at {:08x}".format(length, addr))
        currentProgram.getMemory().createUninitializedBlock(name, toAddr(addr), length, False).setPermissions(read_perm, write_perm, exec_perm)
        pass

def extract_SPRAM_mappings(entries_by_name, src_sym, dst_sym, end_sym):
    """ INT_InitSPRAMRegions_C
    Automatic extraction:
    - last dword inside functions (after code of) custom_get_ISPRAM_Load_Base / custom_get_ISPRAM_CODE_Base / custom_get_ISPRAM_CODE_End
    -> points to array of addresses per core (in this case: core 0 and core 1)
    """
    start, end = entries_by_name[src_sym]
    addr_table_start = get_dword(end-4)
    spram_memcpy_srces = (get_dword(addr_table_start), get_dword(addr_table_start+4))

    start, end = entries_by_name[dst_sym]
    addr_table_start = get_dword(end-4)
    spram_memcpy_dests = (get_dword(addr_table_start), get_dword(addr_table_start+4))
    
    start, end = entries_by_name[end_sym]
    addr_table_start = get_dword(end-4)
    spram_memcpy_ends = (get_dword(addr_table_start), get_dword(addr_table_start+4))
    spram_memcpy_sizes = (spram_memcpy_ends[0]-spram_memcpy_dests[0],spram_memcpy_ends[1]-spram_memcpy_dests[1])
    
    return list(zip(spram_memcpy_srces, spram_memcpy_dests, spram_memcpy_sizes))

def extract_and_add_mappings(entries_by_name):
    ispram_mappings = extract_SPRAM_mappings(entries_by_name, "custom_get_ISPRAM_Load_Base", "custom_get_ISPRAM_CODE_Base", "custom_get_ISPRAM_CODE_End")
    dspram_mappings = extract_SPRAM_mappings(entries_by_name, "custom_get_DSPRAM_Load_Base", "custom_get_DSPRAM_DATA_Base", "custom_get_DSPRAM_DATA_End")

    mapping = ispram_mappings[0]
    name, src, dst, length = "ispram_cpu0", mapping[0], mapping[1], mapping[2]
    add_map(name, dst, length, src, exec_perm=True)
    mapping = ispram_mappings[1]
    name, src, dst, length = "ispram_cpu1", mapping[0], mapping[1], mapping[2]
    add_map(name, dst, length, src, exec_perm=True)
    mapping = dspram_mappings[0]
    name, src, dst, length = "dspram_cpu0", mapping[0], mapping[1], mapping[2]
    add_map(name, dst, length, src)
    mapping = dspram_mappings[1]
    name, src, dst, length = "dspram_cpu1", mapping[0], mapping[1], mapping[2]
    add_map(name, dst, length, src)
    
    #for src, dst, length in ispram_mappings + :
    #    print("Mapping 0x{:x} bytes from {:08x} - {:08x}".format(length, src, dst))

    """ INT_InitPerCoreRegion_C
    Automatic extraction: 
    - last dwords of function INT_InitPerCoreRegion_C are pointers in the following format:
        | memcpy_size | memcpy_src | memcpy_dst | memset_size | memset_addr |
    -> starting from end of INT_InitPerCoreRegion_C, parse "structs" according to above and map regions
    """
    if "INT_InitPerCoreRegion_C" in entries_by_name:
        print("[*] Mapping regions for INT_InitPerCoreRegion_C")
        start, end = entries_by_name["INT_InitPerCoreRegion_C"]
        # TODO: automate this? possibly by scanning from end and detecting the restore + jrc opcodes
        num_percore_regions = 4
        NUM_FIELDS = 5
        cursor = end - 4 * NUM_FIELDS
        for cpu_num in range(2):
            for i in range(num_percore_regions, 0, -1):
                memcpy_size, memcpy_src, memcpy_dst, memset_size, memset_addr = get_dword(cursor), get_dword(cursor+4), get_dword(cursor+8), get_dword(cursor+12), get_dword(cursor+16)
                cursor = end - 4 * NUM_FIELDS
                name = "cpu_{}_percore_region_{}".format(cpu_num, i)
                add_map(name, memcpy_dst, memcpy_size, memcpy_src)
                name = "cpu_{}_percore_region_{}_bss".format(cpu_num, i)
                add_map(name, memset_addr, memset_size)

    """ INT_InitL2cacheLockRegion_C
    Automatic extraction:
    - At end of INT_InitL2cacheLockRegion_C, a single set of pointers resides with the following format:
       | memcpy_size | memcpy_dst | memcpy_src | memset_size | memset_addr | lockcache_start | lockcache_end |
    -> extract
    """
    if "INT_InitL2cacheLockRegion_C" in entries_by_name:
        print("[*] Mapping regions for INT_InitL2cacheLockRegion_C")
        start, end = entries_by_name["INT_InitL2cacheLockRegion_C"]
        cursor = end - 7*4
        memcpy_size, memcpy_dst, memcpy_src, memset_size, memset_addr = get_dword(cursor), get_dword(cursor+4), get_dword(cursor+8), get_dword(cursor+12), get_dword(cursor+16)
        add_map("L2CacheRegion", memcpy_dst, memcpy_size, memcpy_src, exec_perm=True, write_perm=False)
        add_map("L2CacheRegion_bss", memset_addr, memset_size)

    """ INT_InitRegions_C
    Automatic extraction:
    - InitRegions_C: 0x90e5e91c - 0x90e5ec88
    - Data after function code has array in the form
        | memcpy_size | memcpy_src | memcpy_dst | memset_size | memset_src
    - Exception: Entry 3 has an additional dword for an offset to start memsetting from
        | memcpy_size | memcpy_src | memcpy_dst | memset_skip | memset_tot_size | memset_src
    -> we can scan backwards from end of InitRegions_C and extract these pointers/values
    -> to find the outlier, check whether memset_size > memcpy_dst and assume second format
    """
    if "INT_InitRegions_C" in entries_by_name:
        print("[*] Mapping regions for INT_InitRegions_C")
        region_names = [
            "CACHED_EXTSRAM_NVRAM_LTABLE",
            "Image_DYNAMIC_CACHEABLE_EXTSRAM_DEFAULT_NONCACHEABLE_RW",
            "DYNAMIC_CACHEABLE_EXTSRAM_DEFAULT_CACHEABLE_RW",
            "DYNAMIC_CACHEABLE_EXTSRAM_DEFAULT_NONCACHEABLE_RW",
            "DYNAMIC_CACHEABLE_EXTSRAM_DEFAULT_NONCACHEABLE_MCURW_HWRW",
            "DYNAMIC_CACHEABLE_EXTSRAM_DEFAULT_CACHEABLE_MCURW_HWRW",
            "CACHED_EXTSRAM_IOCU2_MCURW_HWRW",
            "CACHED_EXTSRAM_IOCU3_READ_ALLOC_MCURW_HWRW",
            "EXTSRAM_MCURW_HWRW",
            "CACHED_EXTSRAM_MCURW_HWRW",
            "EXTSRAM_DSP_TX",
            "EXTSRAM_DSP_RX",
            "CACHED_EXTSRAM"
        ]

        start, end = entries_by_name["INT_InitRegions_C"]
        cursor = end
        NUM_FIELDS = 5
        for i in range(len(region_names)-1, -1, -1):

            cursor -= NUM_FIELDS * 4
            memcpy_size, memcpy_src, memcpy_dst, memset_size, memset_addr = get_dword(cursor), get_dword(cursor+4), get_dword(cursor+8), get_dword(cursor+12), get_dword(cursor+16)

            # TODO: last memset is done via start / end...
            if i == len(region_names)-1:
                memset_size = memset_addr - memset_size

            elif memset_size > memcpy_dst:
                print("[*] memset_size > memcpy_dst ({:x} < {:x}) heuristic hit, adjusting cursor by 4 bytes".format(memset_size, memcpy_dst))
                cursor -= 4
                memcpy_size, memcpy_src, memcpy_dst, memset_skip, memset_size, memset_addr = get_dword(cursor), get_dword(cursor+4), get_dword(cursor+8), get_dword(cursor+12), get_dword(cursor+16), get_dword(cursor+20)

            add_map(region_names[i], memcpy_dst, memcpy_size, memcpy_src)
            add_map(region_names[i]+"_bss", memset_addr, memset_size)

    if 'custom_mk_ram_info' in entries_by_name:
        # Emulate custom_mk_ram_info and add missing regions
        start, end = entries_by_name['custom_mk_ram_info']

        if handle_fn_disass(start, end, 'custom_mk_ram_info', stage=0):
            print("[*] Mapping leftover regions via emulation of custom_mk_ram_info")
            regions = emulate_custom_mk_ram_info('custom_mk_ram_info')
            map_uninitialized_holes(regions)
        else:
            print("[-] Could not disassemble custom_mk_ram_info with high confidence...")

def disass_functions(entries):
    # Add all function symbols as entry points for disassembly
    remaining_fns = []
    for start, end, name in entries:
        remaining_fns.append((start, end, name))
        addEntryPoint(toAddr(start))

    # Run iteratively:
    # - Figure out correct function entry instruction mode
    # - As long as we have changes, try figuring out more function disassembly
    # Then, mix in Ghidra's auto analysis in the middle and go again
    for stage in [0, 1, 2]:
        if stage == 1:
            # Let Ghidra do its analysis after initial disassembly round
            print("[*] Kicking off full auto analysis now. This will take a while...")
            analyzeAll(currentProgram)
        print("######## STAGE {} - working on {} functions ########".format(stage, len(remaining_fns)))
        has_changes = True
        while remaining_fns and has_changes:
            has_changes = False

            handled_fns = []
            for start, end, name in remaining_fns:
                if handle_fn_disass(start, end, name, stage) is True:
                    handled_fns.append((start,end, name))
                    has_changes = True
            for fn in handled_fns:
                remaining_fns.remove(fn)
            print("Removed {} functions after this round. Remaining: {}".format(len(handled_fns), len(remaining_fns)))

            print("[*] Auto-analysis of changes...")
            analyzeChanges(currentProgram)

    print("[*] Kicking off second auto analysis now")
    analyzeChanges(currentProgram)

    for start, end, name in remaining_fns:
        print("Creating label at 0x{:08x}: {}".format(start, name))
        createLabel(toAddr(start), name, False)
    print("Leftover at the end: {}".format(remaining_fns))

def cleanup_branch_delay_slots():
    # Clean up NOPs/other instructions which are at the end of function assembly
    function = getFirstFunction()
    while function is not None:
        max_addr = function.getBody().getMaxAddress().getOffset()
        insn = getInstructionAt(toAddr(max_addr - 1))
        if insn and insn.getMnemonicString().startswith("jr"):
            after_addr = toAddr(max_addr+1)
            if getInstructionAt(after_addr) is None and getDataAt(after_addr) is None:
                print("-> Need to disassemble at {:#010x}".format(max_addr+1))
                try_disassemble(after_addr.getOffset(), after_addr.getOffset()+1, mips16=True, do_analyze=False)
        function = getFunctionAfter(function)

def create_pointers(blocks, opt_block_names=()):
    blocks = blocks[:]
    for name in opt_block_names:
        memory_block = getMemoryBlock(name)
        if memory_block:
            blocks.append(memory_block)

    for memory_block in blocks:
        base_addr = memory_block.getStart().getOffset()
        for i in range(0, memory_block.getSize(), 4):
            loc = base_addr+i
            if getFunctionContaining(toAddr(loc)) != None:
                continue
            dw = get_dword(loc)
            fn = getFunctionAt(toAddr(dw & ~1))

            if fn is not None:
                print("Found {:#010x}: {:#010x} -> '{}'".format(loc, dw, fn.getName()))
                curr_data = getDataAt(toAddr(loc))
                if curr_data is None or (curr_data.getDataType().getName() != "pointer"):
                    print("### Not a pointer yet, creating pointer")

                    datatype = currentProgram.getDataTypeManager().getPointer(None)
                    for i in range(4):
                        clearListing(toAddr(loc+i))
                    createData(toAddr(loc), datatype)
                else:
                    print("Already a pointer")


def main():
    global main_block

    zero_block = getMemoryBlock(toAddr(0))
    main_block = getMemoryBlock(toAddr(BASE_ADDR))
    if main_block is None:
        if zero_block is None:
            print("[-] Cannot find main memory block")
            return
        else:
            print("[*] Moving base image to 0x{:08x}".format(BASE_ADDR))
            currentProgram.setImageBase(toAddr(BASE_ADDR), True)
    main_block = getMemoryBlock(toAddr(BASE_ADDR))
    main_block.setWrite(False)

    DEBUGINFO_CSV_FILENAME="md1_dbginfo.csv"
    debug_file = os.path.join(os.path.dirname(str(getProgramFile())), DEBUGINFO_CSV_FILENAME)
    if not os.path.isfile(debug_file):
        debug_file = str(askFile("Choose debug file (e.g. {})", "Choose".format(DEBUGINFO_CSV_FILENAME)))
        if not os.path.isfile(debug_file):
            print("[-] debug file does not exist")
            return
    else:
        print("[+] Found debug file at '{}'".format(debug_file))

    entries = parse_debug_csv(debug_file)

    entries_by_name = {name: (start, end) for (start, end, name) in entries}
    extract_and_add_mappings(entries_by_name)

    disass_functions(entries)

    blocks = [main_block]
    add_region_names = ("L2CacheRegion", "dspram_cpu0", "ispram_cpu0", "CACHED_EXTSRAM")
    create_pointers(blocks, add_region_names)

    cleanup_branch_delay_slots()

    # Remove " bad instruction" bookmarks as these got added while trying different
    # modes at function starts
    for bookmark in bookmarkManager.getBookmarksIterator(BookmarkType.ERROR):
        if bookmark.getCategory() == "Bad Instruction":
            if getInstructionAt(bookmark.getAddress()) is not None:
                print("removing bookmark {}".format(bookmark))
                bookmarkManager.removeBookmark(bookmark)

if __name__ == '__main__':
    main()