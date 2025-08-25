import sys
import re

def _parse_input_data(input_str):
    """Parses the input string, collecting all opcode blocks and headers."""
    lines = input_str.splitlines()
    opcode_blocks = []
    current_block = []
    current_header = ""
    cave_start = None
    
    header_pattern = re.compile(r"\[([^\]]+)\]")
    line_pattern = re.compile(r"(\w{2})(\w{2})0000 (\w{8}) (\w{8})(?: (\w{8}))?")
    cave_start_pattern = re.compile(r"cave_start= *(0x)?([0-9a-fA-F]+)")

    for line in lines:
        line = line.strip()
        if not line:
            if current_block:
                opcode_blocks.append((current_header, current_block))
                current_block = []
                current_header = ""
            continue

        match = cave_start_pattern.match(line)
        if match:
            cave_start = int(match.group(2), 16)
            continue
        
        match = header_pattern.match(line)
        if match:
            if current_block:
                opcode_blocks.append((current_header, current_block))
                current_block = []
            current_header = line
            continue
            
        match = line_pattern.match(line)
        if match:
            prefix = match.group(1)
            reg_val = match.group(2)
            addr = int(match.group(3), 16)
            opcode_part1 = int(match.group(4), 16)
            
            if prefix == "08":
                opcode_part2 = int(match.group(5), 16)
                opcode = (opcode_part1 << 32) | opcode_part2
            else:
                opcode = opcode_part1
                
            current_block.append((addr, opcode, prefix, reg_val))

    if current_block:
        opcode_blocks.append((current_header, current_block))
        
    return cave_start, opcode_blocks

def _calculate_target_address(addr, opcode):
    """Calculates the target address of a PC-relative instruction."""
    # B/BL (26-bit immediate)
    if (opcode & 0xFC000000) in [0x14000000, 0x94000000]:
        offset = ((opcode & 0x3FFFFFF) << 2)
        if offset & 0x02000000:
            offset |= 0xFC0000000
        return addr + offset
    
    # LDR (literal) (19-bit immediate)
    elif (opcode & 0x7F000000) == 0x18000000:
        offset = ((opcode >> 5) & 0x7FFFF) << 2
        if offset & 0x00040000:
            offset |= 0xFFFC0000
        return addr + 8 + offset
    
    # ADR (21-bit immediate)
    elif (opcode & 0x9F000000) == 0x10000000:
        offset = ((opcode >> 29) & 0x3) | ((opcode >> 5) & 0x7FFFF) << 2
        if offset & 0x00040000:
            offset |= 0xFFFC0000
        return addr + offset

    return None

def _recalculate_branch_offset(old_opcode, current_pc, new_target_addr):
    """Recalculates the offset for a B/BL branch instruction."""
    imm26 = (new_target_addr - current_pc) >> 2
    new_opcode = (old_opcode & 0xFC000000) | (imm26 & 0x3FFFFFF)
    return new_opcode

def _recalculate_ldr_literal_offset(old_opcode, current_pc, new_target_addr):
    """Recalculates the offset for a PC-relative LDR literal instruction."""
    imm19 = (new_target_addr - (current_pc + 8)) >> 2
    new_opcode = (old_opcode & 0xFFC0001F) | ((imm19 & 0x7FFFF) << 5)
    return new_opcode

def _recalculate_adr_offset(old_opcode, current_pc, new_target_addr):
    """Recalculates the offset for a PC-relative ADR instruction."""
    offset = new_target_addr - current_pc
    imm_hi = (offset >> 14) & 0x3
    imm_lo = (offset >> 2) & 0x7FFFF
    new_opcode = (old_opcode & 0x9F00001F) | (imm_hi << 29) | (imm_lo << 5)
    return new_opcode

def relocate_cheats(input_str):
    """
    Relocates AArch64 cheat codes by identifying the single branch to an external
    address at the beginning or end of the block, and relocating all other instructions.
    """
    cave_start, opcode_blocks = _parse_input_data(input_str)
    
    if cave_start is None:
        return "Error: `cave_start` not found in input. Please add `cave_start=0x...`"

    all_addresses = {addr for _, block in opcode_blocks for addr, _, _, _ in block}
    relocated_output_lines = []

    for header, block in opcode_blocks:
        if not block:
            continue
        
        is_relocatable = False
        patch_point_addr = None
        
        for addr, opcode, _, _ in block:
            if (opcode & 0xFC000000) in [0x14000000, 0x94000000]: # Check for B/BL
                target = _calculate_target_address(addr, opcode)
                if target is not None and target not in all_addresses:
                    is_relocatable = True
                    patch_point_addr = addr
                    break
        
        if not is_relocatable:
            continue

        relocation_map = {}
        relocation_map[patch_point_addr] = patch_point_addr
        
        current_cave_address = cave_start
        
        for addr, _, _, _ in block:
            if addr != patch_point_addr:
                relocation_map[addr] = current_cave_address
                current_cave_address += 4
                
        relocated_block = []
        
        for i, (addr, opcode, prefix, reg_val) in enumerate(block):
            new_addr = relocation_map.get(addr, addr)
            new_opcode = opcode
            
            pc_for_calc = new_addr
            
            original_target_addr = _calculate_target_address(addr, opcode & 0xFFFFFFFF)
            
            if original_target_addr is not None:
                new_target_addr = relocation_map.get(original_target_addr, original_target_addr)
                
                # Recalculate based on the opcode type
                if (opcode & 0xFC000000) in [0x14000000, 0x94000000]:
                    new_opcode = _recalculate_branch_offset(opcode, pc_for_calc, new_target_addr)
                
                elif (opcode & 0x7F000000) == 0x18000000:
                    new_opcode = _recalculate_ldr_literal_offset(opcode, pc_for_calc, new_target_addr)
    
                elif (opcode & 0x9F000000) == 0x10000000:
                    new_opcode = _recalculate_adr_offset(opcode, pc_for_calc, new_target_addr)
            
            if prefix == "08":
                opcode_hi = new_opcode >> 32
                opcode_lo = new_opcode & 0xFFFFFFFF
                relocated_block.append((prefix, reg_val, new_addr, opcode_hi, opcode_lo))
            else:
                relocated_block.append((prefix, reg_val, new_addr, new_opcode))
        
        relocated_output_lines.append(header)
        for instr in relocated_block:
            if instr[0] == "08":
                relocated_output_lines.append(f"{instr[0]}{instr[1]}0000 {instr[2]:08X} {instr[3]:08X} {instr[4]:08X}")
            else:
                relocated_output_lines.append(f"{instr[0]}{instr[1]}0000 {instr[2]:08X} {instr[3]:08X}")
        relocated_output_lines.append("")

    return "\n".join(relocated_output_lines)

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "relocate":
        input_data = sys.stdin.read()
        output = relocate_cheats(input_data)
        print(output)
    else:
        print("Usage: python relocator.py relocate")
        print("Pipe your cheat code text into standard input.")