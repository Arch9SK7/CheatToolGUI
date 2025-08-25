import sys
import re
import struct
import argparse
from enum import Enum

try:
    from keystone import Ks, KS_ARCH_ARM, KS_ARCH_ARM64, KS_MODE_ARM, KS_MODE_THUMB, KS_MODE_LITTLE_ENDIAN, KsError
    KEYSTONE_AVAILABLE = True
except ImportError:
    KEYSTONE_AVAILABLE = False
    print("FATAL ERROR: Keystone library not found. Please install it with 'pip install keystone-engine'", file=sys.stderr)
    sys.exit(1)

class CheatVmOpcodeType(Enum):
    StoreStatic = 0x0
    BeginConditionalBlock = 0x1
    EndConditionalBlock = 0x2
    ControlLoop = 0x3
    LoadRegisterStatic = 0x4
    LoadRegisterMemory = 0x5
    StoreStaticToAddress = 0x6
    PerformArithmeticStatic = 0x7
    BeginKeypressConditionalBlock = 0x8
    PerformArithmeticRegister = 0x9
    StoreRegisterToAddress = 0xA
    Reserved11 = 0xB
    
    BeginRegisterConditionalBlock = 0xC0 
    SaveRestoreRegister = 0xC1
    SaveRestoreRegisterMask = 0xC2
    ReadWriteStaticRegister = 0xC3
    BeginExtendedKeypressConditionalBlock = 0xC4
    
    DoubleExtendedWidth = 0xF0 
    PauseProcess = 0xFF0 
    ResumeProcess = 0xFF1 
    DebugLog = 0xFFF 

class MemoryAccessType(Enum):
    MainNso = 0
    Heap = 1
    Alias = 2
    Aslr = 3

def mem_type_from_str(s):
    s_lower = s.lower().strip()
    if s_lower == "main": return MemoryAccessType.MainNso
    if s_lower == "heap": return MemoryAccessType.Heap
    if s_lower == "alias": return MemoryAccessType.Alias
    if s_lower == "aslr": return MemoryAccessType.Aslr
    if s_lower == "non-relative": return MemoryAccessType.MainNso
    
    raise ValueError(f"Unrecognized memory type string '{s}'. Valid types are Main, Heap, Alias, Aslr, non-relative.")

def parse_bit_width_int(i):
    if i == 1: return 1
    if i == 2: return 2
    if i == 4: return 4
    if i == 8: return 8
    raise ValueError(f"Invalid bit width integer: {i}. Must be 1, 2, 4, or 8.")

def parse_condition_type(s):
    s_lower = s.lower().strip()
    if s_lower == ">": return 1
    if s_lower == ">=": return 2
    if s_lower == "<": return 3
    if s_lower == "<=": return 4
    if s_lower == "==": return 5
    if s_lower == "!=": return 6
    raise ValueError(f"Invalid condition type: {s}. Must be >, >=, <, <=, ==, or !=.")

def parse_arithmetic_type(s):
    s_lower = s.lower().strip() 
    if s_lower == "add" or s_lower == "+": return 0
    if s_lower == "sub" or s_lower == "-": return 1
    if s_lower == "mul" or s_lower == "*": return 2
    if s_lower == "lsl": return 3
    if s_lower == "lsr": return 4
    if s_lower == "and": return 5
    if s_lower == "or": return 6
    if s_lower == "not": return 7
    if s_lower == "xor": return 8
    if s_lower == "mov" or s_lower == "none": return 9
    if s_lower == "fadd": return 10
    if s_lower == "fsub": return 11
    if s_lower == "fmul": return 12
    if s_lower == "fdiv": return 13
    raise ValueError(f"Invalid arithmetic type: {s}. See documentation for valid types (e.g., add, sub, mul, lsl, lsr, and, or, not, xor, mov, fadd, fsub, fmul, fdiv).")

def assemble_instruction(instruction, arch_type, addr=0):
    try:
        ks_arch = None
        ks_mode = KS_MODE_LITTLE_ENDIAN

        if arch_type.upper() == "ARM64":
            ks_arch = KS_ARCH_ARM64
        elif arch_type.upper() == "ARM32":
            ks_arch = KS_ARCH_ARM
            ks_mode |= KS_MODE_ARM
        else:
            return None, f"Unsupported architecture: {arch_type}. Must be ARM32 or ARM64."

        if ks_arch is None:
            return None, "Keystone architecture not set due to invalid input."

        ks = Ks(ks_arch, ks_mode)
        encoding_raw, count = ks.asm(instruction, addr)
        
        if isinstance(encoding_raw, list):
            encoding_bytes = bytes(encoding_raw)
        elif isinstance(encoding_raw, bytes):
            encoding_bytes = encoding_raw
        else:
            return None, "Keystone returned unexpected type."

        if not encoding_bytes and count == 0:
            return b"", None
            
        return encoding_bytes, None
    except KsError as e:
        return None, str(e)
    except Exception as e:
        return None, str(e)

def parse_int(s):
    if isinstance(s, str):
        if s.lower().startswith('0x'):
            return int(s, 0)
        if re.match(r'^\d+$', s):
            return int(s, 10)
        try:
            return int(s, 0)
        except ValueError:
            pass

    raise ValueError(f"Could not parse '{s}' as an integer.")


def extract_reg_num(reg_str):
    match = re.match(r'R(\d+)', reg_str.strip())
    if not match:
        raise ValueError(f"Invalid register format: '{reg_str}'. Expected 'R<number>'.")
    return int(match.group(1))

def assemble_from_string(input_str, arch_type, base_address_override=None):
    output_lines = []
    current_cheat_name = ""
    processed_lines_count = 0
    total_assembled_bytes = 0

    current_mem_type_header = MemoryAccessType.MainNso
    current_reg_header = 0
    current_addr_header = 0x00000000
    
    loop_register_stack = []

    line_prefix_pattern = re.compile(
        r'\[(?:(?P<mem_type>\w+)\+)?(?:b?R(?P<reg_idx>\d+)\+)?(?P<addr>0x[0-9A-Fa-f]+)\]=\s*(?P<value>.*)', 
        re.IGNORECASE
    )
    
    for line_num, line in enumerate(input_str.splitlines(), 1):
        line_stripped = line.strip()
        if not line_stripped or line_stripped.startswith(';'):
            continue
        
        # New logic to handle section separators
        if line_stripped.lower().startswith('sectionstart'):
            section_name = line_stripped[len('sectionstart'):].strip()
            output_lines.append("")
            output_lines.append(f"[--SectionStart:{section_name}--]")
            continue
        
        if line_stripped.lower().startswith('sectionend'):
            section_name = line_stripped[len('sectionend'):].strip()
            output_lines.append("")
            output_lines.append(f"[--SectionEnd:{section_name}--]")
            continue

        if ( (line_stripped.startswith('[') and line_stripped.endswith(']')) or \
     (line_stripped.startswith('{') and line_stripped.endswith('}')) ) and \
   (not '=' in line_stripped):
            if current_cheat_name:
                output_lines.append("")
            current_cheat_name = line_stripped
            output_lines.append(current_cheat_name)
            
            current_mem_type_header = MemoryAccessType.MainNso
            current_reg_header = 0
            current_addr_header = 0x00000000
            loop_register_stack = [] 
            continue

        match = line_prefix_pattern.match(line_stripped)
        
        mem_type_to_use = current_mem_type_header
        register_index_to_use = current_reg_header
        absolute_address_to_use = current_addr_header
        value_to_parse = line_stripped

        if match:
            mem_type_str_raw = match.group('mem_type')
            reg_str = match.group('reg_idx')
            addr_str = match.group('addr')
            value_to_parse = match.group('value').strip()

            mem_type_to_use = mem_type_from_str(mem_type_str_raw) if mem_type_str_raw else current_mem_type_header
            register_index_to_use = int(reg_str) if reg_str else current_reg_header
            absolute_address_to_use = parse_int(addr_str) if addr_str else current_addr_header

            current_mem_type_header = mem_type_to_use
            current_reg_header = register_index_to_use
            current_addr_header = absolute_address_to_use
            if re.match(r'0x[0-9a-fA-F]+$', value_to_parse, re.IGNORECASE):
                hex_value_str = value_to_parse[2:]
                value = int(hex_value_str, 16)
                
                # Determine bit width based on the length of the hex string
                value_len = len(hex_value_str)
                if value_len <= 2:
                    bit_width = 1
                elif value_len <= 4:
                    bit_width = 2
                elif value_len <= 8:
                    bit_width = 4
                else:
                    bit_width = 8
                    
                opcode = CheatVmOpcodeType.StoreStatic
                first_dword = (opcode.value << 28) | (bit_width << 24) | (mem_type_to_use.value << 20) | (register_index_to_use << 16) | ((absolute_address_to_use >> 32) & 0xFF)
                second_dword = absolute_address_to_use & 0xFFFFFFFF
                
                if bit_width == 8:
                    third_dword = (value >> 32) & 0xFFFFFFFF
                    fourth_dword = value & 0xFFFFFFFF
                    assembled_bytes = [first_dword, second_dword, third_dword, fourth_dword]
                else:
                    third_dword = value & 0xFFFFFFFF
                    assembled_bytes = [first_dword, second_dword, third_dword]

                output_lines.append(" ".join([f"{b:08X}" for b in assembled_bytes]))
                total_assembled_bytes += len(assembled_bytes) * 4
                processed_lines_count += 1
                continue

        opcode = None
        first_dword = None
        second_dword = None
        third_dword = None
        fourth_dword = None

        try:
            if value_to_parse.lower() == 'endif':
                opcode = CheatVmOpcodeType.EndConditionalBlock
                first_dword = (opcode.value << 28)
            elif value_to_parse.lower() == 'else':
                opcode = CheatVmOpcodeType.EndConditionalBlock
                first_dword = (opcode.value << 28) | (1 << 24)
            elif value_to_parse.lower() == 'elif':
                opcode = CheatVmOpcodeType.EndConditionalBlock
                first_dword = (opcode.value << 28) | 0x1
            elif value_to_parse.lower() == 'with':
                opcode = CheatVmOpcodeType.EndConditionalBlock
                first_dword = (opcode.value << 28) | 0x2
            elif value_to_parse.lower().startswith('if '):
                cond_str = value_to_parse[3:].strip()

                if cond_str.lower().startswith('keyheld '):
                    opcode = CheatVmOpcodeType.BeginKeypressConditionalBlock
                    key_mask_str = cond_str[8:].strip()
                    k = parse_int(key_mask_str)
                    first_dword = (opcode.value << 28) | (k & 0x0FFFFFFF) 

                elif re.match(r'R(\d+)\s*([<>]|<=|>=|==|!=)\s*R(\d+)\s*W=(?P<width_c0_reg>\d+)', cond_str, re.IGNORECASE): 
                    opcode = CheatVmOpcodeType.BeginRegisterConditionalBlock
                    parts = re.match(r'R(\d+)\s*([<>]|<=|>=|==|!=)\s*R(\d+)\s*W=(?P<width_c0_reg>\d+)', cond_str, re.IGNORECASE)
                    src_reg = int(parts.group(1))
                    cond_type_str = parts.group(2)
                    other_reg = int(parts.group(3))
                    width = parse_bit_width_int(int(parts.group('width_c0_reg')))

                    first_dword = (opcode.value << 24) | \
                                  ((width & 0xF) << 20) | \
                                  ((parse_condition_type(cond_type_str) & 0xF) << 16) | \
                                  ((src_reg & 0xF) << 12) | \
                                  ((5 & 0xF) << 8) | \
                                  ((other_reg & 0xF) << 4) 

                elif re.match(r'R(\d+)\s*([<>]|<=|>=|==|!=)\s*(?P<static_val>i?0x[0-9A-Fa-f]+|[0-9A-Fa-f]+)\s*W=(?P<width_c0_static>\d+)', cond_str, re.IGNORECASE): 
                    opcode = CheatVmOpcodeType.BeginRegisterConditionalBlock
                    parts = re.match(r'R(\d+)\s*([<>]|<=|>=|==|!=)\s*(?P<static_val>i?0x[0-9A-Fa-f]+|[0-9A-Fa-f]+)\s*W=(?P<width_c0_static>\d+)', cond_str, re.IGNORECASE)
                    src_reg = int(parts.group(1))
                    cond_type_str = parts.group(2)
                    static_value_str = parts.group('static_val').lstrip('i')
                    static_value = parse_int(static_value_str) 
                    width = parse_bit_width_int(int(parts.group('width_c0_static')))
                    
                    first_dword = (opcode.value << 24) | \
                                  ((width & 0xF) << 20) | \
                                  ((parse_condition_type(cond_type_str) & 0xF) << 16) | \
                                  ((src_reg & 0xF) << 12) | \
                                  ((4 & 0xF) << 8)
                    
                    if width == 8:
                        val_upper_32 = (static_value >> 32) & 0xFFFFFFFF
                        val_lower_32 = static_value & 0xFFFFFFFF
                        
                        if val_upper_32 == 0: 
                             second_dword = val_lower_32 
                             third_dword = None 
                        else:
                            second_dword = val_upper_32
                            third_dword = val_lower_32
                    else:
                        second_dword = static_value & 0xFFFFFFFF
                        third_dword = None


                elif re.match(r'R(\d+)\s*([<>]|<=|>=|==|!=)\s*\[(?P<mem_type_c0>\w+)(?:\+R(\d+))?(?:\+(?P<offset_c0>0x[0-9A-Fa-f]+))?\]\s*W=(?P<width_c0>\d+)', cond_str, re.IGNORECASE): 
                    opcode = CheatVmOpcodeType.BeginRegisterConditionalBlock
                    parts = re.match(r'R(\d+)\s*([<>]|<=|>=|==|!=)\s*\[(?P<mem_type_c0>\w+)(?:\+R(\d+))?(?:\+(?P<offset_c0>0x[0-9A-Fa-f]+))?\]\s*W=(?P<width_c0>\d+)', cond_str, re.IGNORECASE)
                    src_reg = int(parts.group(1))
                    cond_type_str = parts.group(2)
                    mem_type = mem_type_from_str(parts.group('mem_type_c0')).value
                    addr_reg_group = parts.group(4)
                    rel_addr_group = parts.group('offset_c0')
                    width = parse_bit_width_int(int(parts.group('width_c0')))

                    first_dword = (opcode.value << 24) | \
                                  ((width & 0xF) << 20) | \
                                  ((parse_condition_type(cond_type_str) & 0xF) << 16) | \
                                  ((src_reg & 0xF) << 12) 
                    
                    if addr_reg_group:
                        addr_reg = int(addr_reg_group)
                        if rel_addr_group and parse_int(rel_addr_group) != 0:
                            first_dword |= ((0 & 0xF) << 8) | ((mem_type & 0xF) << 4)
                            second_dword = (addr_reg << 28) | (parse_int(rel_addr_group) & 0xFFFFFFF)
                        else:
                            first_dword |= ((1 & 0xF) << 8) | ((mem_type & 0xF) << 4) | (addr_reg & 0xF)
                    else:
                        if rel_addr_group and parse_int(rel_addr_group) != 0:
                            first_dword |= ((3 & 0xF) << 8) | ((mem_type & 0xF) << 4)
                            second_dword = parse_int(rel_addr_group) & 0xFFFFFFFF
                        else:
                             first_dword |= ((2 & 0xF) << 8) | ((mem_type & 0xF) << 4)


                elif re.match(r'\[(?P<mem_type>\w+)\+R(\d+)\+(0x[0-9A-Fa-f]+)\]\s*([<>]|<=|>=|==|!=)\s*(0x[0-9A-Fa-f]+)', cond_str, re.IGNORECASE):
                    opcode = CheatVmOpcodeType.BeginConditionalBlock
                    parts = re.match(r'\[(?P<mem_type>\w+)\+R(\d+)\+(0x[0-9A-Fa-f]+)\]\s*([<>]|<=|>=|==|!=)\s*(0x[0-9A-Fa-f]+)', cond_str, re.IGNORECASE)
                    mem_type = mem_type_from_str(parts.group('mem_type')).value
                    reg_offset = int(parts.group(2))
                    absolute_address = parse_int(parts.group(3))
                    condition = parse_condition_type(parts.group(4))
                    value = parse_int(parts.group(5))
                    
                    val_abs = abs(value)
                    if val_abs <= 0xFF: width = 1
                    elif val_abs <= 0xFFFF: width = 2
                    elif val_abs <= 0xFFFFFFFF: width = 4
                    else: width = 8

                    first_dword = (opcode.value << 28) | ((width & 0xF) << 24) | ((mem_type & 0xF) << 20) | \
                                  ((condition & 0xF) << 16) | ((1 & 0xF) << 12) | ((reg_offset & 0xF) << 8) | ((absolute_address >> 32) & 0xFF)
                    second_dword = absolute_address & 0xFFFFFFFF
                    if width == 8:
                        third_dword = (value >> 32) & 0xFFFFFFFF
                        fourth_dword = value & 0xFFFFFFFF
                    else:
                        third_dword = value & 0xFFFFFFFF
                
                elif re.match(r'\[(?P<mem_type>\w+)\+(0x[0-9A-Fa-f]+)\]\s*([<>]|<=|>=|==|!=)\s*(0x[0-9A-Fa-f]+)', cond_str, re.IGNORECASE):
                    opcode = CheatVmOpcodeType.BeginConditionalBlock
                    parts = re.match(r'\[(?P<mem_type>\w+)\+(0x[0-9A-Fa-f]+)\]\s*([<>]|<=|>=|==|!=)\s*(0x[0-9A-Fa-f]+)', cond_str, re.IGNORECASE)
                    mem_type = mem_type_from_str(parts.group('mem_type')).value
                    absolute_address = parse_int(parts.group(2))
                    condition = parse_condition_type(parts.group(3))
                    value = parse_int(parts.group(4))
                    
                    val_abs = abs(value)
                    if val_abs <= 0xFF: width = 1
                    elif val_abs <= 0xFFFF: width = 2
                    elif val_abs <= 0xFFFFFFFF: width = 4
                    else: width = 8

                    first_dword = (opcode.value << 28) | ((width & 0xF) << 24) | ((mem_type & 0xF) << 20) | \
                                  ((condition & 0xF) << 16) | ((0 & 0xF) << 12) | ((absolute_address >> 32) & 0xFF)
                    second_dword = absolute_address & 0xFFFFFFFF
                    if width == 8:
                        third_dword = (value >> 32) & 0xFFFFFFFF
                        fourth_dword = value & 0xFFFFFFFF
                    else:
                        third_dword = value & 0xFFFFFFFF

                else:
                    raise ValueError(f"Unrecognized 'If' condition format: '{cond_str}'")

            elif value_to_parse.lower().startswith('loop '):
                if value_to_parse.lower().startswith('loop start r'):
                    opcode = CheatVmOpcodeType.ControlLoop
                    parts = re.match(r'Loop Start R(\d+)\s*=\s*(.*)', value_to_parse, re.IGNORECASE)
                    R = int(parts.group(1))
                    V = parse_int(parts.group(2)) 
                    first_dword = (opcode.value << 28) | (0 << 24) | ((R & 0xF) << 16)
                    second_dword = V & 0xFFFFFFFF 
                    loop_register_stack.append(R) 
                elif value_to_parse.lower().startswith('loop stop'):
                    opcode = CheatVmOpcodeType.ControlLoop
                    parts = re.match(r'Loop Stop(?: R(\d+))?', value_to_parse, re.IGNORECASE)
                    explicit_R = parts.group(1)
                    
                    if explicit_R:
                        R = int(explicit_R)
                    elif loop_register_stack:
                        R = loop_register_stack.pop() 
                    else:
                        R = 0 
                        print(f"Warning (Line {line_num}): 'Loop Stop' encountered with no explicit register and empty loop stack. Defaulting to R0.", file=sys.stderr)

                    first_dword = (opcode.value << 28) | (1 << 24) | ((R & 0xF) << 16)
                else:
                    raise ValueError(f"Unrecognized 'Loop' command: '{value_to_parse}'")
            
            elif re.match(r'R(\d+)\s*=\s*(0x[0-9A-Fa-f]+)', value_to_parse, re.IGNORECASE):
                opcode = CheatVmOpcodeType.LoadRegisterStatic
                parts = re.match(r'R(\d+)\s*=\s*(0x[0-9A-Fa-f]+)', value_to_parse, re.IGNORECASE)
                R = int(parts.group(1))
                V = parse_int(parts.group(2))
                first_dword = (opcode.value << 28) | ((R & 0xF) << 16)
                
                second_dword = (V >> 32) & 0xFFFFFFFF
                third_dword = V & 0xFFFFFFFF

            elif re.match(r'R(\d+)\s*=\s*\[(?P<mem_type_5_3>\w+)\+b?R(\d+)\+(0x[0-9A-Fa-f]+)\]\s*W=(?P<width_5_3>\d+)', value_to_parse, re.IGNORECASE):
                opcode = CheatVmOpcodeType.LoadRegisterMemory
                parts = re.match(r'R(\d+)\s*=\s*\[(?P<mem_type_5_3>\w+)\+b?R(\d+)\+(0x[0-9A-Fa-f]+)\]\s*W=(?P<width_5_3>\d+)', value_to_parse, re.IGNORECASE)
                R_dest = int(parts.group(1))
                M = mem_type_from_str(parts.group('mem_type_5_3')).value
                R_base = int(parts.group(3))
                A = parse_int(parts.group(4))
                T = parse_bit_width_int(int(parts.group('width_5_3')))

                first_dword = (opcode.value << 28) | \
                              ((T & 0xF) << 24) | \
                              ((M & 0xF) << 20) | \
                              ((R_dest & 0xF) << 16) | \
                              ((3 & 0xF) << 12) | \
                              ((R_base & 0xF) << 8) | \
                              0x00

                second_dword = A & 0xFFFFFFFF

            elif re.match(r'R(\d+)\s*=\s*\[b?R(\d+)\+(0x[0-9A-Fa-f]+)\]\s*W=(?P<width_5_1>\d+)', value_to_parse, re.IGNORECASE):
                opcode = CheatVmOpcodeType.LoadRegisterMemory
                parts = re.match(r'R(\d+)\s*=\s*\[b?R(\d+)\+(0x[0-9A-Fa-f]+)\]\s*W=(?P<width_5_1>\d+)', value_to_parse, re.IGNORECASE)
                R_dest = int(parts.group(1))
                R_base = int(parts.group(2))
                A = parse_int(parts.group(3))
                T = parse_bit_width_int(int(parts.group('width_5_1')))
                
                first_dword = (opcode.value << 28) | \
                              ((T & 0xF) << 24) | \
                              ((0 & 0xF) << 20) | \
                              ((R_dest & 0xF) << 16) | \
                              ((1 & 0xF) << 12) | \
                              ((R_base & 0xF) << 8) | \
                              0x00

                second_dword = A & 0xFFFFFFFF
            
            elif re.match(r'R(\d+)\s*=\s*\[(?P<mem_type_5_0>\w+)\+(0x[0-9A-Fa-f]+)\]\s*W=(?P<width_5_0>\d+)', value_to_parse, re.IGNORECASE):
                opcode = CheatVmOpcodeType.LoadRegisterMemory
                parts = re.match(r'R(\d+)\s*=\s*\[(?P<mem_type_5_0>\w+)\+(0x[0-9A-Fa-f]+)\]\s*W=(?P<width_5_0>\d+)', value_to_parse, re.IGNORECASE)
                R_dest = int(parts.group(1))
                M = mem_type_from_str(parts.group('mem_type_5_0')).value
                A = parse_int(parts.group(3))
                T = parse_bit_width_int(int(parts.group('width_5_0')))

                first_dword = (opcode.value << 28) | \
                              ((T & 0xF) << 24) | \
                              ((M & 0xF) << 20) | \
                              ((R_dest & 0xF) << 16) | \
                              ((0 & 0xF) << 12) | \
                              ((A >> 32) & 0xFF)

                second_dword = A & 0xFFFFFFFF
            
            elif re.match(r'\[R(\d+)\+R(\d+)\]\s*=\s*(?P<val_6regreg>0x[0-9A-Fa-f]+|[0-9A-Fa-f]+)\s*W=(?P<width_6regreg>\d+)(?:\s+R(\d+)\s*\+=\s*\d+)?', value_to_parse, re.IGNORECASE):
                opcode = CheatVmOpcodeType.StoreStaticToAddress
                parts = re.match(r'\[R(\d+)\+R(\d+)\]\s*=\s*(?P<val_6regreg>0x[0-9A-Fa-f]+|[0-9A-Fa-f]+)\s*W=(?P<width_6regreg>\d+)(?:\s+R(\d+)\s*\+=\s*\d+)?', value_to_parse, re.IGNORECASE)
                R_base = int(parts.group(1))
                R_offset = int(parts.group(2))
                V = parse_int(parts.group('val_6regreg'))
                T = parse_bit_width_int(int(parts.group('width_6regreg')))
                
                increment_part = parts.group(5) 
                increment = 1 if increment_part else 0

                first_dword = (opcode.value << 28) | \
                              ((T & 0xF) << 24) | \
                              ((2 & 0xF) << 20) | \
                              ((increment & 0x1) << 16) | \
                              ((R_base & 0xF) << 12) | \
                              ((R_offset & 0xF) << 8) 
                
                second_dword = (V >> 32) & 0xFFFFFFFF
                third_dword = V & 0xFFFFFFFF
            
            elif re.match(r'\[R(\d+)\]\s*=\s*(?P<val_6>\s*0x[0-9A-Fa-f]+|[0-9A-Fa-f]+)\s*W=(?P<width_6>\d+)(?:\s+R(\d+)\s*\+=\s*\d+)?', value_to_parse, re.IGNORECASE):
                opcode = CheatVmOpcodeType.StoreStaticToAddress
                parts = re.match(r'\[R(\d+)\]\s*=\s*(?P<val_6>0x[0-9A-Fa-f]+|[0-9A-Fa-f]+)\s*W=(?P<width_6>\d+)(?:\s+R(\d+)\s*\+=\s*\d+)?', value_to_parse, re.IGNORECASE)
                R_base = int(parts.group(1))
                V = parse_int(parts.group('val_6'))
                T = parse_bit_width_int(int(parts.group('width_6')))
                
                increment_part = parts.group(4) 
                increment = 1 if increment_part else 0 

                first_dword = (opcode.value << 28) | \
                              ((T & 0xF) << 24) | \
                              ((0 & 0xF) << 20) | \
                              ((R_base & 0xF) << 16) | \
                              ((increment & 0x1) << 12) | \
                              0x00
                
                second_dword = (V >> 32) & 0xFFFFFFFF
                third_dword = V & 0xFFFFFFFF
            
            elif re.match(r'R(\d+)\s*=\s*R(\d+)\s*([+\-*/]|lsl|lsr|and|or|not|xor|mov|fadd|fsub|fmul|fdiv)\s*(?P<imm_val>0x[0-9A-Fa-f]+|[0-9A-Fa-f]+)\s*W=(?P<width_7imm>\d+)', value_to_parse, re.IGNORECASE): 
                opcode = CheatVmOpcodeType.PerformArithmeticStatic
                parts = re.match(r'R(\d+)\s*=\s*R(\d+)\s*([+\-*/]|lsl|lsr|and|or|not|xor|mov|fadd|fsub|fmul|fdiv)\s*(?P<imm_val>0x[0-9A-Fa-f]+|[0-9A-Fa-f]+)\s*W=(?P<width_7imm>\d+)', value_to_parse, re.IGNORECASE)
                R_dest = int(parts.group(1))
                R_src = int(parts.group(2))
                op_symbol = parts.group(3)
                V_imm = parse_int(parts.group('imm_val')) 
                T = parse_bit_width_int(int(parts.group('width_7imm')))

                C = parse_arithmetic_type(op_symbol)

                first_dword = (opcode.value << 28) | \
                              ((T & 0xF) << 24) | \
                              ((0 & 0xF) << 20) | \
                              ((R_dest & 0xF) << 16) | \
                              ((C & 0xF) << 12) 

                if T == 8:
                    val_upper_32 = (V_imm >> 32) & 0xFFFFFFFF
                    val_lower_32 = V_imm & 0xFFFFFFFF
                    
                    if val_upper_32 == 0:
                        second_dword = val_lower_32
                        third_dword = None
                    else:
                        second_dword = val_upper_32
                        third_dword = val_lower_32
                else:
                    second_dword = V_imm & 0xFFFFFFFF
                    third_dword = None

            elif re.match(r'R(\d+)\s*=\s*R(\d+)\s*([+\-*/]|lsl|lsr|and|or|not|xor|mov|fadd|fsub|fmul|fdiv)\s*(?P<operand>R\d+|i(?:0x[0-9A-Fa-f]+|[0-9A-Fa-f]+))\s*W=(?P<width_9>\d+)', value_to_parse, re.IGNORECASE): 
                opcode = CheatVmOpcodeType.PerformArithmeticRegister
                parts = re.match(r'R(\d+)\s*=\s*R(\d+)\s*([+\-*/]|lsl|lsr|and|or|not|xor|mov|fadd|fsub|fmul|fdiv)\s*(?P<operand>R\d+|i(?:0x[0-9A-Fa-f]+|[0-9A-Fa-f]+))\s*W=(?P<width_9>\d+)', value_to_parse, re.IGNORECASE)
                R_dest = int(parts.group(1))
                R_left_operand = int(parts.group(2))
                op_symbol = parts.group(3)
                operand_str = parts.group('operand')
                T = parse_bit_width_int(int(parts.group('width_9')))
                
                C = parse_arithmetic_type(op_symbol)
                
                if operand_str.startswith('i'):
                    operand_type = 1
                    V_imm = parse_int(operand_str[1:])
                    
                    first_dword = (opcode.value << 28) | ((T & 0xF) << 24) | ((C & 0xF) << 20) | \
                                  ((R_dest & 0xF) << 16) | ((R_left_operand & 0xF) << 12) | \
                                  ((operand_type & 0xF) << 8) 
                    
                    if T == 8: 
                        second_dword = (V_imm >> 32) & 0xFFFFFFFF
                        third_dword = V_imm & 0xFFFFFFFF
                    else: 
                        second_dword = V_imm & 0xFFFFFFFF
                        third_dword = None

                else:
                    operand_type = 0
                    R_right_operand = int(extract_reg_num(operand_str))
                    
                    first_dword = (opcode.value << 28) | ((T & 0xF) << 24) | ((C & 0xF) << 20) | \
                                  ((R_dest & 0xF) << 16) | ((R_left_operand & 0xF) << 12) | \
                                  ((operand_type & 0xF) << 8) | ((R_right_operand & 0xF) << 4) 

            elif re.match(r'\[(?P<mem_type_A>\w+)\+R(\d+)\]\s*=\s*R(\d+)\s*W=(?P<width_A>\d+)(?:\s+R(\d+)\s*\+=\s*\d+)?', value_to_parse, re.IGNORECASE):
                opcode = CheatVmOpcodeType.StoreRegisterToAddress
                parts = re.match(r'\[(?P<mem_type_A>\w+)\+R(\d+)\]\s*=\s*R(\d+)\s*W=(?P<width_A>\d+)(?:\s+R(\d+)\s*\+=\s*\d+)?', value_to_parse, re.IGNORECASE)
                mem_type = mem_type_from_str(parts.group('mem_type_A')).value
                R_base = int(parts.group(2))
                R_src = int(parts.group(3))
                T = parse_bit_width_int(int(parts.group('width_A')))
                
                increment_reg_part = parts.group(5)
                increment = 1 if increment_reg_part else 0 

                first_dword = (opcode.value << 28) | \
                              ((T & 0xF) << 24) | \
                              ((R_src & 0xF) << 20) | \
                              ((R_base & 0xF) << 16) | \
                              ((increment & 0x1) << 12) | \
                              ((3 & 0xF) << 8) | \
                              ((mem_type & 0xF) << 4) 
            
            elif value_to_parse.lower().startswith('saverestoreregister '):
                opcode = CheatVmOpcodeType.SaveRestoreRegister
                parts = re.match(r'SaveRestoreRegister\s+dst=(\d+)\s+src=(\d+)\s+(Save|Restore|ClearSaved|ClearReg)', value_to_parse, re.IGNORECASE)
                D = int(parts.group(1))
                S = int(parts.group(2))
                op_type_str = parts.group(3).lower()
                op_map = {'restore': 0, 'save': 1, 'clearsaved': 2, 'clearreg': 3}
                x = op_map.get(op_type_str)
                if x is None: raise ValueError(f"Invalid Save/Restore operation type: {op_type_str}. Must be Save, Restore, ClearSaved, or ClearReg.")
                
                first_dword = (opcode.value << 24) | \
                              ((0 & 0xF) << 20) | \
                              ((D & 0xF) << 16) | \
                              ((0 & 0xF) << 12) | \
                              ((S & 0xF) << 8) | \
                              ((x & 0xF) << 4) 


            elif value_to_parse.lower().startswith('saverestoreregistermask '):
                opcode = CheatVmOpcodeType.SaveRestoreRegisterMask
                parts = re.match(r'SaveRestoreRegisterMask\s+(Save|Restore|ClearSaved|ClearReg)\s+mask=(0x[0-9A-Fa-f]+)', value_to_parse, re.IGNORECASE)
                op_type_str = parts.group(1).lower()
                op_map = {'restore': 0, 'save': 1, 'clearsaved': 2, 'clearreg': 3}
                x = op_map.get(op_type_str)
                if x is None: raise ValueError(f"Invalid Save/Restore Mask operation type: {op_type_str}. Must be Save, Restore, ClearSaved, or ClearReg.")
                mask = parse_int(parts.group(2))
                
                first_dword = (opcode.value << 24) | \
                              ((x & 0xF) << 20) | \
                              (mask & 0xFFFF) 

            elif value_to_parse.lower().startswith('readwritestaticregister '):
                opcode = CheatVmOpcodeType.ReadWriteStaticRegister
                parts = re.match(r'ReadWriteStaticRegister\s+static_idx=(0x[0-9A-Fa-f]+)\s+idx=(\d+)', value_to_parse, re.IGNORECASE)
                static_reg_idx = parse_int(parts.group(1))
                reg_idx = int(parts.group(2))
                
                first_dword = (opcode.value << 24) | \
                              ((static_reg_idx & 0xFF) << 4) | \
                              (reg_idx & 0xF) 

            else:
                val = None
                bit_width = 4

                data_type_match = re.match(r'\.(float|word|short|byte|double):(.*)', value_to_parse, re.IGNORECASE)

                if data_type_match:
                    data_type = data_type_match.group(1).lower()
                    value_to_pack = data_type_match.group(2).strip()
                    
                    if data_type == "byte":
                        val = parse_int(value_to_pack) & 0xFF
                        bit_width = 1
                    elif data_type == "short":
                        val = parse_int(value_to_pack) & 0xFFFF
                        bit_width = 2
                    elif data_type == "word":
                        val = parse_int(value_to_pack) & 0xFFFFFFFF
                        bit_width = 4
                    elif data_type == "float":
                        float_val = float(value_to_pack)
                        packed_float_bytes = struct.pack('<f', float_val)
                        val = int.from_bytes(packed_float_bytes, 'little')
                        bit_width = 4
                    elif data_type == "double":
                        double_val = float(value_to_pack)
                        packed_double_bytes = struct.pack('<d', double_val)
                        val = int.from_bytes(packed_double_bytes, 'little')
                        bit_width = 8
                elif value_to_parse.lower().startswith('flt:'):
                    float_str = value_to_parse[4:].strip()
                    float_val = float(float_str)
                    packed_float_bytes = struct.pack('<f', float_val)
                    val = int.from_bytes(packed_float_bytes, 'little')
                    bit_width = 4
                elif value_to_parse.lower() == 'nop':
                    assembled_bytes, error = assemble_instruction('nop', arch_type, absolute_address_to_use)
                    if assembled_bytes is None:
                        raise ValueError(f"Assembly for 'nop' failed: {error}")
                    val = int.from_bytes(assembled_bytes, 'little')
                    bit_width = len(assembled_bytes)
                else:
                    instructions = [i.strip() for i in value_to_parse.split(';') if i.strip() and not i.strip().startswith(';')]
                    
                    if not instructions:
                        print(f"Warning (Line {line_num}): No instructions found for Type 0 assembly. Skipping line: '{line_stripped}'", file=sys.stderr)
                        continue
                        
                    assembled_bytes_list = []
                    current_instr_addr_for_keystone = absolute_address_to_use
                    
                    assembly_failed = False
                    for instr_idx, instr in enumerate(instructions):
                        encoding_bytes, error = assemble_instruction(instr, arch_type, current_instr_addr_for_keystone)
                        
                        if encoding_bytes is None:
                            print(f"Error (Line {line_num}): Assembly failed for '{instr}'. Error: {error}. Skipping line: '{line_stripped}'", file=sys.stderr)
                            assembly_failed = True
                            break
                        
                        if len(encoding_bytes) % 4 != 0:
                            print(f"Error (Line {line_num}): Assembled instruction '{instr}' for {arch_type} is not a multiple of 4 bytes ({len(encoding_bytes)} bytes). This is required for Type 0 cheats. Skipping line: '{line_stripped}'", file=sys.stderr)
                            assembly_failed = True
                            break
                            
                        assembled_bytes_list.append(encoding_bytes)
                        current_instr_addr_for_keystone += len(encoding_bytes)

                    if assembly_failed:
                        continue

                    all_assembled_bytes = b"".join(assembled_bytes_list)
                    bit_width = len(all_assembled_bytes)
                    total_assembled_bytes += bit_width

                    if bit_width > 8:
                        output_lines.append(f"; Assembled code block for {mem_type_to_use.name}+R{register_index_to_use}+0x{absolute_address_to_use:08X}")
                        for i in range(0, len(all_assembled_bytes), 4):
                            output_lines.append(f"{int.from_bytes(all_assembled_bytes[i:i+4], 'little'):08X}")
                        processed_lines_count += 1
                        continue
                    elif bit_width > 0:
                        val = int.from_bytes(all_assembled_bytes, 'little')
                    else:
                        raise ValueError("No assembly bytes generated.")
                
                if val is not None:
                    opcode = CheatVmOpcodeType.StoreStatic
                    first_dword = (opcode.value << 28)
                    first_dword |= (parse_bit_width_int(bit_width) & 0xF) << 24
                    first_dword |= (mem_type_to_use.value & 0xF) << 20
                    first_dword |= (register_index_to_use & 0xF) << 16
                    first_dword |= ((absolute_address_to_use >> 32) & 0xFF)

                    addr_lower_32 = absolute_address_to_use & 0xFFFFFFFF
                    
                    if bit_width == 8:
                        val_upper_32 = (val >> 32) & 0xFFFFFFFF
                        val_lower_32 = val & 0xFFFFFFFF
                        output_lines.append(f"{first_dword:08X} {addr_lower_32:08X} {val_upper_32:08X} {val_lower_32:08X}")
                    else:
                        output_lines.append(f"{first_dword:08X} {addr_lower_32:08X} {val:08X}")
                    
                    processed_lines_count += 1
                    continue
                else:
                    print(f"Error (Line {line_num}): Could not parse value or instruction for line: '{line_stripped}'. Skipping.", file=sys.stderr)
                    continue
            
            if first_dword is not None:
                hex_parts = []
                hex_parts.append(f"{first_dword:08X}")
                if second_dword is not None: hex_parts.append(f"{second_dword:08X}")
                if third_dword is not None: hex_parts.append(f"{third_dword:08X}")
                if fourth_dword is not None: hex_parts.append(f"{fourth_dword:08X}")
                output_lines.append(" ".join(hex_parts))
                processed_lines_count += 1
            else:
                 print(f"Error (Line {line_num}): No known opcode pattern matched line: '{line_stripped}'. Skipping.", file=sys.stderr)
                 continue


        except (ValueError, IndexError, KeyError) as e:
            print(f"Error (Line {line_num}): Parsing error for '{value_to_parse}': {e}. Skipping line: '{line_stripped}'", file=sys.stderr)
            continue
        except Exception as e:
            print(f"Critical Error (Line {line_num}): Unhandled exception: {e}. Skipping line: '{line_stripped}'", file=sys.stderr)
            continue

    if processed_lines_count == 0 and not output_lines:
        print("\n--- No valid cheat lines were processed. Check your input format and any errors above. ---", file=sys.stderr)
    elif processed_lines_count > 0:
        print(f"\n--- Successfully processed {processed_lines_count} lines. ---", file=sys.stderr)
    
    return "\n".join(output_lines), total_assembled_bytes

def assemble_raw_code(code_string, arch_type, base_address=0):
    try:
        ks_arch = None
        ks_mode = KS_MODE_LITTLE_ENDIAN

        if arch_type.upper() == "ARM64":
            ks_arch = KS_ARCH_ARM64
        elif arch_type.upper() == "ARM32":
            ks_arch = KS_ARCH_ARM
            ks_mode |= KS_MODE_ARM
        else:
            return None, f"Unsupported architecture: {arch_type}. Must be ARM32 or ARM64.", 0

        if ks_arch is None:
            return None, "Keystone architecture not set due to invalid input."

        ks = Ks(ks_arch, ks_mode)
        encoding_raw, count = ks.asm(code_string, addr=base_address)
        
        if isinstance(encoding_raw, list):
            encoding_bytes = bytes(encoding_raw)
        elif isinstance(encoding_raw, bytes):
            encoding_bytes = encoding_raw
        else:
            return None, f"Unexpected type for Keystone encoding: {type(encoding_raw)}", 0

        if not encoding_bytes and count == 0 and code_string.strip():
            return None, "Keystone returned empty encoding for non-empty code (possible assembly error).", 0
            
        return ''.join('{:02X}'.format(x) for x in encoding_bytes), None, len(encoding_bytes)
    except KsError as e:
        return None, f"ERROR: Keystone Assembly Error: {e}", 0
    except Exception as e:
        return None, f"ERROR: An unexpected error occurred during raw assembly: {e}", 0

def main():
    parser = argparse.ArgumentParser(description="Assemble ARM/ARM64 instructions for Cheat Tool.")
    parser.add_argument("--arch", required=True, choices=["ARM32", "ARM64"],
                        help="Target architecture for assembly (ARM32 or ARM64).")
    parser.add_argument("--base-address", type=lambda x: int(x, 0), default=0,
                        help="Base address for assembly (optional). Use with --raw-assembly.")
    parser.add_argument("--raw-assembly", action="store_true",
                        help="Process input as raw assembly code for direct output, not cheat format.")
    
    args = parser.parse_args()
    
    input_str = sys.stdin.read()
    if input_str.startswith('\ufeff'):
        input_str = input_str[1:]
    if not input_str.strip():
        print("No input provided.", file=sys.stderr)
        return

    try:
        ks_test = None
        if args.arch.upper() == "ARM64":
            ks_test = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
            test_instr = "mov x0, #1"
        elif args.arch.upper() == "ARM32":
            ks_test = Ks(KS_ARCH_ARM, KS_MODE_ARM | KS_MODE_LITTLE_ENDIAN)
            test_instr = "mov r0, #1"
        else:
            print(f"FATAL ERROR: Invalid architecture '{args.arch}' for basic Keystone test.", file=sys.stderr)
            return

        test_encoding_raw, test_count = ks_test.asm(test_instr)
        if not test_encoding_raw or test_count == 0:
            print(f"FATAL ERROR: Keystone failed basic assembly test for '{test_instr}' ({args.arch}).", file=sys.stderr)
            return
    except Exception as e:
        print(f"FATAL ERROR: Keystone library initialized but failed basic test for {args.arch} with exception: {e}", file=sys.stderr)
        return

    if args.raw_assembly:
        assembled_hex, error_message, byte_length = assemble_raw_code(input_str, args.arch.upper(), args.base_address)
        if assembled_hex is not None:
            print(assembled_hex)
            print(f"BYTE_LENGTH:{byte_length}")
        else:
            print(error_message, file=sys.stderr)
    else:
        output_str, total_bytes = assemble_from_string(input_str, args.arch.upper(), args.base_address)
        print(output_str)
        pass
        

if __name__ == "__main__":
    main()