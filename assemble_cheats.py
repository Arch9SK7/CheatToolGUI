import sys
import re
import struct
import argparse # Import argparse for command-line arguments
from enum import Enum

try:
    from keystone import Ks, KS_ARCH_ARM, KS_ARCH_ARM64, KS_MODE_ARM, KS_MODE_THUMB, KS_MODE_LITTLE_ENDIAN
    KEYSTONE_AVAILABLE = True
except ImportError:
    KEYSTONE_AVAILABLE = False
    print("FATAL ERROR: Keystone library not found. Please install it with 'pip install keystone-engine'", file=sys.stderr)
    sys.exit(1)

class CheatVmOpcodeType(Enum):
    StoreStatic = 0
    BeginConditionalBlock = 1
    EndConditionalBlock = 2
    ControlLoop = 3
    LoadRegisterStatic = 4
    LoadRegisterMemory = 5
    StoreStaticToAddress = 6
    PerformArithmeticStatic = 7
    BeginKeypressConditionalBlock = 8
    PerformArithmeticRegister = 9
    StoreRegisterToAddress = 10
    Reserved11 = 11
    ExtendedWidth = 12
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
    s_lower = s.lower() if s else ""
    if s_lower == "main": return MemoryAccessType.MainNso
    if s_lower == "heap": return MemoryAccessType.Heap
    if s_lower == "alias": return MemoryAccessType.Alias
    if s_lower == "aslr": return MemoryAccessType.Aslr
    
    if not s:
        print(f"Warning: No memory type specified in input. Defaulting to MainNso.", file=sys.stderr)
    else:
        print(f"Warning: Unrecognized memory type string '{s}'. Defaulting to MainNso.", file=sys.stderr)
    return MemoryAccessType.MainNso

# Pass arch_type to assemble_instruction
def assemble_instruction(instruction, arch_type, addr=0):
    try:
        ks_arch = None
        ks_mode = KS_MODE_LITTLE_ENDIAN # Common for both ARM32 and ARM64 on Switch/modern platforms

        if arch_type.upper() == "ARM64":
            ks_arch = KS_ARCH_ARM64
        elif arch_type.upper() == "ARM32":
            ks_arch = KS_ARCH_ARM
            ks_mode |= KS_MODE_ARM # Set to ARM mode
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
            print(f"Error: Unexpected type for Keystone encoding: {type(encoding_raw)}", file=sys.stderr)
            return None, "Keystone returned unexpected type."

        if not encoding_bytes and count == 0:
            print(f"Warning: Keystone assembled '{instruction}' but returned no bytes (empty encoding list/bytes).", file=sys.stderr)
            return None, "Empty encoding returned by Keystone."

        return encoding_bytes, None
    except Exception as e:
        print(f"Error: Exception during Keystone assembly of '{instruction}' for {arch_type} at 0x{addr:X}: {e}", file=sys.stderr)
        return None, str(e)

def assemble_from_string(input_str, arch_type):
    output_lines = []
    current_cheat_name = ""
    processed_lines_count = 0 

    for line_num, line in enumerate(input_str.splitlines(), 1):
        line_stripped = line.strip()
        if not line_stripped:
            continue
        
        if line_stripped.startswith('[') and line_stripped.endswith(']') and not '=' in line_stripped:
            if current_cheat_name:
                output_lines.append("")
            current_cheat_name = line_stripped
            output_lines.append(current_cheat_name)
            continue

        match = re.match(r'\[(?:(\w+)\+)?R(\d+)\+0x([0-9A-Fa-f]+)\]=(.*)', line_stripped)
        if not match:
            print(f"Warning (Line {line_num}): Line format not recognized, skipping: '{line_stripped}'", file=sys.stderr)
            continue
            
        mem_type_str_raw, reg_str, addr_str, value_str_raw = match.groups()
        
        mem_type = mem_type_from_str(mem_type_str_raw) 
        register_index = int(reg_str)
        absolute_address = int(addr_str, 16)
        value_to_encode = value_str_raw.strip()

        relative_address = absolute_address 

        val = None
        bit_width = 4 

        if value_to_encode.lower().startswith('flt:'):
            float_str = value_to_encode[4:]
            try:
                float_val = float(float_str)
                packed_float_bytes = struct.pack('<f', float_val)
                val = int.from_bytes(packed_float_bytes, 'little')
                bit_width = 4
            except (ValueError, struct.error) as e:
                print(f"Error (Line {line_num}): Could not parse float value '{float_str}'. Error: {e}. Skipping line: '{line_stripped}'", file=sys.stderr)
                continue
        else:
            instructions = [i.strip() for i in value_to_encode.split(';') if i.strip()]
            
            if not instructions:
                print(f"Warning (Line {line_num}): No instruction found to assemble in line: '{line_stripped}'. Skipping.", file=sys.stderr)
                continue
            
            
            if len(instructions) > 2:
                print(f"Warning (Line {line_num}): More than two instructions on a line are not supported for Type 0: '{line_stripped}'. Skipping.", file=sys.stderr)
                continue

            bit_width = 4 * len(instructions) # Still assuming 4 bytes per instruction
            
            assembled_bytes_list = []
            current_instr_addr = relative_address
            
            assembly_failed = False
            for instr_idx, instr in enumerate(instructions):
                # Pass the arch_type to the assembler
                encoding_bytes, error = assemble_instruction(instr, arch_type, current_instr_addr)
                
                if encoding_bytes is None:
                    assembly_failed = True
                    break
                
                if len(encoding_bytes) != 4:
                    print(f"Error (Line {line_num}): Assembled instruction '{instr}' for {arch_type} is not 4 bytes ({len(encoding_bytes)} bytes). Keystone might be misbehaving or this is a Thumb instruction. Skipping line: '{line_stripped}'", file=sys.stderr)
                    assembly_failed = True
                    break
                
                assembled_bytes_list.append(encoding_bytes)
                current_instr_addr += 4

            if assembly_failed:
                continue

            if len(instructions) == 1:
                val = int.from_bytes(assembled_bytes_list[0], 'little')
            else:
                val1 = int.from_bytes(assembled_bytes_list[0], 'little')
                val2 = int.from_bytes(assembled_bytes_list[1], 'little')
                val = (val2 << 32) | val1

        if val is not None:
            if not (bit_width == 4 or bit_width == 8):
                print(f"Error (Line {line_num}): Invalid bit_width {bit_width}. Must be 4 or 8. Skipping line: '{line_stripped}'", file=sys.stderr)
                continue

            if not (0 <= register_index <= 30): # Allow up to X30 for ARM64, R0-R15 for ARM32 is covered.
                print(f"Error (Line {line_num}): Invalid register index {register_index}. For ARM64, must be 0-30. For ARM32, must be 0-15. Skipping line: '{line_stripped}'", file=sys.stderr)
                continue
            
            first_dword_val = 0x00000000
            first_dword_val |= (bit_width & 0xF) << 24
            first_dword_val |= (mem_type.value & 0xF) << 20
            first_dword_val |= (register_index & 0xF) << 16
            
            # For ARM32, the address upper bits will be zero, so this works for both.
            # For ARM64, it correctly takes the upper 8 bits.
            first_dword_val |= ((relative_address >> 32) & 0xFF)

            addr_lower_32 = relative_address & 0xFFFFFFFF
            
            if bit_width == 8:
                val_lower_32 = val & 0xFFFFFFFF
                val_upper_32 = (val >> 32) & 0xFFFFFFFF
                output_lines.append(f"{first_dword_val:08X} {addr_lower_32:08X} {val_upper_32:08X} {val_lower_32:08X}")
            else:
                output_lines.append(f"{first_dword_val:08X} {addr_lower_32:08X} {val:08X}")
            
            processed_lines_count += 1

    if processed_lines_count == 0 and not output_lines:
        print("\n--- No valid cheat lines were processed. Check your input format and any errors above. ---", file=sys.stderr)
    elif processed_lines_count > 0:
        print(f"\n--- Successfully processed {processed_lines_count} lines. ---", file=sys.stderr)
    
    return "\n".join(output_lines)

def main():
    parser = argparse.ArgumentParser(description="Assemble ARM/ARM64 instructions for Cheat Tool.")
    parser.add_argument("--arch", required=True, choices=["ARM32", "ARM64"],
                        help="Target architecture for assembly (ARM32 or ARM64).")
    
    args = parser.parse_args()
    
    input_str = sys.stdin.read()
    if input_str.startswith('\ufeff'):
        input_str = input_str[1:]
    if not input_str.strip():
        print("No input provided.", file=sys.stderr)
        return

    # Basic Keystone test with the selected architecture
    try:
        if args.arch.upper() == "ARM64":
            ks_test = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
            test_instr = "mov x0, #1"
        elif args.arch.upper() == "ARM32":
            ks_test = Ks(KS_ARCH_ARM, KS_MODE_ARM | KS_MODE_LITTLE_ENDIAN)
            test_instr = "mov r0, #1" # ARM32 test instruction
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

    # Pass the selected architecture to the assembly function
    output_str = assemble_from_string(input_str, args.arch.upper())
    print(output_str)

if __name__ == "__main__":
    main()