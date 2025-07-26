import sys
from enum import Enum

try:
    from capstone import Cs, CS_ARCH_ARM64, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB
    CAPSTONE_AVAILABLE = True
except ImportError:
    CAPSTONE_AVAILABLE = False
    print("FATAL ERROR: Capstone library not found. Please install it with 'pip install capstone-engine'", file=sys.stderr)

TARGET_ARCH = None

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
    Blank = 4

class ConditionalComparisonType(Enum):
    GT = 1
    GE = 2
    LT = 3
    LE = 4
    EQ = 5
    NE = 6

class RegisterArithmeticType(Enum):
    Addition = 0
    Subtraction = 1
    Multiplication = 2
    LeftShift = 3
    RightShift = 4
    LogicalAnd = 5
    LogicalOr = 6
    LogicalNot = 7
    LogicalXor = 8
    None_ = 9
    FloatAddition = 10
    FloatMultiplication = 11
    DoubleAddition = 12
    DoubleMultiplication = 13

class StoreRegisterOffsetType(Enum):
    None_ = 0
    Reg = 1
    Imm = 2
    MemReg = 3
    MemImm = 4
    MemImmReg = 5
    
class CompareRegisterValueType(Enum):
    MemoryRelAddr = 0
    MemoryOfsReg = 1
    RegisterRelAddr = 2
    RegisterOfsReg = 3
    StaticValue = 4
    OtherRegister = 5
    OffsetValue = 6
    
class SaveRestoreRegisterOpType(Enum):
    Restore = 0
    Save = 1
    ClearSaved = 2
    ClearRegs = 3

class DebugLogValueType(Enum):
    MemoryRelAddr = 0
    MemoryOfsReg = 1
    RegisterRelAddr = 2
    RegisterOfsReg = 3
    RegisterValue = 4

CONDITION_STR = {
    ConditionalComparisonType.GT: ">",
    ConditionalComparisonType.GE: ">=",
    ConditionalComparisonType.LT: "<",
    ConditionalComparisonType.LE: "<=",
    ConditionalComparisonType.EQ: "==",
    ConditionalComparisonType.NE: "!=",
}

MATH_STR = {
    RegisterArithmeticType.Addition: "+",
    RegisterArithmeticType.Subtraction: "-",
    RegisterArithmeticType.Multiplication: "*",
    RegisterArithmeticType.LeftShift: "<<",
    RegisterArithmeticType.RightShift: ">>",
    RegisterArithmeticType.LogicalAnd: "&",
    RegisterArithmeticType.LogicalOr: "|",
    RegisterArithmeticType.LogicalNot: "!",
    RegisterArithmeticType.LogicalXor: "^",
    RegisterArithmeticType.None_: "",
    RegisterArithmeticType.FloatAddition: "+f",
    RegisterArithmeticType.FloatMultiplication: "*f",
    RegisterArithmeticType.DoubleAddition: "+d",
    RegisterArithmeticType.DoubleMultiplication: "*d",
}

OPERAND_STR = {
    SaveRestoreRegisterOpType.Restore: "Restore",
    SaveRestoreRegisterOpType.Save: "Save",
    SaveRestoreRegisterOpType.ClearSaved: "ClearSaved",
    SaveRestoreRegisterOpType.ClearRegs: "ClearRegs",
}


class VmInt:
    def __init__(self, value=0):
        self.value = value

class CheatVmOpcode:
    def __init__(self):
        self.opcode = None
        self.size = 0
        self.str = ""

def get_next_dword(opcodes, instruction_ptr):
    if instruction_ptr >= len(opcodes):
        return None, instruction_ptr + 1
    return opcodes[instruction_ptr], instruction_ptr + 1

def get_next_vm_int(opcodes, instruction_ptr, bit_width):
    val = VmInt()
    
    first_dword, instruction_ptr = get_next_dword(opcodes, instruction_ptr)
    if first_dword is None:
        return None, instruction_ptr

    if bit_width == 1:
        val.value = first_dword & 0xFF
    elif bit_width == 2:
        val.value = first_dword & 0xFFFF
    elif bit_width == 4:
        val.value = first_dword
    elif bit_width == 8:
        second_dword, instruction_ptr = get_next_dword(opcodes, instruction_ptr)
        if second_dword is None:
            return None, instruction_ptr
        val.value = (first_dword << 32) | second_dword
    else:
        val.value = first_dword
        
    return val, instruction_ptr


def mem_type_str(mem_type):
    if mem_type == MemoryAccessType.MainNso: return "Main"
    if mem_type == MemoryAccessType.Heap: return "Heap"
    if mem_type == MemoryAccessType.Alias: return "Alias"
    if mem_type == MemoryAccessType.Aslr: return "Aslr"
    return ""

def arm64_disassemble(value, address):
    if not CAPSTONE_AVAILABLE:
        return ""
    
    try:
        md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        code = (value & 0xFFFFFFFF).to_bytes(4, byteorder='little')
        
        disassembled = []
        for i in md.disasm(code, address):
            disassembled.append(f"{i.mnemonic} {i.op_str}")
        return "; ".join(disassembled).strip()
    except Exception as e:
        print(f"Error during ARM64 disassembly: {e}", file=sys.stderr)
        return ""

def arm32_disassemble(value, address):
    if not CAPSTONE_AVAILABLE:
        return ""
    
    code = value.to_bytes(4, byteorder='little')
    
    md_arm = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    disassembled = []
    try:
        for i in md_arm.disasm(code, address):
            disassembled.append(f"{i.mnemonic} {i.op_str}")
        if disassembled:
            return "; ".join(disassembled).strip()
    except Exception as e:
        pass

    md_thumb = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    disassembled = []
    try:
        for i in md_thumb.disasm(code, address):
            disassembled.append(f"{i.mnemonic} {i.op_str}")
        if disassembled:
            return "; ".join(disassembled).strip()
    except Exception as e:
        pass

    return ""


def decode_next_opcode(opcodes, index):
    instruction_ptr = index
    
    first_dword, instruction_ptr = get_next_dword(opcodes, instruction_ptr)
    if first_dword is None:
        return None

    out = CheatVmOpcode()
    
    opcode_val = (first_dword >> 28) & 0xF
    if opcode_val >= CheatVmOpcodeType.ExtendedWidth.value:
        opcode_val = (opcode_val << 4) | ((first_dword >> 24) & 0xF)
    if opcode_val >= CheatVmOpcodeType.DoubleExtendedWidth.value:
        opcode_val = (opcode_val << 4) | ((first_dword >> 20) & 0xF)

    try:
        out.opcode = CheatVmOpcodeType(opcode_val)
    except ValueError:
        out.str = f"Unknown opcode: {hex(opcode_val)}"
        out.size = 1
        return out

    if out.opcode == CheatVmOpcodeType.StoreStatic:
        bit_width = (first_dword >> 24) & 0xF
        mem_type = MemoryAccessType((first_dword >> 20) & 0xF)
        offset_register = (first_dword >> 16) & 0xF
        second_dword, instruction_ptr = get_next_dword(opcodes, instruction_ptr)
        
        rel_address_high_8 = first_dword & 0xFF
        rel_address = (rel_address_high_8 << 32) | second_dword
        
        value, instruction_ptr = get_next_vm_int(opcodes, instruction_ptr, bit_width)
        
        out.str = f"[{mem_type_str(mem_type)}+R{offset_register}+0x{rel_address:010X}] = 0x{value.value:X}"
        
        if CAPSTONE_AVAILABLE:
            if bit_width == 8:
                high_32_bits = (value.value >> 32) & 0xFFFFFFFF
                low_32_bits = value.value & 0xFFFFFFFF

                combined_asm = []
                if TARGET_ARCH == "ARM64":
                    asm_low = arm64_disassemble(low_32_bits, rel_address)
                    asm_high = arm64_disassemble(high_32_bits, rel_address + 4)
                    arch_label = "ARM64"
                elif TARGET_ARCH == "ARM32":
                    asm_low = arm32_disassemble(low_32_bits, rel_address)
                    asm_high = arm32_disassemble(high_32_bits, rel_address + 4)
                    arch_label = "ARM32"
                else:
                    asm_low = ""
                    asm_high = ""
                    arch_label = "UNKNOWN ARCH"

                if asm_low:
                    combined_asm.append(f"[{rel_address:X}] {asm_low}")
                if asm_high:
                    combined_asm.append(f"[{rel_address + 4:X}] {asm_high}")
                
                if combined_asm:
                    out.str += f"  ({arch_label}: {'; '.join(combined_asm)})"
                else:
                    out.str += f"  ({arch_label}: No disassembly)"

            elif bit_width == 4:
                if TARGET_ARCH == "ARM64":
                    asm = arm64_disassemble(value.value, rel_address)
                    if asm:
                        out.str += f"  (ARM64: {asm})"
                elif TARGET_ARCH == "ARM32":
                    asm = arm32_disassemble(value.value, rel_address)
                    if asm:
                        out.str += f"  (ARM32: {asm})"
                else:
                    out.str += " (Disassembly type not determined)"
        else:
            out.str += " (Disassembly skipped - Capstone not available)"
    
    elif out.opcode == CheatVmOpcodeType.BeginConditionalBlock:
        bit_width = (first_dword >> 24) & 0xF
        mem_type = MemoryAccessType((first_dword >> 20) & 0xF)
        cond_type = ConditionalComparisonType((first_dword >> 16) & 0xF)
        include_ofs_reg = ((first_dword >> 12) & 0xF) != 0
        ofs_reg_index = (first_dword >> 8) & 0xF
        second_dword, instruction_ptr = get_next_dword(opcodes, instruction_ptr)
        rel_address_high_8 = first_dword & 0xFF
        rel_address = (rel_address_high_8 << 32) | second_dword
        
        value, instruction_ptr = get_next_vm_int(opcodes, instruction_ptr, bit_width)
        ofs_reg_str = f"R{ofs_reg_index}+" if include_ofs_reg else ""
        out.str = f"If [{mem_type_str(mem_type)}+{ofs_reg_str}0x{rel_address:010X}] {CONDITION_STR.get(cond_type, '?')} 0x{value.value:X}"

    elif out.opcode == CheatVmOpcodeType.EndConditionalBlock:
        end_type = (first_dword >> 24) & 0xF
        out.str = "Else" if end_type == 1 else "Endif"

    elif out.opcode == CheatVmOpcodeType.ControlLoop:
        start_loop = ((first_dword >> 24) & 0xF) == 0
        reg_index = (first_dword >> 16) & 0xF
        if start_loop:
            num_iters, instruction_ptr = get_next_dword(opcodes, instruction_ptr)
            out.str = f"Loop Start R{reg_index} = {num_iters}"
        else:
            out.str = "Loop stop"

    elif out.opcode == CheatVmOpcodeType.LoadRegisterStatic:
        reg_index = (first_dword >> 16) & 0xF
        value, instruction_ptr = get_next_vm_int(opcodes, instruction_ptr, 8)
        out.str = f"R{reg_index} = 0x{value.value:016X}"

    elif out.opcode == CheatVmOpcodeType.LoadRegisterMemory:
        bit_width = (first_dword >> 24) & 0xF
        mem_type = MemoryAccessType((first_dword >> 20) & 0xF)
        reg_index = (first_dword >> 16) & 0xF
        load_from_reg_type = (first_dword >> 12) & 0xF
        offset_register = (first_dword >> 8) & 0xF
        second_dword, instruction_ptr = get_next_dword(opcodes, instruction_ptr)
        
        rel_address_high_8 = first_dword & 0xFF
        rel_address = (rel_address_high_8 << 32) | second_dword
        
        if load_from_reg_type == 3:
            out.str = f"R{reg_index} = [{mem_type_str(mem_type)}+R{offset_register}+0x{rel_address:010X}] W={bit_width}"
        elif load_from_reg_type == 1:
            out.str = f"R{reg_index} = [R{reg_index}+0x{rel_address:010X}] W={bit_width}"
        elif load_from_reg_type == 2:
            out.str = f"R{reg_index} = [R{offset_register}+0x{rel_address:010X}] W={bit_width}"
        else:
            out.str = f"R{reg_index} = [{mem_type_str(mem_type)}+0x{rel_address:010X}] W={bit_width}"


    elif out.opcode == CheatVmOpcodeType.StoreStaticToAddress:
        bit_width = (first_dword >> 24) & 0xF
        reg_index = (first_dword >> 16) & 0xF
        increment_reg = ((first_dword >> 12) & 0xF) != 0
        add_offset_reg = ((first_dword >> 8) & 0xF) != 0
        offset_reg_index = (first_dword >> 4) & 0xF
        value, instruction_ptr = get_next_vm_int(opcodes, instruction_ptr, 8)
        
        if add_offset_reg:
            out.str = f"[R{reg_index}+R{offset_reg_index}] = 0x{value.value:016X} W={bit_width}"
        else:
            out.str = f"[R{reg_index}] = 0x{value.value:016X} W={bit_width}"
        if increment_reg:
            out.str += f" R{reg_index} += {bit_width}"

    elif out.opcode == CheatVmOpcodeType.PerformArithmeticStatic:
        bit_width = (first_dword >> 24) & 0xF
        reg_index = (first_dword >> 16) & 0xF
        math_type = RegisterArithmeticType((first_dword >> 12) & 0xF)
        value, instruction_ptr = get_next_dword(opcodes, instruction_ptr)
        out.str = f"R{reg_index} = R{reg_index} {MATH_STR.get(math_type, '?')} 0x{value:X} W={bit_width}"

    elif out.opcode == CheatVmOpcodeType.BeginKeypressConditionalBlock:
        key_mask = first_dword & 0x0FFFFFFF
        out.str = f"If keyheld 0x{key_mask:X}"
        
    elif out.opcode == CheatVmOpcodeType.PerformArithmeticRegister:
        bit_width = (first_dword >> 24) & 0xF
        math_type = RegisterArithmeticType((first_dword >> 20) & 0xF)
        dst_reg_index = (first_dword >> 16) & 0xF
        src_reg_1_index = (first_dword >> 12) & 0xF
        has_immediate = ((first_dword >> 8) & 0xF) != 0
        if has_immediate:
            value, instruction_ptr = get_next_vm_int(opcodes, instruction_ptr, bit_width)
            out.str = f"R{dst_reg_index} = R{src_reg_1_index} {MATH_STR.get(math_type, '?')} 0x{value.value:X} W={bit_width}"
        else:
            src_reg_2_index = (first_dword >> 4) & 0xF
            out.str = f"R{dst_reg_index} = R{src_reg_1_index} {MATH_STR.get(math_type, '?')} R{src_reg_2_index} W={bit_width}"
    
    elif out.opcode == CheatVmOpcodeType.StoreRegisterToAddress:
        bit_width = (first_dword >> 24) & 0xF
        str_reg_index = (first_dword >> 20) & 0xF
        addr_reg_index = (first_dword >> 16) & 0xF
        increment_reg = ((first_dword >> 12) & 0xF) != 0
        ofs_type = StoreRegisterOffsetType((first_dword >> 8) & 0xF)
        ofs_reg_or_mem_type = (first_dword >> 4) & 0xF

        addr_str = ""
        if ofs_type == StoreRegisterOffsetType.None_:
            addr_str = f"[R{addr_reg_index}]"
        elif ofs_type == StoreRegisterOffsetType.Reg:
            addr_str = f"[R{addr_reg_index}+R{ofs_reg_or_mem_type}]"
        elif ofs_type == StoreRegisterOffsetType.Imm:
            rel_address, instruction_ptr = get_next_vm_int(opcodes, instruction_ptr, 4)
            addr_str = f"[R{addr_reg_index}+0x{rel_address.value:X}]"
        elif ofs_type == StoreRegisterOffsetType.MemReg:
            mem_type = MemoryAccessType(ofs_reg_or_mem_type)
            addr_str = f"[{mem_type_str(mem_type)}+R{addr_reg_index}]"
        elif ofs_type == StoreRegisterOffsetType.MemImm:
            mem_type = MemoryAccessType(ofs_reg_or_mem_type)
            rel_address, instruction_ptr = get_next_vm_int(opcodes, instruction_ptr, 4)
            addr_str = f"[{mem_type_str(mem_type)}+0x{rel_address.value:X}]"
        elif ofs_type == StoreRegisterOffsetType.MemImmReg:
            mem_type = MemoryAccessType(ofs_reg_or_mem_type)
            rel_address, instruction_ptr = get_next_vm_int(opcodes, instruction_ptr, 4)
            addr_str = f"[{mem_type_str(mem_type)}+R{addr_reg_index}+0x{rel_address.value:X}]"
        
        out.str = f"{addr_str} = R{str_reg_index} W={bit_width}"
        if increment_reg:
            out.str += f" R{addr_reg_index} += {bit_width}"
            
    elif out.opcode == CheatVmOpcodeType.BeginRegisterConditionalBlock:
        bit_width = (first_dword >> 20) & 0xF
        cond_type = ConditionalComparisonType((first_dword >> 16) & 0xF)
        val_reg_index = (first_dword >> 12) & 0xF
        comp_type = CompareRegisterValueType((first_dword >> 8) & 0xF)
        
        comp_str = ""
        if comp_type == CompareRegisterValueType.StaticValue:
            value, instruction_ptr = get_next_vm_int(opcodes, instruction_ptr, bit_width)
            comp_str = f"0x{value.value:X}"
        elif comp_type == CompareRegisterValueType.OtherRegister:
            other_reg_index = (first_dword >> 4) & 0xF
            comp_str = f"R{other_reg_index}"
        elif comp_type == CompareRegisterValueType.OffsetValue:
            value, instruction_ptr = get_next_vm_int(opcodes, instruction_ptr, 4)
            comp_str = f"0x{value.value:X}"
        else:
            mem_type_or_reg_idx = (first_dword >> 4) & 0xF
            
            if comp_type in [CompareRegisterValueType.MemoryRelAddr, CompareRegisterValueType.RegisterRelAddr]:
                rel_address, instruction_ptr = get_next_vm_int(opcodes, instruction_ptr, 4)
                if comp_type == CompareRegisterValueType.MemoryRelAddr:
                    mem_type = MemoryAccessType(mem_type_or_reg_idx)
                    comp_str = f"[{mem_type_str(mem_type)}+0x{rel_address.value:X}]"
                else:
                    addr_reg_index = mem_type_or_reg_idx
                    comp_str = f"[R{addr_reg_index}+0x{rel_address.value:X}]"
            else:
                ofs_reg_index = first_dword & 0xF
                if comp_type == CompareRegisterValueType.MemoryOfsReg:
                    mem_type = MemoryAccessType(mem_type_or_reg_idx)
                    comp_str = f"[{mem_type_str(mem_type)}+R{ofs_reg_index}]"
                else:
                    addr_reg_index = mem_type_or_reg_idx
                    comp_str = f"[R{addr_reg_index}+R{ofs_reg_index}]"
        out.str = f"If R{val_reg_index} {CONDITION_STR.get(cond_type, '?')} {comp_str} W={bit_width}"
        
    elif out.opcode == CheatVmOpcodeType.SaveRestoreRegister:
        dst_index = (first_dword >> 16) & 0xF
        src_index = (first_dword >> 8) & 0xF
        op_type = SaveRestoreRegisterOpType((first_dword >> 4) & 0xF)
        out.str = f"SaveRestoreRegister dst={dst_index} src={src_index} {OPERAND_STR.get(op_type, '?')}"
        
    elif out.opcode == CheatVmOpcodeType.SaveRestoreRegisterMask:
        op_type = SaveRestoreRegisterOpType((first_dword >> 20) & 0xF)
        mask = first_dword & 0xFFFF
        out.str = f"SaveRestoreRegisterMask {OPERAND_STR.get(op_type, '?')} mask=0x{mask:04X}"
        
    elif out.opcode == CheatVmOpcodeType.ReadWriteStaticRegister:
        static_idx = (first_dword >> 4) & 0xFF
        idx = first_dword & 0xF
        out.str = f"ReadWriteStaticRegister static_idx=0x{static_idx:X} idx={idx}"
        
    elif out.opcode == CheatVmOpcodeType.BeginExtendedKeypressConditionalBlock:
        auto_repeat = ((first_dword >> 20) & 0xF) != 0
        key_mask, instruction_ptr = get_next_vm_int(opcodes, instruction_ptr, 8)
        out.str = f"If {'keyheld' if auto_repeat else 'keydown'} 0x{key_mask.value:X}"
        
    elif out.opcode == CheatVmOpcodeType.PauseProcess:
        out.str = "PauseProcess"
        
    elif out.opcode == CheatVmOpcodeType.ResumeProcess:
        out.str = "ResumeProcess"
        
    elif out.opcode == CheatVmOpcodeType.DebugLog:
        log_type = DebugLogValueType((first_dword >> 20) & 0xF)
        bit_width = (first_dword >> 16) & 0xF
        value_reg_index = (first_dword >> 12) & 0xF
        
        log_value_str = ""
        if log_type == DebugLogValueType.RegisterValue:
            log_value_str = f"R{value_reg_index}"
        elif log_type == DebugLogValueType.MemoryRelAddr:
            mem_type = MemoryAccessType((first_dword >> 4) & 0xF)
            rel_address, instruction_ptr = get_next_vm_int(opcodes, instruction_ptr, 4)
            log_value_str = f"[{mem_type_str(mem_type)}+0x{rel_address.value:X}]"
        elif log_type == DebugLogValueType.MemoryOfsReg:
            mem_type = MemoryAccessType((first_dword >> 4) & 0xF)
            ofs_reg_index = first_dword & 0xF
            log_value_str = f"[{mem_type_str(mem_type)}+R{ofs_reg_index}]"
        elif log_type == DebugLogValueType.RegisterRelAddr:
            addr_reg_index = (first_dword >> 4) & 0xF
            rel_address, instruction_ptr = get_next_vm_int(opcodes, instruction_ptr, 4)
            log_value_str = f"[R{addr_reg_index}+0x{rel_address.value:X}]"
        elif log_type == DebugLogValueType.RegisterOfsReg:
            addr_reg_index = (first_dword >> 4) & 0xF
            ofs_reg_index = first_dword & 0xF
            log_value_str = f"[R{addr_reg_index}+R{ofs_reg_index}]"

        out.str = f"DebugLog {log_value_str} W={bit_width}"


    else:
        out.str = f"Opcode {out.opcode.name} not implemented in this script."
        if instruction_ptr == index:
            instruction_ptr += 1

    out.size = instruction_ptr - index
    return out

def disassemble_cheat(opcodes):
    output_lines = []
    index = 0
    while index < len(opcodes):
        opcode_info = decode_next_opcode(opcodes, index)
        if not opcode_info:
            print(f"Error: Failed to decode opcode at index {index}.", file=sys.stderr)
            break
        
        raw_opcodes_list = opcodes[index : index + opcode_info.size]
        raw_opcodes_str = " ".join([f"{opc:08X}" for opc in raw_opcodes_list])

        output_lines.append(f"{raw_opcodes_str:<40} {opcode_info.str}")
        
        index += opcode_info.size
    return "\n".join(output_lines)

def disassemble_opcodes_from_string(opcodes_str):
    output_buffer = []

    preprocessed_str = _preprocess_pasted_opcodes(opcodes_str)
    
    current_cheat_opcodes = []
    for line in preprocessed_str.splitlines():
        line = line.strip()
        if not line:
            continue
        if (line.startswith('[') and line.endswith(']')) or \
           (line.startswith('{') and line.endswith('}')):
            if current_cheat_opcodes:
                output_buffer.append(disassemble_cheat(current_cheat_opcodes))
                current_cheat_opcodes = []
            output_buffer.append(f"\n{line}")
        else:
            parts = line.split()
            for part in parts:
                try:
                    current_cheat_opcodes.append(int(part, 16))
                except ValueError:
                    pass

    if current_cheat_opcodes:
        output_buffer.append(disassemble_cheat(current_cheat_opcodes))
    
    return "\n".join(output_buffer)

def _preprocess_pasted_opcodes(opcodes_str):
    lines = opcodes_str.splitlines()
    processed_lines = []
    
    for line in lines:
        stripped_line = line.strip()
        if not stripped_line:
            continue

        if stripped_line.startswith('[') or stripped_line.startswith('{'):
            close_bracket_index = -1
            if stripped_line.startswith('['):
                close_bracket_index = stripped_line.find(']')
            elif stripped_line.startswith('{'):
                close_bracket_index = stripped_line.find('}')
            
            if close_bracket_index != -1:
                header = stripped_line[:close_bracket_index + 1]
                processed_lines.append(header)
                
                remaining_opcodes_str = stripped_line[close_bracket_index + 1:].strip()
                if remaining_opcodes_str:
                    opcode_parts = remaining_opcodes_str.split()
                    processed_lines.extend(opcode_parts)
            else:
                processed_lines.append(stripped_line)
        else:
            opcode_parts = stripped_line.split()
            processed_lines.extend(opcode_parts)

    return "\n".join(processed_lines)


def main():
    global TARGET_ARCH

    if not CAPSTONE_AVAILABLE:
        sys.exit(1)

    for i in range(1, len(sys.argv)):
        if sys.argv[i].lower() == "--arch" and i + 1 < len(sys.argv):
            arch_arg = sys.argv[i+1].strip().upper()
            if arch_arg in ["ARM32", "ARM64"]:
                TARGET_ARCH = arch_arg
            else:
                print(f"Warning: Invalid architecture '{arch_arg}' provided via --arch. Defaulting to ARM64.", file=sys.stderr)
                TARGET_ARCH = "ARM64"
            break

    if TARGET_ARCH is None:
        TARGET_ARCH = "ARM64"
    
    input_str = sys.stdin.read()

    if input_str.startswith('\ufeff'):
        input_str = input_str[1:]
    if not input_str.strip():
        print("No opcode input provided to disassemble.", file=sys.stderr)
        return

    try:
        test_value = 0xD503201F
        if TARGET_ARCH == "ARM64":
            test_disasm = arm64_disassemble(test_value, 0)
        else:
            test_disasm = arm32_disassemble(test_value, 0)

        if not test_disasm:
            print(f"FATAL ERROR: Capstone failed basic disassembly test for 0x{test_value:X} on {TARGET_ARCH}.", file=sys.stderr)
            return
            
    except Exception as e:
        print(f"FATAL ERROR: Capstone library failed basic test with exception: {e}", file=sys.stderr)
        return

    output = disassemble_opcodes_from_string(input_str)
    print(output)

if __name__ == "__main__":
    main()