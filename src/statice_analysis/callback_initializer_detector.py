"""
Callback/Function Pointer Initializer Detector

Detects function pointers in firmware that are initialized in main() but may be
used by interrupt handlers before initialization completes. This is a common
problem in embedded firmware where:

1. Timer/SysTick interrupts are enabled early
2. Interrupt handlers call callback functions using function pointers
3. Function pointers are initialized late in main()
4. Race condition: interrupt fires before pointers are set -> HardFault

Example: P2IM.Robot
- main() calls HAL_Init() which enables SysTick
- SysTick_Handler -> HAL_TIM_PeriodElapsedCallback -> mpu6050_update
- mpu6050_update uses I2C_Read_Reg function pointer (BSS @ 0x20000a48)
- But I2C_Read_Reg is only initialized later in main() @ 0x8005122-8005126
- Result: I2C_Read_Reg = NULL -> blx r4 jumps to 0x00000000 -> HardFault

Solution: Detect these patterns and pre-initialize function pointers
at firmware load time.
"""

import struct
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from pathlib import Path
from elftools.elf.elffile import ELFFile

try:
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
    HAS_CAPSTONE = True
except ImportError:
    HAS_CAPSTONE = False


@dataclass
class FunctionPointerInit:
    """Information about a function pointer initialization"""
    ptr_address: int       # Address of function pointer variable (in BSS/DATA)
    ptr_name: str          # Symbol name if available
    target_address: int    # Address of the function being pointed to
    target_name: str       # Name of target function
    init_location: int     # Where the initialization happens (PC)
    init_function: str     # Name of function containing initialization


class CallbackInitializerDetector:
    """
    Detects function pointer initializations that happen late in main().
    
    These need to be pre-initialized at firmware load time to avoid
    race conditions with interrupt handlers.
    """
    
    def __init__(self, firmware_path: str):
        self.firmware_path = Path(firmware_path)
        self.symbols: Dict[int, str] = {}
        self.reverse_symbols: Dict[str, int] = {}
        self.bss_range: Tuple[int, int] = (0, 0)
        self.data_range: Tuple[int, int] = (0, 0)
        self.text_section: Optional[bytes] = None
        self.text_base: int = 0
        
        self.func_ptr_inits: List[FunctionPointerInit] = []
        
    def analyze(self) -> Dict:
        """Run complete analysis"""
        with open(self.firmware_path, 'rb') as f:
            elf = ELFFile(f)
            self._load_sections(elf)
            self._load_symbols(elf)
            
        # Find function pointer initializations in main()
        self._find_main_func_ptr_inits()
        
        return {
            'function_pointer_inits': self.func_ptr_inits,
            'pre_init_patches': self._generate_pre_init_patches(),
        }
        
    def _load_sections(self, elf: ELFFile):
        """Load section information"""
        for section in elf.iter_sections():
            name = section.name
            addr = section['sh_addr']
            size = section['sh_size']
            
            if name == '.bss':
                self.bss_range = (addr, addr + size)
            elif name == '.data':
                self.data_range = (addr, addr + size)
            elif name == '.text':
                self.text_section = section.data()
                self.text_base = addr
                
    def _load_symbols(self, elf: ELFFile):
        """Load symbol table"""
        for section in elf.iter_sections():
            if section['sh_type'] == 'SHT_SYMTAB':
                for sym in section.iter_symbols():
                    if sym['st_value'] and sym.name:
                        self.symbols[sym['st_value']] = sym.name
                        self.reverse_symbols[sym.name] = sym['st_value']
                        
    def _is_in_bss_or_data(self, addr: int) -> bool:
        """Check if address is in BSS or DATA section"""
        bss_start, bss_end = self.bss_range
        data_start, data_end = self.data_range
        return (bss_start <= addr < bss_end) or (data_start <= addr < data_end)
        
    def _is_code_address(self, addr: int) -> bool:
        """Check if address looks like a code address"""
        # Typical STM32 flash range
        return 0x08000000 <= addr < 0x08200000
        
    def _find_main_func_ptr_inits(self):
        """Find function pointer initializations in main()"""
        if not HAS_CAPSTONE or not self.text_section:
            return
            
        # Find main function
        main_addr = self.reverse_symbols.get('main', 0) & ~1  # Clear Thumb bit
        if not main_addr:
            return
            
        md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
        md.detail = True
        
        # Analyze main function
        offset = main_addr - self.text_base
        if offset < 0 or offset >= len(self.text_section):
            return
            
        # Disassemble up to 512 bytes of main
        chunk_size = min(512, len(self.text_section) - offset)
        chunk = self.text_section[offset:offset + chunk_size]
        
        # Track register values for str instructions
        reg_values: Dict[str, int] = {}
        
        try:
            instructions = list(md.disasm(chunk, main_addr))
            
            for i, insn in enumerate(instructions):
                mnem = insn.mnemonic.lower()
                
                # Look for ldr rN, [pc, #imm] pattern (loading address from literal pool)
                if mnem == 'ldr' and 'pc' in insn.op_str.lower():
                    # Extract the target address from literal pool
                    try:
                        # Parse "r3, [pc, #0x2c]" or "r2, [pc, #0x30]"
                        # Split only on first comma to get register
                        first_comma = insn.op_str.find(',')
                        if first_comma < 0:
                            continue
                        reg = insn.op_str[:first_comma].strip()
                        rest = insn.op_str[first_comma+1:].strip()
                        
                        # Extract offset value from [pc, #0x2c]
                        # Find the # character
                        hash_pos = rest.find('#')
                        if hash_pos < 0:
                            continue
                        
                        # Extract number after #
                        offset_part = rest[hash_pos+1:].replace(']', '').strip()
                        
                        # Calculate literal pool address
                        pc = insn.address + 4  # PC is 4 bytes ahead in Thumb
                        
                        # Handle hex offset (0x2c) or decimal
                        if offset_part.startswith('0x'):
                            offset_val = int(offset_part, 16)
                        else:
                            offset_val = int(offset_part)
                            
                        literal_addr = (pc + offset_val) & ~3  # Align to 4 bytes
                        
                        # Read the value from the literal pool
                        lit_offset = literal_addr - self.text_base
                        if 0 <= lit_offset < len(self.text_section) - 4:
                            value = struct.unpack('<I', self.text_section[lit_offset:lit_offset+4])[0]
                            reg_values[reg] = value
                    except (ValueError, IndexError) as e:
                        pass
                        
                # Look for str rN, [rM] pattern (storing to pointer)
                elif mnem == 'str' and ',' in insn.op_str:
                    try:
                        parts = insn.op_str.split(',')
                        src_reg = parts[0].strip()
                        dst_part = parts[1].strip().replace('[', '').replace(']', '')
                        
                        # Get destination register (pointer to BSS/DATA)
                        dst_parts = dst_part.split('#')
                        dst_reg = dst_parts[0].strip()
                        
                        # Handle hex offset
                        if len(dst_parts) > 1:
                            off_str = dst_parts[1].strip()
                            if off_str.startswith('0x'):
                                dst_offset = int(off_str, 16)
                            else:
                                dst_offset = int(off_str)
                        else:
                            dst_offset = 0
                        
                        # Check if we have values for both registers
                        if src_reg in reg_values and dst_reg in reg_values:
                            src_value = reg_values[src_reg]
                            dst_addr = reg_values[dst_reg] + dst_offset
                            
                            # Check if this is storing a code address to BSS/DATA
                            if self._is_code_address(src_value) and self._is_in_bss_or_data(dst_addr):
                                ptr_name = self.symbols.get(dst_addr, f'ptr_{dst_addr:08X}')
                                target_name = self.symbols.get(src_value & ~1, f'func_{src_value:08X}')
                                
                                self.func_ptr_inits.append(FunctionPointerInit(
                                    ptr_address=dst_addr,
                                    ptr_name=ptr_name,
                                    target_address=src_value,
                                    target_name=target_name,
                                    init_location=insn.address,
                                    init_function='main'
                                ))
                    except (ValueError, IndexError) as e:
                        pass
                        
        except Exception as e:
            import logging
            logging.getLogger(__name__).warning(f"Error analyzing main(): {e}")
            
    def _generate_pre_init_patches(self) -> List[Dict]:
        """Generate memory writes to pre-initialize function pointers"""
        patches = []
        
        for init in self.func_ptr_inits:
            patches.append({
                'address': init.ptr_address,
                'value': init.target_address,
                'name': init.ptr_name,
                'target_name': init.target_name,
                'description': f"Pre-init {init.ptr_name} = {init.target_name} (0x{init.target_address:08X})"
            })
            
        return patches


def detect_late_init_function_pointers(firmware_path: str) -> Dict:
    """
    Main entry point for detecting late-initialized function pointers.
    
    These are function pointers that:
    1. Are in BSS/DATA section
    2. Are initialized in main()
    3. May be used by interrupt handlers before main() completes
    
    Returns patches to pre-initialize these pointers at load time.
    """
    detector = CallbackInitializerDetector(firmware_path)
    return detector.analyze()


def generate_pre_init_code(firmware_path: str) -> str:
    """
    Generate C code to pre-initialize function pointers at firmware load time.
    
    This code should be added to the QEMU board file and called after
    the firmware is loaded but before execution starts.
    """
    result = detect_late_init_function_pointers(firmware_path)
    patches = result.get('pre_init_patches', [])
    
    if not patches:
        return "/* No late-init function pointers detected */\n"
        
    code = '''
/* ================================================================
 * FUNCTION POINTER PRE-INITIALIZATION
 * 
 * These function pointers are initialized late in main() but may be
 * called by interrupt handlers before initialization completes.
 * Pre-initializing them prevents race condition HardFaults.
 * ================================================================ */

struct func_ptr_init {
    uint32_t ptr_address;   /* Address of pointer variable */
    uint32_t value;         /* Value to write (function address) */
    const char *name;       /* Description */
};

'''
    
    # Generate initialization data
    code += "static const struct func_ptr_init g_func_ptr_inits[] = {\n"
    for patch in patches:
        code += f'    {{ 0x{patch["address"]:08X}, 0x{patch["value"]:08X}, "{patch["description"]}" }},\n'
    code += "    { 0, 0, NULL }  /* End marker */\n"
    code += "};\n\n"
    
    # Generate initialization function
    code += '''
/* Pre-initialize function pointers (call after firmware load, before execution) */
static void pre_init_function_pointers(void) {
    for (int i = 0; g_func_ptr_inits[i].name != NULL; i++) {
        uint32_t addr = g_func_ptr_inits[i].ptr_address;
        uint32_t value = g_func_ptr_inits[i].value;
        
        cpu_physical_memory_write(addr, &value, 4);
        
        fprintf(stderr, "PRE-INIT: %s @ 0x%08X = 0x%08X\\n",
                g_func_ptr_inits[i].name, addr, value);
    }
}

'''
    
    return code

