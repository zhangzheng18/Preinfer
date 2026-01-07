"""
CRC/Checksum Function Detector

This module detects CRC and checksum calculation functions in firmware.
It uses multiple heuristics:
1. Symbol name matching (calcCRC, crc16, checksum, etc.)
2. Instruction pattern matching (XOR loops, lookup tables)
3. Known CRC polynomial detection

The detected functions can be hooked to bypass validation.
"""

import struct
import re
from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass
from pathlib import Path
from elftools.elf.elffile import ELFFile

try:
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
    HAS_CAPSTONE = True
except ImportError:
    HAS_CAPSTONE = False


@dataclass
class CRCFunctionInfo:
    """Information about a detected CRC/checksum function"""
    address: int
    name: str
    detection_method: str  # 'symbol', 'pattern', 'polynomial'
    confidence: float      # 0.0 - 1.0
    return_type: str       # 'uint8', 'uint16', 'uint32'
    suggested_return: int  # Value to return to bypass validation


class CRCFunctionDetector:
    """Detects CRC and checksum functions in firmware"""
    
    # Common CRC/checksum function name patterns
    CRC_NAME_PATTERNS = [
        r'crc',
        r'checksum',
        r'check_sum',
        r'calc.*crc',
        r'compute.*crc',
        r'verify',
        r'validate.*crc',
        r'hash',
    ]
    
    # Known CRC polynomials (for detection)
    CRC_POLYNOMIALS = {
        0xA001: ('CRC-16-MODBUS', 16),
        0x8005: ('CRC-16-IBM', 16),
        0x1021: ('CRC-16-CCITT', 16),
        0x04C11DB7: ('CRC-32', 32),
        0xEDB88320: ('CRC-32-ISO', 32),
        0x07: ('CRC-8', 8),
        0x8C: ('CRC-8-MAXIM', 8),
    }
    
    def __init__(self, firmware_path: str):
        self.firmware_path = Path(firmware_path)
        self.crc_functions: List[CRCFunctionInfo] = []
        self.symbols: Dict[int, str] = {}
        self.text_section = None
        
    def analyze(self) -> List[CRCFunctionInfo]:
        """Perform full CRC function analysis"""
        with open(self.firmware_path, 'rb') as f:
            elf = ELFFile(f)
            self._load_symbols(elf)
            self._load_text_section(elf)
            
        # Method 1: Symbol name matching
        self._detect_by_symbol_name()
        
        # Method 2: Instruction pattern matching
        if HAS_CAPSTONE and self.text_section:
            self._detect_by_pattern()
            
        # Method 3: Polynomial detection
        self._detect_by_polynomial()
        
        # Remove duplicates and sort by confidence
        self._deduplicate()
        
        return self.crc_functions
    
    def _load_symbols(self, elf: ELFFile):
        """Load symbol table"""
        for section in elf.iter_sections():
            if section['sh_type'] == 'SHT_SYMTAB':
                for sym in section.iter_symbols():
                    if sym['st_value'] and sym.name:
                        self.symbols[sym['st_value']] = sym.name
                        
    def _load_text_section(self, elf: ELFFile):
        """Load .text section"""
        for section in elf.iter_sections():
            if section.name == '.text':
                self.text_section = {
                    'addr': section['sh_addr'],
                    'data': section.data()
                }
                break
                
    def _detect_by_symbol_name(self):
        """Detect CRC functions by symbol name matching"""
        for addr, name in self.symbols.items():
            name_lower = name.lower()
            
            # Skip data symbols but allow C++ mangled names (_Z...)
            if name.startswith('$'):
                continue
            # Only skip leading _ if it's not a C++ mangled name
            if name.startswith('_') and not name.startswith('_Z'):
                continue
                
            for pattern in self.CRC_NAME_PATTERNS:
                if re.search(pattern, name_lower):
                    # Determine return type from name
                    return_type = 'uint16'
                    if '32' in name or 'long' in name_lower:
                        return_type = 'uint32'
                    elif '8' in name or 'byte' in name_lower:
                        return_type = 'uint8'
                        
                    # For CRC validation bypass, we want to return a matching value
                    # This is typically handled by making the function return
                    # the expected CRC that's already in the data
                    suggested_return = 0  # Will be determined at runtime
                    
                    info = CRCFunctionInfo(
                        address=addr,
                        name=name,
                        detection_method='symbol',
                        confidence=0.9,
                        return_type=return_type,
                        suggested_return=suggested_return
                    )
                    self.crc_functions.append(info)
                    break
                    
    def _detect_by_pattern(self):
        """Detect CRC functions by instruction patterns"""
        if not self.text_section:
            return
            
        md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
        md.detail = True
        
        # Look for XOR-heavy loops (characteristic of CRC calculations)
        code = self.text_section['data']
        base_addr = self.text_section['addr']
        
        # Analyze functions
        for func_addr in self._find_function_starts():
            offset = func_addr - base_addr
            if offset < 0 or offset >= len(code):
                continue
                
            # Check if this function contains CRC-like patterns
            score = self._analyze_function_for_crc(md, code, base_addr, func_addr)
            
            if score >= 0.6:
                # Get function name if available
                name = self.symbols.get(func_addr, f"crc_func_{func_addr:08x}")
                
                info = CRCFunctionInfo(
                    address=func_addr,
                    name=name,
                    detection_method='pattern',
                    confidence=score,
                    return_type='uint16',  # Default assumption
                    suggested_return=0
                )
                self.crc_functions.append(info)
                
    def _find_function_starts(self) -> List[int]:
        """Find function start addresses"""
        func_addrs = []
        for addr, name in self.symbols.items():
            if not name.startswith('$'):
                func_addrs.append(addr)
        return func_addrs
        
    def _analyze_function_for_crc(self, md, code: bytes, base_addr: int, 
                                   func_addr: int) -> float:
        """Analyze a function for CRC-like patterns"""
        offset = func_addr - base_addr
        chunk_size = min(200, len(code) - offset)  # Analyze up to 200 bytes
        if chunk_size <= 0:
            return 0.0
            
        chunk = code[offset:offset + chunk_size]
        
        # Count indicators
        xor_count = 0
        shift_count = 0
        loop_detected = False
        table_load_detected = False
        
        try:
            for insn in md.disasm(chunk, func_addr):
                mnem = insn.mnemonic.lower()
                
                if 'eor' in mnem or 'xor' in mnem:
                    xor_count += 1
                if 'lsr' in mnem or 'lsl' in mnem or 'ror' in mnem:
                    shift_count += 1
                if 'b' in mnem and not 'bl' in mnem:
                    # Backward branch indicates loop
                    if hasattr(insn, 'operands') and insn.operands:
                        try:
                            target = int(insn.op_str.replace('#', ''), 16)
                            if target < insn.address:
                                loop_detected = True
                        except:
                            pass
                # Look for table lookups
                if 'ldr' in mnem and 'pc' in insn.op_str:
                    table_load_detected = True
                    
        except Exception:
            pass
            
        # Calculate score based on indicators
        score = 0.0
        if xor_count >= 2:
            score += 0.3
        if shift_count >= 2:
            score += 0.2
        if loop_detected:
            score += 0.2
        if table_load_detected:
            score += 0.2
        if xor_count >= 4 and shift_count >= 4:
            score += 0.1  # Very strong indicator
            
        return min(score, 1.0)
        
    def _detect_by_polynomial(self):
        """Detect CRC by finding known polynomials in data"""
        if not self.text_section:
            return
            
        data = self.text_section['data']
        
        for i in range(0, len(data) - 4, 4):
            val32 = struct.unpack('<I', data[i:i+4])[0]
            val16 = val32 & 0xFFFF
            
            for poly, (name, bits) in self.CRC_POLYNOMIALS.items():
                if val32 == poly or val16 == poly:
                    # Found polynomial, look for nearby function
                    poly_addr = self.text_section['addr'] + i
                    nearby_func = self._find_nearby_function(poly_addr)
                    
                    if nearby_func:
                        info = CRCFunctionInfo(
                            address=nearby_func,
                            name=self.symbols.get(nearby_func, f"crc_{name}_{nearby_func:08x}"),
                            detection_method='polynomial',
                            confidence=0.85,
                            return_type=f'uint{bits}',
                            suggested_return=0
                        )
                        self.crc_functions.append(info)
                        
    def _find_nearby_function(self, addr: int) -> Optional[int]:
        """Find the nearest function before given address"""
        nearest = None
        for func_addr in self.symbols.keys():
            if func_addr <= addr:
                if nearest is None or func_addr > nearest:
                    nearest = func_addr
        return nearest
        
    def _deduplicate(self):
        """Remove duplicate detections, keeping highest confidence"""
        seen: Dict[int, CRCFunctionInfo] = {}
        
        for info in self.crc_functions:
            if info.address not in seen:
                seen[info.address] = info
            elif info.confidence > seen[info.address].confidence:
                seen[info.address] = info
                
        self.crc_functions = sorted(seen.values(), 
                                    key=lambda x: x.confidence, 
                                    reverse=True)
                                    
    def get_hook_suggestions(self) -> List[Dict]:
        """Generate hook suggestions for bypassing CRC validation"""
        suggestions = []
        
        for info in self.crc_functions:
            suggestion = {
                'address': info.address,
                'name': info.name,
                'confidence': info.confidence,
                'hook_type': 'return_value_override',
                'description': f"Hook {info.name} to bypass CRC validation",
                
                # Generate hook code
                'hook_code': self._generate_hook_code(info)
            }
            suggestions.append(suggestion)
            
        return suggestions
        
    def _generate_hook_code(self, info: CRCFunctionInfo) -> str:
        """Generate C code for hooking the CRC function"""
        return f'''
/* CRC Bypass Hook for {info.name} @ 0x{info.address:08X}
 * Detection method: {info.detection_method}
 * Confidence: {info.confidence:.0%}
 */
#define CRC_FUNC_ADDR_{info.name.upper().replace('::', '_')} 0x{info.address:08X}

/* Strategy: Make CRC always match by returning the expected CRC
 * For Modbus: the expected CRC is the last 2 bytes of the frame
 * For other protocols: may need protocol-specific handling
 */
static uint32_t crc_bypass_hook_{info.address:08x}(CPUState *cpu) {{
    /* Get the CRC from the input data (protocol-specific)
     * This is a placeholder - actual implementation depends on protocol
     */
    return 0;  /* Return matching CRC */
}}
'''


class SerialBufferDetector:
    """Detects serial/UART buffer structures in firmware"""
    
    # Common HAL library patterns for serial buffers
    SERIAL_PATTERNS = {
        'stm32_hal': {
            'rx_buffer_offset': 0x134,  # HardwareSerial._rx_buffer
            'rx_head_offset': 0x138,
            'rx_tail_offset': 0x13a,
            'buffer_size': 64,
            'symbols': ['HardwareSerial', 'Serial', 'USART']
        },
        'arduino': {
            'rx_buffer_offset': 0x20,
            'rx_head_offset': 0x24,
            'rx_tail_offset': 0x26,
            'buffer_size': 64,
            'symbols': ['Serial', 'HardwareSerial']
        },
        'mbed': {
            'rx_buffer_offset': 0x10,
            'rx_head_offset': 0x14,
            'rx_tail_offset': 0x16,
            'buffer_size': 256,
            'symbols': ['BufferedSerial', 'UnbufferedSerial']
        },
        'freertos': {
            'rx_buffer_offset': 0x08,
            'rx_head_offset': 0x0C,
            'rx_tail_offset': 0x0E,
            'buffer_size': 128,
            'symbols': ['xQueueHandle', 'StreamBuffer']
        }
    }
    
    def __init__(self, firmware_path: str):
        self.firmware_path = Path(firmware_path)
        self.detected_hal: Optional[str] = None
        self.serial_objects: List[Dict] = []
        self.symbols: Dict[int, str] = {}
        
    def analyze(self) -> Dict:
        """Analyze firmware for serial buffer patterns"""
        with open(self.firmware_path, 'rb') as f:
            elf = ELFFile(f)
            self._load_symbols(elf)
            
        # Detect HAL library type
        self.detected_hal = self._detect_hal_type()
        
        # Find serial objects
        self.serial_objects = self._find_serial_objects()
        
        return {
            'hal_type': self.detected_hal,
            'serial_objects': self.serial_objects,
            'buffer_config': self.SERIAL_PATTERNS.get(self.detected_hal, {})
        }
        
    def _load_symbols(self, elf: ELFFile):
        """Load symbol table"""
        for section in elf.iter_sections():
            if section['sh_type'] == 'SHT_SYMTAB':
                for sym in section.iter_symbols():
                    if sym['st_value'] and sym.name:
                        self.symbols[sym['st_value']] = sym.name
                        
    def _detect_hal_type(self) -> str:
        """Detect which HAL library is used"""
        symbol_names = list(self.symbols.values())
        symbol_str = ' '.join(symbol_names).lower()
        
        # Check for each HAL type
        hal_scores = {}
        
        for hal_name, config in self.SERIAL_PATTERNS.items():
            score = 0
            for pattern in config['symbols']:
                if pattern.lower() in symbol_str:
                    score += 1
            hal_scores[hal_name] = score
            
        # Additional detection based on specific symbols
        if 'HAL_UART' in symbol_str or 'stm32' in symbol_str:
            hal_scores['stm32_hal'] = hal_scores.get('stm32_hal', 0) + 5
        if 'arduino' in symbol_str or '_ZN14HardwareSerial' in symbol_str:
            hal_scores['arduino'] = hal_scores.get('arduino', 0) + 5
        if 'mbed' in symbol_str:
            hal_scores['mbed'] = hal_scores.get('mbed', 0) + 5
        if 'freertos' in symbol_str.lower() or 'xQueue' in symbol_str:
            hal_scores['freertos'] = hal_scores.get('freertos', 0) + 5
            
        if not hal_scores:
            return 'unknown'
            
        return max(hal_scores, key=hal_scores.get)
        
    def _find_serial_objects(self) -> List[Dict]:
        """Find serial object instances"""
        objects = []
        
        # Look for Serial object symbols
        serial_patterns = [
            r'Serial\d*$',
            r'uart\d*$',
            r'usart\d*$',
            r'serial_\w+$',
        ]
        
        for addr, name in self.symbols.items():
            # Only look in RAM region
            if not (0x20000000 <= addr < 0x20100000):
                continue
                
            for pattern in serial_patterns:
                if re.search(pattern, name, re.IGNORECASE):
                    objects.append({
                        'name': name,
                        'address': addr,
                        'type': 'serial_object'
                    })
                    break
                    
        return objects
        
    def generate_injection_code(self) -> str:
        """Generate C code for serial buffer injection"""
        if not self.detected_hal or self.detected_hal == 'unknown':
            return "/* Unable to detect HAL type for serial injection */"
            
        config = self.SERIAL_PATTERNS[self.detected_hal]
        
        code = f'''
/* Serial Buffer Injection for {self.detected_hal}
 * Auto-detected HAL library configuration
 */

#define SERIAL_RX_BUFFER_OFFSET  0x{config['rx_buffer_offset']:X}
#define SERIAL_RX_HEAD_OFFSET    0x{config['rx_head_offset']:X}
#define SERIAL_RX_TAIL_OFFSET    0x{config['rx_tail_offset']:X}
#define SERIAL_BUFFER_SIZE       {config['buffer_size']}
#define SERIAL_BUFFER_MASK       (SERIAL_BUFFER_SIZE - 1)

/* Inject data into serial buffer at runtime */
static void inject_serial_data(uint32_t serial_obj_addr, 
                               const uint8_t *data, int len) {{
    /* Read buffer configuration */
    uint32_t rx_buf_ptr_addr = serial_obj_addr + SERIAL_RX_BUFFER_OFFSET;
    uint32_t rx_head_addr = serial_obj_addr + SERIAL_RX_HEAD_OFFSET;
    uint32_t rx_tail_addr = serial_obj_addr + SERIAL_RX_TAIL_OFFSET;
    
    uint32_t rx_buf_addr = 0;
    uint16_t rx_head = 0;
    
    cpu_physical_memory_read(rx_buf_ptr_addr, &rx_buf_addr, 4);
    cpu_physical_memory_read(rx_head_addr, &rx_head, 2);
    
    if (rx_buf_addr == 0 || rx_buf_addr < 0x20000000) {{
        return;  /* Buffer not initialized */
    }}
    
    /* Write data to ring buffer */
    for (int i = 0; i < len; i++) {{
        uint32_t write_addr = rx_buf_addr + ((rx_head + i) & SERIAL_BUFFER_MASK);
        cpu_physical_memory_write(write_addr, &data[i], 1);
    }}
    
    /* Update head pointer */
    rx_head = (rx_head + len) & SERIAL_BUFFER_MASK;
    cpu_physical_memory_write(rx_head_addr, &rx_head, 2);
}}
'''
        return code


@dataclass
class SerialPollingInfo:
    """Information about serial polling functions to hook"""
    address: int
    name: str
    hook_type: str  # 'getc' or 'readable'


class SerialPollingDetector:
    """
    Detects serial polling functions that can be hooked to inject data.
    
    Instead of simulating UART hardware registers (which QEMU models may override),
    we hook getc-style functions directly to return injected data.
    """
    
    POLLING_PATTERNS = [
        ('serial_getc', 'getc'),          # Direct serial_getc 
        ('_5_getc', 'getc'),               # mbed Serial::_getc
        ('_base_getc', 'getc'),            # mbed SerialBase::_base_getc
        ('mbed_getc', 'getc'),             # mbed mbed_getc
        ('serial_readable', 'readable'),
        ('available', 'readable'),
    ]
    
    def __init__(self, firmware_path: str):
        self.firmware_path = firmware_path
        self.functions: List[SerialPollingInfo] = []
        
    def analyze(self) -> List[SerialPollingInfo]:
        """Detect serial polling functions"""
        try:
            with open(self.firmware_path, 'rb') as f:
                elf = ELFFile(f)
                
                for section in elf.iter_sections():
                    if section['sh_type'] == 'SHT_SYMTAB':
                        for sym in section.iter_symbols():
                            if sym['st_info']['type'] == 'STT_FUNC' and sym['st_value'] != 0:
                                self._check_symbol(sym)
                                
        except Exception:
            pass
            
        return self.functions
        
    def _check_symbol(self, sym):
        """Check if symbol matches serial polling patterns"""
        name = sym.name.lower()
        
        for pattern, hook_type in self.POLLING_PATTERNS:
            if pattern.lower() in name:
                self.functions.append(SerialPollingInfo(
                    address=sym['st_value'],
                    name=sym.name,
                    hook_type=hook_type
                ))
                break
                
    def get_getc_functions(self) -> List[Dict]:
        """Get all serial/polling functions that need hooking"""
        return [
            {'address': f.address, 'name': f.name, 'hook_type': f.hook_type}
            for f in self.functions
        ]


@dataclass
class HALFunctionInfo:
    """Information about a HAL function that may need bypass"""
    address: int
    name: str
    return_value: int  # Value to return (0 = success for most HAL functions)
    reason: str        # Why bypass is needed


class HALFunctionDetector:
    """
    Detects HAL functions that commonly need to be bypassed in QEMU.
    
    Common issues:
    1. HAL_RCC_* functions fail because RCC is not fully emulated
    2. HAL_FLASH_* functions fail because flash programming is complex
    3. HAL_PWR_* functions fail because power management is not emulated
    """
    
    # HAL functions that commonly need bypass and their recommended return values
    BYPASS_PATTERNS = {
        # RCC (Reset and Clock Control) - always need bypass, return HAL_OK (0)
        'HAL_RCC_OscConfig': {'return': 0, 'reason': 'RCC oscillator config not emulated'},
        'HAL_RCC_ClockConfig': {'return': 0, 'reason': 'RCC clock config not emulated'},
        'HAL_RCC_PeriphCLKConfig': {'return': 0, 'reason': 'RCC peripheral clock not emulated'},
        'HAL_RCCEx_PeriphCLKConfig': {'return': 0, 'reason': 'RCC extended config not emulated'},
        
        # mbed/STM32 clock setup functions - return 1 (success)
        'SetSysClock': {'return': 1, 'reason': 'System clock setup not emulated'},
        'SetSysClock_PLL_HSE': {'return': 1, 'reason': 'HSE clock setup not emulated'},
        'SetSysClock_PLL_HSI': {'return': 1, 'reason': 'HSI clock setup not emulated'},
        'SetSysClock_PLL_MSI': {'return': 1, 'reason': 'MSI clock setup not emulated'},
        
        # PWR (Power Control) - often need bypass
        'HAL_PWR_ConfigPVD': {'return': 0, 'reason': 'PWR PVD not emulated'},
        'HAL_PWREx_EnableOverDrive': {'return': 0, 'reason': 'PWR overdrive not emulated'},
        'HAL_PWREx_ConfigVoltageScaling': {'return': 0, 'reason': 'PWR voltage scaling not emulated'},
        'HAL_PWR_EnableBkUpAccess': {'return': 0, 'reason': 'PWR backup access not emulated'},
        
        # FLASH - programming needs bypass
        'HAL_FLASH_Program': {'return': 0, 'reason': 'Flash programming not emulated'},
        'HAL_FLASH_Unlock': {'return': 0, 'reason': 'Flash unlock not emulated'},
        'HAL_FLASH_Lock': {'return': 0, 'reason': 'Flash lock not emulated'},
        'HAL_FLASHEx_Erase': {'return': 0, 'reason': 'Flash erase not emulated'},
        
        # RTC (Real-Time Clock) - initialization loops
        'RTC_EnterInitMode': {'return': 0, 'reason': 'RTC init mode not emulated'},
        'HAL_RTC_Init': {'return': 0, 'reason': 'RTC not fully emulated'},
        'HAL_RTC_SetTime': {'return': 0, 'reason': 'RTC not fully emulated'},
        'HAL_RTC_SetDate': {'return': 0, 'reason': 'RTC not fully emulated'},
        'HAL_RTCEx_BKUPRead': {'return': 0, 'reason': 'RTC backup not emulated'},
        'RTC_WaitForSynchro': {'return': 0, 'reason': 'RTC sync not emulated'},
        
        # HAL Init - keep HAL_Init but let HAL_InitTick run (no polling)
        'HAL_Init': {'return': 0, 'reason': 'HAL init calls multiple functions'},
        # 'HAL_InitTick': Removed - no polling, just SysTick config
        
        # Wait/Delay functions - skip to speed up execution
        'wait_ms': {'return': 0, 'reason': 'Skip wait for faster execution'},
        'wait_us': {'return': 0, 'reason': 'Skip wait for faster execution'},
        'HAL_Delay': {'return': 0, 'reason': 'Skip delay for faster execution'},
        
        # I2C/SPI - often have timeout issues
        'HAL_I2C_Master_Transmit': {'return': 0, 'reason': 'I2C not fully emulated'},
        'HAL_I2C_Master_Receive': {'return': 0, 'reason': 'I2C not fully emulated'},
        'HAL_SPI_Transmit': {'return': 0, 'reason': 'SPI not fully emulated'},
        'HAL_SPI_Receive': {'return': 0, 'reason': 'SPI not fully emulated'},
        'HAL_SPI_TransmitReceive': {'return': 0, 'reason': 'SPI not fully emulated'},
        
        # ADC - calibration and conversion have polling loops
        'HAL_ADC_Start': {'return': 0, 'reason': 'ADC start has polling'},
        'HAL_ADC_Stop': {'return': 0, 'reason': 'ADC stop has polling'},
        'HAL_ADC_PollForConversion': {'return': 0, 'reason': 'ADC poll has polling'},
        'HAL_ADCEx_Calibration_Start': {'return': 0, 'reason': 'ADC calibration has polling'},
        'HAL_ADCEx_InjectedStart': {'return': 0, 'reason': 'ADC injected has polling'},
        'ADC_Enable': {'return': 0, 'reason': 'ADC enable has polling'},
        'ADC_Disable': {'return': 0, 'reason': 'ADC disable has polling'},
        'ADC_ConversionStop_Disable': {'return': 0, 'reason': 'ADC stop has polling'},
        
        # TIM - only stop functions have polling, start functions are safe
        # 'HAL_TIM_Base_Start': Removed - no polling, just sets registers
        'HAL_TIM_Base_Stop': {'return': 0, 'reason': 'Timer stop has polling'},
        # 'HAL_TIM_PWM_Start': Removed - no polling, just sets registers  
        'HAL_TIM_PWM_Stop': {'return': 0, 'reason': 'PWM stop has polling'},
        
        # Sensor calibration - let calibrate run with simulated I2C data for more code coverage
        # 'mpu6050_calibrate': Removed - let it run, it calls mpu6050_calc_acc_pitch_roll which has different code paths
        'imu_calibrate': {'return': 0, 'reason': 'Skip IMU calibration loop'},
        'sensor_calibrate': {'return': 0, 'reason': 'Skip sensor calibration loop'},
        
        # I2C wait functions (NOT init - we need I2C to work for sensor data)
        'I2C_WaitOnMasterAddressFlagUntilTimeout': {'return': 0, 'reason': 'I2C address wait bypass'},
        'I2C_WaitOnTXEFlagUntilTimeout': {'return': 0, 'reason': 'I2C TXE wait bypass'},
        'I2C_WaitOnBTFFlagUntilTimeout': {'return': 0, 'reason': 'I2C BTF wait bypass'},
        'I2C_WaitOnRXNEFlagUntilTimeout': {'return': 0, 'reason': 'I2C RXNE wait bypass'},
        'I2C_IsAcknowledgeFailed': {'return': 0, 'reason': 'I2C ACK always success'},
        'HAL_I2C_IsDeviceReady': {'return': 0, 'reason': 'I2C device check has polling'},
        'HAL_SPI_Init': {'return': 0, 'reason': 'SPI init has polling'},
        'UART_WaitOnFlagUntilTimeout': {'return': 0, 'reason': 'UART flag wait has polling'},
        'HAL_UART_Transmit': {'return': 0, 'reason': 'UART transmit has polling'},
        'HAL_UART_Receive': {'return': 0, 'reason': 'UART receive has polling'},
        'HAL_UART_Transmit_IT': {'return': 0, 'reason': 'UART transmit IT has polling'},
        'HAL_UART_Receive_IT': {'return': 0, 'reason': 'UART receive IT has polling'},
        
        # Zephyr RTOS specific
        'stm32_clock_control_init': {'return': 0, 'reason': 'Zephyr clock init polling'},
        'config_pll_init': {'return': 0, 'reason': 'Zephyr PLL init polling'},
        'config_enable_default_clocks': {'return': 0, 'reason': 'Zephyr clock enable polling'},
        'z_arm_cpu_idle_init': {'return': 0, 'reason': 'Zephyr idle init not needed'},
        'z_arm_fault_init': {'return': 0, 'reason': 'Zephyr fault init not needed'},
        'uart_stm32_init': {'return': 0, 'reason': 'Zephyr UART init polling'},
        'can_stm32_init': {'return': 0, 'reason': 'Zephyr CAN init polling'},
        'uart_stm32_poll_out': {'return': 0, 'reason': 'Zephyr UART poll out polling'},
        'uart_stm32_poll_in': {'return': 0, 'reason': 'Zephyr UART poll in polling'},
        'z_impl_k_sleep': {'return': 0, 'reason': 'Zephyr sleep bypass'},
        'z_impl_k_msleep': {'return': 0, 'reason': 'Zephyr msleep bypass'},
    }
    
    def __init__(self, firmware_path: str):
        self.firmware_path = firmware_path
        self.functions: List[HALFunctionInfo] = []
        
    def analyze(self) -> List[HALFunctionInfo]:
        """Analyze firmware and detect HAL functions that need bypass"""
        try:
            with open(self.firmware_path, 'rb') as f:
                elf = ELFFile(f)
                
                for section in elf.iter_sections():
                    if section['sh_type'] == 'SHT_SYMTAB':
                        for sym in section.iter_symbols():
                            if sym['st_info']['type'] == 'STT_FUNC':
                                self._check_symbol(sym)
                                
        except Exception as e:
            pass  # Silently handle errors
            
        return self.functions
        
    def _check_symbol(self, sym):
        """Check if symbol matches HAL bypass patterns"""
        name = sym.name
        
        for pattern, info in self.BYPASS_PATTERNS.items():
            if pattern in name:
                self.functions.append(HALFunctionInfo(
                    address=sym['st_value'],
                    name=name,
                    return_value=info['return'],
                    reason=info['reason']
                ))
                break
                
    def get_bypass_patches(self) -> List[Dict]:
        """Get patch information for detected HAL functions"""
        patches = []
        for func in self.functions:
            patches.append({
                'address': func.address,
                'name': func.name,
                'return_value': func.return_value,
                'reason': func.reason
            })
        return patches


@dataclass  
class UARTPollingInfo:
    """Information about UART polling patterns"""
    uart_base: int          # UART peripheral base address
    polling_func: str       # Function name doing the polling
    polling_addr: int       # Address of polling instruction
    mcu_family: str         # STM32F1, STM32F4, STM32L1, etc.


class UARTPollingDetector:
    """
    Detects UART polling patterns in firmware.
    
    Common patterns:
    1. serial_getc style: read SR, check RXNE, loop
    2. HAL_UART_Receive polling
    3. Direct register polling
    """
    
    # Known UART base addresses for different MCU families
    UART_ADDRESSES = {
        'STM32F1': {
            'USART1': 0x40013800,
            'USART2': 0x40004400,
            'USART3': 0x40004800,
        },
        'STM32F4': {
            'USART1': 0x40011000,
            'USART2': 0x40004400,
            'USART3': 0x40004800,
            'UART4': 0x40004C00,
            'UART5': 0x40005000,
            'USART6': 0x40011400,
        },
        'STM32L1': {
            'USART1': 0x40013800,
            'USART2': 0x40004400,
            'USART3': 0x40004800,
            'UART4': 0x40004C00,
            'UART5': 0x40005000,
        },
    }
    
    def __init__(self, firmware_path: str):
        self.firmware_path = firmware_path
        self.polling_points: List[UARTPollingInfo] = []
        self.mcu_family = 'STM32F4'  # Default
        
    def analyze(self) -> List[UARTPollingInfo]:
        """Detect UART polling patterns"""
        try:
            with open(self.firmware_path, 'rb') as f:
                elf = ELFFile(f)
                
                # Detect MCU family from symbols
                self._detect_mcu_family(elf)
                
                # Look for serial_getc, getc, etc.
                for section in elf.iter_sections():
                    if section['sh_type'] == 'SHT_SYMTAB':
                        for sym in section.iter_symbols():
                            if sym['st_info']['type'] == 'STT_FUNC':
                                name_lower = sym.name.lower()
                                if 'serial_getc' in name_lower or 'getc' in name_lower:
                                    # Found potential polling function
                                    for uart_name, uart_addr in self.UART_ADDRESSES.get(
                                            self.mcu_family, {}).items():
                                        self.polling_points.append(UARTPollingInfo(
                                            uart_base=uart_addr,
                                            polling_func=sym.name,
                                            polling_addr=sym['st_value'],
                                            mcu_family=self.mcu_family
                                        ))
                                        break  # Just add first UART
                                        
        except Exception:
            pass
            
        return self.polling_points
        
    def _detect_mcu_family(self, elf):
        """Detect MCU family from symbols"""
        for section in elf.iter_sections():
            if section['sh_type'] == 'SHT_SYMTAB':
                for sym in section.iter_symbols():
                    name = sym.name
                    if 'STM32F1' in name or 'stm32f1' in name:
                        self.mcu_family = 'STM32F1'
                        return
                    elif 'STM32F4' in name or 'stm32f4' in name:
                        self.mcu_family = 'STM32F4'
                        return
                    elif 'STM32L1' in name or 'stm32l1' in name:
                        self.mcu_family = 'STM32L1'
                        return
                    elif 'mbed' in name.lower():
                        # mbed usually uses STM32L1 or STM32F4
                        self.mcu_family = 'STM32L1'
                        
    def get_uart_addresses(self) -> List[int]:
        """Get all UART addresses to inject data"""
        addresses = set()
        for point in self.polling_points:
            addresses.add(point.uart_base)
            
        # If no specific points found, add common UARTs
        if not addresses:
            for uart_addr in self.UART_ADDRESSES.get(self.mcu_family, {}).values():
                addresses.add(uart_addr)
                
        return list(addresses)


def detect_firmware_patterns(firmware_path: str) -> Dict:
    """Main entry point for firmware pattern detection"""
    results = {
        'crc_functions': [],
        'serial_config': {},
        'hook_suggestions': [],
        'injection_code': '',
        'hal_bypass': [],
        'uart_polling': [],
        'serial_getc': []  # New: serial_getc functions to hook
    }
    
    # Detect CRC functions
    crc_detector = CRCFunctionDetector(firmware_path)
    results['crc_functions'] = crc_detector.analyze()
    results['hook_suggestions'] = crc_detector.get_hook_suggestions()
    
    # Detect serial buffer patterns
    serial_detector = SerialBufferDetector(firmware_path)
    results['serial_config'] = serial_detector.analyze()
    results['injection_code'] = serial_detector.generate_injection_code()
    
    # Detect HAL functions that need bypass
    hal_detector = HALFunctionDetector(firmware_path)
    hal_detector.analyze()
    results['hal_bypass'] = hal_detector.get_bypass_patches()
    
    # Detect UART polling patterns
    uart_detector = UARTPollingDetector(firmware_path)
    uart_detector.analyze()
    results['uart_polling'] = uart_detector.get_uart_addresses()
    results['mcu_family'] = uart_detector.mcu_family
    
    # Detect serial polling functions (getc)
    serial_polling_detector = SerialPollingDetector(firmware_path)
    serial_polling_detector.analyze()
    results['serial_getc'] = serial_polling_detector.get_getc_functions()
    
    return results

