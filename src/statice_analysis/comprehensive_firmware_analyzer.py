#!/usr/bin/env python3
"""
综合固件分析器 - 深度分析固件以提升仿真覆盖率

核心功能:
1. 完整MMIO地址检测 (所有形式)
2. 虚函数表分析
3. 轮询循环检测与打破策略
4. 状态机分析
5. 驱动回调检测
"""

import struct
import re
import logging
from pathlib import Path
from typing import Dict, List, Set, Tuple, Optional, Any
from dataclasses import dataclass, field
from collections import defaultdict
from enum import Enum

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

try:
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
    HAS_CAPSTONE = True
except ImportError:
    HAS_CAPSTONE = False
    logger.warning("Capstone not available")

try:
    from elftools.elf.elffile import ELFFile
    HAS_ELFTOOLS = True
except ImportError:
    HAS_ELFTOOLS = False
    logger.warning("pyelftools not available")


class MMIOAccessType(Enum):
    DIRECT_LDR_PC = "direct_ldr_pc"      # LDR Rx, [PC, #imm] 加载MMIO地址
    MOVW_MOVT = "movw_movt"               # MOVW/MOVT 构建32位地址
    BASE_OFFSET = "base_offset"           # LDR/STR Rx, [Ry, #offset]
    BITBAND = "bitband"                   # 位带别名访问
    DATA_SECTION = "data_section"         # 数据段中的MMIO指针
    VTABLE_INDIRECT = "vtable_indirect"   # 虚函数表间接访问


@dataclass
class MMIOAddress:
    """MMIO地址信息"""
    address: int
    access_type: MMIOAccessType
    confidence: float  # 0.0 - 1.0
    access_pc: int = 0
    base_address: int = 0
    offset: int = 0
    register_name: str = ""
    peripheral_name: str = ""
    is_status_reg: bool = False
    is_control_reg: bool = False
    access_count: int = 1


@dataclass
class VTableCall:
    """虚函数表调用"""
    call_site: int
    object_load_pc: int
    vtable_offset: int
    possible_targets: List[int] = field(default_factory=list)


@dataclass
class PollingPattern:
    """轮询模式"""
    start_pc: int
    end_pc: int
    polled_address: Optional[int]
    check_value: int
    loop_type: str  # 'status_poll', 'value_check', 'vtable_return'
    instructions: List[str] = field(default_factory=list)
    break_strategy: str = ""


@dataclass
class PeripheralProfile:
    """外设配置文件"""
    base_address: int
    name: str
    registers: Dict[int, MMIOAddress] = field(default_factory=dict)
    status_registers: List[int] = field(default_factory=list)
    control_registers: List[int] = field(default_factory=list)
    data_registers: List[int] = field(default_factory=list)
    ready_value: int = 0xFF
    irq_number: int = -1


class ComprehensiveFirmwareAnalyzer:
    """综合固件分析器"""
    
    # STM32F4外设地址映射
    PERIPH_MAP = {
        (0x40000000, 0x40000400): ('TIM2', 28),
        (0x40000400, 0x40000800): ('TIM3', 29),
        (0x40000800, 0x40000C00): ('TIM4', 30),
        (0x40000C00, 0x40001000): ('TIM5', 50),
        (0x40002800, 0x40002C00): ('IWDG', -1),
        (0x40002C00, 0x40003000): ('WWDG', 0),
        (0x40003800, 0x40003C00): ('SPI2', 36),
        (0x40003C00, 0x40004000): ('SPI3', 51),
        (0x40004400, 0x40004800): ('USART2', 38),
        (0x40004800, 0x40004C00): ('USART3', 39),
        (0x40004C00, 0x40005000): ('UART4', 52),
        (0x40005000, 0x40005400): ('UART5', 53),
        (0x40005400, 0x40005800): ('I2C1', 31),
        (0x40005800, 0x40005C00): ('I2C2', 33),
        (0x40005C00, 0x40006000): ('I2C3', 72),
        (0x40007000, 0x40007400): ('PWR', -1),
        (0x40010000, 0x40010400): ('TIM1', 27),
        (0x40010400, 0x40010800): ('TIM8', 46),
        (0x40011000, 0x40011400): ('USART1', 37),
        (0x40011400, 0x40011800): ('USART6', 71),
        (0x40012000, 0x40012400): ('ADC1', 18),
        (0x40012400, 0x40012800): ('ADC2', 18),
        (0x40012800, 0x40012C00): ('ADC3', 18),
        (0x40013000, 0x40013400): ('SPI1', 35),
        (0x40013400, 0x40013800): ('SPI4', 84),
        (0x40013800, 0x40013C00): ('SPI5', 85),
        (0x40013C00, 0x40014000): ('SPI6', 86),
        (0x40020000, 0x40020400): ('GPIOA', -1),
        (0x40020400, 0x40020800): ('GPIOB', -1),
        (0x40020800, 0x40020C00): ('GPIOC', -1),
        (0x40020C00, 0x40021000): ('GPIOD', -1),
        (0x40021000, 0x40021400): ('GPIOE', -1),
        (0x40021400, 0x40021800): ('GPIOF', -1),
        (0x40021800, 0x40021C00): ('GPIOG', -1),
        (0x40021C00, 0x40022000): ('GPIOH', -1),
        (0x40022000, 0x40022400): ('GPIOI', -1),
        (0x40023800, 0x40023C00): ('RCC', 5),
        (0x40023C00, 0x40024000): ('FLASH', 4),
        (0x40026000, 0x40026400): ('DMA1', -1),
        (0x40026400, 0x40026800): ('DMA2', -1),
        (0xE000E000, 0xE000F000): ('NVIC', -1),
    }
    
    # 外设寄存器类型
    PERIPH_REGS = {
        'USART': {
            0x00: ('SR', 'status'),
            0x04: ('DR', 'data'),
            0x08: ('BRR', 'control'),
            0x0C: ('CR1', 'control'),
            0x10: ('CR2', 'control'),
            0x14: ('CR3', 'control'),
            'ready_value': 0xC0,  # TXE | TC
        },
        'SPI': {
            0x00: ('CR1', 'control'),
            0x04: ('CR2', 'control'),
            0x08: ('SR', 'status'),
            0x0C: ('DR', 'data'),
            0x10: ('CRCPR', 'control'),
            0x14: ('RXCRCR', 'status'),
            0x18: ('TXCRCR', 'status'),
            'ready_value': 0x03,  # TXE | RXNE
        },
        'I2C': {
            0x00: ('CR1', 'control'),
            0x04: ('CR2', 'control'),
            0x08: ('OAR1', 'control'),
            0x0C: ('OAR2', 'control'),
            0x10: ('DR', 'data'),
            0x14: ('SR1', 'status'),
            0x18: ('SR2', 'status'),
            'ready_value': 0x84,  # TXE | BTF
        },
        'TIM': {
            0x00: ('CR1', 'control'),
            0x04: ('CR2', 'control'),
            0x10: ('SR', 'status'),
            0x14: ('EGR', 'control'),
            0x24: ('CNT', 'data'),
            'ready_value': 0x01,  # UIF
        },
        'ADC': {
            0x00: ('SR', 'status'),
            0x04: ('CR1', 'control'),
            0x08: ('CR2', 'control'),
            0x4C: ('DR', 'data'),
            'ready_value': 0x12,  # EOC | STRT
        },
        'GPIO': {
            0x00: ('MODER', 'control'),
            0x04: ('OTYPER', 'control'),
            0x08: ('OSPEEDR', 'control'),
            0x0C: ('PUPDR', 'control'),
            0x10: ('IDR', 'status'),
            0x14: ('ODR', 'data'),
            0x18: ('BSRR', 'control'),
            'ready_value': 0xFFFF,
        },
    }
    
    def __init__(self, firmware_path: str):
        self.firmware_path = Path(firmware_path)
        self.sections: Dict[str, Dict] = {}
        self.symbols: Dict[str, int] = {}
        self.reverse_symbols: Dict[int, str] = {}
        self.instructions: List = []
        
        self.mmio_addresses: Dict[int, MMIOAddress] = {}
        self.vtable_calls: List[VTableCall] = []
        self.polling_patterns: List[PollingPattern] = []
        self.peripherals: Dict[int, PeripheralProfile] = {}
        
        self._load_elf()
        self._disassemble()
    
    def _load_elf(self):
        """加载ELF文件"""
        if not HAS_ELFTOOLS:
            logger.error("pyelftools required")
            return
        
        with open(self.firmware_path, 'rb') as f:
            elf = ELFFile(f)
            
            for section in elf.iter_sections():
                if section.data():
                    self.sections[section.name] = {
                        'addr': section['sh_addr'],
                        'data': section.data(),
                        'size': len(section.data())
                    }
                
                if section['sh_type'] == 'SHT_SYMTAB':
                    for symbol in section.iter_symbols():
                        if symbol['st_value'] != 0 and symbol.name:
                            self.symbols[symbol.name] = symbol['st_value']
                            self.reverse_symbols[symbol['st_value']] = symbol.name
    
    def _disassemble(self):
        """反汇编代码段"""
        if not HAS_CAPSTONE:
            logger.error("Capstone required")
            return
        
        text = self.sections.get('.text', {})
        if not text:
            return
        
        md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
        md.detail = True
        
        self.instructions = list(md.disasm(text['data'], text['addr']))
        logger.info(f"Disassembled {len(self.instructions)} instructions")
    
    def _read_word(self, addr: int) -> Optional[int]:
        """从任意地址读取4字节"""
        for sec_name, sec in self.sections.items():
            if sec['addr'] <= addr < sec['addr'] + sec['size']:
                offset = addr - sec['addr']
                if offset + 4 <= sec['size']:
                    return struct.unpack('<I', sec['data'][offset:offset+4])[0]
        return None
    
    def analyze_all(self) -> Dict[str, Any]:
        """执行完整分析"""
        logger.info("=" * 60)
        logger.info("综合固件分析")
        logger.info("=" * 60)
        
        # 1. 完整MMIO检测
        self._detect_all_mmio()
        
        # 2. 虚函数表分析
        self._analyze_vtables()
        
        # 3. 轮询模式检测
        self._detect_polling_patterns()
        
        # 4. 构建外设配置文件
        self._build_peripheral_profiles()
        
        # 5. 生成打破策略
        self._generate_break_strategies()
        
        return self._generate_report()
    
    def _detect_all_mmio(self):
        """检测所有形式的MMIO地址"""
        logger.info("\n[1/5] MMIO地址检测")
        
        # 方法1: LDR Rx, [PC, #offset] 从文字池加载
        self._detect_ldr_pc_mmio()
        
        # 方法2: MOVW/MOVT 对
        self._detect_movw_movt_mmio()
        
        # 方法3: 基址+偏移访问
        self._detect_base_offset_mmio()
        
        # 方法4: 位带地址
        self._detect_bitband_mmio()
        
        # 方法5: 数据段指针
        self._detect_data_section_mmio()
        
        logger.info(f"   发现 {len(self.mmio_addresses)} 个唯一MMIO地址")
    
    def _detect_ldr_pc_mmio(self):
        """检测 LDR Rx, [PC, #offset] 形式"""
        text = self.sections.get('.text', {})
        if not text:
            return
        
        count = 0
        for insn in self.instructions:
            if insn.mnemonic in ['ldr', 'ldr.w'] and 'pc' in insn.op_str.lower():
                match = re.search(r'\[pc,\s*#(-?0x[0-9a-f]+|-?\d+)\]', 
                                 insn.op_str.lower())
                if match:
                    try:
                        offset = int(match.group(1), 0)
                        target = ((insn.address + 4) & ~3) + offset
                        val = self._read_word(target)
                        
                        if val and self._is_mmio_address(val):
                            self._add_mmio(val, MMIOAccessType.DIRECT_LDR_PC, 
                                          0.95, insn.address)
                            count += 1
                    except:
                        pass
        
        logger.info(f"   LDR [PC]: {count} 个")
    
    def _detect_movw_movt_mmio(self):
        """检测 MOVW/MOVT 对"""
        count = 0
        i = 0
        while i < len(self.instructions) - 1:
            insn1 = self.instructions[i]
            insn2 = self.instructions[i + 1]
            
            if insn1.mnemonic == 'movw' and insn2.mnemonic == 'movt':
                match1 = re.match(r'(\w+),\s*#(0x[0-9a-f]+|\d+)', insn1.op_str)
                match2 = re.match(r'(\w+),\s*#(0x[0-9a-f]+|\d+)', insn2.op_str)
                
                if match1 and match2 and match1.group(1) == match2.group(1):
                    try:
                        low = int(match1.group(2), 0)
                        high = int(match2.group(2), 0)
                        full = (high << 16) | low
                        
                        if self._is_mmio_address(full):
                            self._add_mmio(full, MMIOAccessType.MOVW_MOVT,
                                          0.99, insn1.address)
                            count += 1
                    except:
                        pass
                    i += 2
                    continue
            i += 1
        
        logger.info(f"   MOVW/MOVT: {count} 个")
    
    def _detect_base_offset_mmio(self):
        """检测基址+偏移访问"""
        count = 0
        reg_values: Dict[str, int] = {}
        
        for i, insn in enumerate(self.instructions):
            # 跟踪寄存器值
            if insn.mnemonic in ['movs', 'mov', 'mov.w']:
                match = re.match(r'(\w+),\s*#(0x[0-9a-f]+|\d+)', insn.op_str)
                if match:
                    reg_values[match.group(1)] = int(match.group(2), 0)
            
            # LDR Rx, [PC] 加载基址
            if insn.mnemonic in ['ldr', 'ldr.w'] and 'pc' in insn.op_str.lower():
                match_reg = re.match(r'(\w+),', insn.op_str)
                match_off = re.search(r'\[pc,\s*#(-?0x[0-9a-f]+|-?\d+)\]', 
                                     insn.op_str.lower())
                if match_reg and match_off:
                    try:
                        offset = int(match_off.group(1), 0)
                        target = ((insn.address + 4) & ~3) + offset
                        val = self._read_word(target)
                        if val:
                            reg_values[match_reg.group(1)] = val
                    except:
                        pass
            
            # 检测基址+偏移访问
            if insn.mnemonic in ['ldr', 'str', 'ldr.w', 'str.w', 
                                  'ldrb', 'strb', 'ldrh', 'strh']:
                match = re.search(r'\[(\w+),\s*#(0x[0-9a-f]+|\d+)\]', insn.op_str)
                if match:
                    base_reg = match.group(1)
                    offset = int(match.group(2), 0)
                    
                    if base_reg in reg_values:
                        base = reg_values[base_reg]
                        full = base + offset
                        
                        if self._is_mmio_address(full):
                            mmio = self._add_mmio(full, MMIOAccessType.BASE_OFFSET,
                                                 0.85, insn.address, base, offset)
                            count += 1
        
        logger.info(f"   基址+偏移: {count} 个")
    
    def _detect_bitband_mmio(self):
        """检测位带地址"""
        count = 0
        
        for insn in self.instructions:
            if insn.mnemonic in ['ldr', 'ldr.w'] and 'pc' in insn.op_str.lower():
                match = re.search(r'\[pc,\s*#(-?0x[0-9a-f]+|-?\d+)\]', 
                                 insn.op_str.lower())
                if match:
                    try:
                        offset = int(match.group(1), 0)
                        target = ((insn.address + 4) & ~3) + offset
                        val = self._read_word(target)
                        
                        if val and 0x42000000 <= val < 0x44000000:
                            # 解码位带地址
                            offset_from_base = val - 0x42000000
                            byte_offset = offset_from_base // 32
                            actual = 0x40000000 + byte_offset
                            
                            self._add_mmio(actual, MMIOAccessType.BITBAND,
                                          0.90, insn.address)
                            count += 1
                    except:
                        pass
        
        logger.info(f"   位带地址: {count} 个")
    
    def _detect_data_section_mmio(self):
        """检测数据段中的MMIO指针"""
        count = 0
        
        for sec_name in ['.data', '.rodata', '.bss']:
            sec = self.sections.get(sec_name, {})
            if not sec or not sec.get('data'):
                continue
            
            data = sec['data']
            for i in range(0, len(data) - 3, 4):
                val = struct.unpack('<I', data[i:i+4])[0]
                if self._is_mmio_address(val):
                    self._add_mmio(val, MMIOAccessType.DATA_SECTION,
                                  0.60, sec['addr'] + i)
                    count += 1
        
        logger.info(f"   数据段指针: {count} 个")
    
    def _is_mmio_address(self, addr: int) -> bool:
        """判断是否是MMIO地址"""
        return (0x40000000 <= addr < 0x60000000 or
                0xE0000000 <= addr < 0xE1000000)
    
    def _add_mmio(self, addr: int, access_type: MMIOAccessType,
                  confidence: float, pc: int = 0,
                  base: int = 0, offset: int = 0) -> MMIOAddress:
        """添加MMIO地址"""
        if addr in self.mmio_addresses:
            existing = self.mmio_addresses[addr]
            existing.access_count += 1
            if confidence > existing.confidence:
                existing.confidence = confidence
                existing.access_type = access_type
            return existing
        
        # 识别外设和寄存器
        periph_name = "UNKNOWN"
        reg_name = ""
        is_status = False
        is_control = False
        irq = -1
        
        for (start, end), (name, irq_num) in self.PERIPH_MAP.items():
            if start <= addr < end:
                periph_name = name
                irq = irq_num
                reg_offset = addr - start
                
                # 查找寄存器类型
                for prefix in ['USART', 'SPI', 'I2C', 'TIM', 'ADC', 'GPIO']:
                    if prefix in name:
                        regs = self.PERIPH_REGS.get(prefix, {})
                        if reg_offset in regs:
                            reg_name, reg_type = regs[reg_offset]
                            is_status = reg_type == 'status'
                            is_control = reg_type == 'control'
                        break
                break
        
        mmio = MMIOAddress(
            address=addr,
            access_type=access_type,
            confidence=confidence,
            access_pc=pc,
            base_address=base,
            offset=offset,
            peripheral_name=periph_name,
            register_name=reg_name,
            is_status_reg=is_status,
            is_control_reg=is_control
        )
        
        self.mmio_addresses[addr] = mmio
        return mmio
    
    def _analyze_vtables(self):
        """分析虚函数表调用"""
        logger.info("\n[2/5] 虚函数表分析")
        
        # 检测模式: ldr r0, [rx]; ldr r3, [r0]; ldr r3, [r3, #off]; blx r3
        for i in range(len(self.instructions) - 3):
            i1, i2, i3, i4 = self.instructions[i:i+4]
            
            if (i1.mnemonic.startswith('ldr') and
                i2.mnemonic.startswith('ldr') and
                i3.mnemonic.startswith('ldr') and
                i4.mnemonic == 'blx'):
                
                # 提取虚函数表偏移
                match = re.search(r'#(0x[0-9a-f]+|\d+)', i3.op_str)
                vtable_offset = int(match.group(1), 0) if match else 0
                
                self.vtable_calls.append(VTableCall(
                    call_site=i4.address,
                    object_load_pc=i1.address,
                    vtable_offset=vtable_offset
                ))
        
        logger.info(f"   发现 {len(self.vtable_calls)} 个虚函数调用")
    
    def _detect_polling_patterns(self):
        """检测轮询模式"""
        logger.info("\n[3/5] 轮询模式检测")
        
        # 检测后向跳转形成的循环
        for i, insn in enumerate(self.instructions):
            if insn.mnemonic.startswith('b') and insn.mnemonic != 'bl':
                if '#' in insn.op_str:
                    try:
                        target = int(insn.op_str.split('#')[1].split()[0], 16)
                        
                        # 后向跳转 = 潜在循环
                        if target < insn.address:
                            loop_size = insn.address - target
                            
                            # 小循环更可能是轮询
                            if loop_size < 100:
                                # 分析循环体
                                pattern = self._analyze_loop(target, insn.address)
                                if pattern:
                                    self.polling_patterns.append(pattern)
                    except:
                        pass
        
        logger.info(f"   发现 {len(self.polling_patterns)} 个轮询模式")
    
    def _analyze_loop(self, start: int, end: int) -> Optional[PollingPattern]:
        """分析循环体"""
        loop_instrs = []
        polled_addr = None
        has_status_check = False
        has_vtable_call = False
        
        for insn in self.instructions:
            if start <= insn.address <= end:
                loop_instrs.append(f"{insn.mnemonic} {insn.op_str}")
                
                # 检查是否读取MMIO
                if insn.mnemonic.startswith('ldr'):
                    for addr in self.mmio_addresses:
                        mmio = self.mmio_addresses[addr]
                        if mmio.is_status_reg and mmio.access_pc == insn.address:
                            polled_addr = addr
                            has_status_check = True
                
                # 检查是否有虚函数调用
                if insn.mnemonic == 'blx' and not insn.op_str.startswith('#'):
                    has_vtable_call = True
        
        if not loop_instrs:
            return None
        
        loop_type = 'unknown'
        if has_status_check:
            loop_type = 'status_poll'
        elif has_vtable_call:
            loop_type = 'vtable_return'
        elif any('cmp' in i for i in loop_instrs):
            loop_type = 'value_check'
        
        return PollingPattern(
            start_pc=start,
            end_pc=end,
            polled_address=polled_addr,
            check_value=0,
            loop_type=loop_type,
            instructions=loop_instrs
        )
    
    def _build_peripheral_profiles(self):
        """构建外设配置文件"""
        logger.info("\n[4/5] 构建外设配置文件")
        
        # 按外设分组MMIO地址
        periph_mmio: Dict[str, List[MMIOAddress]] = defaultdict(list)
        
        for addr, mmio in self.mmio_addresses.items():
            periph_mmio[mmio.peripheral_name].append(mmio)
        
        for name, mmios in periph_mmio.items():
            if name == "UNKNOWN":
                continue
            
            # 找到基址
            base = min(m.address for m in mmios)
            base = (base >> 10) << 10  # 对齐到1KB
            
            # 查找IRQ和就绪值
            irq = -1
            ready_value = 0xFF
            
            for (start, end), (pname, pirq) in self.PERIPH_MAP.items():
                if pname == name:
                    irq = pirq
                    break
            
            for prefix, regs in self.PERIPH_REGS.items():
                if prefix in name:
                    ready_value = regs.get('ready_value', 0xFF)
                    break
            
            profile = PeripheralProfile(
                base_address=base,
                name=name,
                ready_value=ready_value,
                irq_number=irq
            )
            
            for mmio in mmios:
                offset = mmio.address - base
                profile.registers[offset] = mmio
                
                if mmio.is_status_reg:
                    profile.status_registers.append(offset)
                elif mmio.is_control_reg:
                    profile.control_registers.append(offset)
                else:
                    profile.data_registers.append(offset)
            
            self.peripherals[base] = profile
        
        logger.info(f"   构建 {len(self.peripherals)} 个外设配置")
    
    def _generate_break_strategies(self):
        """生成轮询打破策略"""
        logger.info("\n[5/5] 生成打破策略")
        
        for pattern in self.polling_patterns:
            if pattern.loop_type == 'status_poll' and pattern.polled_address:
                # 找到对应外设
                for base, profile in self.peripherals.items():
                    if base <= pattern.polled_address < base + 0x400:
                        pattern.break_strategy = (
                            f"Toggle {profile.name} status register "
                            f"(offset 0x{pattern.polled_address - base:03X}) "
                            f"to 0x{profile.ready_value:02X} after 10 reads"
                        )
                        break
            
            elif pattern.loop_type == 'vtable_return':
                pattern.break_strategy = (
                    "Virtual function returns value controlling loop; "
                    "inject return value 0 or >7 to exit"
                )
            
            elif pattern.loop_type == 'value_check':
                pattern.break_strategy = (
                    "Memory value check loop; "
                    "toggle checked value to break condition"
                )
        
        break_count = sum(1 for p in self.polling_patterns if p.break_strategy)
        logger.info(f"   生成 {break_count} 个打破策略")
    
    def _generate_report(self) -> Dict[str, Any]:
        """生成分析报告"""
        return {
            'mmio_addresses': {
                'total': len(self.mmio_addresses),
                'by_type': self._count_by_type(),
                'by_peripheral': self._count_by_peripheral(),
                'details': [
                    {
                        'address': f"0x{addr:08X}",
                        'peripheral': m.peripheral_name,
                        'register': m.register_name,
                        'type': m.access_type.value,
                        'confidence': m.confidence,
                        'is_status': m.is_status_reg
                    }
                    for addr, m in sorted(self.mmio_addresses.items())
                ]
            },
            'vtable_calls': {
                'total': len(self.vtable_calls),
                'sites': [f"0x{vc.call_site:08X}" for vc in self.vtable_calls[:10]]
            },
            'polling_patterns': {
                'total': len(self.polling_patterns),
                'by_type': self._count_polling_types(),
                'patterns': [
                    {
                        'range': f"0x{p.start_pc:08X}-0x{p.end_pc:08X}",
                        'type': p.loop_type,
                        'polled_addr': f"0x{p.polled_address:08X}" if p.polled_address else None,
                        'strategy': p.break_strategy
                    }
                    for p in self.polling_patterns[:10]
                ]
            },
            'peripherals': {
                'total': len(self.peripherals),
                'profiles': [
                    {
                        'name': p.name,
                        'base': f"0x{p.base_address:08X}",
                        'registers': len(p.registers),
                        'status_regs': p.status_registers,
                        'ready_value': f"0x{p.ready_value:02X}",
                        'irq': p.irq_number
                    }
                    for p in self.peripherals.values()
                ]
            }
        }
    
    def _count_by_type(self) -> Dict[str, int]:
        counts = defaultdict(int)
        for m in self.mmio_addresses.values():
            counts[m.access_type.value] += 1
        return dict(counts)
    
    def _count_by_peripheral(self) -> Dict[str, int]:
        counts = defaultdict(int)
        for m in self.mmio_addresses.values():
            counts[m.peripheral_name] += 1
        return dict(counts)
    
    def _count_polling_types(self) -> Dict[str, int]:
        counts = defaultdict(int)
        for p in self.polling_patterns:
            counts[p.loop_type] += 1
        return dict(counts)
    
    def generate_smart_peripheral_c_code(self) -> str:
        """生成智能外设C代码"""
        code = '''/*
 * Auto-generated Smart Peripherals
 * Based on comprehensive firmware analysis
 */

'''
        
        for base, profile in self.peripherals.items():
            if not profile.status_registers:
                continue
            
            code += f'''
/* {profile.name} @ 0x{profile.base_address:08X} */
#define {profile.name}_BASE 0x{profile.base_address:08X}
#define {profile.name}_READY 0x{profile.ready_value:02X}

'''
        
        return code


def analyze_firmware(firmware_path: str) -> Dict[str, Any]:
    """便捷函数：综合分析固件"""
    analyzer = ComprehensiveFirmwareAnalyzer(firmware_path)
    return analyzer.analyze_all()


if __name__ == '__main__':
    import sys
    import json
    
    if len(sys.argv) < 2:
        print("Usage: python comprehensive_firmware_analyzer.py <firmware.elf>")
        sys.exit(1)
    
    result = analyze_firmware(sys.argv[1])
    
    print("\n" + "=" * 60)
    print("分析结果摘要")
    print("=" * 60)
    
    print(f"\nMMIO地址: {result['mmio_addresses']['total']}")
    print(f"  按类型: {result['mmio_addresses']['by_type']}")
    print(f"  按外设: {result['mmio_addresses']['by_peripheral']}")
    
    print(f"\n虚函数调用: {result['vtable_calls']['total']}")
    
    print(f"\n轮询模式: {result['polling_patterns']['total']}")
    print(f"  按类型: {result['polling_patterns']['by_type']}")
    
    print(f"\n外设配置: {result['peripherals']['total']}")
    for p in result['peripherals']['profiles']:
        print(f"  {p['name']}: {p['registers']}个寄存器, ready=0x{p['ready_value']}")

