#!/usr/bin/env python3
"""
高级MMIO地址检测器 v2 - 基于深入分析的改进版本

支持的访问模式:
1. PC相对加载 (LDR Rd, [PC, #imm]) - 高置信度
2. 基地址+偏移访问 (LDR Rd, [Rn, #imm]) - 需要跟踪寄存器值
3. MOVW/MOVT组合加载 - 高置信度
4. ADD/SUB计算偏移 - 中等置信度

核心改进:
- 全局寄存器值跟踪
- 基地址传播分析
- 函数内分析优化
"""

import struct
import logging
import re
from pathlib import Path
from typing import Dict, List, Set, Tuple, Optional
from dataclasses import dataclass, field
from collections import defaultdict

try:
    from elftools.elf.elffile import ELFFile
    HAS_ELFTOOLS = True
except ImportError:
    HAS_ELFTOOLS = False

try:
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
    HAS_CAPSTONE = True
except ImportError:
    HAS_CAPSTONE = False

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class MMIOAccess:
    """MMIO访问记录"""
    address: int                    # MMIO地址
    instruction_addr: int           # 指令地址
    access_type: str                # 'read', 'write', 'load'
    access_size: int                # 1, 2, or 4 bytes
    detection_method: str           # 检测方法
    base_register: Optional[str] = None
    offset: int = 0
    confidence: float = 1.0


@dataclass 
class RegisterState:
    """寄存器状态"""
    value: Optional[int] = None
    is_mmio_base: bool = False
    source_addr: int = 0  # 值来源的指令地址


# MMIO地址范围
MMIO_RANGES = {
    'STM32': [
        (0x40000000, 0x5FFFFFFF),  # 外设区域
        (0xE0000000, 0xE00FFFFF),  # 系统控制区域
    ],
    'DEFAULT': [
        (0x40000000, 0x5FFFFFFF),
        (0xE0000000, 0xE00FFFFF),
    ],
}


class AdvancedMMIODetector:
    """
    高级MMIO检测器 v2
    """
    
    def __init__(self, firmware_path: str, mcu_family: str = 'DEFAULT'):
        self.firmware_path = Path(firmware_path)
        self.mcu_family = mcu_family
        self.mmio_ranges = MMIO_RANGES.get(mcu_family, MMIO_RANGES['DEFAULT'])
        
        # ELF数据
        self.code_sections: Dict[int, bytes] = {}
        self.data_sections: Dict[int, bytes] = {}
        self.symbols: Dict[str, int] = {}
        
        # 分析结果
        self.mmio_accesses: List[MMIOAccess] = []
        self.register_states: Dict[str, RegisterState] = {}
        
        # 检测统计
        self.stats = {
            'pc_relative': 0,
            'movw_movt': 0,
            'base_offset': 0,
            'add_offset': 0,
            'total_instructions': 0
        }
        
        self._load_elf()
    
    def _load_elf(self):
        """加载ELF文件"""
        if not HAS_ELFTOOLS:
            logger.warning("pyelftools not installed")
            return
        
        try:
            with open(self.firmware_path, 'rb') as f:
                elf = ELFFile(f)
                
                for section in elf.iter_sections():
                    addr = section['sh_addr']
                    data = section.data()
                    
                    if section['sh_flags'] & 0x4:  # 可执行
                        self.code_sections[addr] = data
                    elif section['sh_flags'] & 0x2:  # 可写
                        self.data_sections[addr] = data
                    elif section['sh_type'] == 'SHT_PROGBITS' and data:
                        self.data_sections[addr] = data
                    
                    # 加载符号
                    if section['sh_type'] == 'SHT_SYMTAB':
                        for symbol in section.iter_symbols():
                            if symbol['st_value'] != 0 and symbol.name:
                                self.symbols[symbol.name] = symbol['st_value']
                
        except Exception as e:
            logger.error(f"Failed to load ELF: {e}")
    
    def _is_mmio_address(self, addr: int) -> bool:
        """检查地址是否在MMIO范围内"""
        for start, end in self.mmio_ranges:
            if start <= addr <= end:
                return True
        return False
    
    def _read_word_at(self, addr: int) -> Optional[int]:
        """从任意段读取一个32位字"""
        # 优先检查代码段（常量池通常在代码段中）
        for section_addr, section_data in self.code_sections.items():
            section_end = section_addr + len(section_data)
            if section_addr <= addr < section_end - 3:
                offset = addr - section_addr
                return struct.unpack('<I', section_data[offset:offset+4])[0]
        
        # 然后检查数据段
        for section_addr, section_data in self.data_sections.items():
            section_end = section_addr + len(section_data)
            if section_addr <= addr < section_end - 3:
                offset = addr - section_addr
                return struct.unpack('<I', section_data[offset:offset+4])[0]
        
        return None
    
    def detect_all_mmio(self) -> List[int]:
        """检测所有MMIO地址"""
        logger.info("=== Advanced MMIO Detection v2 ===")
        
        if not HAS_CAPSTONE:
            logger.error("Capstone is required for MMIO detection")
            return []
        
        # 单次完整遍历，跟踪所有寄存器状态
        self._analyze_with_register_tracking()
        
        # 提取唯一地址并按置信度排序
        address_confidence: Dict[int, float] = {}
        for access in self.mmio_accesses:
            addr = access.address
            if addr not in address_confidence or access.confidence > address_confidence[addr]:
                address_confidence[addr] = access.confidence
        
        # 按置信度过滤
        high_confidence = [addr for addr, conf in address_confidence.items() if conf >= 0.8]
        medium_confidence = [addr for addr, conf in address_confidence.items() if 0.5 <= conf < 0.8]
        
        result = sorted(set(high_confidence + medium_confidence))
        
        logger.info(f"Detection complete:")
        logger.info(f"  Total instructions analyzed: {self.stats['total_instructions']}")
        logger.info(f"  PC-relative loads: {self.stats['pc_relative']}")
        logger.info(f"  MOVW/MOVT pairs: {self.stats['movw_movt']}")
        logger.info(f"  Base+offset accesses: {self.stats['base_offset']}")
        logger.info(f"  ADD offset computes: {self.stats['add_offset']}")
        logger.info(f"  High confidence addresses: {len(high_confidence)}")
        logger.info(f"  Medium confidence addresses: {len(medium_confidence)}")
        logger.info(f"  Total unique addresses: {len(result)}")
        
        return result
    
    def _analyze_with_register_tracking(self):
        """使用寄存器跟踪进行全面分析"""
        md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
        md.detail = True
        
        for section_addr, section_data in self.code_sections.items():
            if len(section_data) < 4:
                continue
            
            # 每个代码段重置寄存器状态
            self.register_states = {}
            
            try:
                for insn in md.disasm(section_data, section_addr):
                    self.stats['total_instructions'] += 1
                    self._analyze_instruction_v2(insn)
                    
            except Exception as e:
                logger.debug(f"Disassembly error: {e}")
    
    def _analyze_instruction_v2(self, insn):
        """分析单条指令 - 改进版"""
        mnemonic = insn.mnemonic.lower()
        op_str = insn.op_str.lower()
        
        # 1. PC相对加载 (最高置信度)
        if mnemonic in ['ldr', 'ldr.w'] and 'pc' in op_str:
            self._handle_pc_relative_load(insn, mnemonic, op_str)
        
        # 2. MOVW/MOVT 组合
        elif mnemonic in ['movw', 'movt']:
            self._handle_movw_movt(insn, mnemonic, op_str)
        
        # 3. 普通MOV
        elif mnemonic in ['mov', 'movs']:
            self._handle_mov(insn, mnemonic, op_str)
        
        # 4. LDR/STR 基址+偏移
        elif mnemonic in ['ldr', 'ldr.w', 'str', 'str.w', 'ldrb', 'strb', 'ldrh', 'strh']:
            self._handle_base_offset_access(insn, mnemonic, op_str)
        
        # 5. ADD/SUB 计算地址
        elif mnemonic in ['add', 'adds', 'add.w', 'sub', 'subs']:
            self._handle_add_sub(insn, mnemonic, op_str)
    
    def _handle_pc_relative_load(self, insn, mnemonic, op_str):
        """处理PC相对加载"""
        match = re.search(r'(\w+),\s*\[pc(?:,\s*#(-?0x[0-9a-f]+|-?\d+))?\]', op_str)
        if not match:
            return
        
        dest_reg = match.group(1)
        offset_str = match.group(2)
        offset = int(offset_str, 0) if offset_str else 0
        
        # 计算目标地址（Thumb模式下PC对齐到4）
        pc = (insn.address + 4) & ~3
        target = pc + offset
        
        # 读取常量池中的值
        value = self._read_word_at(target)
        if value is None:
            return
        
        # 更新寄存器状态
        is_mmio = self._is_mmio_address(value)
        self.register_states[dest_reg] = RegisterState(
            value=value,
            is_mmio_base=is_mmio,
            source_addr=insn.address
        )
        
        if is_mmio:
            self.stats['pc_relative'] += 1
            self.mmio_accesses.append(MMIOAccess(
                address=value,
                instruction_addr=insn.address,
                access_type='load',
                access_size=4,
                detection_method='pc_relative',
                confidence=0.95
            ))
    
    def _handle_movw_movt(self, insn, mnemonic, op_str):
        """处理MOVW/MOVT组合"""
        match = re.match(r'(\w+),\s*#(0x[0-9a-f]+|\d+)', op_str)
        if not match:
            return
        
        dest_reg = match.group(1)
        value = int(match.group(2), 0)
        
        if mnemonic == 'movw':
            # MOVW: 加载低16位
            self.register_states[dest_reg] = RegisterState(
                value=value & 0xFFFF,
                is_mmio_base=False,
                source_addr=insn.address
            )
        elif mnemonic == 'movt':
            # MOVT: 加载高16位
            if dest_reg in self.register_states and self.register_states[dest_reg].value is not None:
                low16 = self.register_states[dest_reg].value & 0xFFFF
                full_value = (value << 16) | low16
                
                is_mmio = self._is_mmio_address(full_value)
                self.register_states[dest_reg] = RegisterState(
                    value=full_value,
                    is_mmio_base=is_mmio,
                    source_addr=insn.address
                )
                
                if is_mmio:
                    self.stats['movw_movt'] += 1
                    self.mmio_accesses.append(MMIOAccess(
                        address=full_value,
                        instruction_addr=insn.address,
                        access_type='load',
                        access_size=4,
                        detection_method='movw_movt',
                        confidence=0.95
                    ))
    
    def _handle_mov(self, insn, mnemonic, op_str):
        """处理普通MOV指令"""
        match = re.match(r'(\w+),\s*#(0x[0-9a-f]+|\d+)', op_str)
        if match:
            dest_reg = match.group(1)
            value = int(match.group(2), 0)
            
            self.register_states[dest_reg] = RegisterState(
                value=value,
                is_mmio_base=self._is_mmio_address(value),
                source_addr=insn.address
            )
    
    def _handle_base_offset_access(self, insn, mnemonic, op_str):
        """处理基址+偏移访问"""
        # 匹配 [Rn] 或 [Rn, #imm]
        match = re.match(r'(\w+),\s*\[(\w+)(?:,\s*#(-?0x[0-9a-f]+|-?\d+))?\]', op_str)
        if not match:
            return
        
        data_reg = match.group(1)
        base_reg = match.group(2)
        offset_str = match.group(3)
        offset = int(offset_str, 0) if offset_str else 0
        
        # 检查基址寄存器是否有已知MMIO基地址
        if base_reg not in self.register_states:
            return
        
        state = self.register_states[base_reg]
        if state.value is None:
            return
        
        # 计算完整地址
        full_addr = state.value + offset
        
        if self._is_mmio_address(full_addr):
            self.stats['base_offset'] += 1
            
            access_type = 'read' if mnemonic.startswith('ldr') else 'write'
            access_size = 4
            if 'b' in mnemonic:
                access_size = 1
            elif 'h' in mnemonic:
                access_size = 2
            
            self.mmio_accesses.append(MMIOAccess(
                address=full_addr,
                instruction_addr=insn.address,
                access_type=access_type,
                access_size=access_size,
                detection_method='base_offset',
                base_register=base_reg,
                offset=offset,
                confidence=0.85 if state.is_mmio_base else 0.7
            ))
    
    def _handle_add_sub(self, insn, mnemonic, op_str):
        """处理ADD/SUB地址计算"""
        # 匹配 ADD Rd, Rn, #imm
        match = re.match(r'(\w+),\s*(\w+),\s*#(-?0x[0-9a-f]+|-?\d+)', op_str)
        if not match:
            return
        
        dest_reg = match.group(1)
        src_reg = match.group(2)
        imm = int(match.group(3), 0)
        
        if src_reg not in self.register_states:
            return
        
        state = self.register_states[src_reg]
        if state.value is None:
            return
        
        # 计算新值
        if 'sub' in mnemonic:
            new_value = state.value - imm
        else:
            new_value = state.value + imm
        
        is_mmio = self._is_mmio_address(new_value)
        self.register_states[dest_reg] = RegisterState(
            value=new_value,
            is_mmio_base=is_mmio,
            source_addr=insn.address
        )
        
        if is_mmio and state.is_mmio_base:
            self.stats['add_offset'] += 1
            self.mmio_accesses.append(MMIOAccess(
                address=new_value,
                instruction_addr=insn.address,
                access_type='compute',
                access_size=4,
                detection_method='add_offset',
                confidence=0.75
            ))
    
    def get_accesses_by_address(self, mmio_addr: int) -> List[MMIOAccess]:
        """获取特定地址的所有访问"""
        return [a for a in self.mmio_accesses if a.address == mmio_addr]
    
    def get_statistics(self) -> Dict:
        """获取检测统计"""
        return {
            'total_accesses': len(self.mmio_accesses),
            'unique_addresses': len(set(a.address for a in self.mmio_accesses)),
            'by_method': {
                'pc_relative': self.stats['pc_relative'],
                'movw_movt': self.stats['movw_movt'],
                'base_offset': self.stats['base_offset'],
                'add_offset': self.stats['add_offset']
            },
            'total_instructions': self.stats['total_instructions']
        }
    
    def get_peripheral_blocks(self) -> List[Dict]:
        """
        将MMIO地址聚类为外设块
        
        STM32外设通常是1KB (0x400)对齐的
        """
        addresses = self.detect_all_mmio()
        
        # 按1KB边界分组
        blocks = defaultdict(list)
        for addr in addresses:
            block_base = (addr >> 10) << 10  # 1KB对齐
            blocks[block_base].append(addr)
        
        result = []
        for base, addrs in sorted(blocks.items()):
            # 识别外设类型
            periph_type = self._identify_peripheral_type(base)
            
            result.append({
                'base_address': base,
                'registers': sorted(addrs),
                'register_count': len(addrs),
                'type': periph_type,
                'size': max(addrs) - base + 4 if addrs else 0x400
            })
        
        return result
    
    def _identify_peripheral_type(self, base: int) -> str:
        """根据基地址识别外设类型"""
        # STM32F4外设映射
        stm32f4_map = {
            0x40000000: 'TIM2',
            0x40000400: 'TIM3',
            0x40000800: 'TIM4',
            0x40000C00: 'TIM5',
            0x40001000: 'TIM6',
            0x40001400: 'TIM7',
            0x40001800: 'TIM12',
            0x40001C00: 'TIM13',
            0x40002000: 'TIM14',
            0x40002800: 'RTC_BKP',
            0x40002C00: 'WWDG',
            0x40003000: 'IWDG',
            0x40003800: 'SPI2_I2S2',
            0x40003C00: 'SPI3_I2S3',
            0x40004400: 'USART2',
            0x40004800: 'USART3',
            0x40004C00: 'UART4',
            0x40005000: 'UART5',
            0x40005400: 'I2C1',
            0x40005800: 'I2C2',
            0x40005C00: 'I2C3',
            0x40006400: 'CAN1',
            0x40006800: 'CAN2',
            0x40007000: 'PWR',
            0x40007400: 'DAC',
            0x40010000: 'TIM1',
            0x40010400: 'TIM8',
            0x40011000: 'USART1',
            0x40011400: 'USART6',
            0x40012000: 'ADC',
            0x40012C00: 'SDIO',
            0x40013000: 'SPI1',
            0x40013400: 'SPI4',
            0x40013800: 'SYSCFG',
            0x40013C00: 'EXTI',
            0x40014000: 'TIM9',
            0x40014400: 'TIM10',
            0x40014800: 'TIM11',
            0x40020000: 'GPIOA',
            0x40020400: 'GPIOB',
            0x40020800: 'GPIOC',
            0x40020C00: 'GPIOD',
            0x40021000: 'GPIOE',
            0x40021400: 'GPIOF',
            0x40021800: 'GPIOG',
            0x40021C00: 'GPIOH',
            0x40022000: 'GPIOI',
            0x40023000: 'CRC',
            0x40023800: 'RCC',
            0x40023C00: 'FLASH',
            0x40026000: 'DMA1',
            0x40026400: 'DMA2',
            0x50000000: 'USB_OTG_FS',
            0x50040000: 'DCMI',
            0xE000E000: 'NVIC',
            0xE000E010: 'SYSTICK',
            0xE000E100: 'NVIC_ISER',
            0xE000ED00: 'SCB',
        }
        
        return stm32f4_map.get(base, f'UNKNOWN_0x{base:08X}')


def detect_mmio_addresses(firmware_path: str, mcu_family: str = 'DEFAULT') -> List[int]:
    """便捷函数"""
    detector = AdvancedMMIODetector(firmware_path, mcu_family)
    return detector.detect_all_mmio()


if __name__ == '__main__':
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python advanced_mmio_detector.py <firmware.elf>")
        sys.exit(1)
    
    firmware = sys.argv[1]
    detector = AdvancedMMIODetector(firmware)
    addresses = detector.detect_all_mmio()
    
    print(f"\nDetected {len(addresses)} MMIO addresses:")
    for addr in addresses:
        print(f"  0x{addr:08X}")
    
    print(f"\nPeripheral blocks:")
    for block in detector.get_peripheral_blocks():
        print(f"  {block['type']} @ 0x{block['base_address']:08X}: {block['register_count']} registers")
