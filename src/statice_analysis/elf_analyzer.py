#!/usr/bin/env python3
"""
ELF分析器模块
负责ELF文件解析、内存布局分析、架构识别等基础功能
"""

import logging
import struct
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from pathlib import Path

try:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import SymbolTableSection
    HAS_ELFTOOLS = True
except ImportError:
    HAS_ELFTOOLS = False

logger = logging.getLogger(__name__)

@dataclass
class ELFInfo:
    """ELF基本信息"""
    arch: str
    endianness: str
    word_size: int
    entry_point: int
    sections: Dict[str, Dict[str, Any]]
    symbols: Dict[str, Dict[str, Any]]
    memory_layout: List[Dict[str, Any]]

@dataclass
class MemoryRegion:
    """内存区域信息"""
    start: int
    end: int
    type: str  # 'flash', 'ram', 'peripheral'
    name: str
    readable: bool = True
    writable: bool = False
    executable: bool = False

class ELFAnalyzer:
    """
    ELF分析器
    专门负责ELF文件的解析和内存布局分析
    """
    
    def __init__(self, firmware_path: str):
        self.firmware_path = Path(firmware_path)
        if not self.firmware_path.exists():
            raise FileNotFoundError(f"Firmware file not found: {firmware_path}")
        if not HAS_ELFTOOLS:
            raise RuntimeError("pyelftools is required for ELF parsing")
        
        self.elf_info: Optional[ELFInfo] = None
        self.memory_regions: List[MemoryRegion] = []
    
    def parse_elf(self) -> ELFInfo:
        """
        解析ELF文件的基础信息
        """
        logger.info(f"Parsing ELF file: {self.firmware_path}")
        
        with open(self.firmware_path, 'rb') as f:
            elf_data = ELFFile(f)
            header = elf_data.header
            
            # 基础架构检测
            machine = header['e_machine']
            if machine == 'EM_ARM':
                base_arch = 'arm'
            elif machine == 'EM_AARCH64':
                base_arch = 'aarch64'
            else:
                base_arch = str(machine).lower()
            
            # 字节序和字长
            endianness = 'little' if header['e_ident']['EI_DATA'] == 'ELFDATA2LSB' else 'big'
            word_size = 8 if header['e_ident']['EI_CLASS'] == 'ELFCLASS64' else 4
            entry_point = header['e_entry']
            
            # 解析节区、符号表、内存布局
            sections = self._parse_sections(elf_data)
            symbols = self._parse_symbols(elf_data)
            memory_layout = self._build_memory_layout(elf_data)
            
            # ⭐ 增强架构检测：根据内存布局和符号特征推断具体MCU类型
            specific_arch = self._detect_specific_architecture(
                base_arch, entry_point, memory_layout, symbols
            )
            
            self.elf_info = ELFInfo(
                arch=specific_arch,
                endianness=endianness,
                word_size=word_size,
                entry_point=entry_point,
                sections=sections,
                symbols=symbols,
                memory_layout=memory_layout
            )
            
            logger.info(f"ELF parsed: {specific_arch} {endianness}-endian {word_size*8}-bit")
            return self.elf_info
    
    def _parse_sections(self, elf_data: ELFFile) -> Dict[str, Dict[str, Any]]:
        """解析ELF节区"""
        sections = {}
        for section in elf_data.iter_sections():
            section_info = {
                'name': section.name,
                'type': section['sh_type'],
                'addr': section['sh_addr'],
                'size': section['sh_size'],
                'flags': section['sh_flags'],
                'data': None
            }
            
            # 加载重要节区的数据
            # ⭐ 支持多种命名: .text/text (Zephyr), .rodata/rodata, .data/data, .reset (MIPS PIC32)
            important_sections = ['.text', 'text', '.rodata', 'rodata', '.data', 'data', 
                                  '.vector_table', '.bss', 'rom_start', '.reset', '.init', '.fini']
            if (section['sh_type'] != 'SHT_NOBITS' and 
                section['sh_size'] > 0 and 
                section.name in important_sections):
                try:
                    section_info['data'] = section.data()
                    logger.debug(f"Loaded section {section.name}: {len(section_info['data'])} bytes")
                except Exception as e:
                    logger.debug(f"Failed to load section {section.name}: {e}")
            
            sections[section.name] = section_info
        return sections
    
    def _parse_symbols(self, elf_data: ELFFile) -> Dict[str, Dict[str, Any]]:
        """解析符号表"""
        symbols = {}
        for section in elf_data.iter_sections():
            if isinstance(section, SymbolTableSection):
                for symbol in section.iter_symbols():
                    if symbol.name and symbol['st_value'] > 0:
                        symbols[symbol.name] = {
                            'value': symbol['st_value'],
                            'size': symbol['st_size'],
                            'type': symbol['st_info']['type'],
                            'bind': symbol['st_info']['bind'],
                            'section': symbol['st_shndx']
                        }
        
        logger.info(f"Found {len(symbols)} symbols")
        return symbols
    
    def _build_memory_layout(self, elf_data: ELFFile) -> List[Dict[str, Any]]:
        """构建内存布局"""
        memory_layout = []
        
        for segment in elf_data.iter_segments():
            if segment['p_type'] == 'PT_LOAD':
                memory_layout.append({
                    'vaddr': segment['p_vaddr'],
                    'paddr': segment['p_paddr'],
                    'size': segment['p_memsz'],
                    'file_size': segment['p_filesz'],
                    'executable': bool(segment['p_flags'] & 0x1),
                    'writable': bool(segment['p_flags'] & 0x2),
                    'readable': bool(segment['p_flags'] & 0x4)
                })
        
        logger.info(f"Found {len(memory_layout)} loadable segments")
        return memory_layout
    
    def _detect_specific_architecture(self, base_arch: str, entry_point: int, 
                                     memory_layout: List[Dict], symbols: Dict) -> str:
        """
        ⭐ 智能架构检测：根据内存布局和符号特征推断具体MCU类型
        
        支持的架构：
        - STM32F4: Flash @ 0x08000000, SRAM @ 0x20000000
        - SAM3X:   Flash @ 0x00080000, SRAM @ 0x20000000
        - MAX32:   Flash @ 0x00000000, SRAM @ 0x20000000
        - NXP:     Flash @ 0x00000000, SRAM @ 0x1FFF0000
        """
        if base_arch != 'arm':
            return base_arch
        
        # 特征1: Flash基地址
        flash_bases = set()
        for seg in memory_layout:
            vaddr = seg['vaddr']
            if seg['executable'] and not seg['writable']:
                # 对齐到1MB边界
                flash_base = (vaddr >> 20) << 20
                flash_bases.add(flash_base)
        
        # 特征2: 符号名称模式
        symbol_names = set(symbols.keys())
        has_stm32_symbols = any(s.lower().startswith('stm32') for s in symbol_names)
        has_sam3_symbols = any('sam3' in s.lower() or 'atsam' in s.lower() for s in symbol_names)
        has_max32_symbols = any('max32' in s.lower() or 'maxim' in s.lower() for s in symbol_names)
        has_nxp_symbols = any('kinetis' in s.lower() or 'k64' in s.lower() or 'k6' in s.lower() for s in symbol_names)
        
        # 特征3: 入口点地址
        entry_base = (entry_point >> 24) << 24
        
        # 决策逻辑
        if 0x08000000 in flash_bases or entry_base == 0x08000000:
            # STM32系列特征：Flash @ 0x08000000
            if has_stm32_symbols:
                logger.info("  检测到STM32系列特征（Flash @ 0x08000000 + STM32符号）")
                return 'STM32F4'  # 可以进一步细分F1/F4等
            else:
                logger.info("  检测到STM32系列特征（Flash @ 0x08000000）")
                return 'STM32'
        
        elif 0x00080000 in flash_bases or (0x00000000 in flash_bases and 0x00080000 <= entry_point < 0x00100000):
            # SAM3X特征：Flash @ 0x00080000 或入口点在此范围
            if has_sam3_symbols:
                logger.info("  检测到SAM3X系列特征（Flash @ 0x00080000 + SAM3符号）")
                return 'SAM3X'
            else:
                logger.info("  检测到SAM3X系列特征（Flash @ 0x00080000）")
                return 'SAM3X'
        
        elif 0x00000000 in flash_bases and entry_point < 0x00020000:
            # MAX32 或其他 Cortex-M系列：Flash @ 0x00000000，入口点在低地址
            if has_max32_symbols:
                logger.info("  检测到MAX32系列特征（Flash @ 0x00000000 + MAX32符号）")
                return 'MAX32'
            elif has_nxp_symbols:
                logger.info("  检测到NXP Kinetis系列特征（Flash @ 0x00000000 + NXP符号）")
                return 'K64F'
            else:
                logger.info("  检测到通用Cortex-M特征（Flash @ 0x00000000）")
                return 'Cortex-M'
        
        # 默认返回基础架构
        logger.info(f"  使用基础架构: {base_arch} (无法识别具体MCU类型)")
        return base_arch
    
    def analyze_memory_layout(self) -> List[MemoryRegion]:
        """
        分析MCU内存布局，识别Flash/RAM区域
        """
        if not self.elf_info:
            raise ValueError("ELF not parsed yet. Call parse_elf() first.")
        
        logger.info("Analyzing MCU memory layout")
        self.memory_regions.clear()
        
        # 从ELF段信息构建内存区域
        for segment in self.elf_info.memory_layout:
            vaddr = segment['vaddr']
            size = segment['size']
            
            # 根据地址范围和属性推断内存类型
            region_type = self._classify_memory_region(vaddr, size, segment)
            region_name = self._generate_region_name(vaddr, region_type)
            
            memory_region = MemoryRegion(
                start=vaddr,
                end=vaddr + size - 1,
                type=region_type,
                name=region_name,
                readable=segment['readable'],
                writable=segment['writable'],
                executable=segment['executable']
            )
            
            self.memory_regions.append(memory_region)
            logger.debug(f"Memory region: {region_name} 0x{vaddr:08x}-0x{vaddr+size-1:08x} ({region_type})")
        
        logger.info(f"Identified {len(self.memory_regions)} memory regions")
        return self.memory_regions
    
    def _classify_memory_region(self, vaddr: int, size: int, segment: Dict) -> str:
        """根据段属性分类内存区域"""
        if segment['executable'] and not segment['writable']:
            return 'flash'
        elif segment['writable'] and not segment['executable']:
            return 'ram'
        elif segment['writable'] and segment['readable']:
            return 'data'
        return 'unknown'
    
    def _generate_region_name(self, vaddr: int, region_type: str) -> str:
        """生成内存区域名称"""
        if region_type == 'flash':
            return f"FLASH_0x{vaddr:08x}"
        elif region_type == 'ram':
            return f"RAM_0x{vaddr:08x}"
        elif region_type == 'peripheral':
            return f"PERIPHERAL_0x{vaddr:08x}"
        else:
            return f"UNKNOWN_0x{vaddr:08x}"
    
    def is_address_in_firmware_memory(self, addr: int) -> bool:
        """检查地址是否在固件内存范围内"""
        for region in self.memory_regions:
            if region.type in ['flash', 'ram'] and region.start <= addr <= region.end:
                return True
        return False
    
    def is_potential_mmio_address(self, addr: int) -> bool:
        """
        检查是否是潜在的MMIO地址
        
        ⭐ 支持ARM/MIPS/RISC-V多架构
        """
        if addr == 0 or addr < 0x1000:
            return False
        
        # 地址必须4字节对齐
        if addr % 4 != 0:
            return False
        
        # 地址应该在32位范围内
        if addr > 0xFFFFFFFF:
            return False
        
        # ========== ARM架构 ==========
        
        # Flash区域（代码存储，不是外设）
        # STM32: 0x08000000-0x0FFFFFFF
        if 0x08000000 <= addr < 0x10000000:
            return False
        
        # SRAM区域（数据存储，不是外设）
        # 0x20000000-0x2FFFFFFF (主SRAM + 其他SRAM)
        if 0x20000000 <= addr < 0x30000000:
            return False
        
        # CCMRAM区域（STM32专用）
        # 0x10000000-0x1000FFFF
        if 0x10000000 <= addr < 0x10010000:
            return False
        
        # Backup SRAM (STM32)
        # 0x40024000
        if 0x40024000 <= addr < 0x40025000:
            return False
        
        # APB/AHB外设区域（主要外设区域）
        # 0x40000000-0x5FFFFFFF
        if 0x40000000 <= addr < 0x60000000:
            return True
        
        # System区域（NVIC, SysTick, Debug等）
        # 0xE0000000-0xE00FFFFF
        if 0xE0000000 <= addr < 0xE0100000:
            return True
        
        # SAM3X外设区域补充
        # 0x400E0000-0x400FFFFF (PMC, RSTC, etc.)
        if 0x400E0000 <= addr < 0x40100000:
            return True
        
        # MAX32外设区域 (已被0x40000000-0x60000000覆盖)
        
        # ========== MIPS架构 ==========
        
        # MIPS KSEG0/KSEG1: 0x80000000-0xBFFFFFFF
        # 但需要排除RAM区域
        if 0x80000000 <= addr <= 0x9FFFFFFF:
            # KSEG0 cached区域，通常是RAM，不是MMIO
            return False
        
        # MIPS KSEG1: 0xA0000000-0xBFFFFFFF (uncached, 常用于MMIO)
        if 0xA0000000 <= addr <= 0xBFFFFFFF:
            return True
        
        # MIPS物理外设区 (PIC32等)
        if 0x1F800000 <= addr <= 0x1FFFFFFF:
            return True
        
        # MIPS KSEG2/KSEG3: 0xC0000000-0xFFFFFFFF (kernel space, 可能有MMIO)
        # 暂时排除，因为通常不用于MCU
        
        # ========== RISC-V架构 ==========
        
        # RISC-V典型外设区
        if 0x10000000 <= addr < 0x20000000:
            return True
        
        # RISC-V部分MCU也使用0x40000000+
        # (已被ARM区域覆盖)
        
        # 默认：不是MMIO
        return False
    
    def read_constant_from_memory(self, addr: int) -> Optional[int]:
        """
        从内存地址读取常量值
        
        ⭐ 改进：遍历所有PT_LOAD段，而不仅仅是.text段
        支持SAM3X、STM32、MAX32等不同架构和内存布局
        """
        if not self.elf_info:
            return None
        
        if not HAS_ELFTOOLS:
            return None
        
        # ⭐ 适配增强的架构检测
        if not self.elf_info or not self.elf_info.arch:
            word_size = 4  # 默认32位
        else:
            arch_lower = self.elf_info.arch.lower()
            is_32bit_arm = ('arm' in arch_lower or 'stm32' in arch_lower or 'sam3' in arch_lower or
                            'max32' in arch_lower or 'cortex' in arch_lower or 'k64' in arch_lower)
            
            word_size = 4 if is_32bit_arm else 8
        
        try:
            # 方法1: 直接从ELF文件读取，遍历所有PT_LOAD段
            with open(self.firmware_path, 'rb') as f:
                elf_data = ELFFile(f)
                
                for segment in elf_data.iter_segments():
                    if segment['p_type'] == 'PT_LOAD':
                        seg_start = segment['p_vaddr']
                        seg_size = segment['p_memsz']
                        seg_end = seg_start + seg_size
                        
                        # 检查地址是否在此段范围内
                        if seg_start <= addr < seg_end:
                            # 计算段内偏移
                            offset = addr - seg_start
                            
                            # 确保有足够的数据
                            seg_data = segment.data()
                            if offset + word_size <= len(seg_data):
                                data = seg_data[offset:offset+word_size]
                                
                                # 根据字节序解包
                                if self.elf_info.endianness == 'little':
                                    if word_size == 4:
                                        value = struct.unpack('<I', data)[0]
                                    else:
                                        value = struct.unpack('<Q', data)[0]
                                else:
                                    if word_size == 4:
                                        value = struct.unpack('>I', data)[0]
                                    else:
                                        value = struct.unpack('>Q', data)[0]
                                
                                logger.debug(f"Read constant from 0x{addr:08x} = 0x{value:08x} (segment 0x{seg_start:08x}-0x{seg_end:08x})")
                                return value
            
            # 方法2: 如果方法1失败，尝试从已加载的段数据读取
            for section_name, section_info in self.elf_info.sections.items():
                if section_info['data'] is None:
                    continue
                
                sec_start = section_info['addr']
                sec_size = section_info['size']
                sec_end = sec_start + sec_size
                
                if sec_start <= addr < sec_end:
                    offset = addr - sec_start
                    if offset + word_size <= len(section_info['data']):
                        data = section_info['data'][offset:offset+word_size]
                        
                        if self.elf_info.endianness == 'little':
                            if word_size == 4:
                                value = struct.unpack('<I', data)[0]
                            else:
                                value = struct.unpack('<Q', data)[0]
                        else:
                            if word_size == 4:
                                value = struct.unpack('>I', data)[0]
                            else:
                                value = struct.unpack('>Q', data)[0]
                        
                        logger.debug(f"Read constant from 0x{addr:08x} = 0x{value:08x} (section {section_name})")
                        return value
        
        except Exception as e:
            logger.debug(f"Failed to read constant from 0x{addr:08x}: {e}")
        
        return None
    
    def get_function_name_for_address(self, addr: int) -> Optional[str]:
        """根据地址获取函数名"""
        for name, info in self.elf_info.symbols.items():
            if (info['type'] == 'STT_FUNC' and 
                info['value'] <= addr < info['value'] + info['size']):
                return name
        return None
    
    def get_executable_segments(self) -> List[Dict[str, Any]]:
        """
        ⭐ 新增：获取所有可执行的PT_LOAD段
        
        这对于MIPS/RISC-V等架构很重要，因为代码可能在程序头而非.text段
        
        Returns:
            List of executable segments with vaddr, size, and data
        """
        if not self.elf_info:
            raise ValueError("ELF not parsed yet. Call parse_elf() first.")
        
        executable_segments = []
        
        # Re-open ELF file to read segment data
        with open(self.firmware_path, 'rb') as f:
            elf_data = ELFFile(f)
            
            for segment in elf_data.iter_segments():
                if segment['p_type'] == 'PT_LOAD':
                    # Check if executable (PF_X flag)
                    if segment['p_flags'] & 0x1:  # PF_X (executable)
                        try:
                            seg_data = segment.data()
                            if seg_data and len(seg_data) > 0:
                                executable_segments.append({
                                    'vaddr': segment['p_vaddr'],
                                    'paddr': segment['p_paddr'],
                                    'size': segment['p_filesz'],
                                    'mem_size': segment['p_memsz'],
                                    'data': seg_data,
                                    'flags': segment['p_flags']
                                })
                                logger.debug(f"Found executable segment: "
                                           f"vaddr=0x{segment['p_vaddr']:08X}, "
                                           f"size={segment['p_filesz']} bytes")
                        except Exception as e:
                            logger.warning(f"Failed to read segment data: {e}")
        
        logger.info(f"Found {len(executable_segments)} executable segment(s)")
        return executable_segments
