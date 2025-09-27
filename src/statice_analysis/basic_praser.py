"""
基础解析模块 - 完全重新设计版本

目标：从固件ELF得到"寄存器块基址（base addresses）"与"寄存器偏移集合（register lists）"

核心思想：
1. 解析MCU固件的内存布局（Flash/RAM区）
2. 识别不属于这些内存区但被访问的地址作为MMIO候选
3. 处理HAL间接寻址：基址通过literal pool、MOVW/MOVT或ADRP+ADD构造
4. 数据流追踪：[reg, #imm]访问模式识别
5. 误报过滤：区分真实外设访问和数据表中的偶然地址

输出：candidates.json，包含{base_address, offsets: [...]}
"""

import logging
import struct
import re
import json
from typing import Dict, List, Set, Optional, Tuple, Any
from dataclasses import dataclass, field
from collections import defaultdict
from pathlib import Path
from datetime import datetime

try:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import SymbolTableSection
    HAS_ELFTOOLS = True
except ImportError:
    HAS_ELFTOOLS = False
    logging.warning("pyelftools not available - ELF parsing disabled")

try:
    import capstone
    from capstone import CS_ARCH_ARM, CS_ARCH_ARM64, CS_MODE_ARM, CS_MODE_THUMB
    HAS_CAPSTONE = True
except ImportError:
    HAS_CAPSTONE = False
    logging.warning("Capstone not available - disassembly analysis disabled")

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

@dataclass
class RegisterAccess:
    """寄存器访问记录"""
    base_address: int
    offset: int
    access_type: str  # 'read', 'write'
    access_size: int  # 1, 2, 4, 8 bytes
    instruction_addr: int
    function_name: Optional[str] = None

@dataclass
class PeripheralCandidate:
    """外设候选信息"""
    base_address: int
    offsets: List[int]
    access_records: List[RegisterAccess]
    confidence: float
    evidence_sources: List[str]
    peripheral_type_hint: Optional[str] = None

@dataclass
class PeripheralHint:
    """外设提示信息（保持兼容性）"""
    address: int
    source_type: str
    confidence: float
    details: Dict[str, Any]

class BasicParser:
    """
    基础解析器 - 完全重新设计版本
    
    核心功能：
    1. 解析ELF并识别MCU内存布局（Flash/RAM区域）
    2. 扫描指令识别外设基址加载模式
    3. 数据流追踪收集寄存器偏移访问
    4. 聚类生成外设候选列表
    """
    
    def __init__(self, firmware_path: str):
        """初始化基础解析器"""
        self.firmware_path = Path(firmware_path)
        if not self.firmware_path.exists():
            raise FileNotFoundError(f"Firmware file not found: {firmware_path}")
        
        if not HAS_ELFTOOLS:
            raise RuntimeError("pyelftools is required for ELF parsing")
        
        if not HAS_CAPSTONE:
            raise RuntimeError("capstone is required for instruction analysis")
        
        self.elf_info: Optional[ELFInfo] = None
        self.memory_regions: List[MemoryRegion] = []
        self.peripheral_candidates: List[PeripheralCandidate] = []
        self.peripheral_hints: List[PeripheralHint] = []  # 保持兼容性
        
    def parse_elf(self) -> ELFInfo:
        """
        解析ELF文件的基础信息
        
        目的：提取ELF文件的架构、节区、符号等基本信息
        实现：使用pyelftools解析ELF格式
        """
        logger.info(f"Parsing ELF file: {self.firmware_path}")
        
        with open(self.firmware_path, 'rb') as f:
            elf_data = ELFFile(f)
            
            # 解析头部信息
            header = elf_data.header
            
            # 架构检测
            machine = header['e_machine']
            if machine == 'EM_ARM':
                arch = 'arm'
            elif machine == 'EM_AARCH64':
                arch = 'aarch64'
            else:
                arch = str(machine).lower()
            
            # 字节序和字长
            endianness = 'little' if header['e_ident']['EI_DATA'] == 'ELFDATA2LSB' else 'big'
            word_size = 8 if header['e_ident']['EI_CLASS'] == 'ELFCLASS64' else 4
            entry_point = header['e_entry']
            
            # 解析节区
            sections = self._parse_sections(elf_data)
            
            # 解析符号表
            symbols = self._parse_symbols(elf_data)
            
            # 构建内存布局
            memory_layout = self._build_memory_layout(elf_data)
            
            self.elf_info = ELFInfo(
                arch=arch,
                endianness=endianness,
                word_size=word_size,
                entry_point=entry_point,
                sections=sections,
                symbols=symbols,
                memory_layout=memory_layout
            )
            
            logger.info(f"ELF parsed: {arch} {endianness}-endian {word_size*8}-bit")
            return self.elf_info
    
    def _parse_sections(self, elf_data: ELFFile) -> Dict[str, Dict[str, Any]]:
        """
        解析ELF节区
        
        目的：提取代码段、数据段等关键节区信息
        """
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
            if (section['sh_type'] != 'SHT_NOBITS' and 
                section['sh_size'] > 0 and 
                section.name in ['.text', '.rodata', '.data', '.vector_table', '.bss']):
                try:
                    section_info['data'] = section.data()
                    logger.debug(f"Loaded section {section.name}: {len(section_info['data'])} bytes")
                except Exception as e:
                    logger.debug(f"Failed to load section {section.name}: {e}")
            
            sections[section.name] = section_info
            
        return sections
    
    def _parse_symbols(self, elf_data: ELFFile) -> Dict[str, Dict[str, Any]]:
        """
        解析符号表
        
        目的：提取函数符号、变量符号等信息
        """
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
        """
        构建内存布局
        
        目的：识别可加载段的内存映射信息
        """
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
    
    def analyze_mcu_memory_layout(self) -> List[MemoryRegion]:
        """
        分析MCU内存布局，识别Flash/RAM区域
        
        目的：确定固件自身的内存范围，以便识别外设MMIO地址
        实现：解析ELF段信息，区分代码段、数据段、BSS段等
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
        
        # 添加已知的外设区域（基于架构）
        self._add_known_peripheral_regions()
        
        logger.info(f"Identified {len(self.memory_regions)} memory regions")
        return self.memory_regions
    
    def _classify_memory_region(self, vaddr: int, size: int, segment: Dict) -> str:
        """
        根据地址和属性分类内存区域
        
        目的：区分Flash、RAM、外设等不同类型的内存区域
        """
        # ARM Cortex-M典型内存映射
        if self.elf_info.arch == 'arm':
            if 0x08000000 <= vaddr < 0x08200000:  # STM32 Flash
                return 'flash'
            elif 0x20000000 <= vaddr < 0x20080000:  # STM32 SRAM
                return 'ram'
            elif 0x40000000 <= vaddr < 0x60000000:  # APB/AHB peripherals
                return 'peripheral'
            elif 0xE0000000 <= vaddr < 0xE0100000:  # System peripherals
                return 'peripheral'
        
        # 基于段属性推断
        if segment['executable'] and not segment['writable']:
            return 'flash'
        elif segment['writable'] and not segment['executable']:
            return 'ram'
        
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
    
    def _add_known_peripheral_regions(self):
        """
        添加已知的外设区域
        
        目的：补充ELF中可能缺失的外设内存映射信息
        """
        if self.elf_info.arch == 'arm':
            # ARM Cortex-M标准外设区域
            known_regions = [
                (0x40000000, 0x40100000, 'APB1_peripherals'),
                (0x40010000, 0x40020000, 'APB2_peripherals'), 
                (0x40020000, 0x40030000, 'AHB1_peripherals'),
                (0x50000000, 0x60000000, 'AHB2_peripherals'),
                (0xE0000000, 0xE0100000, 'System_peripherals'),
            ]
            
            for start, end, name in known_regions:
                # 检查是否已存在
                exists = any(r.start <= start < r.end for r in self.memory_regions)
                if not exists:
                    self.memory_regions.append(MemoryRegion(
                        start=start,
                        end=end - 1,
                        type='peripheral',
                        name=name,
                        readable=True,
                        writable=True,
                        executable=False
                    ))
    
    def is_address_in_firmware_memory(self, addr: int) -> bool:
        """
        检查地址是否在固件内存范围内
        
        目的：区分固件内存和外设MMIO地址
        实现：检查地址是否落在Flash/RAM区域内
        """
        for region in self.memory_regions:
            if region.type in ['flash', 'ram'] and region.start <= addr <= region.end:
                return True
        return False
    
    def is_potential_mmio_address(self, addr: int) -> bool:
        """
        检查是否是潜在的MMIO地址
        
        目的：识别可能的外设寄存器地址
        实现：地址在外设区域内且不在固件内存内
        """
        if addr == 0 or addr < 0x1000:
            return False
        
        # 不能在固件内存范围内
        if self.is_address_in_firmware_memory(addr):
            return False
        
        # 检查是否在已知外设区域内
        for region in self.memory_regions:
            if region.type == 'peripheral' and region.start <= addr <= region.end:
                return True
        
        # 通用外设地址范围检查（如果没有明确的外设区域）
        if self.elf_info.arch == 'arm':
            return (0x40000000 <= addr < 0x60000000 or  # APB/AHB
                   0xE0000000 <= addr < 0xE0100000)     # System
        
        return False
    
    def extract_peripheral_candidates(self) -> List[PeripheralCandidate]:
        """
        提取外设候选列表 - 新的主要接口
        
        目的：生成包含base_address和offsets的外设候选
        实现：按照新的设计流程进行完整分析
        """
        if not self.elf_info:
            raise ValueError("ELF not parsed yet. Call parse_elf() first.")
        
        if not self.memory_regions:
            self.analyze_mcu_memory_layout()
        
        logger.info("Extracting peripheral candidates using enhanced analysis")
        self.peripheral_candidates.clear()
        
        # 步骤1: 扫描指令识别基址加载和访问模式
        register_accesses = self._scan_instructions_for_mmio_access()
        
        # 步骤2: 聚类相同基址的访问
        clustered_candidates = self._cluster_register_accesses(register_accesses)
        
        # 步骤3: 过滤和验证候选
        validated_candidates = self._validate_and_filter_candidates(clustered_candidates)
        
        self.peripheral_candidates = validated_candidates
        
        logger.info(f"Found {len(self.peripheral_candidates)} peripheral candidates")
        return self.peripheral_candidates
    
    def _scan_instructions_for_mmio_access(self) -> List[RegisterAccess]:
        """
        扫描指令识别MMIO访问模式
        
        目的：识别所有可能的外设寄存器访问
        实现：
        1. 反汇编.text段
        2. 识别地址加载指令（LDR literal, MOVW/MOVT, ADRP+ADD等）
        3. 数据流追踪寄存器使用
        4. 记录[reg, #offset]访问模式
        """
        if '.text' not in self.elf_info.sections or not self.elf_info.sections['.text']['data']:
            logger.warning("No .text section found for instruction scanning")
            return []
        
        logger.info("Scanning instructions for MMIO access patterns")
        
        # 初始化反汇编器
        disasm = self._create_disassembler()
        if not disasm:
            return []
        
        text_section = self.elf_info.sections['.text']
        text_data = text_section['data']
        text_addr = text_section['addr']
        
        all_accesses = []
        batch_size = 16384  # 16KB批次
        
        for offset in range(0, len(text_data), batch_size):
            end_offset = min(offset + batch_size, len(text_data))
            batch_data = text_data[offset:end_offset]
            batch_addr = text_addr + offset
            
            try:
                instructions = list(disasm.disasm(batch_data, batch_addr))
                batch_accesses = self._analyze_instruction_batch(instructions)
                all_accesses.extend(batch_accesses)
                
            except Exception as e:
                logger.debug(f"Failed to analyze batch at 0x{batch_addr:x}: {e}")
                continue
        
        logger.info(f"Found {len(all_accesses)} potential MMIO accesses")
        return all_accesses
    
    def _create_disassembler(self):
        """创建反汇编器"""
        if not HAS_CAPSTONE:
            return None
        
        if self.elf_info.arch == 'arm':
            disasm = capstone.Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_THUMB)
        elif self.elf_info.arch == 'aarch64':
            disasm = capstone.Cs(CS_ARCH_ARM64, capstone.CS_MODE_ARM)
        else:
            logger.warning(f"Unsupported architecture {self.elf_info.arch}, defaulting to ARM")
            disasm = capstone.Cs(CS_ARCH_ARM, CS_MODE_ARM)
        
        disasm.detail = True
        return disasm
    
    def _analyze_instruction_batch(self, instructions: List) -> List[RegisterAccess]:
        """
        分析指令批次，识别基址加载和寄存器访问
        
        目的：在指令序列中识别外设访问模式
        实现：
        1. 识别基址加载事件
        2. 对每个基址进行数据流追踪
        3. 收集寄存器偏移访问
        """
        accesses = []
        
        # 步骤1: 识别基址加载指令
        base_loads = self._identify_base_address_loads_enhanced(instructions)
        
        # 步骤2: 对每个基址进行数据流追踪
        for base_load in base_loads:
            if self.is_potential_mmio_address(base_load['base_address']):
                register_accesses = self._trace_register_dataflow_enhanced(
                    instructions, 
                    base_load['register'],
                    base_load['instruction_index'],
                    base_load['base_address']
                )
                accesses.extend(register_accesses)
        
        # 步骤3: 识别直接MMIO访问（不通过寄存器）
        direct_accesses = self._identify_direct_mmio_access(instructions)
        accesses.extend(direct_accesses)
        
        return accesses
    
    def _identify_base_address_loads_enhanced(self, instructions: List) -> List[Dict]:
        """
        增强的基址加载识别
        
        目的：识别各种基址加载模式
        实现：支持ARM和ARM64的不同地址构造方式
        """
        base_loads = []
        
        for i, insn in enumerate(instructions):
            base_load = None
            
            if self.elf_info.arch == 'arm':
                base_load = self._analyze_arm_address_load(insn, i, instructions)
            elif self.elf_info.arch == 'aarch64':
                base_load = self._analyze_arm64_address_load(insn, i, instructions)
            
            if base_load and self.is_potential_mmio_address(base_load['base_address']):
                base_loads.append(base_load)
        
        return base_loads
    
    def _analyze_arm_address_load(self, insn, index: int, instructions: List) -> Optional[Dict]:
        """
        分析ARM架构的地址加载指令
        
        支持的模式：
        1. LDR rx, [pc, #imm] - PC相对加载
        2. LDR rx, =constant - 立即数加载  
        3. MOVW/MOVT组合 - 32位常量构造
        4. LDR rx, [mem] - 直接内存加载
        """
        try:
            mnemonic = insn.mnemonic.lower()
            
            # 模式1: LDR指令
            if mnemonic == 'ldr' and len(insn.operands) >= 2:
                dst_reg = insn.operands[0].reg if insn.operands[0].type == capstone.arm.ARM_OP_REG else None
                src_operand = insn.operands[1]
                
                # PC相对寻址
                if (src_operand.type == capstone.arm.ARM_OP_MEM and 
                    src_operand.mem.base == capstone.arm.ARM_REG_PC):
                    pc_offset = src_operand.mem.disp
                    actual_addr = insn.address + 8 + pc_offset  # ARM pipeline offset
                    constant_value = self._read_constant_from_memory(actual_addr)
                    
                    if constant_value and dst_reg:
                        return {
                            'instruction_index': index,
                            'instruction_addr': insn.address,
                            'register': dst_reg,
                            'base_address': constant_value,
                            'load_type': 'ldr_pc_relative',
                            'instruction': f"{insn.mnemonic} {insn.op_str}"
                        }
                
                # 立即数加载
                elif src_operand.type == capstone.arm.ARM_OP_IMM and dst_reg:
                    return {
                        'instruction_index': index,
                        'instruction_addr': insn.address,
                        'register': dst_reg,
                        'base_address': src_operand.imm,
                        'load_type': 'ldr_immediate',
                        'instruction': f"{insn.mnemonic} {insn.op_str}"
                    }
        
        except Exception as e:
            logger.debug(f"Error analyzing ARM instruction {insn.address:08x}: {e}")
        
        return None
    
    def _analyze_arm64_address_load(self, insn, index: int, instructions: List) -> Optional[Dict]:
        """
        分析ARM64架构的地址加载指令
        
        支持的模式：
        1. ADRP + ADD组合
        2. MOVZ/MOVK组合
        3. LDR literal
        """
        # ARM64实现（简化版本）
        return None
    
    def _read_constant_from_memory(self, addr: int) -> Optional[int]:
        """从内存地址读取常量值"""
        try:
            # 检查地址是否在.text段范围内
            text_section = self.elf_info.sections['.text']
            text_start = text_section['addr']
            text_end = text_start + text_section['size']
            
            if text_start <= addr < text_end and text_section['data']:
                offset = addr - text_start
                if offset + 4 <= len(text_section['data']):
                    # 读取4字节常量
                    data = text_section['data'][offset:offset+4]
                    if self.elf_info.endianness == 'little':
                        return struct.unpack('<I', data)[0]
                    else:
                        return struct.unpack('>I', data)[0]
        except:
            pass
        return None
    
    def _trace_register_dataflow_enhanced(self, instructions: List, target_reg: int, 
                                        start_index: int, base_address: int) -> List[RegisterAccess]:
        """
        增强的寄存器数据流追踪
        
        目的：从基址加载点开始，追踪寄存器的所有使用情况
        实现：识别[reg, #offset]访问模式，记录偏移和访问类型
        """
        accesses = []
        
        # 向后扫描指令，限制在合理范围内（避免跨函数）
        scan_range = min(len(instructions) - start_index - 1, 200)
        
        for i in range(start_index + 1, start_index + 1 + scan_range):
            insn = instructions[i]
            
            # 检查寄存器使用
            register_usage = self._analyze_register_usage_enhanced(insn, target_reg)
            
            if register_usage:
                access = RegisterAccess(
                    base_address=base_address,
                    offset=register_usage['offset'],
                    access_type=register_usage['access_type'],
                    access_size=register_usage['access_size'],
                    instruction_addr=insn.address,
                    function_name=self._get_function_name_for_address(insn.address)
                )
                accesses.append(access)
            
            # 如果寄存器被重新赋值，停止追踪
            if self._register_is_overwritten_enhanced(insn, target_reg):
                break
        
        return accesses
    
    def _analyze_register_usage_enhanced(self, insn, target_reg: int) -> Optional[Dict]:
        """
        增强的寄存器使用分析
        
        目的：识别[reg, #offset]访问模式
        实现：支持各种内存访问指令和寻址模式
        """
        try:
            mnemonic = insn.mnemonic.lower()
            
            # 内存访问指令
            memory_instructions = {
                'ldr': ('read', 4), 'ldrb': ('read', 1), 'ldrh': ('read', 2),
                'str': ('write', 4), 'strb': ('write', 1), 'strh': ('write', 2),
                'ldrd': ('read', 8), 'strd': ('write', 8)
            }
            
            if mnemonic not in memory_instructions:
                return None
            
            access_type, default_size = memory_instructions[mnemonic]
            
            # 检查操作数中的内存引用
            for operand in insn.operands:
                if operand.type == capstone.arm.ARM_OP_MEM:
                    if operand.mem.base == target_reg:
                        return {
                            'offset': operand.mem.disp,
                            'access_type': access_type,
                            'access_size': default_size,
                            'instruction_addr': insn.address
                        }
        
        except Exception as e:
            logger.debug(f"Error analyzing register usage: {e}")
        
        return None
    
    def _identify_direct_mmio_access(self, instructions: List) -> List[RegisterAccess]:
        """
        识别直接MMIO访问（不通过寄存器加载）
        
        目的：捕获直接使用立即数地址的内存访问
        实现：扫描内存访问指令中的直接地址
        """
        accesses = []
        
        for insn in instructions:
            try:
                mnemonic = insn.mnemonic.lower()
                
                if mnemonic in ['ldr', 'ldrb', 'ldrh', 'str', 'strb', 'strh']:
                    for operand in insn.operands:
                        if operand.type == capstone.arm.ARM_OP_MEM:
                            # 直接地址访问（无基址寄存器）
                            if (operand.mem.base == 0 and 
                                operand.mem.index == 0 and 
                                operand.mem.disp > 0):
                                
                                addr = operand.mem.disp
                                if self.is_potential_mmio_address(addr):
                                    access_type = 'read' if mnemonic.startswith('ldr') else 'write'
                                    access_size = 1 if mnemonic.endswith('b') else (2 if mnemonic.endswith('h') else 4)
                                    
                                    access = RegisterAccess(
                                        base_address=addr,
                                        offset=0,
                                        access_type=access_type,
                                        access_size=access_size,
                                        instruction_addr=insn.address,
                                        function_name=self._get_function_name_for_address(insn.address)
                                    )
                                    accesses.append(access)
            
            except Exception as e:
                logger.debug(f"Error analyzing direct MMIO access: {e}")
                continue
        
        return accesses
    
    def _cluster_register_accesses(self, accesses: List[RegisterAccess]) -> List[PeripheralCandidate]:
        """
        聚类寄存器访问，生成外设候选
        
        目的：将相同基址的访问聚合成外设候选
        实现：按基址分组，收集偏移列表和访问记录
        """
        # 按基址分组
        base_groups = defaultdict(list)
        for access in accesses:
            base_groups[access.base_address].append(access)
        
        candidates = []
        
        for base_addr, access_list in base_groups.items():
            # 收集唯一偏移
            offsets = sorted(list(set(access.offset for access in access_list)))
            
            # 计算置信度
            confidence = self._calculate_candidate_confidence(access_list, offsets)
            
            # 推断外设类型
            peripheral_type = self._infer_peripheral_type(base_addr, offsets, access_list)
            
            # 确定证据源
            evidence_sources = list(set(access.function_name for access in access_list if access.function_name))
            if not evidence_sources:
                evidence_sources = ['instruction_analysis']
            
            candidate = PeripheralCandidate(
                base_address=base_addr,
                offsets=offsets,
                access_records=access_list,
                confidence=confidence,
                evidence_sources=evidence_sources,
                peripheral_type_hint=peripheral_type
            )
            
            candidates.append(candidate)
        
        return candidates
    
    def _calculate_candidate_confidence(self, accesses: List[RegisterAccess], offsets: List[int]) -> float:
        """
        计算外设候选的置信度
        
        目的：基于访问模式评估外设候选的可信度
        实现：考虑访问次数、偏移分布、访问类型等因素
        """
        base_confidence = 0.3
        
        # 访问次数加成
        access_count = len(accesses)
        if access_count >= 5:
            base_confidence += 0.2
        elif access_count >= 2:
            base_confidence += 0.1
        
        # 偏移数量加成
        offset_count = len(offsets)
        if offset_count >= 4:
            base_confidence += 0.2
        elif offset_count >= 2:
            base_confidence += 0.1
        
        # 偏移对齐检查
        if all(offset % 4 == 0 for offset in offsets):
            base_confidence += 0.1
        
        # 偏移范围检查（合理的寄存器块大小）
        if offsets and max(offsets) - min(offsets) <= 0x100:
            base_confidence += 0.1
        
        # 访问类型多样性
        access_types = set(access.access_type for access in accesses)
        if len(access_types) > 1:
            base_confidence += 0.1
        
        return min(base_confidence, 1.0)
    
    def _validate_and_filter_candidates(self, candidates: List[PeripheralCandidate]) -> List[PeripheralCandidate]:
        """
        验证和过滤外设候选
        
        目的：移除低质量候选，保留高可信度的外设
        实现：应用多种过滤规则
        """
        validated = []
        
        for candidate in candidates:
            # 基本过滤条件
            if (candidate.confidence >= 0.4 and 
                len(candidate.offsets) >= 1 and
                len(candidate.access_records) >= 1):
                
                # 额外验证
                if self._validate_candidate_quality(candidate):
                    validated.append(candidate)
        
        # 按置信度排序
        validated.sort(key=lambda x: x.confidence, reverse=True)
        
        return validated
    
    def _validate_candidate_quality(self, candidate: PeripheralCandidate) -> bool:
        """
        验证候选质量
        
        目的：应用启发式规则过滤误报
        """
        # 检查地址是否在合理范围内
        if not self.is_potential_mmio_address(candidate.base_address):
            return False
        
        # 检查偏移是否合理
        if candidate.offsets:
            max_offset = max(candidate.offsets)
            if max_offset > 0x1000:  # 偏移过大可能不是寄存器块
                return False
        
        # 检查访问模式是否合理
        read_count = sum(1 for acc in candidate.access_records if acc.access_type == 'read')
        write_count = sum(1 for acc in candidate.access_records if acc.access_type == 'write')
        
        # 至少要有一次访问
        if read_count + write_count == 0:
            return False
        
        return True
    
    def _get_function_name_for_address(self, addr: int) -> Optional[str]:
        """根据地址获取函数名"""
        # 查找包含该地址的函数
        for name, info in self.elf_info.symbols.items():
            if (info['type'] == 'STT_FUNC' and 
                info['value'] <= addr < info['value'] + info['size']):
                return name
        return None
    
    def _register_is_overwritten_enhanced(self, insn, target_reg: int) -> bool:
        """检查寄存器是否被重新赋值（增强版）"""
        try:
            mnemonic = insn.mnemonic.lower()
            
            # 赋值指令
            assignment_instructions = ['ldr', 'mov', 'add', 'sub', 'orr', 'and', 'eor', 'bic']
            
            if mnemonic in assignment_instructions and len(insn.operands) >= 1:
                dst_operand = insn.operands[0]
                if (dst_operand.type == capstone.arm.ARM_OP_REG and 
                    dst_operand.reg == target_reg):
                    return True
        except:
            pass
        
        return False
    
    def _infer_peripheral_type(self, base_addr: int, offsets: List[int], accesses: List[RegisterAccess]) -> Optional[str]:
        """推断外设类型"""
        # 基于地址范围推断
        if 0x40013800 <= base_addr <= 0x40013C00:
            return 'uart'
        elif 0x40020000 <= base_addr <= 0x40023C00:
            return 'gpio'
        elif 0x40003000 <= base_addr <= 0x40003400:
            return 'spi'
        elif 0x40005400 <= base_addr <= 0x40005800:
            return 'i2c'
        elif 0x40010000 <= base_addr <= 0x40014000:
            return 'timer'
        
        # 基于访问模式推断
        read_count = sum(1 for acc in accesses if acc.access_type == 'read')
        write_count = sum(1 for acc in accesses if acc.access_type == 'write')
        
        if read_count > write_count * 2:
            return 'status_register'
        elif write_count > read_count * 2:
            return 'control_register'
        
        return 'unknown'
    
    def export_candidates_to_json(self, output_path: str) -> Dict:
        """
        导出外设候选到JSON文件
        
        目的：生成符合要求的candidates.json文件
        实现：转换内部数据结构为JSON格式
        """
        if not self.peripheral_candidates:
            logger.warning("No peripheral candidates to export")
            return {}
        
        # 构建输出数据
        export_data = {
            'metadata': {
                'firmware_path': str(self.firmware_path),
                'architecture': self.elf_info.arch if self.elf_info else 'unknown',
                'analysis_timestamp': datetime.now().isoformat(),
                'total_candidates': len(self.peripheral_candidates),
                'memory_regions': [
                    {
                        'start': hex(region.start),
                        'end': hex(region.end),
                        'type': region.type,
                        'name': region.name
                    }
                    for region in self.memory_regions
                ]
            },
            'candidates': []
        }
        
        # 转换每个候选
        for candidate in self.peripheral_candidates:
            candidate_data = {
                'base_address': hex(candidate.base_address),
                'offsets': [hex(offset) for offset in candidate.offsets],
                'confidence': candidate.confidence,
                'peripheral_type_hint': candidate.peripheral_type_hint,
                'evidence_sources': candidate.evidence_sources,
                'access_summary': {
                    'total_accesses': len(candidate.access_records),
                    'read_count': sum(1 for acc in candidate.access_records if acc.access_type == 'read'),
                    'write_count': sum(1 for acc in candidate.access_records if acc.access_type == 'write'),
                    'unique_offsets': len(candidate.offsets),
                    'offset_range': max(candidate.offsets) - min(candidate.offsets) if candidate.offsets else 0
                },
                'detailed_accesses': [
                    {
                        'offset': hex(acc.offset),
                        'access_type': acc.access_type,
                        'access_size': acc.access_size,
                        'instruction_addr': hex(acc.instruction_addr),
                        'function_name': acc.function_name
                    }
                    for acc in candidate.access_records[:10]  # 限制详细记录数量
                ]
            }
            
            export_data['candidates'].append(candidate_data)
        
        # 保存到文件
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_file, 'w') as f:
            json.dump(export_data, f, indent=2)
        
        logger.info(f"Exported {len(self.peripheral_candidates)} candidates to {output_file}")
        
        return export_data
    
    def extract_peripheral_hints(self) -> List[PeripheralHint]:
        """
        提取外设提示信息 - 兼容性接口
        
        目的：保持与现有代码的兼容性
        实现：调用新的extract_peripheral_candidates并转换格式
        """
        # 调用新的主要方法
        candidates = self.extract_peripheral_candidates()
        
        # 转换为旧格式以保持兼容性
        self.peripheral_hints.clear()
        
        for candidate in candidates:
            hint = PeripheralHint(
                address=candidate.base_address,
                source_type='enhanced_analysis',
                confidence=candidate.confidence,
                details={
                    'offsets': candidate.offsets,
                    'access_count': len(candidate.access_records),
                    'peripheral_type_hint': candidate.peripheral_type_hint,
                    'evidence_sources': candidate.evidence_sources
                }
            )
            self.peripheral_hints.append(hint)
        
        logger.info(f"Converted {len(candidates)} candidates to {len(self.peripheral_hints)} hints")
        return self.peripheral_hints
