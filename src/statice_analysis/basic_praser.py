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
class InstructionEvidence:
    """指令证据记录"""
    addr: int
    instruction: str
    description: str
    raw_bytes: Optional[bytes] = None

@dataclass
class RegisterAccess:
    """寄存器访问记录"""
    base_address: int
    offset: int
    access_type: str  # 'read', 'write'
    access_size: int  # 1, 2, 4, 8 bytes
    instruction_addr: int
    function_name: Optional[str] = None
    evidence_chain: List[InstructionEvidence] = field(default_factory=list)
    discovery_method: str = 'unknown'  # 'direct', 'hal_pattern', 'literal_pool'

@dataclass
class OffsetStats:
    """偏移统计信息"""
    offset: int
    read_count: int
    write_count: int
    instructions: List[str]  # 相关指令记录

@dataclass
class PeripheralCandidate:
    """外设候选信息 - 重新设计"""
    base_address: int
    size: int  # 外设大小（最大偏移+4）
    offset_stats: Dict[int, OffsetStats]  # 偏移统计
    refs: List[str]  # 引用函数
    instructions: List[str]  # 所有相关指令

@dataclass
class PeripheralHint:
    """外设提示信息（保持兼容性）"""
    address: int
    source_type: str
    confidence: float
    details: Dict[str, Any]

class BasicParser:
    """
    基础解析器
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
        根据段属性分类内存区域 - 纯粹基于ELF属性，不依赖机器类型
        """
        # 基于段属性推断
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
    
    def _add_known_peripheral_regions(self):
        """
        不再添加预定义的外设区域 - 纯粹基于分析结果
        """
        # 移除机器类型相关的预定义区域
        pass
    
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
        检查是否是潜在的MMIO地址 - 纯粹基于逻辑判断
        
        目的：识别可能的外设寄存器地址
        实现：不在固件内存内 + 基本合理性检查
        """
        if addr == 0 or addr < 0x1000:
            return False
        
        # 不能在固件内存范围内
        if self.is_address_in_firmware_memory(addr):
            return False
        
        # 地址必须4字节对齐（外设寄存器基本要求）
        if addr % 4 != 0:
            return False
        
        # 地址应该在合理范围内（避免明显错误的地址）
        if addr > 0xFFFFFFFF:
            return False
        
        return True
    
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
                    base_load['base_address'],
                    base_load  # 传递完整的基址加载信息
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
                            'instruction': f"{insn.mnemonic} {insn.op_str}",
                            'evidence_chain': [
                                {
                                    'addr': insn.address,
                                    'instruction': f"{insn.mnemonic} {insn.op_str}",
                                    'description': f"LDR PC相对加载: r{dst_reg} = [PC+{pc_offset}] = [0x{actual_addr:08x}]"
                                },
                                {
                                    'addr': actual_addr,
                                    'instruction': f".word 0x{constant_value:08x}",
                                    'description': f"字面量池值: 0x{constant_value:08x} -> r{dst_reg}"
                                }
                            ]
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
        1. ADRP + ADD组合 - 页面基址 + 偏移
        2. MOVZ/MOVK组合 - 多指令常量构造
        3. LDR literal - PC相对字面量加载
        """
        try:
            mnemonic = insn.mnemonic.lower()
            
            # 模式1: ADRP指令（需要与ADD配对）
            if mnemonic == 'adrp' and len(insn.operands) >= 2:
                dst_reg = insn.operands[0].reg if insn.operands[0].type == capstone.arm64.ARM64_OP_REG else None
                if dst_reg and insn.operands[1].type == capstone.arm64.ARM64_OP_IMM:
                    # 查找后续的ADD指令
                    add_result = self._find_matching_add_arm64(instructions, index + 1, dst_reg)
                    if add_result:
                        page_base = insn.operands[1].imm
                        add_offset = add_result['offset']
                        combined_addr = page_base + add_offset
                        
                        return {
                            'instruction_index': index,
                            'instruction_addr': insn.address,
                            'register': dst_reg,
                            'base_address': combined_addr,
                            'load_type': 'adrp_add',
                            'instruction': f"{insn.mnemonic} {insn.op_str}",
                            'evidence_chain': [
                                {
                                    'addr': insn.address,
                                    'instruction': f"{insn.mnemonic} {insn.op_str}",
                                    'description': f"ADRP页面基址: 0x{page_base:016x}"
                                },
                                {
                                    'addr': add_result['addr'],
                                    'instruction': add_result['instruction'],
                                    'description': f"ADD偏移: +0x{add_offset:x} = 0x{combined_addr:016x}"
                                }
                            ]
                        }
            
            # 模式2: MOVZ指令（需要与MOVK配对）
            elif mnemonic == 'movz' and len(insn.operands) >= 2:
                dst_reg = insn.operands[0].reg if insn.operands[0].type == capstone.arm64.ARM64_OP_REG else None
                if dst_reg and insn.operands[1].type == capstone.arm64.ARM64_OP_IMM:
                    # 查找后续的MOVK指令序列
                    movk_results = self._find_matching_movk_sequence_arm64(instructions, index + 1, dst_reg)
                    if movk_results:
                        base_value = insn.operands[1].imm
                        combined_value = base_value
                        evidence_chain = [{
                            'addr': insn.address,
                            'instruction': f"{insn.mnemonic} {insn.op_str}",
                            'description': f"MOVZ基础值: 0x{base_value:x}"
                        }]
                        
                        # 组合所有MOVK指令
                        for movk in movk_results:
                            shift = movk['shift']
                            value = movk['value']
                            combined_value |= (value << shift)
                            evidence_chain.append({
                                'addr': movk['addr'],
                                'instruction': movk['instruction'],
                                'description': f"MOVK位移{shift}: 0x{value:x} << {shift}"
                            })
                        
                        evidence_chain.append({
                            'addr': 0,
                            'instruction': 'COMBINED',
                            'description': f"最终地址: 0x{combined_value:016x}"
                        })
                        
                        return {
                            'instruction_index': index,
                            'instruction_addr': insn.address,
                            'register': dst_reg,
                            'base_address': combined_value,
                            'load_type': 'movz_movk',
                            'instruction': f"{insn.mnemonic} {insn.op_str}",
                            'evidence_chain': evidence_chain
                        }
            
            # 模式3: LDR literal
            elif mnemonic == 'ldr' and len(insn.operands) >= 2:
                dst_reg = insn.operands[0].reg if insn.operands[0].type == capstone.arm64.ARM64_OP_REG else None
                src_operand = insn.operands[1]
                
                if (dst_reg and src_operand.type == capstone.arm64.ARM64_OP_MEM and 
                    src_operand.mem.base == capstone.arm64.ARM64_REG_INVALID):
                    # PC相对地址
                    target_addr = insn.address + src_operand.mem.disp
                    constant_value = self._read_constant_from_memory_arm64(target_addr)
                    
                    if constant_value:
                        return {
                            'instruction_index': index,
                            'instruction_addr': insn.address,
                            'register': dst_reg,
                            'base_address': constant_value,
                            'load_type': 'ldr_literal_arm64',
                            'instruction': f"{insn.mnemonic} {insn.op_str}",
                            'evidence_chain': [
                                {
                                    'addr': insn.address,
                                    'instruction': f"{insn.mnemonic} {insn.op_str}",
                                    'description': f"LDR literal from 0x{target_addr:016x}"
                                },
                                {
                                    'addr': target_addr,
                                    'instruction': f".quad 0x{constant_value:016x}",
                                    'description': f"字面量值: 0x{constant_value:016x}"
                                }
                            ]
                        }
        
        except Exception as e:
            logger.debug(f"Error analyzing ARM64 instruction {insn.address:08x}: {e}")
        
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
                                          start_index: int, base_address: int, 
                                          base_load_info: Optional[Dict] = None) -> List[RegisterAccess]:
        """
        增强的寄存器数据流追踪
        
        目的：从基址加载点开始，追踪寄存器的所有使用情况
        实现：识别[reg, #offset]访问模式，记录偏移和访问类型
        """
        accesses = []
        
        # 构建基址加载证据链
        base_load_evidence = []
        if base_load_info and 'evidence_chain' in base_load_info:
            for evidence in base_load_info['evidence_chain']:
                base_load_evidence.append(InstructionEvidence(
                    addr=evidence.get('addr', 0),
                    instruction=evidence.get('instruction', ''),
                    description=evidence.get('description', '')
                ))
        
        # 向后扫描指令，限制在合理范围内（避免跨函数）
        scan_range = min(len(instructions) - start_index - 1, 200)
        
        for i in range(start_index + 1, start_index + 1 + scan_range):
            insn = instructions[i]
            
            # 检查寄存器使用
            register_usage = self._analyze_register_usage_enhanced(insn, target_reg)
            
            if register_usage:
                # 构建完整证据链
                evidence_chain = []
                
                # 1. 添加基址加载证据
                evidence_chain.extend(base_load_evidence)
                
                # 2. 添加当前访问指令
                evidence_chain.append(InstructionEvidence(
                    addr=insn.address,
                    instruction=f"{insn.mnemonic} {insn.op_str}",
                    description=f"{register_usage['access_type'].upper()} [0x{base_address:08x} + 0x{register_usage['offset']:02x}]"
                ))
                
                access = RegisterAccess(
                    base_address=base_address,
                    offset=register_usage['offset'],
                    access_type=register_usage['access_type'],
                    access_size=register_usage['access_size'],
                    instruction_addr=insn.address,
                    function_name=self._get_function_name_for_address(insn.address),
                    evidence_chain=evidence_chain,
                    discovery_method='hal_pattern'
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
                                    
                                    # 构建证据链
                                    evidence_chain = [InstructionEvidence(
                                        addr=insn.address,
                                        instruction=f"{insn.mnemonic} {insn.op_str}",
                                        description=f"直接{access_type.upper()}访问 0x{addr:08x}"
                                    )]
                                    
                                    access = RegisterAccess(
                                        base_address=addr,
                                        offset=0,
                                        access_type=access_type,
                                        access_size=access_size,
                                        instruction_addr=insn.address,
                                        function_name=self._get_function_name_for_address(insn.address),
                                        evidence_chain=evidence_chain,
                                        discovery_method='direct'
                                    )
                                    accesses.append(access)
            
            except Exception as e:
                logger.debug(f"Error analyzing direct MMIO access: {e}")
                continue
        
        return accesses
    
    def _cluster_register_accesses(self, accesses: List[RegisterAccess]) -> List[PeripheralCandidate]:
        """
        聚类寄存器访问，生成外设候选
        目的：将相同基址的访问聚合成外设，统计读写次数和指令
        """
        # 按基址分组
        base_groups = defaultdict(list)
        for access in accesses:
            # 只处理有效的MMIO地址
            if self.is_potential_mmio_address(access.base_address):
                base_groups[access.base_address].append(access)
        
        candidates = []
        
        for base_addr, access_list in base_groups.items():
            # 按偏移统计读写次数
            offset_stats = {}
            all_instructions = []
            refs = set()
            
            for access in access_list:
                offset = access.offset
                
                # 初始化偏移统计
                if offset not in offset_stats:
                    offset_stats[offset] = OffsetStats(
                        offset=offset,
                        read_count=0,
                        write_count=0,
                        instructions=[]
                    )
                
                # 统计读写次数
                if access.access_type == 'read':
                    offset_stats[offset].read_count += 1
                elif access.access_type == 'write':
                    offset_stats[offset].write_count += 1
                
                # 收集指令信息
                if access.evidence_chain:
                    for evidence in access.evidence_chain:
                        instruction_info = f"0x{evidence.addr:08x}: {evidence.instruction}"
                        offset_stats[offset].instructions.append(instruction_info)
                        all_instructions.append(instruction_info)
                
                # 收集引用函数
                if access.function_name:
                    refs.add(access.function_name)
            
            # 计算外设大小
            if offset_stats:
                max_offset = max(offset_stats.keys())
                size = max_offset + 4  # 假设最后一个寄存器是4字节
            else:
                size = 4
            
            candidate = PeripheralCandidate(
                base_address=base_addr,
                size=size,
                offset_stats=offset_stats,
                refs=list(refs),
                instructions=list(set(all_instructions))  # 去重
            )
            
            candidates.append(candidate)
        
        return candidates
    
    
    def _validate_and_filter_candidates(self, candidates: List[PeripheralCandidate]) -> List[PeripheralCandidate]:
        """
        验证和过滤外设候选
        目的：基本合理性检查，不计算置信度
        """
        validated = []
        
        for candidate in candidates:
            # 基本过滤条件
            if (len(candidate.offset_stats) >= 1 and 
                candidate.base_address > 0):
                # 基本验证
                if self._validate_candidate_quality(candidate):
                    validated.append(candidate)
        
        # 按基址排序
        validated.sort(key=lambda x: x.base_address)
        return validated
    
    def _validate_candidate_quality(self, candidate: PeripheralCandidate) -> bool:
        """
        验证候选质量
        目的：基本合理性检查
        """
        # 检查地址是否合理
        if not self.is_potential_mmio_address(candidate.base_address):
            return False
        # 检查是否有有效的偏移统计
        if not candidate.offset_stats:
            return False
        # 检查偏移是否合理（不超过64KB）
        max_offset = max(candidate.offset_stats.keys())
        if max_offset > 0x10000:
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
    
    
    def export_candidates_to_json(self, output_path: str) -> Dict:
        """
        导出外设候选到JSON文件 - 按用户要求的格式
        格式：
        """
        if not self.peripheral_candidates:
            logger.warning("No peripheral candidates to export")
            return {}
        
        # 构建输出数据 - 按用户要求的格式
        export_data = {}
        
        for candidate in self.peripheral_candidates:
            base_addr_hex = f"0x{candidate.base_address:x}"
            
            # 构建偏移列表，格式：0x00(read_count/write_count)
            offsets = []
            for offset, stats in candidate.offset_stats.items():
                offset_str = f"0x{offset:02x}({stats.read_count}/{stats.write_count})"
                offsets.append(offset_str)
            
            # 构建指令字符串
            insn_str = "; ".join(candidate.instructions)
            
            export_data[base_addr_hex] = {
                "size": f"0x{candidate.size:x}",
                "offsets": offsets,
                "refs": candidate.refs,
                "insn": insn_str
            }
        
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
    
    # ARM64辅助方法
    def _find_matching_add_arm64(self, instructions: List, start_index: int, target_reg: int) -> Optional[Dict]:
        """查找匹配的ADD指令（ARM64）"""
        for i in range(start_index, min(start_index + 5, len(instructions))):
            insn = instructions[i]
            if (insn.mnemonic.lower() == 'add' and 
                len(insn.operands) >= 3 and
                insn.operands[0].type == capstone.arm64.ARM64_OP_REG and
                insn.operands[0].reg == target_reg and
                insn.operands[1].type == capstone.arm64.ARM64_OP_REG and
                insn.operands[1].reg == target_reg and
                insn.operands[2].type == capstone.arm64.ARM64_OP_IMM):
                return {
                    'offset': insn.operands[2].imm,
                    'addr': insn.address,
                    'instruction': f"{insn.mnemonic} {insn.op_str}"
                }
        return None
    
    def _find_matching_movk_sequence_arm64(self, instructions: List, start_index: int, target_reg: int) -> List[Dict]:
        """查找匹配的MOVK指令序列（ARM64）"""
        movk_results = []
        for i in range(start_index, min(start_index + 10, len(instructions))):
            insn = instructions[i]
            if (insn.mnemonic.lower() == 'movk' and 
                len(insn.operands) >= 2 and
                insn.operands[0].type == capstone.arm64.ARM64_OP_REG and
                insn.operands[0].reg == target_reg and
                insn.operands[1].type == capstone.arm64.ARM64_OP_IMM):
                
                # 获取位移值（通常在第三个操作数中）
                shift = 0
                if len(insn.operands) >= 3 and insn.operands[2].type == capstone.arm64.ARM64_OP_IMM:
                    shift = insn.operands[2].imm
                
                movk_results.append({
                    'value': insn.operands[1].imm,
                    'shift': shift,
                    'addr': insn.address,
                    'instruction': f"{insn.mnemonic} {insn.op_str}"
                })
            elif insn.mnemonic.lower() in ['mov', 'ldr', 'str'] and len(insn.operands) >= 1:
                # 如果寄存器被重新使用，停止搜索
                if (insn.operands[0].type == capstone.arm64.ARM64_OP_REG and 
                    insn.operands[0].reg == target_reg):
                    break
        
        return movk_results
    
    def _read_constant_from_memory_arm64(self, addr: int) -> Optional[int]:
        """从内存读取ARM64常量（8字节）"""
        try:
            text_section = self.elf_info.sections['.text']
            text_start = text_section['addr']
            text_end = text_start + text_section['size']
            
            if text_start <= addr < text_end and text_section['data']:
                offset = addr - text_start
                if offset + 8 <= len(text_section['data']):
                    data = text_section['data'][offset:offset+8]
                    if self.elf_info.endianness == 'little':
                        return struct.unpack('<Q', data)[0]
                    else:
                        return struct.unpack('>Q', data)[0]
        except:
            pass
        return None
