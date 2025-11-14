#!/usr/bin/env python3
"""
地址加载分析器模块
负责识别各种地址加载模式，包括增强的Thumb-2、复合地址计算等
"""

import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass

try:
    import capstone
    from capstone import CS_ARCH_ARM, CS_ARCH_ARM64, CS_MODE_ARM, CS_MODE_THUMB
    HAS_CAPSTONE = True
except ImportError:
    HAS_CAPSTONE = False

logger = logging.getLogger(__name__)

@dataclass
class AddressLoadInfo:
    """地址加载信息"""
    instruction_index: int
    instruction_addr: int
    register: int
    base_address: int
    load_type: str
    instruction: str
    evidence_chain: List[Dict[str, Any]]
    confidence: float = 1.0  # 置信度

class AddressLoader:
    """
    地址加载分析器
    专门负责识别各种地址加载模式，包括增强功能
    """
    
    def __init__(self, elf_analyzer):
        self.elf_analyzer = elf_analyzer
        self.symbol_table = {}  # 符号传播表
        self.constant_pool = {}  # 常量池
    
    def analyze_address_loads(self, instructions: List) -> List[AddressLoadInfo]:
        """
        分析指令序列中的地址加载模式
        增强功能：
        1. Thumb-2 / IT blocks 支持
        2. 复合地址计算
        3. 符号传播
        4. ⭐ 常量池解析 (Literal Pool) - 新增
        """
        logger.info("Analyzing address loads with enhanced patterns")
        
        address_loads = []
        
        # 第一遍：识别基础地址加载
        basic_loads = self._identify_basic_loads(instructions)
        address_loads.extend(basic_loads)
        
        # ⭐ 新增：提取常量池中的MMIO地址
        logger.info("⭐ Extracting MMIO addresses from literal pool")
        literal_pool_loads = self._extract_literal_pool_mmio(instructions)
        logger.info(f"  → Found {len(literal_pool_loads)} MMIO addresses from literal pool")
        address_loads.extend(literal_pool_loads)
        
        # 第二遍：识别复合地址计算
        compound_loads = self._identify_compound_loads(instructions, basic_loads)
        address_loads.extend(compound_loads)
        
        # 第三遍：符号传播分析
        propagated_loads = self._analyze_symbol_propagation(instructions, address_loads)
        address_loads.extend(propagated_loads)
        
        logger.info(f"Found {len(address_loads)} address load patterns")
        return address_loads
    
    def _identify_basic_loads(self, instructions: List) -> List[AddressLoadInfo]:
        """识别基础地址加载模式 - 支持ARM/MIPS/RISC-V"""
        loads = []
        
        # ⭐ 适配增强的架构检测 - 支持多架构
        if not self.elf_analyzer.elf_info or not self.elf_analyzer.elf_info.arch:
            # 默认假设ARM
            arch_type = 'arm'
        else:
            arch_lower = self.elf_analyzer.elf_info.arch.lower()
            
            if ('arm' in arch_lower or 'stm32' in arch_lower or 'sam3' in arch_lower or
                'max32' in arch_lower or 'cortex' in arch_lower or 'k64' in arch_lower):
                arch_type = 'arm'
            elif 'aarch64' in arch_lower:
                arch_type = 'aarch64'
            elif 'mips' in arch_lower or 'em_mips' in arch_lower:
                arch_type = 'mips'
            elif 'riscv' in arch_lower or 'em_riscv' in arch_lower:
                arch_type = 'riscv'
            else:
                arch_type = 'arm'  # 默认
        
        for i, insn in enumerate(instructions):
            load_info = None
            
            if arch_type == 'arm':
                load_info = self._analyze_arm_address_load_enhanced(insn, i, instructions)
            elif arch_type == 'aarch64':
                load_info = self._analyze_arm64_address_load_enhanced(insn, i, instructions)
            elif arch_type == 'mips':
                load_info = self._analyze_mips_address_load(insn, i, instructions)
            elif arch_type == 'riscv':
                load_info = self._analyze_riscv_address_load(insn, i, instructions)
            
            if load_info and self.elf_analyzer.is_potential_mmio_address(load_info.base_address):
                loads.append(load_info)
        
        return loads
    
    def _analyze_arm_address_load_enhanced(self, insn, index: int, instructions: List) -> Optional[AddressLoadInfo]:
        """
        增强的ARM地址加载分析
        新增支持：
        1. ldr r3, =imm 伪指令的混合序列
        2. Thumb-2 IT blocks
        3. 更多的literal pool模式
        """
        try:
            mnemonic = insn.mnemonic.lower()
            
            # 模式1: 标准LDR指令
            if mnemonic == 'ldr' and len(insn.operands) >= 2:
                result = self._analyze_ldr_instruction_enhanced(insn, index, instructions)
                if result:
                    return result
            
            # 模式2: MOVW/MOVT组合 (完整实现)
            elif mnemonic == 'movw' and len(insn.operands) >= 2:
                result = self._analyze_movw_movt_enhanced(insn, index, instructions)
                if result:
                    return result
            
            # 模式3: 新增 - ADR指令 (PC相对地址)
            elif mnemonic == 'adr' and len(insn.operands) >= 2:
                result = self._analyze_adr_instruction(insn, index)
                if result:
                    return result
            
            # 模式4: 新增 - Thumb-2 LDR.W指令
            elif mnemonic in ['ldr.w', 'ldrw'] and len(insn.operands) >= 2:
                result = self._analyze_thumb2_ldr(insn, index, instructions)
                if result:
                    return result
        
        except Exception as e:
            logger.debug(f"Error analyzing ARM instruction {insn.address:08x}: {e}")
        
        return None
    
    def _analyze_ldr_instruction_enhanced(self, insn, index: int, instructions: List) -> Optional[AddressLoadInfo]:
        """
        增强的LDR指令分析
        ✅ IDA Pro验证通过的PC计算方法
        """
        dst_reg = insn.operands[0].reg if insn.operands[0].type == capstone.arm.ARM_OP_REG else None
        src_operand = insn.operands[1]
        
        # PC相对寻址 (LDR Rx, [PC, #offset] 或 LDR Rx, =address)
        if (src_operand.type == capstone.arm.ARM_OP_MEM and 
            src_operand.mem.base == capstone.arm.ARM_REG_PC):
            offset = src_operand.mem.disp
            
            # ARM架构规范（IDA Pro验证通过）:
            # Thumb-2: PC = Align(当前指令 + 4, 4)
            # literal_addr = PC + offset
            pc_value = insn.address + 4
            pc_aligned = pc_value & ~0x3  # 对齐到4字节边界
            actual_addr = pc_aligned + offset
            
            constant_value = self.elf_analyzer.read_constant_from_memory(actual_addr)
            
            if constant_value and dst_reg:
                return AddressLoadInfo(
                    instruction_index=index,
                    instruction_addr=insn.address,
                    register=dst_reg,
                    base_address=constant_value,
                    load_type='ldr_pc_relative',
                    instruction=f"{insn.mnemonic} {insn.op_str}",
                    evidence_chain=[
                        {
                            'addr': insn.address,
                            'instruction': f"{insn.mnemonic} {insn.op_str}",
                            'description': f"PC相对寻址加载",
                            'literal_pool': actual_addr,
                            'value': constant_value,
                            'pc_calculation': {
                                'pc_value': pc_value,
                                'pc_aligned': pc_aligned,
                                'offset': offset,
                                'formula': f"({insn.address:#x} + 4) & ~0x3 + {offset:#x}"
                            }
                        }
                    ],
                    confidence=1.0
                )
        
        # 立即数加载
        elif src_operand.type == capstone.arm.ARM_OP_IMM and dst_reg:
            return AddressLoadInfo(
                instruction_index=index,
                instruction_addr=insn.address,
                register=dst_reg,
                base_address=src_operand.imm,
                load_type='ldr_immediate',
                instruction=f"{insn.mnemonic} {insn.op_str}",
                evidence_chain=[{
                    'addr': insn.address,
                    'instruction': f"{insn.mnemonic} {insn.op_str}",
                    'description': f"LDR立即数: r{dst_reg} = 0x{src_operand.imm:08x}"
                }],
                confidence=0.9
            )
        
        return None
    
    def _analyze_movw_movt_enhanced(self, insn, index: int, instructions: List) -> Optional[AddressLoadInfo]:
        """增强的MOVW/MOVT分析"""
        dst_reg = insn.operands[0].reg if insn.operands[0].type == capstone.arm.ARM_OP_REG else None
        if dst_reg and insn.operands[1].type == capstone.arm.ARM_OP_IMM:
            # 查找后续的MOVT指令
            movt_result = self._find_matching_movt_enhanced(instructions, index + 1, dst_reg)
            if movt_result:
                low_16 = insn.operands[1].imm & 0xFFFF
                high_16 = movt_result['value'] & 0xFFFF
                combined_addr = (high_16 << 16) | low_16
                
                return AddressLoadInfo(
                    instruction_index=index,
                    instruction_addr=insn.address,
                    register=dst_reg,
                    base_address=combined_addr,
                    load_type='movw_movt',
                    instruction=f"{insn.mnemonic} {insn.op_str}",
                    evidence_chain=[
                        {
                            'addr': insn.address,
                            'instruction': f"{insn.mnemonic} {insn.op_str}",
                            'description': f"MOVW低16位: r{dst_reg} = 0x{low_16:04x}"
                        },
                        {
                            'addr': movt_result['addr'],
                            'instruction': movt_result['instruction'],
                            'description': f"MOVT高16位: r{dst_reg} = 0x{high_16:04x}0000 | 0x{low_16:04x}"
                        },
                        {
                            'addr': 0,
                            'instruction': 'COMBINED',
                            'description': f"最终地址: r{dst_reg} = 0x{combined_addr:08x}"
                        }
                    ],
                    confidence=0.98
                )
        
        return None
    
    def _analyze_adr_instruction(self, insn, index: int) -> Optional[AddressLoadInfo]:
        """
        分析ADR指令 - PC相对地址
        ✅ IDA Pro验证通过的PC计算
        """
        try:
            dst_reg = insn.operands[0].reg if insn.operands[0].type == capstone.arm.ARM_OP_REG else None
            if dst_reg and insn.operands[1].type == capstone.arm.ARM_OP_IMM:
                # ARM架构规范（与LDR一致）:
                # PC = Align(当前指令 + 4, 4)
                pc_value = insn.address + 4
                pc_aligned = pc_value & ~0x3
                target_addr = pc_aligned + insn.operands[1].imm
                
                return AddressLoadInfo(
                    instruction_index=index,
                    instruction_addr=insn.address,
                    register=dst_reg,
                    base_address=target_addr,
                    load_type='adr_pc_relative',
                    instruction=f"{insn.mnemonic} {insn.op_str}",
                    evidence_chain=[{
                        'addr': insn.address,
                        'instruction': f"{insn.mnemonic} {insn.op_str}",
                        'description': f"ADR PC相对: r{dst_reg} = PC_aligned + {insn.operands[1].imm} = 0x{target_addr:08x}",
                        'pc_calculation': {
                            'pc_value': pc_value,
                            'pc_aligned': pc_aligned,
                            'offset': insn.operands[1].imm,
                            'target': target_addr
                        }
                    }],
                    confidence=0.9
                )
        except:
            pass
        return None
    
    def _analyze_thumb2_ldr(self, insn, index: int, instructions: List) -> Optional[AddressLoadInfo]:
        """
        分析Thumb-2 LDR.W指令
        ✅ 使用与标准LDR相同的IDA Pro验证通过的PC计算
        """
        try:
            dst_reg = insn.operands[0].reg if insn.operands[0].type == capstone.arm.ARM_OP_REG else None
            src_operand = insn.operands[1]
            
            if dst_reg and src_operand.type == capstone.arm.ARM_OP_MEM:
                # 检查是否是PC相对寻址
                if src_operand.mem.base == capstone.arm.ARM_REG_PC:
                    offset = src_operand.mem.disp
                    
                    # 使用与标准LDR相同的计算方法
                    pc_value = insn.address + 4
                    pc_aligned = pc_value & ~0x3
                    actual_addr = pc_aligned + offset
                    
                    constant_value = self.elf_analyzer.read_constant_from_memory(actual_addr)
                    
                    if constant_value:
                        return AddressLoadInfo(
                            instruction_index=index,
                            instruction_addr=insn.address,
                            register=dst_reg,
                            base_address=constant_value,
                            load_type='thumb2_ldr_pc',
                            instruction=f"{insn.mnemonic} {insn.op_str}",
                            evidence_chain=[{
                                'addr': insn.address,
                                'instruction': f"{insn.mnemonic} {insn.op_str}",
                                'description': f"Thumb-2 LDR.W PC相对",
                                'literal_pool': actual_addr,
                                'value': constant_value,
                                'pc_calculation': {
                                    'pc_value': pc_value,
                                    'pc_aligned': pc_aligned,
                                    'offset': offset
                                }
                            }],
                            confidence=1.0
                        )
        except:
            pass
        return None
    
    def _analyze_arm64_address_load_enhanced(self, insn, index: int, instructions: List) -> Optional[AddressLoadInfo]:
        """
        增强的ARM64地址加载分析
        新增支持：
        1. adrp + ldr [reg, offset] 模式
        2. 更多的MOVZ/MOVK组合
        """
        try:
            mnemonic = insn.mnemonic.lower()
            
            # 模式1: ADRP指令（需要与ADD或LDR配对）
            if mnemonic == 'adrp' and len(insn.operands) >= 2:
                result = self._analyze_adrp_enhanced(insn, index, instructions)
                if result:
                    return result
            
            # 模式2: MOVZ指令（需要与MOVK配对）
            elif mnemonic == 'movz' and len(insn.operands) >= 2:
                result = self._analyze_movz_movk_enhanced(insn, index, instructions)
                if result:
                    return result
            
            # 模式3: LDR literal
            elif mnemonic == 'ldr' and len(insn.operands) >= 2:
                result = self._analyze_arm64_ldr_literal(insn, index)
                if result:
                    return result
        
        except Exception as e:
            logger.debug(f"Error analyzing ARM64 instruction {insn.address:08x}: {e}")
        
        return None
    
    def _analyze_adrp_enhanced(self, insn, index: int, instructions: List) -> Optional[AddressLoadInfo]:
        """增强的ADRP分析，支持ADRP + LDR模式"""
        dst_reg = insn.operands[0].reg if insn.operands[0].type == capstone.arm64.ARM64_OP_REG else None
        if dst_reg and insn.operands[1].type == capstone.arm64.ARM64_OP_IMM:
            page_base = insn.operands[1].imm
            
            # 查找后续的ADD或LDR指令
            next_insn = self._find_matching_adrp_continuation(instructions, index + 1, dst_reg)
            if next_insn:
                if next_insn['type'] == 'add':
                    combined_addr = page_base + next_insn['offset']
                    load_type = 'adrp_add'
                elif next_insn['type'] == 'ldr':
                    # ADRP + LDR [reg, offset] 模式
                    target_addr = page_base + next_insn['offset']
                    combined_addr = self.elf_analyzer.read_constant_from_memory(target_addr)
                    if not combined_addr:
                        return None
                    load_type = 'adrp_ldr_indirect'
                else:
                    return None
                
                evidence_chain = [
                    {
                        'addr': insn.address,
                        'instruction': f"{insn.mnemonic} {insn.op_str}",
                        'description': f"ADRP页面基址: 0x{page_base:016x}"
                    },
                    {
                        'addr': next_insn['addr'],
                        'instruction': next_insn['instruction'],
                        'description': f"{next_insn['type'].upper()}: 最终地址 0x{combined_addr:016x}"
                    }
                ]
                
                return AddressLoadInfo(
                    instruction_index=index,
                    instruction_addr=insn.address,
                    register=dst_reg,
                    base_address=combined_addr,
                    load_type=load_type,
                    instruction=f"{insn.mnemonic} {insn.op_str}",
                    evidence_chain=evidence_chain,
                    confidence=0.95 if next_insn['type'] == 'add' else 0.85
                )
        
        return None
    
    def _identify_compound_loads(self, instructions: List, basic_loads: List[AddressLoadInfo]) -> List[AddressLoadInfo]:
        """
        识别复合地址计算
        例如：ldr r3, [pc, #imm]; add r3, r3, #offset
        """
        logger.info("Identifying compound address calculations")
        compound_loads = []
        
        # 为基础加载建立索引
        load_by_reg = {}
        for load in basic_loads:
            load_by_reg[f"r{load.register}_{load.instruction_addr}"] = load
        
        for i, insn in enumerate(instructions):
            try:
                mnemonic = insn.mnemonic.lower()
                
                # 扩展支持的指令：ADD, SUB, ORR, BIC, LSL, LSR
                if mnemonic in ['add', 'sub', 'orr', 'bic', 'lsl', 'lsr', 'asr'] and len(insn.operands) >= 2:
                    dst_reg = insn.operands[0].reg if insn.operands[0].type in [capstone.arm.ARM_OP_REG, capstone.arm64.ARM64_OP_REG] else None
                    
                    if dst_reg:
                        # 情况1: dst = dst op imm (自修改)
                        if len(insn.operands) >= 3:
                            src_reg = insn.operands[1].reg if insn.operands[1].type in [capstone.arm.ARM_OP_REG, capstone.arm64.ARM64_OP_REG] else None
                            
                            if src_reg and insn.operands[2].type in [capstone.arm.ARM_OP_IMM, capstone.arm64.ARM64_OP_IMM]:
                                # 查找源寄存器的基础加载
                                base_load = self._find_recent_load_for_register(basic_loads, src_reg, insn.address)
                                if base_load:
                                    offset = insn.operands[2].imm
                                    
                                    # 根据指令计算新地址
                                    if mnemonic == 'add':
                                        new_addr = base_load.base_address + offset
                                    elif mnemonic == 'sub':
                                        new_addr = base_load.base_address - offset
                                    elif mnemonic == 'orr':
                                        new_addr = base_load.base_address | offset
                                    elif mnemonic == 'bic':
                                        new_addr = base_load.base_address & ~offset
                                    elif mnemonic in ['lsl', 'lsr', 'asr']:
                                        # 位移操作
                                        if mnemonic == 'lsl':
                                            new_addr = base_load.base_address << offset
                                        elif mnemonic == 'lsr':
                                            new_addr = base_load.base_address >> offset
                                        else:  # asr
                                            new_addr = base_load.base_address >> offset
                                        # 限制在32位
                                        new_addr &= 0xFFFFFFFF
                                    else:
                                        continue
                                    
                                    if self.elf_analyzer.is_potential_mmio_address(new_addr):
                                        compound_load = AddressLoadInfo(
                                            instruction_index=i,
                                            instruction_addr=insn.address,
                                            register=dst_reg,
                                            base_address=new_addr,
                                            load_type=f'compound_{mnemonic}',
                                            instruction=f"{insn.mnemonic} {insn.op_str}",
                                            evidence_chain=base_load.evidence_chain + [{
                                                'addr': insn.address,
                                                'instruction': f"{insn.mnemonic} {insn.op_str}",
                                                'description': f"复合{mnemonic.upper()}: 0x{base_load.base_address:08x} {mnemonic} {offset} = 0x{new_addr:08x}"
                                            }],
                                            confidence=base_load.confidence * 0.85  # 稍微提高置信度
                                        )
                                        compound_loads.append(compound_load)
                        
                        # 情况2: 条件指令中的地址（IT block）
                        # ARM Thumb-2 IT (If-Then) block
                        if i > 0 and instructions[i-1].mnemonic.lower().startswith('it'):
                            # 这是IT block中的条件指令，也应该分析
                            base_load = self._find_recent_load_for_register(basic_loads, dst_reg, insn.address)
                            if base_load and len(insn.operands) >= 2:
                                if insn.operands[1].type in [capstone.arm.ARM_OP_IMM, capstone.arm64.ARM64_OP_IMM]:
                                    # 条件指令中的地址也可能是MMIO
                                    conditional_addr = insn.operands[1].imm
                                    if self.elf_analyzer.is_potential_mmio_address(conditional_addr):
                                        compound_loads.append(AddressLoadInfo(
                                            instruction_index=i,
                                            instruction_addr=insn.address,
                                            register=dst_reg,
                                            base_address=conditional_addr,
                                            load_type='conditional_load',
                                            instruction=f"IT+{insn.mnemonic} {insn.op_str}",
                                            evidence_chain=[{
                                                'addr': insn.address,
                                                'instruction': f"{insn.mnemonic} {insn.op_str}",
                                                'description': f"条件加载: IT block中的地址 0x{conditional_addr:08x}"
                                            }],
                                            confidence=0.7
                                        ))
            
            except Exception as e:
                logger.debug(f"Error analyzing compound calculation: {e}")
                continue
        
        logger.info(f"Found {len(compound_loads)} compound address calculations")
        return compound_loads
    
    def _analyze_symbol_propagation(self, instructions: List, existing_loads: List[AddressLoadInfo]) -> List[AddressLoadInfo]:
        """
        符号传播分析
        处理寄存器拷贝、全局变量加载等
        """
        logger.info("Analyzing symbol propagation")
        propagated_loads = []
        
        # 建立符号传播表
        symbol_map = {}  # reg -> AddressLoadInfo
        
        for load in existing_loads:
            symbol_map[f"r{load.register}"] = load
        
        for i, insn in enumerate(instructions):
            try:
                mnemonic = insn.mnemonic.lower()
                
                # 寄存器拷贝传播
                if mnemonic == 'mov' and len(insn.operands) >= 2:
                    dst_reg = insn.operands[0].reg if insn.operands[0].type in [capstone.arm.ARM_OP_REG, capstone.arm64.ARM64_OP_REG] else None
                    src_reg = insn.operands[1].reg if insn.operands[1].type in [capstone.arm.ARM_OP_REG, capstone.arm64.ARM64_OP_REG] else None
                    
                    if dst_reg and src_reg:
                        src_key = f"r{src_reg}"
                        if src_key in symbol_map:
                            # 传播符号信息
                            original_load = symbol_map[src_key]
                            propagated_load = AddressLoadInfo(
                                instruction_index=i,
                                instruction_addr=insn.address,
                                register=dst_reg,
                                base_address=original_load.base_address,
                                load_type='register_copy',
                                instruction=f"{insn.mnemonic} {insn.op_str}",
                                evidence_chain=original_load.evidence_chain + [{
                                    'addr': insn.address,
                                    'instruction': f"{insn.mnemonic} {insn.op_str}",
                                    'description': f"寄存器拷贝: r{dst_reg} = r{src_reg} (0x{original_load.base_address:08x})"
                                }],
                                confidence=original_load.confidence * 0.9
                            )
                            propagated_loads.append(propagated_load)
                            symbol_map[f"r{dst_reg}"] = propagated_load
                
                # ORR reg, reg, #0 形式的拷贝
                elif mnemonic == 'orr' and len(insn.operands) >= 3:
                    dst_reg = insn.operands[0].reg if insn.operands[0].type in [capstone.arm.ARM_OP_REG, capstone.arm64.ARM64_OP_REG] else None
                    src_reg = insn.operands[1].reg if insn.operands[1].type in [capstone.arm.ARM_OP_REG, capstone.arm64.ARM64_OP_REG] else None
                    
                    if (dst_reg and src_reg and 
                        insn.operands[2].type in [capstone.arm.ARM_OP_IMM, capstone.arm64.ARM64_OP_IMM] and
                        insn.operands[2].imm == 0):
                        
                        src_key = f"r{src_reg}"
                        if src_key in symbol_map:
                            original_load = symbol_map[src_key]
                            propagated_load = AddressLoadInfo(
                                instruction_index=i,
                                instruction_addr=insn.address,
                                register=dst_reg,
                                base_address=original_load.base_address,
                                load_type='orr_copy',
                                instruction=f"{insn.mnemonic} {insn.op_str}",
                                evidence_chain=original_load.evidence_chain + [{
                                    'addr': insn.address,
                                    'instruction': f"{insn.mnemonic} {insn.op_str}",
                                    'description': f"ORR拷贝: r{dst_reg} = r{src_reg} | 0 (0x{original_load.base_address:08x})"
                                }],
                                confidence=original_load.confidence * 0.85
                            )
                            propagated_loads.append(propagated_load)
                            symbol_map[f"r{dst_reg}"] = propagated_load
            
            except Exception as e:
                logger.debug(f"Error in symbol propagation: {e}")
                continue
        
        logger.info(f"Found {len(propagated_loads)} propagated symbols")
        return propagated_loads
    
    # 辅助方法
    def _find_matching_movt_enhanced(self, instructions: List, start_index: int, target_reg: int) -> Optional[Dict]:
        """增强的MOVT查找，支持更大的搜索范围"""
        for i in range(start_index, min(start_index + 15, len(instructions))):  # 扩大搜索范围
            insn = instructions[i]
            if (insn.mnemonic.lower() == 'movt' and 
                len(insn.operands) >= 2 and
                insn.operands[0].type == capstone.arm.ARM_OP_REG and
                insn.operands[0].reg == target_reg and
                insn.operands[1].type == capstone.arm.ARM_OP_IMM):
                return {
                    'value': insn.operands[1].imm,
                    'addr': insn.address,
                    'instruction': f"{insn.mnemonic} {insn.op_str}"
                }
            # 如果寄存器被重新赋值，停止搜索
            elif (len(insn.operands) >= 1 and 
                  insn.operands[0].type == capstone.arm.ARM_OP_REG and 
                  insn.operands[0].reg == target_reg and
                  insn.mnemonic.lower() in ['mov', 'ldr', 'movw']):
                break
        return None
    
    def _find_matching_adrp_continuation(self, instructions: List, start_index: int, target_reg: int) -> Optional[Dict]:
        """查找ADRP的后续指令（ADD或LDR）"""
        for i in range(start_index, min(start_index + 8, len(instructions))):
            insn = instructions[i]
            mnemonic = insn.mnemonic.lower()
            
            if mnemonic == 'add' and len(insn.operands) >= 3:
                if (insn.operands[0].type == capstone.arm64.ARM64_OP_REG and
                    insn.operands[0].reg == target_reg and
                    insn.operands[1].type == capstone.arm64.ARM64_OP_REG and
                    insn.operands[1].reg == target_reg and
                    insn.operands[2].type == capstone.arm64.ARM64_OP_IMM):
                    return {
                        'type': 'add',
                        'offset': insn.operands[2].imm,
                        'addr': insn.address,
                        'instruction': f"{insn.mnemonic} {insn.op_str}"
                    }
            
            elif mnemonic == 'ldr' and len(insn.operands) >= 2:
                # 检查是否是 ldr reg, [target_reg, #offset]
                if (insn.operands[0].type == capstone.arm64.ARM64_OP_REG and
                    insn.operands[1].type == capstone.arm64.ARM64_OP_MEM and
                    insn.operands[1].mem.base == target_reg):
                    return {
                        'type': 'ldr',
                        'offset': insn.operands[1].mem.disp,
                        'addr': insn.address,
                        'instruction': f"{insn.mnemonic} {insn.op_str}"
                    }
        
        return None
    
    def _find_recent_load_for_register(self, loads: List[AddressLoadInfo], register: int, current_addr: int) -> Optional[AddressLoadInfo]:
        """查找寄存器最近的地址加载"""
        # 在当前地址之前查找最近的加载
        recent_load = None
        min_distance = float('inf')
        
        for load in loads:
            if (load.register == register and 
                load.instruction_addr < current_addr):
                distance = current_addr - load.instruction_addr
                if distance < min_distance:
                    min_distance = distance
                    recent_load = load
        
        return recent_load
    
    def _analyze_movz_movk_enhanced(self, insn, index: int, instructions: List) -> Optional[AddressLoadInfo]:
        """增强的MOVZ/MOVK分析"""
        dst_reg = insn.operands[0].reg if insn.operands[0].type == capstone.arm64.ARM64_OP_REG else None
        if dst_reg and insn.operands[1].type == capstone.arm64.ARM64_OP_IMM:
            # 查找后续的MOVK指令序列
            movk_results = self._find_matching_movk_sequence_enhanced(instructions, index + 1, dst_reg)
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
                
                return AddressLoadInfo(
                    instruction_index=index,
                    instruction_addr=insn.address,
                    register=dst_reg,
                    base_address=combined_value,
                    load_type='movz_movk',
                    instruction=f"{insn.mnemonic} {insn.op_str}",
                    evidence_chain=evidence_chain,
                    confidence=0.95
                )
        
        return None
    
    def _find_matching_movk_sequence_enhanced(self, instructions: List, start_index: int, target_reg: int) -> List[Dict]:
        """增强的MOVK序列查找"""
        movk_results = []
        for i in range(start_index, min(start_index + 15, len(instructions))):  # 扩大搜索范围
            insn = instructions[i]
            if (insn.mnemonic.lower() == 'movk' and 
                len(insn.operands) >= 2 and
                insn.operands[0].type == capstone.arm64.ARM64_OP_REG and
                insn.operands[0].reg == target_reg and
                insn.operands[1].type == capstone.arm64.ARM64_OP_IMM):
                
                # 获取位移值
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
    
    def _analyze_arm64_ldr_literal(self, insn, index: int) -> Optional[AddressLoadInfo]:
        """分析ARM64 LDR literal指令"""
        dst_reg = insn.operands[0].reg if insn.operands[0].type == capstone.arm64.ARM64_OP_REG else None
        src_operand = insn.operands[1]
        
        if (dst_reg and src_operand.type == capstone.arm64.ARM64_OP_MEM and 
            src_operand.mem.base == capstone.arm64.ARM64_REG_INVALID):
            # PC相对地址
            target_addr = insn.address + src_operand.mem.disp
            constant_value = self.elf_analyzer.read_constant_from_memory(target_addr)
            
            if constant_value:
                return AddressLoadInfo(
                    instruction_index=index,
                    instruction_addr=insn.address,
                    register=dst_reg,
                    base_address=constant_value,
                    load_type='ldr_literal_arm64',
                    instruction=f"{insn.mnemonic} {insn.op_str}",
                    evidence_chain=[
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
                    ],
                    confidence=0.9
                )
        
        return None
    
    def _extract_literal_pool_mmio(self, instructions: List) -> List[AddressLoadInfo]:
        """
        ⭐ 新增：从常量池(Literal Pool)中提取MMIO地址
        
        解决问题：
        - IDA Pro显示: LDR R3, =0x40021000
        - 实际编译为: LDR R3, [PC, #offset]
        - 真实值在常量池: .word 0x40021000
        
        ARM Thumb-2模式下，PC相对寻址的计算方式：
        - target_addr = (PC + 4) + offset
        - PC指向当前指令+4（已对齐到4字节）
        """
        import struct
        
        literal_pool_loads = []
        seen_addresses = set()  # 去重
        
        for i, insn in enumerate(instructions):
            try:
                # 只处理LDR指令
                if insn.mnemonic.lower() not in ['ldr', 'ldr.w']:
                    continue
                
                if len(insn.operands) < 2:
                    continue
                
                dst_reg = insn.operands[0].reg if insn.operands[0].type == capstone.arm.ARM_OP_REG else None
                src_operand = insn.operands[1]
                
                # 检查是否是PC相对寻址
                if (src_operand.type == capstone.arm.ARM_OP_MEM and 
                    src_operand.mem.base == capstone.arm.ARM_REG_PC):
                    
                    offset = src_operand.mem.disp
                    
                    # ⭐ ARM Thumb-2 PC计算：(PC+4) + offset
                    # 注意：Capstone返回的address已经是对齐的
                    current_pc = insn.address
                    
                    # Thumb模式：PC+4，然后对齐到4字节
                    aligned_pc = (current_pc + 4) & ~0x3
                    pool_addr = aligned_pc + offset
                    
                    # 从ELF读取常量池的值
                    constant_value = self._read_word_from_elf(pool_addr)
                    
                    if constant_value is None:
                        continue
                    
                    # ⭐ 判断是否是MMIO地址
                    if not self._is_mmio_address(constant_value):
                        continue
                    
                    # 去重
                    if constant_value in seen_addresses:
                        continue
                    seen_addresses.add(constant_value)
                    
                    # 记录到常量池字典
                    self.constant_pool[insn.address] = {
                        'value': constant_value,
                        'pool_addr': pool_addr,
                        'target_reg': dst_reg
                    }
                    
                    # 创建AddressLoadInfo
                    load_info = AddressLoadInfo(
                        instruction_index=i,
                        instruction_addr=insn.address,
                        register=dst_reg,
                        base_address=constant_value,
                        load_type='ldr_literal_pool',
                        instruction=f"{insn.mnemonic} {insn.op_str}",
                        evidence_chain=[
                            {
                                'addr': insn.address,
                                'instruction': f"{insn.mnemonic} {insn.op_str}",
                                'description': f"LDR from literal pool @ 0x{pool_addr:08x}"
                            },
                            {
                                'addr': pool_addr,
                                'instruction': f".word 0x{constant_value:08x}",
                                'description': f"Literal pool value: 0x{constant_value:08x}"
                            }
                        ],
                        confidence=0.95
                    )
                    
                    literal_pool_loads.append(load_info)
                    logger.debug(f"  Literal pool @ {insn.address:#08x}: {constant_value:#010x}")
                    
            except Exception as e:
                logger.debug(f"Error extracting literal pool at {insn.address:#x}: {e}")
                continue
        
        return literal_pool_loads
    
    def _read_word_from_elf(self, addr: int) -> Optional[int]:
        """
        从ELF文件中读取指定地址的4字节word
        
        搜索顺序: text → rodata → data
        """
        import struct
        
        # ⭐ 修正：直接访问elf_info.sections
        for section_name in ['text', '.text', 'rodata', '.rodata', 'data', '.data', '.data.rel.ro']:
            try:
                if section_name not in self.elf_analyzer.elf_info.sections:
                    continue
                
                section_info = self.elf_analyzer.elf_info.sections[section_name]
                section_addr = section_info['addr']
                section_data = section_info['data']
                
                if not section_data:
                    continue
                
                section_size = len(section_data)
                
                # 检查地址是否在这个段中
                if section_addr <= addr < section_addr + section_size:
                    offset = addr - section_addr
                    
                    # 确保不会越界
                    if offset + 4 <= section_size:
                        word = struct.unpack('<I', section_data[offset:offset+4])[0]
                        return word
                        
            except Exception as e:
                logger.debug(f"Error reading from section {section_name}: {e}")
                continue
        
        return None
    
    def _is_mmio_address(self, addr: int) -> bool:
        """
        判断地址是否是MMIO地址
        
        ARM Cortex-M内存映射:
        - 0x40000000-0x5FFFFFFF: 外设区
        - 0xE0000000-0xE00FFFFF: 系统外设 (NVIC, SCB, SysTick等)
        
        MIPS内存映射:
        - 0xA0000000-0xBFFFFFFF: KSEG1 (uncached, unmapped) - 常用于外设MMIO
        - 0x1F800000-0x1FFFFFFF: 物理外设区 (PIC32等)
        
        RISC-V内存映射:
        - 0x10000000-0x1FFFFFFF: 外设区 (典型)
        - 0x40000000-0x5FFFFFFF: 外设区 (部分MCU)
        """
        # ARM外设区域 (标准)
        if 0x40000000 <= addr < 0x60000000:
            return True
        
        # ARM系统外设区域 (Cortex-M)
        if 0xE0000000 <= addr < 0xE0100000:
            return True
        
        # NXP Kinetis特殊区域
        if 0x50000000 <= addr < 0x54000000:
            return True
        
        # ⭐ MIPS KSEG1 uncached区域 (常用于MMIO)
        if 0xA0000000 <= addr <= 0xBFFFFFFF:
            return True
        
        # ⭐ MIPS物理外设区 (PIC32等)
        if 0x1F800000 <= addr <= 0x1FFFFFFF:
            return True
        
        # ⭐ RISC-V典型外设区
        if 0x10000000 <= addr < 0x20000000:
            return True
        
        return False
    
    # ==================== MIPS地址加载分析 ====================
    
    def _analyze_mips_address_load(self, insn, index: int, instructions: List) -> Optional[AddressLoadInfo]:
        """
        MIPS地址加载分析
        
        常见模式:
        1. lui $t0, upper16   # 加载高16位
           ori $t0, $t0, lower16  # 或运算低16位
        2. lw $t0, offset($gp) # 从全局指针加载
        3. la $t0, addr        # 伪指令，由汇编器展开
        """
        try:
            mnemonic = insn.mnemonic.lower()
            
            # 模式1: LUI+ORI组合
            if mnemonic == 'lui' and len(insn.operands) >= 2:
                # 获取高16位
                try:
                    upper16 = insn.operands[1].imm
                    dest_reg = insn.operands[0].reg
                    
                    # 查找后续的ORI指令
                    for j in range(index + 1, min(index + 5, len(instructions))):
                        next_insn = instructions[j]
                        if (next_insn.mnemonic.lower() == 'ori' and 
                            len(next_insn.operands) >= 3 and
                            next_insn.operands[1].reg == dest_reg):
                            
                            lower16 = next_insn.operands[2].imm
                            address = (upper16 << 16) | lower16
                            
                            if self._is_mmio_address(address):
                                return AddressLoadInfo(
                                    instruction_index=j,  # ⭐ 使用ORI指令的索引
                                    instruction_addr=next_insn.address,  # ⭐ 使用ORI指令的地址（最终定义点）
                                    register=dest_reg,
                                    base_address=address,
                                    load_type='lui_ori',
                                    instruction=f"{insn.mnemonic} {insn.op_str}",
                                    evidence_chain=[
                                        {'addr': insn.address, 'instruction': f"{insn.mnemonic} {insn.op_str}"},
                                        {'addr': next_insn.address, 'instruction': f"{next_insn.mnemonic} {next_insn.op_str}"}
                                    ],
                                    confidence=0.95
                                )
                except Exception as e:
                    logger.debug(f"Error parsing MIPS LUI at {insn.address:#x}: {e}")
            
            # 模式2: LW/SW with immediate
            elif mnemonic in ['lw', 'sw', 'lb', 'sb', 'lh', 'sh'] and len(insn.operands) >= 2:
                try:
                    # MIPS格式: lw $t0, offset($base)
                    if insn.operands[1].type == capstone.mips.MIPS_OP_MEM:
                        mem = insn.operands[1].mem
                        # 如果是绝对地址（base=0）
                        if mem.base == 0 and mem.disp != 0:
                            address = mem.disp & 0xFFFFFFFF
                            if self._is_mmio_address(address):
                                return AddressLoadInfo(
                                    instruction_index=index,
                                    instruction_addr=insn.address,
                                    register=insn.operands[0].reg,
                                    base_address=address,
                                    load_type='mips_mem',
                                    instruction=f"{insn.mnemonic} {insn.op_str}",
                                    confidence=0.9
                                )
                except Exception as e:
                    logger.debug(f"Error parsing MIPS MEM at {insn.address:#x}: {e}")
        
        except Exception as e:
            logger.debug(f"Error analyzing MIPS instruction {insn.address:#x}: {e}")
        
        return None
    
    # ==================== RISC-V地址加载分析 ====================
    
    def _analyze_riscv_address_load(self, insn, index: int, instructions: List) -> Optional[AddressLoadInfo]:
        """
        RISC-V地址加载分析
        
        常见模式:
        1. lui rd, upper20    # 加载高20位
           addi rd, rd, lower12  # 加偏移低12位
        2. la rd, symbol      # 伪指令（由lui+addi展开）
        3. lw/sw rd, offset(rs) # 内存访问
        """
        try:
            mnemonic = insn.mnemonic.lower()
            
            # 模式1: LUI+ADDI组合
            if mnemonic == 'lui' and len(insn.operands) >= 2:
                try:
                    upper20 = insn.operands[1].imm
                    dest_reg = insn.operands[0].reg
                    
                    # 查找后续的ADDI指令
                    for j in range(index + 1, min(index + 5, len(instructions))):
                        next_insn = instructions[j]
                        if (next_insn.mnemonic.lower() in ['addi', 'add'] and 
                            len(next_insn.operands) >= 3):
                            
                            # 检查是否操作同一个寄存器
                            if next_insn.operands[1].reg == dest_reg:
                                # RISC-V: addi rd, rs, imm
                                if next_insn.operands[2].type == capstone.riscv.RISCV_OP_IMM:
                                    lower12 = next_insn.operands[2].imm
                                    # 处理符号扩展
                                    if lower12 & 0x800:  # 负数
                                        lower12 = lower12 - 0x1000
                                    
                                    address = (upper20 << 12) + lower12
                                    address = address & 0xFFFFFFFF  # 32位
                                    
                                    if self._is_mmio_address(address):
                                        return AddressLoadInfo(
                                            instruction_index=j,  # ⭐ 使用ADDI指令的索引
                                            instruction_addr=next_insn.address,  # ⭐ 使用ADDI指令的地址（最终定义点）
                                            register=dest_reg,
                                            base_address=address,
                                            load_type='lui_addi',
                                            instruction=f"{insn.mnemonic} {insn.op_str}",
                                            evidence_chain=[
                                                {'addr': insn.address, 'instruction': f"{insn.mnemonic} {insn.op_str}"},
                                                {'addr': next_insn.address, 'instruction': f"{next_insn.mnemonic} {next_insn.op_str}"}
                                            ],
                                            confidence=0.95
                                        )
                except Exception as e:
                    logger.debug(f"Error parsing RISC-V LUI at {insn.address:#x}: {e}")
            
            # 模式2: LI伪指令 (已展开为实际指令)
            elif mnemonic == 'li' and len(insn.operands) >= 2:
                try:
                    if insn.operands[1].type == capstone.riscv.RISCV_OP_IMM:
                        address = insn.operands[1].imm & 0xFFFFFFFF
                        if self._is_mmio_address(address):
                            return AddressLoadInfo(
                                instruction_index=index,
                                instruction_addr=insn.address,
                                register=insn.operands[0].reg,
                                base_address=address,
                                load_type='riscv_li',
                                instruction=f"{insn.mnemonic} {insn.op_str}",
                                confidence=0.9
                            )
                except Exception as e:
                    logger.debug(f"Error parsing RISC-V LI at {insn.address:#x}: {e}")
            
            # 模式3: LW/SW with absolute address
            elif mnemonic in ['lw', 'sw', 'lb', 'sb', 'lh', 'sh', 'ld', 'sd'] and len(insn.operands) >= 2:
                try:
                    if insn.operands[1].type == capstone.riscv.RISCV_OP_MEM:
                        mem = insn.operands[1].mem
                        # 如果是绝对地址（base=0）
                        if mem.base == 0 and mem.disp != 0:
                            address = mem.disp & 0xFFFFFFFF
                            if self._is_mmio_address(address):
                                return AddressLoadInfo(
                                    instruction_index=index,
                                    instruction_addr=insn.address,
                                    register=insn.operands[0].reg,
                                    base_address=address,
                                    load_type='riscv_mem',
                                    instruction=f"{insn.mnemonic} {insn.op_str}",
                                    confidence=0.9
                                )
                except Exception as e:
                    logger.debug(f"Error parsing RISC-V MEM at {insn.address:#x}: {e}")
        
        except Exception as e:
            logger.debug(f"Error analyzing RISC-V instruction {insn.address:#x}: {e}")
        
        return None
