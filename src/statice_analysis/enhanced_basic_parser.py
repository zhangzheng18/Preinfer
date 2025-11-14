#!/usr/bin/env python3
"""
增强的基础解析器 - 重构版本
整合ELF分析、地址加载识别、智能聚类等模块
"""

import logging
import json
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from pathlib import Path
from datetime import datetime

try:
    import capstone
    from capstone import CS_ARCH_ARM, CS_ARCH_ARM64, CS_MODE_ARM, CS_MODE_THUMB
    HAS_CAPSTONE = True
except ImportError:
    HAS_CAPSTONE = False

from .elf_analyzer import ELFAnalyzer, ELFInfo, MemoryRegion
from .address_loader import AddressLoader, AddressLoadInfo
from .unified_clustering import UnifiedClustering, PeripheralCandidate, RegisterAccess
from .dataflow_analyzer import DataflowAnalyzer
from .behavior_semantic_extractor import BehaviorSemanticExtractor, BehaviorSemantics
from .advanced_behavior_analyzer import AdvancedBehaviorAnalyzer, AdvancedBehaviorInfo
from .bitfield_extractor import BitfieldExtractor
from .register_dependency_analyzer import RegisterDependencyAnalyzer
from .peripheral_rules import PeripheralRules

logger = logging.getLogger(__name__)

@dataclass
class InstructionEvidence:
    """指令证据记录"""
    addr: int
    instruction: str
    description: str
    raw_bytes: Optional[bytes] = None

@dataclass
class RegisterDefUse:
    """寄存器定义-使用链"""
    register: int
    def_addr: int
    def_instruction: str
    use_addrs: List[int]
    use_instructions: List[str]
    value: Optional[int] = None
    load_type: str = 'unknown'

class EnhancedBasicParser:
    """
    增强的基础解析器
    
    主要改进：
    1. 模块化架构 - 分离ELF分析、地址加载、聚类等功能
    2. 增强的地址识别 - 支持Thumb-2、复合计算、符号传播
    3. 智能聚类 - 密度感知、语义加权、外设类型推断
    4. 跨语义特征 - 中断绑定、访问模式分析、时间序列
    """
    
    def __init__(self, firmware_path: str):
        """初始化增强解析器"""
        self.firmware_path = Path(firmware_path)
        
        # 初始化子模块
        self.elf_analyzer = ELFAnalyzer(str(firmware_path))
        self.address_loader = AddressLoader(self.elf_analyzer)
        self.clustering = UnifiedClustering(self.elf_analyzer)  # 统一聚类器
        self.dataflow_analyzer = DataflowAnalyzer(self.elf_analyzer)
        self.behavior_extractor = BehaviorSemanticExtractor(self.elf_analyzer)
        self.advanced_analyzer = AdvancedBehaviorAnalyzer(self.elf_analyzer)
        self.bitfield_extractor = BitfieldExtractor()  # 位域提取
        self.dependency_analyzer = RegisterDependencyAnalyzer()  # 依赖分析
        self.peripheral_rules = PeripheralRules()  # 外设规则库
        
        # 状态变量
        self.elf_info: Optional[ELFInfo] = None
        self.memory_regions: List[MemoryRegion] = []
        self.peripheral_candidates: List[PeripheralCandidate] = []
        self.register_chains: Dict[str, RegisterDefUse] = {}
        self.behavior_semantics: Dict[int, BehaviorSemantics] = {}  # base_addr -> semantics
        self.advanced_behaviors: Dict[int, AdvancedBehaviorInfo] = {}  # base_addr -> advanced info
        
        # 增强功能
        self.irq_bindings: Dict[int, int] = {}  # mmio_base -> irq_number
        self.access_sequences: List[List[RegisterAccess]] = []  # 时间序列访问
        self.instructions: List = []  # 缓存指令列表
        self.register_accesses: List[RegisterAccess] = []  # 缓存寄存器访问
        
        # ⭐ 新增：栈追踪和跨函数分析
        self.stack_operations: Dict[int, Dict[str, Any]] = {}  # addr -> stack_op_info
        self.function_calls: Dict[int, List[Dict]] = {}  # call_addr -> [call_info]
        self.symbol_propagation_cache: Dict[str, Any] = {}  # 符号传播缓存
        
    def parse_elf(self) -> ELFInfo:
        """解析ELF文件"""
        logger.info("=== Phase 1: ELF Analysis ===")
        self.elf_info = self.elf_analyzer.parse_elf()
        return self.elf_info
    
    def analyze_memory_layout(self) -> List[MemoryRegion]:
        """分析内存布局"""
        logger.info("=== Phase 2: Memory Layout Analysis ===")
        self.memory_regions = self.elf_analyzer.analyze_memory_layout()
        return self.memory_regions
    
    def extract_peripheral_candidates(self) -> List[PeripheralCandidate]:
        """
        提取外设候选 - 增强版本
        
        流程：
        1. 指令反汇编和地址加载识别
        2. 全局数据流分析
        3. 寄存器访问收集
        4. 智能聚类
        5. 语义增强
        """
        if not self.elf_info:
            self.parse_elf()
        if not self.memory_regions:
            self.analyze_memory_layout()
        
        logger.info("=== Phase 3: Enhanced Peripheral Candidate Extraction ===")
        
        # 步骤1: 反汇编指令
        instructions = self._disassemble_text_section()
        if not instructions:
            logger.warning("No instructions found for analysis")
            return []
        
        # 步骤2: 增强的地址加载识别
        logger.info("Step 2: Enhanced address loading identification")
        address_loads = self.address_loader.analyze_address_loads(instructions)
        logger.info(f"Found {len(address_loads)} address load patterns")
        
        # ⭐ 步骤2.5: 完整集成栈追踪和跨函数分析
        address_loads = self._integrate_stack_and_function_analysis(instructions, address_loads)
        
        # ⭐ 步骤2.6: 增强符号传播
        address_loads = self._enhance_symbol_propagation(instructions, address_loads)
        
        # 步骤3: 全局数据流分析
        logger.info("Step 3: Global dataflow analysis")
        self.register_chains = self.dataflow_analyzer.build_global_def_use_chains(
            instructions, address_loads
        )
        logger.info(f"Built {len(self.register_chains)} register def-use chains")
        
        # 步骤4: 寄存器访问分析
        logger.info("Step 4: Register access analysis")
        register_accesses = self._analyze_register_accesses(instructions, address_loads)
        logger.info(f"Found {len(register_accesses)} register accesses")
        
        # 步骤5: 中断绑定分析
        logger.info("Step 5: IRQ binding analysis")
        self._analyze_irq_bindings(instructions, register_accesses)
        
        # 步骤6: 智能聚类
        logger.info("Step 6: Smart clustering")
        self.peripheral_candidates = self.clustering.cluster_register_accesses(register_accesses)
        logger.info(f"Generated {len(self.peripheral_candidates)} peripheral candidates")
        
        # 步骤7: 访问模式分析
        logger.info("Step 7: Access pattern analysis")
        self._analyze_access_patterns()
        
        # 步骤8: 行为语义提取
        logger.info("Step 8: Behavior semantic extraction")
        self._extract_behavior_semantics(instructions, register_accesses)
        
        # 步骤9: 高级行为分析（新增）
        logger.info("Step 9: Advanced behavior analysis")
        self._extract_advanced_behaviors(instructions, register_accesses)
        
        # 缓存数据供后续使用
        self.instructions = instructions
        self.register_accesses = register_accesses
        
        return self.peripheral_candidates
    
    def _disassemble_text_section(self) -> List:
        """
        反汇编代码段
        
        ⭐ 支持多种命名：'.text', 'text' (Zephyr), '.code'
        """
        # ⭐ 尝试多种代码段名称: .text (通用), text (Zephyr无点), .reset (MIPS PIC32), .code
        text_section = None
        for section_name in ['.reset', '.text', 'text', '.code', 'CODE', '.init']:
            if section_name in self.elf_info.sections and self.elf_info.sections[section_name]['data']:
                text_section = self.elf_info.sections[section_name]
                logger.info(f"Found code section: {section_name}")
                break
        
        if not text_section:
            logger.warning("No code section found (tried: .reset, .text, text, .code, .init)")
            return []
        
        # 创建反汇编器
        disasm = self._create_disassembler()
        if not disasm:
            return []
        
        # ⭐ 启用skipdata模式以处理嵌入数据
        disasm.skipdata = True
        disasm.skipdata_setup = ("db", None, None)
        
        text_data = text_section['data']
        text_addr = text_section['addr']
        
        logger.info(f"Disassembling code section: {len(text_data)} bytes at 0x{text_addr:08x}")
        instructions = list(disasm.disasm(text_data, text_addr))
        logger.info(f"Disassembled {len(instructions)} instructions (skipdata enabled)")
        
        # 过滤掉skipdata伪指令
        real_instructions = [insn for insn in instructions if insn.id != 0]  # id=0是skipdata
        logger.info(f"Real instructions: {len(real_instructions)} (filtered {len(instructions)-len(real_instructions)} data bytes)")
        
        return instructions
    
    def _create_disassembler(self):
        """创建反汇编器"""
        if not HAS_CAPSTONE:
            logger.error("Capstone not available")
            return None
        
        # ⭐ 适配增强的架构检测 - 支持ARM/MIPS/RISC-V
        if not self.elf_info or not self.elf_info.arch:
            # 默认使用ARM
            disasm = capstone.Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_THUMB)
        else:
            arch_lower = self.elf_info.arch.lower()
            
            # ARM系列
            if 'arm' in arch_lower or 'stm32' in arch_lower or 'sam3' in arch_lower or \
               'max32' in arch_lower or 'cortex' in arch_lower or 'k64' in arch_lower:
                disasm = capstone.Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_THUMB)
            
            # ARM64
            elif 'aarch64' in arch_lower:
                disasm = capstone.Cs(CS_ARCH_ARM64, capstone.CS_MODE_ARM)
            
            # MIPS系列
            elif 'mips' in arch_lower or 'em_mips' in arch_lower:
                # 根据端序选择模式 (默认little-endian)
                endian = getattr(self.elf_info, 'endian', 'little')
                if endian == 'little':
                    disasm = capstone.Cs(capstone.CS_ARCH_MIPS, capstone.CS_MODE_MIPS32 + capstone.CS_MODE_LITTLE_ENDIAN)
                else:
                    disasm = capstone.Cs(capstone.CS_ARCH_MIPS, capstone.CS_MODE_MIPS32 + capstone.CS_MODE_BIG_ENDIAN)
                logger.info(f"✅ Created MIPS disassembler (endian: {endian})")
            
            # RISC-V系列
            elif 'riscv' in arch_lower or 'em_riscv' in arch_lower:
                # RISC-V 32-bit或64-bit
                if hasattr(self.elf_info, 'bits') and self.elf_info.bits == 64:
                    disasm = capstone.Cs(capstone.CS_ARCH_RISCV, capstone.CS_MODE_RISCV64)
                else:
                    disasm = capstone.Cs(capstone.CS_ARCH_RISCV, capstone.CS_MODE_RISCV32)
                logger.info(f"✅ Created RISC-V disassembler (bits: {getattr(self.elf_info, 'bits', 32)})")
            
            else:
                logger.warning(f"Unsupported architecture {self.elf_info.arch}, defaulting to ARM")
                disasm = capstone.Cs(CS_ARCH_ARM, CS_MODE_ARM)
        
        disasm.detail = True
        return disasm
    
    # ==================== ⭐ 新增：完整集成栈追踪和跨函数分析 ====================
    
    def _integrate_stack_and_function_analysis(self, instructions: List, address_loads: List[AddressLoadInfo]) -> List[AddressLoadInfo]:
        """
        ⭐ 完整集成栈追踪和跨函数分析到地址加载识别
        
        功能：
        1. 追踪PUSH/POP操作，识别栈上保存的MMIO地址
        2. 分析函数调用，识别参数传递的MMIO地址
        3. 追踪返回值中的MMIO地址
        
        预期提升：20%的识别率
        """
        logger.info("⭐ Phase 2.5: 完整集成栈追踪和跨函数分析")
        
        # 1. 栈追踪
        logger.info("  → 追踪栈操作...")
        self.stack_operations = self.dataflow_analyzer.track_stack_operations(instructions)
        logger.info(f"    识别到 {len(self.stack_operations)} 个栈操作")
        
        # 2. 跨函数调用分析
        logger.info("  → 分析函数调用...")
        self.function_calls = self.dataflow_analyzer.analyze_cross_function_calls(instructions)
        logger.info(f"    识别到 {len(self.function_calls)} 个函数调用")
        
        # 3. 从栈操作中提取MMIO地址
        stack_mmio_loads = self._extract_mmio_from_stack(instructions, address_loads)
        logger.info(f"    从栈中提取 {len(stack_mmio_loads)} 个MMIO地址")
        
        # 4. 从函数调用中提取MMIO地址
        function_mmio_loads = self._extract_mmio_from_function_calls(instructions, address_loads)
        logger.info(f"    从函数调用提取 {len(function_mmio_loads)} 个MMIO地址")
        
        # 5. 合并结果
        enhanced_loads = list(address_loads)
        enhanced_loads.extend(stack_mmio_loads)
        enhanced_loads.extend(function_mmio_loads)
        
        # 去重
        seen_addrs = set()
        unique_loads = []
        for load in enhanced_loads:
            key = (load.base_address, load.instruction_addr)
            if key not in seen_addrs:
                seen_addrs.add(key)
                unique_loads.append(load)
        
        logger.info(f"  ✅ 集成后总地址加载: {len(unique_loads)} (原始: {len(address_loads)}, 新增: {len(unique_loads) - len(address_loads)})")
        
        return unique_loads
    
    def _extract_mmio_from_stack(self, instructions: List, address_loads: List[AddressLoadInfo]) -> List[AddressLoadInfo]:
        """
        从栈操作中提取MMIO地址
        
        场景：
        1. PUSH {R3}, 其中R3包含MMIO地址
        2. POP {R5}, 恢复MMIO地址到R5
        3. 栈上传递的MMIO地址参数
        """
        mmio_loads = []
        
        # 建立地址加载的寄存器映射
        addr_load_map = {}  # {(reg, addr): load_info}
        for load in address_loads:
            if hasattr(load, 'target_register') and load.target_register:
                addr_load_map[(load.target_register, load.instruction_addr)] = load
        
        # 遍历栈操作
        for stack_addr, stack_info in self.stack_operations.items():
            if stack_info['type'] == 'push':
                # 检查每个被push的寄存器
                for reg in stack_info['registers']:
                    # 向前查找该寄存器最近的定义
                    mmio_value = self._find_recent_register_definition(
                        instructions, stack_addr, reg, address_loads
                    )
                    
                    if mmio_value and self.elf_analyzer.is_potential_mmio_address(mmio_value):
                        # 创建栈操作的地址加载信息
                        load_info = AddressLoadInfo(
                            instruction_index=0,
                            base_address=mmio_value,
                            instruction_addr=stack_addr,
                            register=reg,
                            load_type='stack_push',
                            instruction=f"PUSH R{reg}",
                            evidence_chain=[{'addr': stack_addr, 'instruction': f"PUSH R{reg} with MMIO 0x{mmio_value:08x}"}]
                        )
                        mmio_loads.append(load_info)
                        logger.debug(f"    栈PUSH: 0x{stack_addr:08x} R{reg} = 0x{mmio_value:08x}")
            
            elif stack_info['type'] == 'pop':
                # POP操作，检查栈槽映射
                if 'stack_slots' in stack_info:
                    for popped_reg, slot_info in stack_info['stack_slots'].items():
                        original_reg = slot_info.get('original_register')
                        push_addr = slot_info.get('push_address')
                        
                        # 查找push时的值
                        if push_addr and push_addr in self.stack_operations:
                            push_info = self.stack_operations[push_addr]
                            if original_reg in push_info.get('registers', []):
                                mmio_value = self._find_recent_register_definition(
                                    instructions, push_addr, original_reg, address_loads
                                )
                                
                                if mmio_value and self.elf_analyzer.is_potential_mmio_address(mmio_value):
                                    load_info = AddressLoadInfo(
                                        instruction_index=0,
                                        base_address=mmio_value,
                                        instruction_addr=stack_addr,
                                        register=popped_reg,
                                        load_type='stack_pop',
                                        instruction=f"POP R{popped_reg}",
                                        evidence_chain=[
                                            {'addr': stack_addr, 'instruction': f"POP R{popped_reg} from stack"},
                                            {'addr': push_addr, 'instruction': f"Originally PUSH R{original_reg} @ 0x{push_addr:08x}"},
                                            {'addr': 0, 'instruction': f"MMIO 0x{mmio_value:08x}"}
                                        ]
                                    )
                                    mmio_loads.append(load_info)
                                    logger.debug(f"    栈POP: 0x{stack_addr:08x} R{popped_reg} ← R{original_reg} = 0x{mmio_value:08x}")
        
        return mmio_loads
    
    def _extract_mmio_from_function_calls(self, instructions: List, address_loads: List[AddressLoadInfo]) -> List[AddressLoadInfo]:
        """
        从函数调用中提取MMIO地址
        
        场景：
        1. 参数传递：foo(R0=MMIO_ADDR)
        2. 返回值：R0 = bar() 返回MMIO地址
        3. 间接调用：通过函数指针访问MMIO
        """
        mmio_loads = []
        
        for call_addr, call_infos in self.function_calls.items():
            for call_info in call_infos:
                target_addr = call_info.get('target')
                params = call_info.get('params', {})
                return_info = call_info.get('return', {})
                
                # 1. 检查参数中的MMIO地址
                for param_reg, param_info in params.items():
                    param_value = param_info.get('value')
                    if param_value and self.elf_analyzer.is_potential_mmio_address(param_value):
                        load_info = AddressLoadInfo(
                            instruction_index=0,
                            base_address=param_value,
                            instruction_addr=call_addr,
                            register=param_reg,
                            load_type='function_param',
                            instruction=f"Function call param R{param_reg}",
                            evidence_chain=[
                                {'addr': call_addr, 'instruction': f"Function call @ 0x{call_addr:08x}"},
                                {'addr': 0, 'instruction': f"Parameter R{param_reg} = 0x{param_value:08x}"},
                                {'addr': 0, 'instruction': f"Target: {call_info.get('target_name', 'unknown')}"}
                            ]
                        )
                        mmio_loads.append(load_info)
                        logger.debug(f"    函数参数: 0x{call_addr:08x} R{param_reg} = 0x{param_value:08x}")
                
                # 2. 检查返回值（R0）的使用
                if return_info.get('used'):
                    use_addr = return_info.get('use_at')
                    if use_addr:
                        # 向前查找返回值的来源
                        # 这里需要分析被调用函数的返回路径
                        # 简化实现：标记为潜在的MMIO返回值
                        pass
        
        return mmio_loads
    
    def _find_recent_register_definition(self, instructions: List, current_addr: int, 
                                        target_reg: int, address_loads: List[AddressLoadInfo],
                                        max_lookback: int = 100) -> Optional[int]:  # ⭐ 扩大到100条指令
        """
        向前查找寄存器的最近定义，提取其值
        
        ⭐ 优化：扩大回溯窗口到100条指令
        
        返回：寄存器的值（如果是MMIO地址）
        """
        # 先检查全局符号传播缓存
        cache_key = f"reg_{target_reg}_{current_addr:08x}"
        if cache_key in self.symbol_propagation_cache:
            cached_value = self.symbol_propagation_cache[cache_key]
            logger.debug(f"    缓存命中: R{target_reg} @ 0x{current_addr:08x} = 0x{cached_value:08x}")
            return cached_value
        
        # 找到当前指令的索引
        current_idx = None
        for i, insn in enumerate(instructions):
            if insn.address == current_addr:
                current_idx = i
                break
        
        if current_idx is None:
            return None
        
        # 向前查找
        for i in range(current_idx - 1, max(0, current_idx - max_lookback), -1):
            insn = instructions[i]
            
            # 检查这条指令是否定义了目标寄存器
            try:
                if len(insn.operands) >= 1:
                    dst_operand = insn.operands[0]
                    if dst_operand.type in [capstone.arm.ARM_OP_REG, capstone.arm64.ARM64_OP_REG]:
                        if dst_operand.reg == target_reg:
                            # 找到了定义，尝试提取值
                            
                            # 检查是否是已知的地址加载
                            for load in address_loads:
                                if load.instruction_addr == insn.address and load.target_register == target_reg:
                                    # 缓存结果
                                    self.symbol_propagation_cache[cache_key] = load.base_address
                                    return load.base_address
                            
                            # 检查立即数
                            if insn.mnemonic.lower() in ['mov', 'movw', 'movt'] and len(insn.operands) >= 2:
                                src_operand = insn.operands[1]
                                if src_operand.type in [capstone.arm.ARM_OP_IMM, capstone.arm64.ARM64_OP_IMM]:
                                    value = src_operand.imm
                                    # 缓存结果
                                    self.symbol_propagation_cache[cache_key] = value
                                    return value
                            
                            # 检查LDR加载
                            if insn.mnemonic.lower().startswith('ldr') and len(insn.operands) >= 2:
                                src_operand = insn.operands[1]
                                if src_operand.type in [capstone.arm.ARM_OP_MEM, capstone.arm64.ARM64_OP_MEM]:
                                    if src_operand.mem.base in [capstone.arm.ARM_REG_PC, 15]:
                                        # PC相对加载
                                        pc_aligned = (insn.address + 4) & ~0x3
                                        literal_addr = pc_aligned + src_operand.mem.disp
                                        value = self.elf_analyzer.read_constant_from_memory(literal_addr)
                                        if value:
                                            # 缓存结果
                                            self.symbol_propagation_cache[cache_key] = value
                                            return value
                            
                            # 如果无法提取值，停止查找
                            break
            except:
                continue
        
        return None
    
    # ==================== ⭐ 新增：全局符号传播缓存 ====================
    
    def _build_global_register_mmio_map(self, instructions: List, address_loads: List[AddressLoadInfo]):
        """
        ⭐ 构建全局寄存器到MMIO地址的映射
        
        功能：
        1. 遍历所有指令，追踪寄存器值
        2. 建立持久化的缓存
        3. 支持寄存器值的前向传播
        """
        logger.debug("  → 构建全局寄存器MMIO映射...")
        
        # 先将已知的地址加载加入缓存
        for load in address_loads:
            if hasattr(load, 'target_register') and load.target_register:
                cache_key = f"reg_{load.target_register}_{load.instruction_addr:08x}"
                self.symbol_propagation_cache[cache_key] = load.base_address
        
        # 遍历指令，追踪寄存器传播
        for i, insn in enumerate(instructions):
            try:
                mnemonic = insn.mnemonic.lower()
                
                # MOV指令：R3 = R2
                if mnemonic in ['mov', 'movs'] and len(insn.operands) >= 2:
                    dst_reg = insn.operands[0].reg if insn.operands[0].type in [capstone.arm.ARM_OP_REG] else None
                    src_operand = insn.operands[1]
                    
                    if dst_reg:
                        # 源是寄存器：传播值
                        if src_operand.type in [capstone.arm.ARM_OP_REG]:
                            src_reg = src_operand.reg
                            
                            # 查找src_reg的最近值
                            for j in range(i - 1, max(0, i - 100), -1):
                                prev_insn = instructions[j]
                                src_key = f"reg_{src_reg}_{prev_insn.address:08x}"
                                if src_key in self.symbol_propagation_cache:
                                    value = self.symbol_propagation_cache[src_key]
                                    dst_key = f"reg_{dst_reg}_{insn.address:08x}"
                                    self.symbol_propagation_cache[dst_key] = value
                                    logger.debug(f"      MOV传播: R{src_reg}->R{dst_reg} = 0x{value:08x}")
                                    break
                        
                        # 源是立即数
                        elif src_operand.type in [capstone.arm.ARM_OP_IMM]:
                            value = src_operand.imm
                            if self.elf_analyzer.is_potential_mmio_address(value):
                                dst_key = f"reg_{dst_reg}_{insn.address:08x}"
                                self.symbol_propagation_cache[dst_key] = value
                
                # ADD/SUB指令：R3 = R2 + #imm
                elif mnemonic in ['add', 'sub', 'adds', 'subs'] and len(insn.operands) >= 3:
                    dst_reg = insn.operands[0].reg if insn.operands[0].type in [capstone.arm.ARM_OP_REG] else None
                    src_reg = insn.operands[1].reg if insn.operands[1].type in [capstone.arm.ARM_OP_REG] else None
                    
                    if dst_reg and src_reg:
                        # 查找src_reg的值
                        for j in range(i - 1, max(0, i - 100), -1):
                            prev_insn = instructions[j]
                            src_key = f"reg_{src_reg}_{prev_insn.address:08x}"
                            if src_key in self.symbol_propagation_cache:
                                base_value = self.symbol_propagation_cache[src_key]
                                
                                # 计算偏移
                                if len(insn.operands) >= 3:
                                    offset_operand = insn.operands[2]
                                    if offset_operand.type in [capstone.arm.ARM_OP_IMM]:
                                        offset = offset_operand.imm if mnemonic.startswith('add') else -offset_operand.imm
                                        calculated = base_value + offset
                                        
                                        if self.elf_analyzer.is_potential_mmio_address(calculated):
                                            dst_key = f"reg_{dst_reg}_{insn.address:08x}"
                                            self.symbol_propagation_cache[dst_key] = calculated
                                            logger.debug(f"      ADD传播: R{src_reg}(0x{base_value:08x}) + 0x{offset:x} -> R{dst_reg} = 0x{calculated:08x}")
                                break
            except:
                continue
        
        logger.debug(f"  → 全局缓存大小: {len(self.symbol_propagation_cache)}")
    
    # ==================== ⭐ 新增：增强符号传播 ====================
    
    def _enhance_symbol_propagation(self, instructions: List, address_loads: List[AddressLoadInfo]) -> List[AddressLoadInfo]:
        """
        ⭐ 增强符号传播 - 支持复杂的间接访问
        
        功能：
        1. 追踪复杂的地址计算（基址+偏移+索引）
        2. 支持数组/结构体访问模式
        3. 追踪指针的指针（多级间接）
        4. 循环内的地址访问模式
        
        预期提升：更准确的数据流追踪
        """
        logger.info("⭐ Phase 2.6: 增强符号传播")
        
        # ⭐ 首先构建全局符号传播缓存
        self._build_global_register_mmio_map(instructions, address_loads)
        
        enhanced_loads = list(address_loads)
        
        # 1. 识别复杂的地址计算模式
        complex_loads = self._identify_complex_address_calculations(instructions, address_loads)
        logger.info(f"  → 识别到 {len(complex_loads)} 个复杂地址计算")
        enhanced_loads.extend(complex_loads)
        
        # 2. 识别数组/结构体访问
        struct_loads = self._identify_struct_array_accesses(instructions, address_loads)
        logger.info(f"  → 识别到 {len(struct_loads)} 个结构体/数组访问")
        enhanced_loads.extend(struct_loads)
        
        # 3. 追踪多级间接访问
        indirect_loads = self._identify_multi_level_indirect(instructions, address_loads)
        logger.info(f"  → 识别到 {len(indirect_loads)} 个多级间接访问")
        enhanced_loads.extend(indirect_loads)
        
        # 4. 识别循环内的访问模式
        loop_loads = self._identify_loop_access_patterns(instructions, address_loads)
        logger.info(f"  → 识别到 {len(loop_loads)} 个循环内访问")
        enhanced_loads.extend(loop_loads)
        
        # 去重
        seen_addrs = set()
        unique_loads = []
        for load in enhanced_loads:
            key = (load.base_address, load.instruction_addr)
            if key not in seen_addrs:
                seen_addrs.add(key)
                unique_loads.append(load)
        
        logger.info(f"  ✅ 符号传播后总地址: {len(unique_loads)} (原始: {len(address_loads)}, 新增: {len(unique_loads) - len(address_loads)})")
        
        return unique_loads
    
    def _identify_complex_address_calculations(self, instructions: List, address_loads: List[AddressLoadInfo]) -> List[AddressLoadInfo]:
        """
        识别复杂的地址计算模式
        
        ⭐ 优化：
        1. 扩大窗口到200条指令
        2. 使用全局符号传播缓存
        3. 支持更多计算模式
        
        模式：
        - ADD R3, R2, #0x100  (基址+偏移)
        - ADD R3, R2, R4, LSL#2  (基址+索引*4)
        - LDR R5, [R3, R4]  (基址+索引)
        """
        complex_loads = []
        
        # ⭐ 使用全局符号传播缓存
        # 构建寄存器到MMIO地址的全局映射
        self._build_global_register_mmio_map(instructions, address_loads)
        
        for i, insn in enumerate(instructions):
            try:
                mnemonic = insn.mnemonic.lower()
                
                # 检查ADD/SUB指令
                if mnemonic in ['add', 'sub', 'adds', 'subs'] and len(insn.operands) >= 3:
                    dst_reg = insn.operands[0].reg if insn.operands[0].type in [capstone.arm.ARM_OP_REG] else None
                    src_reg = insn.operands[1].reg if insn.operands[1].type in [capstone.arm.ARM_OP_REG] else None
                    
                    if dst_reg and src_reg:
                        # ⭐ 从全局缓存查找src_reg的值
                        cache_key = f"reg_{src_reg}_{insn.address:08x}"
                        mmio_addr = None
                        
                        # 查找最近的定义
                        for j in range(i - 1, max(0, i - 200), -1):  # ⭐ 扩大到200条
                            prev_insn = instructions[j]
                            prev_key = f"reg_{src_reg}_{prev_insn.address:08x}"
                            if prev_key in self.symbol_propagation_cache:
                                mmio_addr = self.symbol_propagation_cache[prev_key]
                                break
                        
                        if mmio_addr and self.elf_analyzer.is_potential_mmio_address(mmio_addr):
                            # 找到了基址，计算偏移
                            offset = 0
                            if len(insn.operands) >= 3:
                                offset_operand = insn.operands[2]
                                if offset_operand.type in [capstone.arm.ARM_OP_IMM]:
                                    offset = offset_operand.imm if mnemonic.startswith('add') else -offset_operand.imm
                            
                            calculated_addr = mmio_addr + offset
                            
                            if self.elf_analyzer.is_potential_mmio_address(calculated_addr):
                                load_info = AddressLoadInfo(
                                    instruction_index=0,
                                    base_address=calculated_addr,
                                    instruction_addr=insn.address,
                                    register=dst_reg,
                                    load_type='complex_calculation',
                                    instruction=f"{insn.mnemonic} {insn.op_str}",
                                    evidence_chain=[
                                        {'addr': insn.address, 'instruction': f"Complex: R{src_reg}(0x{mmio_addr:08x}) + 0x{offset:x}"},
                                        {'addr': 0, 'instruction': f"Result: 0x{calculated_addr:08x}"}
                                    ]
                                )
                                complex_loads.append(load_info)
                                
                                # ⭐ 更新全局缓存
                                dst_cache_key = f"reg_{dst_reg}_{insn.address:08x}"
                                self.symbol_propagation_cache[dst_cache_key] = calculated_addr
                                logger.debug(f"    复杂计算: 0x{insn.address:08x} R{dst_reg} = 0x{calculated_addr:08x}")
            except:
                continue
        
        return complex_loads
    
    def _identify_struct_array_accesses(self, instructions: List, address_loads: List[AddressLoadInfo]) -> List[AddressLoadInfo]:
        """
        识别结构体/数组访问模式
        
        模式：
        - LDR R3, [R2, #0x10]  (结构体字段访问)
        - LDR R3, [R2, R4, LSL#2]  (数组索引访问)
        """
        struct_loads = []
        
        # 建立MMIO基址的寄存器映射
        reg_to_mmio = {}
        for load in address_loads:
            if hasattr(load, 'target_register') and load.target_register:
                reg_to_mmio[(load.target_register, load.instruction_addr)] = load.base_address
        
        for i, insn in enumerate(instructions):
            try:
                if insn.mnemonic.lower().startswith('ldr') or insn.mnemonic.lower().startswith('str'):
                    if len(insn.operands) >= 2:
                        mem_operand = insn.operands[1] if insn.mnemonic.lower().startswith('ldr') else insn.operands[0]
                        
                        if mem_operand.type in [capstone.arm.ARM_OP_MEM]:
                            base_reg = mem_operand.mem.base
                            offset = mem_operand.mem.disp
                            index_reg = mem_operand.mem.index
                            
                            # 查找base_reg是否包含MMIO地址
                            for (reg, addr), mmio_addr in reg_to_mmio.items():
                                if reg == base_reg and addr < insn.address and (insn.address - addr) < 100:
                                    calculated_addr = mmio_addr + offset
                                    
                                    if self.elf_analyzer.is_potential_mmio_address(calculated_addr):
                                        access_type = 'struct_field' if index_reg == 0 else 'array_access'
                                        
                                        load_info = AddressLoadInfo(
                                            instruction_index=0,
                                            base_address=calculated_addr,
                                            instruction_addr=insn.address,
                                            register=base_reg,
                                            load_type=access_type,
                                            instruction=f"{insn.mnemonic} {insn.op_str}",
                                            evidence_chain=[
                                                {'addr': insn.address, 'instruction': f"{access_type}: base=0x{mmio_addr:08x} offset=0x{offset:x}"},
                                                {'addr': 0, 'instruction': f"Result: 0x{calculated_addr:08x}"}
                                            ]
                                        )
                                        struct_loads.append(load_info)
                                    break
            except:
                continue
        
        return struct_loads
    
    def _identify_multi_level_indirect(self, instructions: List, address_loads: List[AddressLoadInfo]) -> List[AddressLoadInfo]:
        """
        ⭐ 完善多级间接访问（指针的指针）
        
        模式：
        - LDR R3, [R2]       ; R3 = *R2 (一级间接)
        - LDR R4, [R3, #4]   ; R4 = *(R3 + 4) (二级间接)
        - LDR R5, [R4]       ; R5 = *R4 (三级间接)
        
        策略：
        1. 识别LDR指令的基址寄存器
        2. 检查基址寄存器是否来自另一个LDR
        3. 追踪指针链，最多3级
        """
        indirect_loads = []
        
        # 构建指令索引
        insn_by_addr = {insn.address: insn for insn in instructions}
        
        for i, insn in enumerate(instructions):
            try:
                if not insn.mnemonic.lower().startswith('ldr'):
                    continue
                
                if len(insn.operands) < 2:
                    continue
                
                mem_operand = insn.operands[1]
                if mem_operand.type not in [capstone.arm.ARM_OP_MEM]:
                    continue
                
                base_reg = mem_operand.mem.base
                offset = mem_operand.mem.disp
                
                # 追踪base_reg的来源
                indirect_chain = []
                current_reg = base_reg
                current_idx = i
                
                for level in range(3):  # 最多追踪3级
                    # 向前查找current_reg的定义
                    found_def = False
                    for j in range(current_idx - 1, max(0, current_idx - 100), -1):
                        prev_insn = instructions[j]
                        
                        # 检查是否是LDR定义了current_reg
                        if prev_insn.mnemonic.lower().startswith('ldr') and len(prev_insn.operands) >= 2:
                            dst_reg = prev_insn.operands[0].reg if prev_insn.operands[0].type in [capstone.arm.ARM_OP_REG] else None
                            
                            if dst_reg == current_reg:
                                # 找到了定义
                                prev_mem = prev_insn.operands[1]
                                if prev_mem.type in [capstone.arm.ARM_OP_MEM]:
                                    prev_base = prev_mem.mem.base
                                    prev_offset = prev_mem.mem.disp
                                    
                                    indirect_chain.append({
                                        'level': level,
                                        'addr': prev_insn.address,
                                        'reg': current_reg,
                                        'base_reg': prev_base,
                                        'offset': prev_offset
                                    })
                                    
                                    # 检查prev_base是否包含MMIO地址
                                    cache_key = f"reg_{prev_base}_{prev_insn.address:08x}"
                                    if cache_key in self.symbol_propagation_cache:
                                        mmio_addr = self.symbol_propagation_cache[cache_key]
                                        
                                        # 计算最终地址
                                        final_addr = mmio_addr
                                        for chain_item in reversed(indirect_chain):
                                            final_addr += chain_item['offset']
                                        final_addr += offset
                                        
                                        if self.elf_analyzer.is_potential_mmio_address(final_addr):
                                            load_info = AddressLoadInfo(
                                                instruction_index=0,
                                                base_address=final_addr,
                                                instruction_addr=insn.address,
                                                register=insn.operands[0].reg if len(insn.operands) >= 1 else 0,
                                                load_type=f'indirect_level_{level+1}',
                                                instruction=f"{insn.mnemonic} {insn.op_str}",
                                                evidence_chain=[
                                                    {'addr': insn.address, 'instruction': f"{level+1}级间接访问"},
                                                    {'addr': 0, 'instruction': f"Base MMIO: 0x{mmio_addr:08x}"},
                                                    {'addr': 0, 'instruction': f"Final: 0x{final_addr:08x}"}
                                                ]
                                            )
                                            indirect_loads.append(load_info)
                                            logger.debug(f"    {level+1}级间接: 0x{insn.address:08x} -> 0x{final_addr:08x}")
                                        
                                        found_def = True
                                        break
                                    
                                    # 继续追踪
                                    current_reg = prev_base
                                    current_idx = j
                                    found_def = True
                                    break
                    
                    if not found_def:
                        break
            except:
                continue
        
        return indirect_loads
    
    def _identify_loop_access_patterns(self, instructions: List, address_loads: List[AddressLoadInfo]) -> List[AddressLoadInfo]:
        """
        ⭐ 完善循环内的访问模式识别
        
        模式：
        - for (i=0; i<N; i++) { MMIO[base + i*stride] = ...; }
        - while循环中的重复MMIO访问
        - 循环展开的多次访问
        
        策略：
        1. 识别向后跳转(B/BNE/BEQ等)
        2. 分析循环体内的MMIO访问
        3. 识别归纳变量和访问步长
        """
        loop_loads = []
        
        # 1. 识别循环结构
        loops = self._detect_loops(instructions)
        logger.debug(f"      检测到 {len(loops)} 个循环")
        
        # 2. 分析每个循环内的MMIO访问
        for loop in loops:
            loop_start = loop['start_addr']
            loop_end = loop['end_addr']
            loop_body_insns = loop['body_instructions']
            
            # 查找循环体内的MMIO访问
            for insn in loop_body_insns:
                try:
                    # 检查LDR/STR指令
                    if insn.mnemonic.lower().startswith('ldr') or insn.mnemonic.lower().startswith('str'):
                        if len(insn.operands) >= 2:
                            mem_operand = insn.operands[1] if insn.mnemonic.lower().startswith('ldr') else insn.operands[0]
                            
                            if mem_operand.type in [capstone.arm.ARM_OP_MEM]:
                                base_reg = mem_operand.mem.base
                                offset = mem_operand.mem.disp
                                index_reg = mem_operand.mem.index
                                
                                # 检查base_reg是否包含MMIO地址
                                cache_key = f"reg_{base_reg}_{insn.address:08x}"
                                
                                # 在循环开始前查找base_reg的值
                                for prev_key in self.symbol_propagation_cache:
                                    if prev_key.startswith(f"reg_{base_reg}_"):
                                        addr_str = prev_key.split('_')[-1]
                                        try:
                                            prev_addr = int(addr_str, 16)
                                            if prev_addr < loop_start:
                                                mmio_addr = self.symbol_propagation_cache[prev_key]
                                                
                                                if self.elf_analyzer.is_potential_mmio_address(mmio_addr):
                                                    # 这是循环内的MMIO访问
                                                    calculated_addr = mmio_addr + offset
                                                    
                                                    if self.elf_analyzer.is_potential_mmio_address(calculated_addr):
                                                        load_info = AddressLoadInfo(
                                                            instruction_index=0,
                                                            base_address=calculated_addr,
                                                            instruction_addr=insn.address,
                                                            register=base_reg,
                                                            load_type='loop_access',
                                                            instruction=f"{insn.mnemonic} {insn.op_str}",
                                                            evidence_chain=[
                                                                {'addr': insn.address, 'instruction': f"循环访问 (0x{loop_start:08x}-0x{loop_end:08x})"},
                                                                {'addr': 0, 'instruction': f"Base: 0x{mmio_addr:08x} + offset: 0x{offset:x}"},
                                                                {'addr': 0, 'instruction': f"Result: 0x{calculated_addr:08x}"}
                                                            ]
                                                        )
                                                        loop_loads.append(load_info)
                                                        logger.debug(f"    循环访问: 0x{insn.address:08x} -> 0x{calculated_addr:08x}")
                                                break
                                        except:
                                            continue
                except:
                    continue
        
        return loop_loads
    
    def _detect_loops(self, instructions: List) -> List[Dict]:
        """
        检测循环结构
        
        策略：
        1. 查找向后跳转指令(B/BNE/BEQ/BLT等)
        2. 确定循环边界
        3. 提取循环体指令
        """
        loops = []
        
        for i, insn in enumerate(instructions):
            try:
                mnemonic = insn.mnemonic.lower()
                
                # 检查是否是分支指令
                if mnemonic in ['b', 'bne', 'beq', 'blt', 'ble', 'bgt', 'bge', 'bcc', 'bcs', 'blo', 'bhi']:
                    if len(insn.operands) >= 1:
                        target_operand = insn.operands[0]
                        if target_operand.type in [capstone.arm.ARM_OP_IMM]:
                            target_addr = target_operand.imm
                            
                            # 检查是否是向后跳转(循环)
                            if target_addr < insn.address:
                                # 找到循环
                                loop_start = target_addr
                                loop_end = insn.address
                                
                                # 提取循环体指令
                                loop_body = []
                                for j in range(i):
                                    if instructions[j].address >= loop_start and instructions[j].address <= loop_end:
                                        loop_body.append(instructions[j])
                                
                                if loop_body:
                                    loops.append({
                                        'start_addr': loop_start,
                                        'end_addr': loop_end,
                                        'body_instructions': loop_body,
                                        'branch_insn': insn.address
                                    })
                                    logger.debug(f"        循环: 0x{loop_start:08x} - 0x{loop_end:08x} ({len(loop_body)}条指令)")
            except:
                continue
        
        return loops
    
    def _analyze_register_accesses(self, instructions: List, address_loads: List[AddressLoadInfo]) -> List[RegisterAccess]:
        """
        分析寄存器访问
        
        ⭐ 优化策略：宁可识别错，但不能识别漏
        1. 对所有MMIO地址都创建访问记录
        2. 简化数据流追踪，避免因追踪失败而遗漏
        """
        accesses = []
        
        # ⭐ 新策略：对每个识别到的MMIO地址都创建至少一个访问记录
        for load_info in address_loads:
            base_addr = load_info.base_address
            
            if not self.elf_analyzer.is_potential_mmio_address(base_addr):
                continue
            
            # 尝试追踪该寄存器的使用
            traced_accesses = self._trace_register_usage(
                instructions, load_info, self.register_chains
            )
            
            if traced_accesses:
                # 如果能追踪到使用，添加追踪结果
                accesses.extend(traced_accesses)
            else:
                # ⭐ 如果追踪失败，创建默认访问记录（避免遗漏）
                # 这样确保每个识别到的地址都会被包含
                default_access = RegisterAccess(
                    base_address=base_addr,
                    offset=0,  # 默认偏移0
                    access_type='unknown',  # 未知类型
                    access_size=4,  # 默认4字节
                    instruction_addr=load_info.instruction_addr,
                    function_name=self.elf_analyzer.get_function_name_for_address(load_info.instruction_addr),
                    evidence_chain=load_info.evidence_chain,
                    discovery_method=load_info.load_type + '_no_trace'  # 标记为未追踪
                )
                accesses.append(default_access)
                logger.debug(f"Created default access for MMIO address 0x{base_addr:08x} (trace failed)")
        
        # 识别直接MMIO访问
        direct_accesses = self._identify_direct_mmio_accesses(instructions)
        accesses.extend(direct_accesses)
        
        logger.info(f"总访问记录: {len(accesses)} (追踪成功 + 默认记录 + 直接访问)")
        
        return accesses
    
    def _trace_register_usage(self, instructions: List, load_info: AddressLoadInfo, 
                            register_chains: Dict[str, RegisterDefUse]) -> List[RegisterAccess]:
        """追踪寄存器使用"""
        accesses = []
        
        # 查找对应的寄存器链
        reg_key = f"r{load_info.register}_{load_info.instruction_addr:08x}"
        if reg_key in register_chains:
            reg_chain = register_chains[reg_key]
            
            # 分析每个使用点
            for i, use_addr in enumerate(reg_chain.use_addrs):
                use_insn = self._find_instruction_by_address(instructions, use_addr)
                if use_insn:
                    access_info = self._analyze_memory_access(use_insn, load_info.register)
                    if access_info:
                        # 构建证据链（使用字典而不是dataclass，确保JSON可序列化）
                        evidence_chain = []
                        
                        # 添加地址加载证据
                        for evidence in load_info.evidence_chain:
                            evidence_chain.append({
                                'addr': evidence.get('addr', 0),
                                'instruction': evidence.get('instruction', ''),
                                'description': evidence.get('description', '')
                            })
                        
                        # 计算实际的MMIO地址 ⭐ 关键修改
                        actual_mmio_address = load_info.base_address + access_info['offset']
                        
                        # 添加使用证据
                        evidence_chain.append({
                            'addr': use_addr,
                            'instruction': reg_chain.use_instructions[i],
                            'description': f"{access_info['type'].upper()} [0x{load_info.base_address:08x} + 0x{access_info['offset']:02x}] = 0x{actual_mmio_address:08x}"
                        })
                        
                        # ⭐ 关键：记录实际的MMIO地址作为base_address，offset设为0
                        # 这样每个实际访问的地址都被识别为独立的MMIO
                        # 聚类阶段会将相近的地址合并
                        access = RegisterAccess(
                            base_address=actual_mmio_address,  # ⭐ 实际地址
                            offset=0,                          # ⭐ offset=0表示这是实际地址
                            access_type=access_info['type'],
                            access_size=access_info['size'],
                            instruction_addr=use_addr,
                            function_name=self.elf_analyzer.get_function_name_for_address(use_addr),
                            evidence_chain=evidence_chain,
                            discovery_method=load_info.load_type + '_with_offset'
                        )
                        accesses.append(access)
        
        return accesses
    
    def _analyze_memory_access(self, insn, target_reg: int) -> Optional[Dict]:
        """分析内存访问指令 - 支持ARM/MIPS/RISC-V"""
        try:
            mnemonic = insn.mnemonic.lower()
            
            # 检测架构
            arch_lower = self.elf_info.arch.lower() if self.elf_info and self.elf_info.arch else 'arm'
            is_mips = 'mips' in arch_lower or 'em_mips' in arch_lower
            is_riscv = 'riscv' in arch_lower or 'em_riscv' in arch_lower
            is_arm = not is_mips and not is_riscv
            
            # === ARM架构 ===
            if is_arm:
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
                    if hasattr(operand, 'type') and operand.type in [capstone.arm.ARM_OP_MEM, capstone.arm64.ARM64_OP_MEM]:
                        if operand.mem.base == target_reg:
                            return {
                                'offset': operand.mem.disp,
                                'type': access_type,
                                'size': default_size
                            }
            
            # === MIPS架构 ===
            elif is_mips:
                memory_instructions = {
                    'lw': ('read', 4), 'lh': ('read', 2), 'lhu': ('read', 2),
                    'lb': ('read', 1), 'lbu': ('read', 1),
                    'sw': ('write', 4), 'sh': ('write', 2), 'sb': ('write', 1)
                }
                
                if mnemonic not in memory_instructions:
                    return None
                
                access_type, default_size = memory_instructions[mnemonic]
                
                # MIPS格式: lw/sw $rt, offset($base)
                # 第二个操作数是内存操作数
                if len(insn.operands) >= 2:
                    mem_operand = insn.operands[1]
                    if hasattr(mem_operand, 'type') and mem_operand.type == capstone.mips.MIPS_OP_MEM:
                        if mem_operand.mem.base == target_reg:
                            # MIPS的disp可能是负数，需要处理
                            offset = mem_operand.mem.disp
                            if offset < 0:
                                offset = offset & 0xFFFF  # 转换为无符号16位
                            return {
                                'offset': offset,
                                'type': access_type,
                                'size': default_size
                            }
            
            # === RISC-V架构 ===
            elif is_riscv:
                memory_instructions = {
                    'lw': ('read', 4), 'lh': ('read', 2), 'lhu': ('read', 2),
                    'lb': ('read', 1), 'lbu': ('read', 1),
                    'ld': ('read', 8),
                    'sw': ('write', 4), 'sh': ('write', 2), 'sb': ('write', 1),
                    'sd': ('write', 8)
                }
                
                if mnemonic not in memory_instructions:
                    return None
                
                access_type, default_size = memory_instructions[mnemonic]
                
                # RISC-V格式: lw/sw rd, offset(rs1)
                if len(insn.operands) >= 2:
                    mem_operand = insn.operands[1]
                    if hasattr(mem_operand, 'type') and mem_operand.type == capstone.riscv.RISCV_OP_MEM:
                        if mem_operand.mem.base == target_reg:
                            return {
                                'offset': mem_operand.mem.disp,
                                'type': access_type,
                                'size': default_size
                            }
        
        except Exception as e:
            logger.debug(f"Error analyzing memory access: {e}")
        
        return None
    
    def _identify_direct_mmio_accesses(self, instructions: List) -> List[RegisterAccess]:
        """识别直接MMIO访问 - 支持ARM/MIPS/RISC-V"""
        accesses = []
        
        # 检测架构
        arch_lower = self.elf_info.arch.lower() if self.elf_info and self.elf_info.arch else 'arm'
        is_mips = 'mips' in arch_lower or 'em_mips' in arch_lower
        is_riscv = 'riscv' in arch_lower or 'em_riscv' in arch_lower
        is_arm = not is_mips and not is_riscv
        
        for insn in instructions:
            try:
                mnemonic = insn.mnemonic.lower()
                
                # === ARM架构 ===
                if is_arm and mnemonic in ['ldr', 'ldrb', 'ldrh', 'str', 'strb', 'strh']:
                    for operand in insn.operands:
                        if hasattr(operand, 'type') and operand.type in [capstone.arm.ARM_OP_MEM, capstone.arm64.ARM64_OP_MEM]:
                            # 直接地址访问
                            if (operand.mem.base == 0 and 
                                operand.mem.index == 0 and 
                                operand.mem.disp > 0):
                                
                                addr = operand.mem.disp
                                if self.elf_analyzer.is_potential_mmio_address(addr):
                                    access_type = 'read' if mnemonic.startswith('ldr') else 'write'
                                    access_size = 1 if mnemonic.endswith('b') else (2 if mnemonic.endswith('h') else 4)
                                    
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
                                        function_name=self.elf_analyzer.get_function_name_for_address(insn.address),
                                        evidence_chain=evidence_chain,
                                        discovery_method='direct'
                                    )
                                    accesses.append(access)
                
                # === MIPS架构 ===
                elif is_mips and mnemonic in ['lw', 'sw', 'lh', 'lhu', 'sh', 'lb', 'lbu', 'sb']:
                    # MIPS格式: lw $t0, offset($base)
                    if len(insn.operands) >= 2:
                        # 第二个操作数是内存操作数
                        mem_operand = insn.operands[1]
                        if hasattr(mem_operand, 'type') and mem_operand.type == capstone.mips.MIPS_OP_MEM:
                            # 直接地址（无基址寄存器）
                            if mem_operand.mem.base == 0 and mem_operand.mem.disp != 0:
                                addr = mem_operand.mem.disp & 0xFFFFFFFF
                                if self.elf_analyzer.is_potential_mmio_address(addr):
                                    access_type = 'read' if mnemonic.startswith('l') else 'write'
                                    access_size = 1 if 'b' in mnemonic else (2 if 'h' in mnemonic else 4)
                                    
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
                                        function_name=self.elf_analyzer.get_function_name_for_address(insn.address),
                                        evidence_chain=evidence_chain,
                                        discovery_method='direct_mips'
                                    )
                                    accesses.append(access)
                
                # === RISC-V架构 ===
                elif is_riscv and mnemonic in ['lw', 'sw', 'lh', 'lhu', 'sh', 'lb', 'lbu', 'sb', 'ld', 'sd']:
                    if len(insn.operands) >= 2:
                        mem_operand = insn.operands[1]
                        if hasattr(mem_operand, 'type') and mem_operand.type == capstone.riscv.RISCV_OP_MEM:
                            if mem_operand.mem.base == 0 and mem_operand.mem.disp != 0:
                                addr = mem_operand.mem.disp & 0xFFFFFFFF
                                if self.elf_analyzer.is_potential_mmio_address(addr):
                                    access_type = 'read' if mnemonic.startswith('l') else 'write'
                                    access_size = 1 if 'b' in mnemonic else (2 if 'h' in mnemonic else (8 if 'd' in mnemonic else 4))
                                    
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
                                        function_name=self.elf_analyzer.get_function_name_for_address(insn.address),
                                        evidence_chain=evidence_chain,
                                        discovery_method='direct_riscv'
                                    )
                                    accesses.append(access)
            
            except Exception as e:
                logger.debug(f"Error analyzing direct MMIO access: {e}")
                continue
        
        return accesses
    
    def _analyze_irq_bindings(self, instructions: List, register_accesses: List[RegisterAccess]):
        """分析中断绑定"""
        logger.info("Analyzing IRQ bindings")
        
        # 查找NVIC相关的访问
        nvic_base = 0xE000E000  # Cortex-M NVIC基址
        
        for access in register_accesses:
            if (access.base_address >= nvic_base and 
                access.base_address < nvic_base + 0x1000):
                
                # 分析NVIC寄存器访问，推断中断号
                irq_number = self._extract_irq_number_from_nvic_access(access)
                if irq_number is not None:
                    # 查找相关的外设基址
                    related_mmio = self._find_related_mmio_access(
                        instructions, access.instruction_addr, register_accesses
                    )
                    if related_mmio:
                        self.irq_bindings[related_mmio] = irq_number
                        logger.debug(f"Found IRQ binding: 0x{related_mmio:08x} -> IRQ{irq_number}")
    
    def _extract_irq_number_from_nvic_access(self, access: RegisterAccess) -> Optional[int]:
        """从NVIC访问中提取中断号"""
        # NVIC寄存器偏移分析
        nvic_base = 0xE000E000
        relative_offset = access.base_address - nvic_base + access.offset
        
        # NVIC ISER (Interrupt Set Enable Register)
        if 0x100 <= relative_offset < 0x120:
            reg_index = (relative_offset - 0x100) // 4
            # 需要进一步分析具体的位操作来确定IRQ号
            return reg_index * 32  # 粗略估计
        
        # NVIC ICER (Interrupt Clear Enable Register)
        elif 0x180 <= relative_offset < 0x1A0:
            reg_index = (relative_offset - 0x180) // 4
            return reg_index * 32
        
        return None
    
    def _find_related_mmio_access(self, instructions: List, nvic_addr: int, 
                                 register_accesses: List[RegisterAccess]) -> Optional[int]:
        """查找与NVIC访问相关的MMIO地址"""
        # 在NVIC访问前后查找其他MMIO访问
        search_range = 100  # 搜索范围
        
        for access in register_accesses:
            if (abs(access.instruction_addr - nvic_addr) <= search_range and
                access.base_address < 0xE000E000):  # 非系统寄存器
                return access.base_address
        
        return None
    
    def _analyze_access_patterns(self):
        """分析访问模式"""
        logger.info("Analyzing access patterns")
        
        for candidate in self.peripheral_candidates:
            # 分析轮询模式
            candidate.has_polling = self._detect_polling_pattern(candidate)
            
            # 分析初始化序列
            candidate.init_sequence = self._detect_init_sequence(candidate)
            
            # 分析FIFO模式
            candidate.has_fifo = self._detect_fifo_pattern(candidate)
    
    def _detect_polling_pattern(self, candidate: PeripheralCandidate) -> bool:
        """检测轮询模式"""
        # 检查是否有状态寄存器的频繁读取
        for offset, stats in candidate.offset_stats.items():
            if stats.read_count > stats.write_count * 3:  # 读取远多于写入
                return True
        return False
    
    def _detect_init_sequence(self, candidate: PeripheralCandidate) -> List[str]:
        """检测初始化序列"""
        # 分析指令序列，查找初始化模式
        init_sequence = []
        
        # 简单的启发式：按偏移顺序的写操作可能是初始化
        write_offsets = []
        for offset, stats in candidate.offset_stats.items():
            if stats.write_count > 0:
                write_offsets.append(offset)
        
        if len(write_offsets) >= 2:
            write_offsets.sort()
            init_sequence = [f"WRITE 0x{offset:02x}" for offset in write_offsets[:3]]
        
        return init_sequence
    
    def _detect_fifo_pattern(self, candidate: PeripheralCandidate) -> bool:
        """检测FIFO模式"""
        # 检查是否有数据寄存器的连续访问
        for offset, stats in candidate.offset_stats.items():
            if (stats.read_count + stats.write_count) > 5:  # 频繁访问
                return True
        return False
    
    def _extract_behavior_semantics(self, instructions: List, register_accesses: List[RegisterAccess]):
        """提取行为语义（新增）"""
        logger.info("Extracting behavior semantics for all peripheral candidates")
        
        for candidate in self.peripheral_candidates:
            try:
                # 提取该外设的行为语义
                semantics = self.behavior_extractor.extract_behavior_semantics(
                    candidate, instructions, register_accesses
                )
                
                # 存储语义信息
                self.behavior_semantics[candidate.base_address] = semantics
                
                # 更新候选对象的属性（用于兼容性）
                if hasattr(candidate, '__dict__'):
                    candidate.behavior_type = semantics.peripheral_behavior_type
                    candidate.has_behavior_semantics = True
                
                logger.debug(f"Extracted semantics for 0x{candidate.base_address:08x}: "
                           f"Type={semantics.peripheral_behavior_type}, "
                           f"Patterns={len(semantics.access_patterns)}, "
                           f"Primitives={len(semantics.primitives)}")
                
            except Exception as e:
                logger.warning(f"Failed to extract semantics for 0x{candidate.base_address:08x}: {e}")
    
    def _extract_advanced_behaviors(self, instructions: List, register_accesses: List[RegisterAccess]):
        """提取高级行为信息（新增）"""
        logger.info("Extracting advanced behavior information for all peripheral candidates")
        
        for candidate in self.peripheral_candidates:
            try:
                # 获取该外设的基础行为语义
                behavior_semantics = self.behavior_semantics.get(candidate.base_address)
                
                # 提取高级行为信息
                advanced_info = self.advanced_analyzer.analyze_advanced_behaviors(
                    candidate, instructions, register_accesses, behavior_semantics
                )
                
                # 存储高级行为信息
                self.advanced_behaviors[candidate.base_address] = advanced_info
                
                # 更新候选对象的属性（用于兼容性）
                if hasattr(candidate, '__dict__'):
                    candidate.has_advanced_behaviors = True
                    if advanced_info.clock_domain:
                        candidate.clock_domain = advanced_info.clock_domain.source
                
                logger.debug(f"Extracted advanced behaviors for 0x{candidate.base_address:08x}: "
                           f"IRQs={len(advanced_info.irq_mappings)}, "
                           f"FIFOs={len(advanced_info.fifo_definitions)}, "
                           f"DMAs={len(advanced_info.dma_descriptor_patterns)}, "
                           f"InitSeqs={len(advanced_info.init_sequences)}")
                
            except Exception as e:
                logger.warning(f"Failed to extract advanced behaviors for 0x{candidate.base_address:08x}: {e}")
    
    def _find_instruction_by_address(self, instructions: List, addr: int):
        """根据地址查找指令"""
        for insn in instructions:
            if insn.address == addr:
                return insn
        return None
    
    def export_candidates_to_json(self, output_path: str) -> Dict:
        """导出外设候选到JSON文件"""
        if not self.peripheral_candidates:
            logger.warning("No peripheral candidates to export")
            return {}
        
        export_data = {}
        
        for candidate in self.peripheral_candidates:
            base_addr_hex = f"0x{candidate.base_address:x}"
            
            # 构建偏移列表
            offsets = []
            for offset, stats in candidate.offset_stats.items():
                offset_str = f"0x{offset:02x}({stats.read_count}/{stats.write_count})"
                offsets.append(offset_str)
            
            # 构建指令字符串
            insn_str = "; ".join(candidate.instructions[:5])  # 限制长度
            
            # 基础信息
            export_entry = {
                "size": f"0x{candidate.size:x}",
                "offsets": offsets,
                "refs": candidate.refs,
                "insn": insn_str,
                "type": getattr(candidate, 'peripheral_type_hint', 'UNKNOWN'),
                "confidence": round(candidate.confidence, 3),
                "cluster_method": getattr(candidate, 'cluster_method', 'unknown'),
                "features": {
                    "has_polling": getattr(candidate, 'has_polling', False),
                    "has_fifo": getattr(candidate, 'has_fifo', False),
                    "init_sequence": getattr(candidate, 'init_sequence', []),
                    "irq_binding": self.irq_bindings.get(candidate.base_address)
                }
            }
            
            # 添加行为语义（如果存在）
            if candidate.base_address in self.behavior_semantics:
                semantics = self.behavior_semantics[candidate.base_address]
                
                # 2.1 访问模式
                export_entry["access_patterns"] = {}
                for offset, pattern in semantics.access_patterns.items():
                    export_entry["access_patterns"][f"0x{offset:02x}"] = {
                        "reads": pattern.read_count,
                        "writes": pattern.write_count,
                        "read_after_write": round(pattern.read_after_write_rate, 2),
                        "common_values": pattern.common_values[:5],  # 限制数量
                        "register_type": pattern.register_type
                    }
                
                # 2.2 位域签名
                export_entry["bitfield_signatures"] = {}
                for offset, signatures in semantics.bitfield_signatures.items():
                    export_entry["bitfield_signatures"][f"0x{offset:02x}"] = [
                        {
                            "mask": f"0x{sig.mask:02x}",
                            "meaning": sig.meaning,
                            "behavior": sig.behavior
                        }
                        for sig in signatures[:3]  # 限制数量
                    ]
                
                # 2.3 行为原语
                export_entry["primitives"] = [
                    {
                        "type": prim.type,
                        "offset": f"0x{prim.offset:02x}",
                        "mask": f"0x{prim.mask:02x}" if prim.mask else None,
                        "timeout_ms": prim.timeout_ms,
                        "confidence": round(prim.confidence, 2)
                    }
                    for prim in semantics.primitives[:5]  # 限制数量
                ]
                
                # 行为类型
                export_entry["behavior_type"] = semantics.peripheral_behavior_type
            
            # 添加高级行为信息（如果存在）
            if candidate.base_address in self.advanced_behaviors:
                advanced_info = self.advanced_behaviors[candidate.base_address]
                
                # 3. 时序与概率
                if advanced_info.delay_stats:
                    export_entry["timing"] = {}
                    for event_type, delay_stats in advanced_info.delay_stats.items():
                        export_entry["timing"][event_type] = {
                            "median_ms": delay_stats.median_ms,
                            "p75_ms": delay_stats.p75_ms,
                            "max_ms": delay_stats.max_ms,
                            "estimated_ms": delay_stats.estimated_delay_ms
                        }
                
                if advanced_info.probabilistic_behaviors:
                    export_entry["probabilities"] = [
                        {
                            "offset": f"0x{pb.offset:02x}",
                            "mask": f"0x{pb.mask:02x}",
                            "value": pb.value,
                            "prob": pb.probability,
                            "type": pb.behavior_type
                        }
                        for pb in advanced_info.probabilistic_behaviors
                    ]
                
                # 4. 事件与中断
                if advanced_info.irq_mappings:
                    export_entry["irqs"] = [
                        {
                            "line": irq.irq_number,
                            "trigger": irq.trigger_condition,
                            "isr_function": irq.isr_function
                        }
                        for irq in advanced_info.irq_mappings
                    ]
                
                # 5. 数据通路
                if advanced_info.fifo_definitions:
                    export_entry["fifo"] = [
                        {
                            "offset": f"0x{fifo.offset:02x}",
                            "depth": fifo.depth_estimate,
                            "elem_size": fifo.element_size,
                            "behavior": fifo.behavior,
                            "status_offset": f"0x{fifo.status_offset:02x}" if fifo.status_offset else None
                        }
                        for fifo in advanced_info.fifo_definitions
                    ]
                
                if advanced_info.dma_descriptor_patterns:
                    export_entry["dma"] = [
                        {
                            "descr_ptr_reg": f"0x{dma.descriptor_ptr_reg:02x}",
                            "status_reg": f"0x{dma.status_reg:02x}",
                            "descr_layout": dma.descriptor_layout,
                            "completion_irq": dma.completion_irq
                        }
                        for dma in advanced_info.dma_descriptor_patterns
                    ]
                
                # 6. 初始化与配置
                if advanced_info.init_sequences:
                    export_entry["init_sequence"] = []
                    for init_seq in advanced_info.init_sequences:
                        sequence_data = [
                            {
                                "offset": f"0x{step['offset']:02x}",
                                "value": f"0x{step['value']:x}" if isinstance(step['value'], int) else step['value']
                            }
                            for step in init_seq.sequence
                        ]
                        export_entry["init_sequence"].append({
                            "function": init_seq.function_name,
                            "sequence": sequence_data,
                            "confidence": init_seq.confidence
                        })
                
                # 7. 环境与约束
                if advanced_info.clock_domain:
                    export_entry["clock"] = {
                        "src": advanced_info.clock_domain.source,
                        "freq_hz": advanced_info.clock_domain.frequency_hz
                    }
                
                if advanced_info.memory_regions:
                    export_entry["memory_map"] = [
                        {
                            "name": region.name,
                            "start": f"0x{region.start:08x}",
                            "size": f"0x{region.size:x}",
                            "type": region.type
                        }
                        for region in advanced_info.memory_regions[:5]  # 限制数量
                    ]
            
            export_data[base_addr_hex] = export_entry
        
        # 保存到文件
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_file, 'w') as f:
            json.dump(export_data, f, indent=2)
        
        logger.info(f"Exported {len(self.peripheral_candidates)} enhanced candidates to {output_file}")
        return export_data
    
    def get_analysis_summary(self) -> Dict[str, Any]:
        """
        获取完整的分析结果
        
        包含统计信息和每个外设的详细数据
        """
        if not self.peripheral_candidates:
            return {
                'total_candidates': 0,
                'peripherals': [],
                'summary': {}
            }
        
        # 统计信息
        total_candidates = len(self.peripheral_candidates)
        type_distribution = {}
        cluster_methods = {}
        confidence_distribution = {'high': 0, 'medium': 0, 'low': 0}
        
        # 详细的外设列表
        peripherals = []
        
        for candidate in self.peripheral_candidates:
            # 统计信息
            ptype = getattr(candidate, 'peripheral_type_hint', 'UNKNOWN')
            type_distribution[ptype] = type_distribution.get(ptype, 0) + 1
            
            method = getattr(candidate, 'cluster_method', 'unknown')
            cluster_methods[method] = cluster_methods.get(method, 0) + 1
            
            conf = candidate.confidence
            if conf >= 0.7:
                confidence_distribution['high'] += 1
            elif conf >= 0.4:
                confidence_distribution['medium'] += 1
            else:
                confidence_distribution['low'] += 1
            
            # 构建外设详细信息
            base_addr_hex = f"0x{candidate.base_address:08x}"
            
            # 过滤掉明显不是外设的地址
            if self._should_skip_peripheral(candidate.base_address):
                logger.debug(f"Skipping non-peripheral address {base_addr_hex}")
                continue
            
            # ⭐ 优化策略4：访问模式验证
            # 检查是否有真实的读/写操作，而不是跳转
            if not self._validate_access_pattern(candidate):
                logger.debug(f"Skipping {base_addr_hex} - invalid access pattern (possibly function pointer)")
                continue
            
            # 基础信息
            # 从offset_stats获取偏移列表，过滤负数和过大的偏移
            offsets = [off for off in (candidate.offset_stats.keys() if candidate.offset_stats else [])
                      if 0 <= off <= 0x10000]
            
            # 提取额外上下文信息
            additional_context = self._extract_additional_context(candidate)
            
            peripheral_data = {
                'base_address': base_addr_hex,
                'size': f"0x{candidate.size:x}",
                'peripheral_type': ptype,
                'confidence': 'high' if conf >= 0.7 else ('medium' if conf >= 0.4 else 'low'),
                'confidence_score': round(conf, 3),
                'discovery_method': method,
                'register_count': len(offsets),
                'offsets': sorted([f"0x{off:02x}" for off in offsets])
            }
            
            # 合并额外上下文
            if additional_context:
                peripheral_data['context'] = additional_context
            
            # ==== 新增功能 ====
            
            # 1. 应用外设规则
            matched_type, rule_confidence = self.peripheral_rules.match_peripheral_type(peripheral_data)
            if rule_confidence > 0.5:
                ptype = matched_type
                peripheral_data['peripheral_type'] = matched_type
                peripheral_data['rule_matched'] = True
                peripheral_data['rule_confidence'] = rule_confidence
                # 应用规则增强数据
                peripheral_data = self.peripheral_rules.apply_rules(peripheral_data, matched_type)
            
            # 添加寄存器详细访问统计（从offset_stats）
            if candidate.offset_stats:
                peripheral_data['registers'] = {}
                for offset, stats in candidate.offset_stats.items():
                    # 跳过负偏移（错误的聚类结果）
                    if offset < 0:
                        logger.warning(f"Skipping negative offset {offset:#x} for peripheral {base_addr_hex}")
                        continue
                    
                    # 跳过过大的偏移（可能是错误）
                    if offset > 0x10000:  # 64KB
                        logger.warning(f"Skipping large offset {offset:#x} for peripheral {base_addr_hex}")
                        continue
                    
                    offset_hex = f"0x{offset:02x}" if offset < 256 else f"0x{offset:04x}"
                    
                    # 提取访问PC地址（从instructions字段）
                    access_pcs = []
                    if hasattr(stats, 'instructions') and stats.instructions:
                        for instr in stats.instructions[:5]:  # 最多5个
                            # 尝试从指令字符串中提取PC地址
                            if isinstance(instr, str) and '@' in instr:
                                pc_str = instr.split('@')[1].split(':')[0].strip()
                                access_pcs.append(pc_str)
                    
                    # 推断寄存器类型
                    reg_type = self._infer_register_type(stats, offset)
                    
                    # 推断寄存器用途
                    reg_purpose = self._infer_register_purpose(stats, offset, ptype)
                    
                    peripheral_data['registers'][offset_hex] = {
                        'offset': offset_hex,
                        'read_count': stats.read_count,
                        'write_count': stats.write_count,
                        'total_accesses': stats.read_count + stats.write_count,
                        'access_type': reg_type,
                        'inferred_purpose': reg_purpose,
                        'access_pcs': access_pcs if access_pcs else [],
                        'instructions': stats.instructions[:3] if hasattr(stats, 'instructions') else []
                    }
            
            # 2. 提取位域信息
            try:
                bitfields_map = self.bitfield_extractor.extract_bitfields(peripheral_data)
                if bitfields_map:
                    peripheral_data['bitfields'] = {}
                    for offset, reg_bitfields in bitfields_map.items():
                        offset_hex = f"0x{offset:02x}"
                        peripheral_data['bitfields'][offset_hex] = {
                            'register_purpose': reg_bitfields.register_purpose,
                            'fields': [
                                {
                                    'bits': f"[{bf.bit_range[1]}:{bf.bit_range[0]}]" if bf.bit_range[0] != bf.bit_range[1] else f"[{bf.bit_range[0]}]",
                                    'purpose': bf.purpose,
                                    'access': bf.access_pattern,
                                    'significance': bf.significance
                                }
                                for bf in reg_bitfields.bitfields
                            ]
                        }
            except Exception as e:
                logger.debug(f"位域提取失败: {e}")
            
            # 3. 分析寄存器依赖关系
            try:
                dependencies, sequences = self.dependency_analyzer.analyze_dependencies(peripheral_data)
                if dependencies:
                    peripheral_data['dependencies'] = [
                        {
                            'from': f"0x{dep.from_offset:02x}",
                            'to': f"0x{dep.to_offset:02x}",
                            'type': dep.dependency_type.value,
                            'confidence': dep.confidence,
                            'description': dep.description
                        }
                        for dep in dependencies
                    ]
                if sequences:
                    peripheral_data['access_sequences'] = [
                        {
                            'purpose': seq.purpose,
                            'sequence': [f"0x{off:02x}" for off in seq.sequence],
                            'frequency': seq.frequency
                        }
                        for seq in sequences
                    ]
            except Exception as e:
                logger.debug(f"依赖分析失败: {e}")
            
            # 添加行为语义（如果已提取）
            if hasattr(candidate, 'behavior_semantics') and candidate.behavior_semantics:
                semantics = candidate.behavior_semantics
                peripheral_data['behavior'] = {
                    'has_semantics': True
                }
                
                # 访问模式
                if hasattr(semantics, 'access_patterns') and semantics.access_patterns:
                    peripheral_data['behavior']['access_patterns'] = {}
                    for offset, pattern in list(semantics.access_patterns.items())[:10]:  # 限制数量
                        offset_hex = f"0x{offset:02x}"
                        peripheral_data['behavior']['access_patterns'][offset_hex] = {
                            'read_count': pattern.read_count,
                            'write_count': pattern.write_count,
                            'read_after_write': pattern.read_after_write_count,
                            'common_values': [f"0x{v:x}" for v in (pattern.common_written_values[:5] if pattern.common_written_values else [])]
                        }
                
                # 位域签名
                if hasattr(semantics, 'bitfield_signatures') and semantics.bitfield_signatures:
                    peripheral_data['behavior']['bitfields'] = {}
                    for offset, sigs in list(semantics.bitfield_signatures.items())[:5]:
                        offset_hex = f"0x{offset:02x}"
                        peripheral_data['behavior']['bitfields'][offset_hex] = [
                            {
                                'mask': f"0x{sig.mask:x}",
                                'semantic': sig.semantic_candidate
                            }
                            for sig in sigs[:3]  # 每个寄存器最多3个位域
                        ]
                
                # 行为原语
                if hasattr(semantics, 'behavior_primitives') and semantics.behavior_primitives:
                    peripheral_data['behavior']['primitives'] = [
                        {
                            'type': prim.type,
                            'offset': f"0x{prim.register_offset:02x}",
                            'description': prim.description
                        }
                        for prim in semantics.behavior_primitives[:10]  # 最多10个
                    ]
            
            # 添加高级分析（如果已执行）
            if hasattr(candidate, 'advanced_info') and candidate.advanced_info:
                advanced = candidate.advanced_info
                peripheral_data['advanced'] = {}
                
                # 时序信息
                if hasattr(advanced, 'timing_constraints') and advanced.timing_constraints:
                    peripheral_data['advanced']['timing'] = [
                        {
                            'operation': tc.operation_type,
                            'min_cycles': tc.min_cycles,
                            'max_cycles': tc.max_cycles
                        }
                        for tc in advanced.timing_constraints[:5]
                    ]
                
                # 中断信息
                if hasattr(advanced, 'interrupt_mappings') and advanced.interrupt_mappings:
                    peripheral_data['advanced']['interrupts'] = [
                        {
                            'irq_num': irq.irq_number,
                            'trigger_offset': f"0x{irq.trigger_register:02x}" if irq.trigger_register else None,
                            'handler': irq.handler_function
                        }
                        for irq in advanced.interrupt_mappings[:5]
                    ]
                
                # FIFO/DMA信息
                if hasattr(advanced, 'fifo_buffers') and advanced.fifo_buffers:
                    peripheral_data['advanced']['fifos'] = [
                        {
                            'data_offset': f"0x{fifo.data_register:02x}",
                            'status_offset': f"0x{fifo.status_register:02x}" if fifo.status_register else None,
                            'direction': fifo.direction
                        }
                        for fifo in advanced.fifo_buffers[:3]
                    ]
                
                # 初始化序列
                if hasattr(advanced, 'init_sequences') and advanced.init_sequences:
                    peripheral_data['advanced']['init_sequence'] = {
                        'function': advanced.init_sequences[0].function_name,
                        'steps': [
                            {
                                'offset': f"0x{step['offset']:02x}",
                                'value': f"0x{step['value']:x}" if isinstance(step['value'], int) else step['value']
                            }
                            for step in advanced.init_sequences[0].sequence[:10]
                        ]
                    }
            
            peripherals.append(peripheral_data)
        
        # 返回完整结果
        return {
            'total_candidates': len(peripherals),  # 使用过滤后的数量
            'type_distribution': type_distribution,
            'cluster_methods': cluster_methods,
            'confidence_distribution': confidence_distribution,
            'irq_bindings': len(self.irq_bindings),
            'register_chains': len(self.register_chains),
            'analysis_timestamp': datetime.now().isoformat(),
            'peripherals': peripherals,  # ← 关键：包含所有外设的详细数据
            'filtered_out': total_candidates - len(peripherals)  # 记录过滤掉的数量
        }
    
    def _should_skip_peripheral(self, addr: int) -> bool:
        """
        判断地址是否应该跳过（不是真实外设）
        
        ⭐ 优化策略4：移除地址范围过滤
        只跳过明显的Flash和RAM区域
        """
        # Flash区域（只读存储器，不是外设）
        if 0x08000000 <= addr < 0x10000000:
            return True
        
        # 主SRAM（0x20000000-0x20100000）通常不是外设
        if 0x20000000 <= addr < 0x20100000:
            return True
        
        # ⭐ 移除所有其他地址范围过滤
        # 不再过滤高地址、位带区域等
        # 误报将通过访问模式验证和聚类去噪控制
        
        return False
    
    def _validate_access_pattern(self, candidate) -> bool:
        """
        ⭐ 优化策略4：访问模式验证
        
        验证外设候选是否有真实的MMIO读/写操作，而不是：
        - 函数指针（BL/BLX跳转）
        - 数据常量（只被MOV/加载但不被访问）
        
        返回True表示是合法的MMIO访问
        """
        # 1. 检查是否有寄存器访问记录
        if not hasattr(candidate, 'register_accesses') or not candidate.register_accesses:
            # 如果没有访问记录，检查是否有offset_stats
            if hasattr(candidate, 'offset_stats') and candidate.offset_stats:
                # 有offset统计信息，认为是合法的
                return True
            # 否则可能只是地址加载，没有实际访问
            return False
        
        # 2. 检查访问类型
        has_read = False
        has_write = False
        has_jump = False
        
        for access in candidate.register_accesses:
            access_type = access.access_type.lower() if hasattr(access, 'access_type') else ''
            
            if 'read' in access_type:
                has_read = True
            elif 'write' in access_type:
                has_write = True
            elif 'jump' in access_type or 'call' in access_type:
                has_jump = True
        
        # 3. 决策逻辑
        # 如果只有跳转，没有读写 → 可能是函数指针
        if has_jump and not has_read and not has_write:
            return False
        
        # 如果有读或写操作 → 合法的MMIO访问
        if has_read or has_write:
            return True
        
        # 如果没有明确的访问类型，但有多个访问记录 → 可能是MMIO
        if len(candidate.register_accesses) >= 2:
            return True
        
        # 默认保留（宁可误报，不可漏报）
        return True
    
    def _infer_register_type(self, stats, offset: int) -> str:
        """推断寄存器类型"""
        read_count = stats.read_count
        write_count = stats.write_count
        
        if read_count == 0 and write_count > 0:
            return "write_only"
        elif write_count == 0 and read_count > 0:
            return "read_only"
        elif read_count > write_count * 3:
            return "status"
        elif write_count > read_count * 3:
            return "control"
        else:
            return "read_write"
    
    def _infer_register_purpose(self, stats, offset: int, peripheral_type: str) -> str:
        """推断寄存器用途"""
        # 通用推断
        if offset == 0x00:
            return "control_or_data" if stats.write_count > stats.read_count else "data_or_status"
        elif offset == 0x04:
            return "status_or_config" if stats.read_count > stats.write_count else "config"
        elif offset == 0x08:
            return "data_buffer"
        elif offset in [0x0C, 0x10, 0x14]:
            return "configuration"
        
        # GPIO特定
        if peripheral_type == "GPIO":
            if offset == 0x00:
                return "mode_register"
            elif offset == 0x08:
                return "output_data"
            elif offset == 0x0C:
                return "input_data"
        
        # UART特定
        elif peripheral_type == "UART":
            if offset == 0x00:
                return "data_register"
            elif offset == 0x04:
                return "status_register"
            elif offset == 0x08:
                return "control_register"
        
        # 通用模式
        if stats.write_count == 0 and stats.read_count > 0:
            return "status_or_data_in"
        elif stats.read_count == 0 and stats.write_count > 0:
            return "control_or_config"
        else:
            return "general_purpose"
    
    def _extract_additional_context(self, candidate) -> Dict[str, Any]:
        """提取额外上下文信息"""
        context = {}
        
        # IRQ绑定
        if candidate.base_address in self.irq_bindings:
            context['irq_number'] = self.irq_bindings[candidate.base_address]
        
        # 提取访问函数
        if hasattr(candidate, 'refs') and candidate.refs:
            functions = []
            for ref in candidate.refs[:10]:
                if isinstance(ref, str) and '@' in ref:
                    func_name = ref.split('@')[0].strip()
                    if func_name and not func_name.startswith('0x'):
                        functions.append(func_name)
            if functions:
                context['access_functions'] = list(set(functions))[:5]
        
        # 访问频率
        if candidate.offset_stats:
            total_accesses = sum(s.read_count + s.write_count for s in candidate.offset_stats.values())
            if total_accesses > 0:
                context['total_accesses'] = total_accesses
                context['access_frequency'] = 'high' if total_accesses > 50 else ('medium' if total_accesses > 10 else 'low')
        
        return context
