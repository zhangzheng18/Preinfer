#!/usr/bin/env python3
"""
数据流分析器模块
负责更鲁棒的数据流追踪，包括寄存器别名分析、内存转寄存器传播、函数参数传递等
"""

import logging
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from collections import defaultdict

try:
    import capstone
    HAS_CAPSTONE = True
except ImportError:
    HAS_CAPSTONE = False

logger = logging.getLogger(__name__)

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
    aliases: Set[int] = field(default_factory=set)  # 寄存器别名
    propagation_chain: List[str] = field(default_factory=list)  # 传播链

@dataclass
class GlobalVariable:
    """全局变量信息"""
    address: int
    name: str
    size: int
    initial_value: Optional[int] = None

@dataclass
class FunctionParameter:
    """函数参数信息"""
    function_addr: int
    function_name: str
    parameter_index: int
    register: int
    value: Optional[int] = None

class DataflowAnalyzer:
    """
    数据流分析器
    实现更鲁棒的数据流追踪功能
    """
    
    def __init__(self, elf_analyzer):
        self.elf_analyzer = elf_analyzer
        self.global_variables: Dict[int, GlobalVariable] = {}
        self.function_parameters: Dict[str, List[FunctionParameter]] = {}
        self.register_aliases: Dict[int, Set[int]] = defaultdict(set)
        
    def build_global_def_use_chains(self, instructions: List, address_loads: List) -> Dict[str, RegisterDefUse]:
        """
        构建全局寄存器定义-使用链
        增强功能：
        1. 寄存器别名分析
        2. 内存转寄存器传播
        3. 函数参数传递
        """
        logger.info("Building enhanced global def-use chains")
        
        register_chains = {}
        current_defs = {}  # reg -> latest RegisterDefUse
        
        # 第一遍：识别全局变量
        self._identify_global_variables(instructions)
        
        # 第二遍：识别函数参数
        self._identify_function_parameters(instructions)
        
        # 第三遍：构建基础def-use链
        for i, insn in enumerate(instructions):
            try:
                # 检查寄存器定义
                defined_regs = self._get_defined_registers(insn)
                for reg in defined_regs:
                    # 提取值信息
                    value_info = self._extract_value_info(insn, i, instructions, address_loads)
                    
                    # 创建def-use链
                    reg_key = f"r{reg}_{insn.address:08x}"
                    reg_chain = RegisterDefUse(
                        register=reg,
                        def_addr=insn.address,
                        def_instruction=f"{insn.mnemonic} {insn.op_str}",
                        use_addrs=[],
                        use_instructions=[],
                        value=value_info.get('value') if value_info else None,
                        load_type=value_info.get('load_type', 'unknown') if value_info else 'unknown'
                    )
                    
                    register_chains[reg_key] = reg_chain
                    current_defs[reg] = reg_chain
                
                # 检查寄存器使用
                used_regs = self._get_used_registers(insn)
                for reg in used_regs:
                    if reg in current_defs:
                        current_defs[reg].use_addrs.append(insn.address)
                        current_defs[reg].use_instructions.append(f"{insn.mnemonic} {insn.op_str}")
                
                # 检查寄存器拷贝/别名
                aliases = self._detect_register_aliases(insn)
                for src_reg, dst_reg in aliases:
                    if src_reg in current_defs:
                        # 传播值到目标寄存器
                        self._propagate_register_value(current_defs[src_reg], dst_reg, insn, register_chains)
                
                # 检查内存到寄存器的传播
                memory_loads = self._detect_memory_to_register_propagation(insn)
                for mem_addr, dst_reg in memory_loads:
                    global_var = self._get_global_variable_at_address(mem_addr)
                    if global_var and global_var.initial_value:
                        # 创建从全局变量传播的def-use链
                        self._create_global_variable_chain(global_var, dst_reg, insn, register_chains)
            
            except Exception as e:
                logger.debug(f"Error analyzing instruction {insn.address:08x}: {e}")
                continue
        
        # 第四遍：函数参数传播
        self._analyze_function_parameter_propagation(instructions, register_chains)
        
        logger.info(f"Built {len(register_chains)} enhanced def-use chains")
        return register_chains
    
    def _identify_global_variables(self, instructions: List):
        """识别全局变量"""
        logger.info("Identifying global variables")
        
        # 从符号表获取全局变量
        if self.elf_analyzer.elf_info and self.elf_analyzer.elf_info.symbols:
            for name, symbol_info in self.elf_analyzer.elf_info.symbols.items():
                if (symbol_info['type'] in ['STT_OBJECT', 'STT_COMMON'] and
                    symbol_info['bind'] == 'STB_GLOBAL'):
                    
                    global_var = GlobalVariable(
                        address=symbol_info['value'],
                        name=name,
                        size=symbol_info['size']
                    )
                    
                    # 尝试读取初始值
                    if symbol_info['size'] in [4, 8]:
                        initial_value = self.elf_analyzer.read_constant_from_memory(symbol_info['value'])
                        if initial_value:
                            global_var.initial_value = initial_value
                    
                    self.global_variables[symbol_info['value']] = global_var
        
        logger.info(f"Found {len(self.global_variables)} global variables")
    
    def _identify_function_parameters(self, instructions: List):
        """识别函数参数"""
        logger.info("Identifying function parameters")
        
        # ARM调用约定：r0-r3是参数寄存器
        param_registers = [0, 1, 2, 3] if self.elf_analyzer.elf_info.arch == 'arm' else [0, 1, 2, 3, 4, 5, 6, 7]
        
        # 查找函数入口点
        function_entries = set()
        if self.elf_analyzer.elf_info and self.elf_analyzer.elf_info.symbols:
            for name, symbol_info in self.elf_analyzer.elf_info.symbols.items():
                if symbol_info['type'] == 'STT_FUNC':
                    function_entries.add(symbol_info['value'])
        
        # 分析函数入口处的参数使用
        for insn in instructions:
            if insn.address in function_entries:
                func_name = self.elf_analyzer.get_function_name_for_address(insn.address)
                if func_name:
                    # 分析接下来几条指令中的参数寄存器使用
                    params = self._analyze_function_entry_parameters(
                        instructions, insn.address, param_registers
                    )
                    if params:
                        self.function_parameters[func_name] = params
        
        logger.info(f"Identified parameters for {len(self.function_parameters)} functions")
    
    def _analyze_function_entry_parameters(self, instructions: List, entry_addr: int, 
                                         param_registers: List[int]) -> List[FunctionParameter]:
        """分析函数入口的参数使用"""
        parameters = []
        
        # 在函数入口后的前20条指令中查找参数寄存器的使用
        entry_index = None
        for i, insn in enumerate(instructions):
            if insn.address == entry_addr:
                entry_index = i
                break
        
        if entry_index is None:
            return parameters
        
        used_params = set()
        for i in range(entry_index, min(entry_index + 20, len(instructions))):
            insn = instructions[i]
            
            # 检查参数寄存器的使用
            used_regs = self._get_used_registers(insn)
            for reg in used_regs:
                if reg in param_registers and reg not in used_params:
                    param = FunctionParameter(
                        function_addr=entry_addr,
                        function_name=self.elf_analyzer.get_function_name_for_address(entry_addr),
                        parameter_index=param_registers.index(reg),
                        register=reg
                    )
                    parameters.append(param)
                    used_params.add(reg)
            
            # 如果参数寄存器被重新定义，停止分析该寄存器
            defined_regs = self._get_defined_registers(insn)
            for reg in defined_regs:
                if reg in param_registers:
                    used_params.add(reg)
        
        return parameters
    
    def _detect_register_aliases(self, insn) -> List[Tuple[int, int]]:
        """检测寄存器别名"""
        aliases = []
        
        try:
            mnemonic = insn.mnemonic.lower()
            
            # MOV指令
            if mnemonic == 'mov' and len(insn.operands) >= 2:
                dst_reg = self._get_register_from_operand(insn.operands[0])
                src_reg = self._get_register_from_operand(insn.operands[1])
                if dst_reg is not None and src_reg is not None:
                    aliases.append((src_reg, dst_reg))
            
            # ORR reg, reg, #0 形式
            elif mnemonic == 'orr' and len(insn.operands) >= 3:
                dst_reg = self._get_register_from_operand(insn.operands[0])
                src_reg = self._get_register_from_operand(insn.operands[1])
                if (dst_reg is not None and src_reg is not None and
                    insn.operands[2].type in [capstone.arm.ARM_OP_IMM, capstone.arm64.ARM64_OP_IMM] and
                    insn.operands[2].imm == 0):
                    aliases.append((src_reg, dst_reg))
            
            # ADD reg, reg, #0 形式
            elif mnemonic == 'add' and len(insn.operands) >= 3:
                dst_reg = self._get_register_from_operand(insn.operands[0])
                src_reg = self._get_register_from_operand(insn.operands[1])
                if (dst_reg is not None and src_reg is not None and
                    insn.operands[2].type in [capstone.arm.ARM_OP_IMM, capstone.arm64.ARM64_OP_IMM] and
                    insn.operands[2].imm == 0):
                    aliases.append((src_reg, dst_reg))
        
        except Exception as e:
            logger.debug(f"Error detecting register aliases: {e}")
        
        return aliases
    
    def _detect_memory_to_register_propagation(self, insn) -> List[Tuple[int, int]]:
        """检测内存到寄存器的传播"""
        propagations = []
        
        try:
            mnemonic = insn.mnemonic.lower()
            
            # LDR指令从全局地址加载
            if mnemonic == 'ldr' and len(insn.operands) >= 2:
                dst_reg = self._get_register_from_operand(insn.operands[0])
                src_operand = insn.operands[1]
                
                if dst_reg is not None and src_operand.type in [capstone.arm.ARM_OP_MEM, capstone.arm64.ARM64_OP_MEM]:
                    # 直接地址访问
                    if (src_operand.mem.base == 0 and 
                        src_operand.mem.index == 0 and 
                        src_operand.mem.disp > 0):
                        
                        mem_addr = src_operand.mem.disp
                        # 检查是否是全局变量地址
                        if not self.elf_analyzer.is_address_in_firmware_memory(mem_addr):
                            propagations.append((mem_addr, dst_reg))
        
        except Exception as e:
            logger.debug(f"Error detecting memory propagation: {e}")
        
        return propagations
    
    def _propagate_register_value(self, src_chain: RegisterDefUse, dst_reg: int, 
                                insn, register_chains: Dict[str, RegisterDefUse]):
        """传播寄存器值"""
        # 创建新的def-use链，继承源寄存器的值
        reg_key = f"r{dst_reg}_{insn.address:08x}"
        
        propagated_chain = RegisterDefUse(
            register=dst_reg,
            def_addr=insn.address,
            def_instruction=f"{insn.mnemonic} {insn.op_str}",
            use_addrs=[],
            use_instructions=[],
            value=src_chain.value,
            load_type='register_copy',
            aliases={src_chain.register},
            propagation_chain=src_chain.propagation_chain + [f"r{src_chain.register}->r{dst_reg}"]
        )
        
        register_chains[reg_key] = propagated_chain
        
        # 更新别名关系
        self.register_aliases[dst_reg].add(src_chain.register)
        self.register_aliases[src_chain.register].add(dst_reg)
    
    def _create_global_variable_chain(self, global_var: GlobalVariable, dst_reg: int, 
                                    insn, register_chains: Dict[str, RegisterDefUse]):
        """创建从全局变量传播的def-use链"""
        reg_key = f"r{dst_reg}_{insn.address:08x}"
        
        global_chain = RegisterDefUse(
            register=dst_reg,
            def_addr=insn.address,
            def_instruction=f"{insn.mnemonic} {insn.op_str}",
            use_addrs=[],
            use_instructions=[],
            value=global_var.initial_value,
            load_type='global_variable',
            propagation_chain=[f"global_{global_var.name}->r{dst_reg}"]
        )
        
        register_chains[reg_key] = global_chain
    
    def _analyze_function_parameter_propagation(self, instructions: List, 
                                              register_chains: Dict[str, RegisterDefUse]):
        """分析函数参数传播"""
        logger.info("Analyzing function parameter propagation")
        
        # 查找函数调用
        for i, insn in enumerate(instructions):
            if self._is_function_call(insn):
                # 分析调用前的参数准备
                call_params = self._analyze_call_parameters(instructions, i)
                
                # 查找被调用函数的参数使用
                target_func = self._get_call_target(insn)
                if target_func and target_func in self.function_parameters:
                    # 传播参数值
                    func_params = self.function_parameters[target_func]
                    for param in func_params:
                        if param.parameter_index < len(call_params):
                            param_value = call_params[param.parameter_index]
                            if param_value:
                                # 创建参数传播链
                                self._create_parameter_propagation_chain(
                                    param, param_value, insn, register_chains
                                )
    
    def _is_function_call(self, insn) -> bool:
        """检查是否是函数调用指令"""
        mnemonic = insn.mnemonic.lower()
        return mnemonic in ['bl', 'blx', 'call']
    
    def _analyze_call_parameters(self, instructions: List, call_index: int) -> List[Optional[int]]:
        """分析函数调用的参数"""
        # ARM调用约定：r0-r3是参数寄存器
        param_registers = [0, 1, 2, 3]
        param_values = [None] * 4
        
        # 在调用前的几条指令中查找参数准备
        start_index = max(0, call_index - 10)
        
        for i in range(start_index, call_index):
            insn = instructions[i]
            
            # 检查参数寄存器的定义
            defined_regs = self._get_defined_registers(insn)
            for reg in defined_regs:
                if reg in param_registers:
                    param_index = param_registers.index(reg)
                    # 尝试提取参数值
                    value = self._extract_immediate_value(insn)
                    if value:
                        param_values[param_index] = value
        
        return param_values
    
    def _get_call_target(self, insn) -> Optional[str]:
        """获取函数调用目标"""
        try:
            if len(insn.operands) >= 1:
                target_operand = insn.operands[0]
                if target_operand.type in [capstone.arm.ARM_OP_IMM, capstone.arm64.ARM64_OP_IMM]:
                    target_addr = target_operand.imm
                    return self.elf_analyzer.get_function_name_for_address(target_addr)
        except:
            pass
        return None
    
    def _create_parameter_propagation_chain(self, param: FunctionParameter, param_value: int,
                                          call_insn, register_chains: Dict[str, RegisterDefUse]):
        """创建参数传播链"""
        # 在函数入口创建参数def-use链
        reg_key = f"r{param.register}_{param.function_addr:08x}_param"
        
        param_chain = RegisterDefUse(
            register=param.register,
            def_addr=param.function_addr,
            def_instruction=f"PARAM{param.parameter_index}",
            use_addrs=[],
            use_instructions=[],
            value=param_value,
            load_type='function_parameter',
            propagation_chain=[f"call@0x{call_insn.address:08x}->param{param.parameter_index}"]
        )
        
        register_chains[reg_key] = param_chain
    
    def _extract_value_info(self, insn, index: int, instructions: List, address_loads: List) -> Optional[Dict]:
        """提取值信息（增强版）"""
        # 首先检查是否是已知的地址加载
        for load in address_loads:
            if load.instruction_addr == insn.address:
                return {
                    'value': load.base_address,
                    'load_type': load.load_type
                }
        
        # 检查立即数
        immediate_value = self._extract_immediate_value(insn)
        if immediate_value:
            return {
                'value': immediate_value,
                'load_type': 'immediate'
            }
        
        return None
    
    def _extract_immediate_value(self, insn) -> Optional[int]:
        """提取立即数值"""
        try:
            mnemonic = insn.mnemonic.lower()
            
            if mnemonic in ['mov', 'ldr'] and len(insn.operands) >= 2:
                src_operand = insn.operands[1]
                if src_operand.type in [capstone.arm.ARM_OP_IMM, capstone.arm64.ARM64_OP_IMM]:
                    return src_operand.imm
        except:
            pass
        return None
    
    def _get_register_from_operand(self, operand) -> Optional[int]:
        """从操作数获取寄存器号"""
        try:
            if operand.type in [capstone.arm.ARM_OP_REG, capstone.arm64.ARM64_OP_REG]:
                return operand.reg
        except:
            pass
        return None
    
    def _get_defined_registers(self, insn) -> List[int]:
        """获取指令定义的寄存器 - 支持ARM/MIPS/RISC-V"""
        defined_regs = []
        try:
            if len(insn.operands) >= 1:
                dst_operand = insn.operands[0]
                mnemonic = insn.mnemonic.lower()
                
                # ARM/ARM64
                if dst_operand.type in [capstone.arm.ARM_OP_REG, capstone.arm64.ARM64_OP_REG]:
                    # 排除存储指令
                    if mnemonic not in ['str', 'strb', 'strh', 'strd', 'sw', 'sh', 'sb', 'sd']:
                        defined_regs.append(dst_operand.reg)
                
                # MIPS
                elif hasattr(capstone, 'mips') and dst_operand.type == capstone.mips.MIPS_OP_REG:
                    # MIPS load指令定义目标寄存器
                    if mnemonic in ['lw', 'lh', 'lhu', 'lb', 'lbu', 'ld', 'lui', 'li', 'addiu', 'addi', 'ori', 'move']:
                        defined_regs.append(dst_operand.reg)
                
                # RISC-V
                elif hasattr(capstone, 'riscv') and dst_operand.type == capstone.riscv.RISCV_OP_REG:
                    # RISC-V load指令和算术指令定义目标寄存器
                    if mnemonic not in ['sw', 'sh', 'sb', 'sd']:
                        defined_regs.append(dst_operand.reg)
        except:
            pass
        return defined_regs
    
    def _get_used_registers(self, insn) -> List[int]:
        """获取指令使用的寄存器 - 支持ARM/MIPS/RISC-V"""
        used_regs = []
        try:
            mnemonic = insn.mnemonic.lower()
            
            for i, operand in enumerate(insn.operands):
                # ARM/ARM64
                if operand.type in [capstone.arm.ARM_OP_REG, capstone.arm64.ARM64_OP_REG]:
                    # 跳过目标寄存器（除非是内存访问指令）
                    if i == 0 and mnemonic not in ['str', 'strb', 'strh', 'strd', 'ldr', 'ldrb', 'ldrh', 'ldrd', 
                                                     'sw', 'sh', 'sb', 'sd', 'lw', 'lh', 'lhu', 'lb', 'lbu', 'ld']:
                        continue
                    used_regs.append(operand.reg)
                
                elif operand.type in [capstone.arm.ARM_OP_MEM, capstone.arm64.ARM64_OP_MEM]:
                    # ARM内存操作数中的寄存器
                    if operand.mem.base != 0:
                        used_regs.append(operand.mem.base)
                    if operand.mem.index != 0:
                        used_regs.append(operand.mem.index)
                
                # MIPS
                elif hasattr(capstone, 'mips') and operand.type == capstone.mips.MIPS_OP_REG:
                    # MIPS: load/store指令的第一个操作数是目标/源寄存器，需要特殊处理
                    if i == 0 and mnemonic in ['lw', 'lh', 'lhu', 'lb', 'lbu', 'ld', 'lui']:
                        # load指令的目标寄存器，跳过
                        continue
                    elif i == 0 and mnemonic in ['sw', 'sh', 'sb', 'sd']:
                        # store指令的源寄存器，算作使用
                        used_regs.append(operand.reg)
                    else:
                        # 其他位置的寄存器操作数
                        used_regs.append(operand.reg)
                
                elif hasattr(capstone, 'mips') and operand.type == capstone.mips.MIPS_OP_MEM:
                    # MIPS内存操作数中的基址寄存器
                    if operand.mem.base != 0:
                        used_regs.append(operand.mem.base)
                
                # RISC-V
                elif hasattr(capstone, 'riscv') and operand.type == capstone.riscv.RISCV_OP_REG:
                    # RISC-V: 类似MIPS的处理
                    if i == 0 and mnemonic not in ['sw', 'sh', 'sb', 'sd']:
                        # 非store指令的目标寄存器，跳过
                        continue
                    used_regs.append(operand.reg)
                
                elif hasattr(capstone, 'riscv') and operand.type == capstone.riscv.RISCV_OP_MEM:
                    # RISC-V内存操作数中的基址寄存器
                    if operand.mem.base != 0:
                        used_regs.append(operand.mem.base)
        
        except:
            pass
        return used_regs
    
    # ==================== ⭐ 新增：栈追踪支持 ====================
    
    def track_stack_operations(self, instructions: List) -> Dict[int, Dict[str, any]]:
        """
        ⭐ 栈操作追踪：追踪PUSH/POP指令，维护栈状态
        
        返回：{instruction_address: {'type': 'push'/'pop', 'registers': [...]}}
        """
        logger.info("Tracking stack operations")
        stack_ops = {}
        stack_depth = 0
        stack_slots = {}  # {slot_offset: {register: X, address: Y}}
        
        for insn in instructions:
            try:
                mnemonic = insn.mnemonic.lower()
                
                # PUSH操作
                if mnemonic in ['push', 'stmdb', 'stmfd']:
                    pushed_regs = []
                    for operand in insn.operands:
                        if operand.type in [capstone.arm.ARM_OP_REG, capstone.arm64.ARM64_OP_REG]:
                            pushed_regs.append(operand.reg)
                    
                    if pushed_regs:
                        # 记录栈操作
                        stack_ops[insn.address] = {
                            'type': 'push',
                            'registers': pushed_regs,
                            'stack_depth': stack_depth
                        }
                        
                        # 更新栈槽
                        for reg in pushed_regs:
                            stack_slots[stack_depth] = {
                                'register': reg,
                                'push_address': insn.address
                            }
                            stack_depth += 4
                
                # POP操作
                elif mnemonic in ['pop', 'ldmia', 'ldmfd']:
                    popped_regs = []
                    for operand in insn.operands:
                        if operand.type in [capstone.arm.ARM_OP_REG, capstone.arm64.ARM64_OP_REG]:
                            popped_regs.append(operand.reg)
                    
                    if popped_regs:
                        # 记录栈操作
                        stack_ops[insn.address] = {
                            'type': 'pop',
                            'registers': popped_regs,
                            'stack_depth': stack_depth,
                            'stack_slots': {}
                        }
                        
                        # 尝试匹配栈槽
                        for reg in reversed(popped_regs):
                            stack_depth -= 4
                            if stack_depth in stack_slots:
                                original_reg = stack_slots[stack_depth]['register']
                                push_addr = stack_slots[stack_depth]['push_address']
                                
                                # 记录寄存器映射
                                stack_ops[insn.address]['stack_slots'][reg] = {
                                    'original_register': original_reg,
                                    'push_address': push_addr
                                }
                                logger.debug(f"Stack mapping: R{original_reg} (push @0x{push_addr:08x}) -> R{reg} (pop @0x{insn.address:08x})")
                
                # 显式栈指针操作
                elif mnemonic in ['sub', 'add'] and len(insn.operands) >= 3:
                    # SUB SP, SP, #imm 或 ADD SP, SP, #imm
                    dst_reg = self._get_register_from_operand(insn.operands[0])
                    src_reg = self._get_register_from_operand(insn.operands[1])
                    
                    # ARM: R13 = SP
                    if dst_reg == 13 and src_reg == 13:
                        imm_operand = insn.operands[2]
                        if imm_operand.type in [capstone.arm.ARM_OP_IMM, capstone.arm64.ARM64_OP_IMM]:
                            if mnemonic == 'sub':
                                stack_depth += imm_operand.imm
                            else:
                                stack_depth -= imm_operand.imm
                            
                            stack_ops[insn.address] = {
                                'type': 'sp_adjust',
                                'adjustment': imm_operand.imm if mnemonic == 'sub' else -imm_operand.imm,
                                'stack_depth': stack_depth
                            }
            
            except Exception as e:
                logger.debug(f"Error tracking stack at 0x{insn.address:08x}: {e}")
                continue
        
        logger.info(f"Tracked {len(stack_ops)} stack operations")
        return stack_ops
    
    # ==================== ⭐ 新增：跨函数调用链分析 ====================
    
    def analyze_cross_function_calls(self, instructions: List) -> Dict[int, List[Dict]]:
        """
        ⭐ 跨函数调用链分析：追踪函数调用的参数和返回值传播
        
        返回：{call_address: [{'target': addr, 'params': {...}, 'return': {...}}]}
        """
        logger.info("Analyzing cross-function calls")
        call_chains = {}
        
        for i, insn in enumerate(instructions):
            try:
                mnemonic = insn.mnemonic.lower()
                
                # 函数调用指令
                if mnemonic in ['bl', 'blx', 'call']:
                    # 提取目标地址
                    target_addr = None
                    if len(insn.operands) >= 1:
                        if insn.operands[0].type in [capstone.arm.ARM_OP_IMM, capstone.arm64.ARM64_OP_IMM]:
                            target_addr = insn.operands[0].imm
                        elif insn.operands[0].type in [capstone.arm.ARM_OP_REG, capstone.arm64.ARM64_OP_REG]:
                            # 间接调用，尝试反向追踪寄存器值
                            target_reg = insn.operands[0].reg
                            target_addr = self._trace_register_value_backward(
                                instructions, i, target_reg
                            )
                    
                    if target_addr:
                        # 分析调用前的参数准备（R0-R3）
                        params = self._analyze_call_parameters(instructions, i)
                        
                        # 分析调用后的返回值使用（R0）
                        return_usage = self._analyze_return_value_usage(instructions, i)
                        
                        call_info = {
                            'target': target_addr,
                            'target_name': self.elf_analyzer.get_function_name_for_address(target_addr),
                            'params': params,
                            'return': return_usage
                        }
                        
                        if insn.address not in call_chains:
                            call_chains[insn.address] = []
                        call_chains[insn.address].append(call_info)
                        
                        logger.debug(f"Call chain: 0x{insn.address:08x} -> {call_info['target_name'] or f'0x{target_addr:08x}'}")
            
            except Exception as e:
                logger.debug(f"Error analyzing call at 0x{insn.address:08x}: {e}")
                continue
        
        logger.info(f"Analyzed {len(call_chains)} function calls")
        return call_chains
    
    def _trace_register_value_backward(self, instructions: List, current_index: int, 
                                      target_reg: int, max_lookback: int = 10) -> Optional[int]:
        """向后追踪寄存器值"""
        for i in range(current_index - 1, max(0, current_index - max_lookback), -1):
            insn = instructions[i]
            
            # 检查是否定义了目标寄存器
            defined_regs = self._get_defined_registers(insn)
            if target_reg in defined_regs:
                # 尝试提取值
                immediate_value = self._extract_immediate_value(insn)
                if immediate_value:
                    return immediate_value
                
                # 如果是LDR指令，尝试读取
                if insn.mnemonic.lower() == 'ldr' and len(insn.operands) >= 2:
                    src_operand = insn.operands[1]
                    if src_operand.type in [capstone.arm.ARM_OP_MEM, capstone.arm64.ARM64_OP_MEM]:
                        if (src_operand.mem.base in [capstone.arm.ARM_REG_PC, 15]):  # PC相对
                            # 计算literal地址
                            pc_aligned = (insn.address + 4) & ~0x3
                            literal_addr = pc_aligned + src_operand.mem.disp
                            value = self.elf_analyzer.read_constant_from_memory(literal_addr)
                            if value:
                                return value
        
        return None
    
    def _analyze_call_parameters(self, instructions: List, call_index: int) -> Dict[int, any]:
        """分析函数调用的参数（R0-R3）"""
        params = {}
        param_registers = [0, 1, 2, 3]  # ARM calling convention
        
        # 向前查找参数准备（最多10条指令）
        for i in range(max(0, call_index - 10), call_index):
            insn = instructions[i]
            
            # 检查是否设置了参数寄存器
            defined_regs = self._get_defined_registers(insn)
            for reg in defined_regs:
                if reg in param_registers and reg not in params:
                    # 尝试提取参数值
                    immediate_value = self._extract_immediate_value(insn)
                    if immediate_value:
                        params[reg] = {
                            'value': immediate_value,
                            'set_at': insn.address
                        }
        
        return params
    
    def _analyze_return_value_usage(self, instructions: List, call_index: int) -> Dict[str, any]:
        """分析函数返回值的使用（R0）"""
        return_usage = {'used': False, 'use_at': None}
        
        # 向后查找返回值使用（最多5条指令）
        for i in range(call_index + 1, min(len(instructions), call_index + 6)):
            insn = instructions[i]
            
            # 检查R0是否被使用
            used_regs = self._get_used_registers(insn)
            if 0 in used_regs:
                return_usage['used'] = True
                return_usage['use_at'] = insn.address
                break
            
            # 如果R0被重新定义（不是从函数返回），停止查找
            defined_regs = self._get_defined_registers(insn)
            if 0 in defined_regs:
                break
        
        return return_usage
    
    def _get_global_variable_at_address(self, addr: int) -> Optional[GlobalVariable]:
        """获取指定地址的全局变量"""
        return self.global_variables.get(addr)
    
    def get_register_aliases(self, register: int) -> Set[int]:
        """获取寄存器的所有别名"""
        return self.register_aliases.get(register, set())
    
    def get_propagation_sources(self, reg_chain: RegisterDefUse) -> List[str]:
        """获取值的传播来源"""
        sources = []
        
        if reg_chain.load_type == 'register_copy':
            sources.extend([f"Register alias: r{alias}" for alias in reg_chain.aliases])
        elif reg_chain.load_type == 'global_variable':
            sources.append("Global variable")
        elif reg_chain.load_type == 'function_parameter':
            sources.append("Function parameter")
        
        sources.extend(reg_chain.propagation_chain)
        return sources

