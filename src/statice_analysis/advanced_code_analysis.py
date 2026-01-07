#!/usr/bin/env python3
"""
高级代码分析 - 调用图、中断向量表、状态机推断

核心功能:
1. 调用图分析 - 识别所有可达代码路径
2. 中断向量表分析 - 提取所有中断处理程序
3. 状态机推断 - 识别状态变量和转换

目标: 最大化唯一PC覆盖率
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

try:
    from elftools.elf.elffile import ELFFile
    HAS_ELFTOOLS = True
except ImportError:
    HAS_ELFTOOLS = False


@dataclass
class FunctionInfo:
    """函数信息"""
    address: int
    name: str
    size: int = 0
    calls: List[int] = field(default_factory=list)
    callers: List[int] = field(default_factory=list)
    is_interrupt_handler: bool = False
    irq_number: int = -1
    is_reachable: bool = False
    basic_blocks: int = 0


@dataclass
class InterruptHandler:
    """中断处理程序"""
    vector_index: int
    irq_number: int  # vector_index - 16
    handler_address: int
    handler_name: str
    is_default: bool = False
    trigger_condition: str = ""


@dataclass
class StateMachine:
    """状态机"""
    state_variable_addr: int
    state_variable_name: str
    states: List[int] = field(default_factory=list)
    transitions: Dict[int, List[Tuple[int, int]]] = field(default_factory=dict)
    # transitions: {from_state: [(to_state, trigger_pc), ...]}
    switch_pc: int = 0


@dataclass
class RTOSInfo:
    """RTOS检测结果"""
    detected: bool = False
    rtos_type: str = "none"  # freertos, riot, zephyr, mbed, chibios, none
    task_functions: List[int] = field(default_factory=list)  # Task entry points
    scheduler_funcs: List[int] = field(default_factory=list)  # Scheduler functions
    mutex_funcs: List[int] = field(default_factory=list)  # Mutex/semaphore functions
    queue_funcs: List[int] = field(default_factory=list)  # Queue functions
    confidence: float = 0.0


@dataclass
class IndirectCallInfo:
    """间接调用信息"""
    call_site: int           # 调用位置
    target_register: str     # 目标寄存器 (如 "r4", "r7")
    possible_targets: List[int] = field(default_factory=list)  # 可能的目标地址
    function_ptr_addr: int = 0  # 函数指针变量地址
    source_function: int = 0   # 所在函数


@dataclass
class CallGraphAnalysisResult:
    """调用图分析结果"""
    functions: Dict[int, FunctionInfo]
    entry_points: List[int]
    unreachable_functions: List[int]
    interrupt_handlers: List[InterruptHandler]
    state_machines: List[StateMachine]
    call_depth: Dict[int, int]  # function_addr -> max call depth
    rtos_info: RTOSInfo = field(default_factory=RTOSInfo)  # ⭐ RTOS检测
    indirect_calls: List[IndirectCallInfo] = field(default_factory=list)  # ⭐ 间接调用


class AdvancedCodeAnalyzer:
    """高级代码分析器"""
    
    # ARM Cortex-M 中断名称
    CORTEX_M_IRQS = {
        0: "SP_Main",
        1: "Reset",
        2: "NMI",
        3: "HardFault",
        4: "MemManage",
        5: "BusFault",
        6: "UsageFault",
        7: "Reserved",
        8: "Reserved",
        9: "Reserved",
        10: "Reserved",
        11: "SVCall",
        12: "Debug_Monitor",
        13: "Reserved",
        14: "PendSV",
        15: "SysTick",
    }
    
    # STM32F4 外设中断
    STM32F4_IRQS = {
        16: "WWDG",
        17: "PVD",
        18: "TAMP_STAMP",
        19: "RTC_WKUP",
        20: "FLASH",
        21: "RCC",
        22: "EXTI0",
        23: "EXTI1",
        24: "EXTI2",
        25: "EXTI3",
        26: "EXTI4",
        27: "DMA1_Stream0",
        28: "DMA1_Stream1",
        29: "DMA1_Stream2",
        30: "DMA1_Stream3",
        31: "DMA1_Stream4",
        32: "DMA1_Stream5",
        33: "DMA1_Stream6",
        34: "ADC",
        35: "CAN1_TX",
        36: "CAN1_RX0",
        37: "CAN1_RX1",
        38: "CAN1_SCE",
        39: "EXTI9_5",
        40: "TIM1_BRK_TIM9",
        41: "TIM1_UP_TIM10",
        42: "TIM1_TRG_COM_TIM11",
        43: "TIM1_CC",
        44: "TIM2",
        45: "TIM3",
        46: "TIM4",
        47: "I2C1_EV",
        48: "I2C1_ER",
        49: "I2C2_EV",
        50: "I2C2_ER",
        51: "SPI1",
        52: "SPI2",
        53: "USART1",
        54: "USART2",
        55: "USART3",
        56: "EXTI15_10",
        57: "RTC_Alarm",
        58: "OTG_FS_WKUP",
        59: "TIM8_BRK_TIM12",
        60: "TIM8_UP_TIM13",
        61: "TIM8_TRG_COM_TIM14",
        62: "TIM8_CC",
        63: "DMA1_Stream7",
        64: "FSMC",
        65: "SDIO",
        66: "TIM5",
        67: "SPI3",
        68: "UART4",
        69: "UART5",
        70: "TIM6_DAC",
        71: "TIM7",
        72: "DMA2_Stream0",
        73: "DMA2_Stream1",
        74: "DMA2_Stream2",
        75: "DMA2_Stream3",
        76: "DMA2_Stream4",
        77: "ETH",
        78: "ETH_WKUP",
        79: "CAN2_TX",
        80: "CAN2_RX0",
        81: "CAN2_RX1",
        82: "CAN2_SCE",
        83: "OTG_FS",
        84: "DMA2_Stream5",
        85: "DMA2_Stream6",
        86: "DMA2_Stream7",
        87: "USART6",
        88: "I2C3_EV",
        89: "I2C3_ER",
        90: "OTG_HS_EP1_OUT",
        91: "OTG_HS_EP1_IN",
        92: "OTG_HS_WKUP",
        93: "OTG_HS",
        94: "DCMI",
        95: "CRYP",
        96: "HASH_RNG",
        97: "FPU",
    }
    
    def __init__(self, firmware_path: str):
        self.firmware_path = Path(firmware_path)
        self.sections: Dict[str, Dict] = {}
        self.symbols: Dict[str, int] = {}
        self.reverse_symbols: Dict[int, str] = {}
        self.instructions: List = []
        self.instruction_map: Dict[int, Any] = {}
        
        self.functions: Dict[int, FunctionInfo] = {}
        self.interrupt_handlers: List[InterruptHandler] = []
        self.state_machines: List[StateMachine] = []
        self.call_graph: Dict[int, Set[int]] = defaultdict(set)
        self.reverse_call_graph: Dict[int, Set[int]] = defaultdict(set)
        
        self._load_elf()
        self._disassemble()
    
    def _load_elf(self):
        """加载ELF"""
        if not HAS_ELFTOOLS:
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
        """反汇编"""
        if not HAS_CAPSTONE:
            return
        
        text = self.sections.get('.text', {})
        if not text:
            return
        
        md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
        md.detail = True
        
        self.instructions = list(md.disasm(text['data'], text['addr']))
        for insn in self.instructions:
            self.instruction_map[insn.address] = insn
    
    def _read_word(self, addr: int) -> Optional[int]:
        """读取4字节"""
        for sec in self.sections.values():
            if sec['addr'] <= addr < sec['addr'] + sec['size']:
                offset = addr - sec['addr']
                if offset + 4 <= sec['size']:
                    return struct.unpack('<I', sec['data'][offset:offset+4])[0]
        return None
    
    def analyze_all(self) -> CallGraphAnalysisResult:
        """执行完整分析"""
        logger.info("=" * 60)
        logger.info("高级代码分析")
        logger.info("=" * 60)
        
        # 1. 提取中断向量表
        self._extract_interrupt_vectors()
        
        # 2. 识别函数
        self._identify_functions()
        
        # 3. 构建调用图
        self._build_call_graph()
        
        # 4. 计算可达性
        self._compute_reachability()
        
        # 5. 推断状态机
        self._infer_state_machines()
        
        # 6. 计算调用深度
        call_depth = self._compute_call_depth()
        
        # ⭐ 7. RTOS检测
        rtos_info = self._detect_rtos()
        
        # ⭐ 8. 间接调用分析
        indirect_calls = self._analyze_indirect_calls()
        
        # 收集未执行函数
        unreachable = [addr for addr, func in self.functions.items() 
                       if not func.is_reachable]
        
        return CallGraphAnalysisResult(
            functions=self.functions,
            entry_points=[h.handler_address for h in self.interrupt_handlers],
            unreachable_functions=unreachable,
            interrupt_handlers=self.interrupt_handlers,
            state_machines=self.state_machines,
            call_depth=call_depth,
            rtos_info=rtos_info,
            indirect_calls=indirect_calls
        )
    
    def _extract_interrupt_vectors(self):
        """提取中断向量表"""
        logger.info("\n[1/5] 中断向量表分析")
        
        # 向量表通常在0x08000000
        vector_base = 0x08000000
        
        # 读取向量表
        vectors = []
        for i in range(100):
            vec = self._read_word(vector_base + i * 4)
            if vec is not None:
                vectors.append(vec)
            else:
                break
        
        if not vectors:
            logger.warning("  无法读取向量表")
            return
        
        # 找出默认处理程序（最常见的地址）
        handler_counts = defaultdict(int)
        for vec in vectors[1:]:  # 跳过SP
            if vec != 0:
                handler_counts[vec] += 1
        
        default_handler = max(handler_counts.items(), key=lambda x: x[1])[0] if handler_counts else 0
        
        logger.info(f"  默认处理程序: 0x{default_handler:08X}")
        
        # 提取非默认处理程序
        for i, vec in enumerate(vectors):
            if i == 0:  # SP
                continue
            
            is_default = (vec == default_handler)
            
            # 获取IRQ名称
            if i < 16:
                irq_name = self.CORTEX_M_IRQS.get(i, f"IRQ_{i}")
            else:
                irq_name = self.STM32F4_IRQS.get(i, f"IRQ{i-16}")
            
            handler_name = self.reverse_symbols.get(vec & ~1, f"handler_{i}")
            
            handler = InterruptHandler(
                vector_index=i,
                irq_number=i - 16 if i >= 16 else i,
                handler_address=vec & ~1,  # 清除Thumb位
                handler_name=handler_name,
                is_default=is_default,
                trigger_condition=self._get_interrupt_trigger(i)
            )
            
            self.interrupt_handlers.append(handler)
            
            if not is_default and vec != 0:
                logger.info(f"  {irq_name:20s} -> 0x{vec:08X}")
        
        non_default = [h for h in self.interrupt_handlers if not h.is_default and h.handler_address != 0]
        logger.info(f"  非默认处理程序: {len(non_default)}个")
    
    def _get_interrupt_trigger(self, vector_index: int) -> str:
        """获取中断触发条件"""
        triggers = {
            15: "SysTick timer underflow",
            22: "EXTI line 0 interrupt",
            23: "EXTI line 1 interrupt", 
            24: "EXTI line 2 interrupt",
            25: "EXTI line 3 interrupt",
            26: "EXTI line 4 interrupt",
            39: "EXTI lines 5-9 interrupt",
            44: "TIM2 global interrupt",
            45: "TIM3 global interrupt",
            46: "TIM4 global interrupt",
            51: "SPI1 global interrupt",
            52: "SPI2 global interrupt",
            53: "USART1 global interrupt",
            54: "USART2 global interrupt",
            55: "USART3 global interrupt",
        }
        return triggers.get(vector_index, "Peripheral interrupt")
    
    def _identify_functions(self):
        """识别函数"""
        logger.info("\n[2/5] 函数识别")
        
        # 从符号表添加函数
        for name, addr in self.symbols.items():
            if isinstance(name, str) and 0x08000000 <= addr < 0x08100000:
                if not name.startswith('$'):
                    self.functions[addr] = FunctionInfo(
                        address=addr,
                        name=name
                    )
        
        # 从中断向量表添加
        for handler in self.interrupt_handlers:
            if handler.handler_address not in self.functions:
                self.functions[handler.handler_address] = FunctionInfo(
                    address=handler.handler_address,
                    name=handler.handler_name,
                    is_interrupt_handler=True,
                    irq_number=handler.irq_number
                )
            else:
                self.functions[handler.handler_address].is_interrupt_handler = True
                self.functions[handler.handler_address].irq_number = handler.irq_number
        
        # 扫描BL指令发现更多函数
        for insn in self.instructions:
            if insn.mnemonic == 'bl':
                try:
                    target = int(insn.op_str.replace('#', ''), 16)
                    if target not in self.functions and 0x08000000 <= target < 0x08100000:
                        self.functions[target] = FunctionInfo(
                            address=target,
                            name=f"sub_{target:08X}"
                        )
                except:
                    pass
        
        logger.info(f"  识别函数: {len(self.functions)}个")
        logger.info(f"  中断处理程序: {sum(1 for f in self.functions.values() if f.is_interrupt_handler)}个")
    
    def _build_call_graph(self):
        """构建调用图"""
        logger.info("\n[3/5] 构建调用图")
        
        current_func = None
        
        for insn in self.instructions:
            # 判断当前指令属于哪个函数
            for addr in sorted(self.functions.keys(), reverse=True):
                if insn.address >= addr:
                    current_func = addr
                    break
            
            if current_func is None:
                continue
            
            # BL指令 = 直接调用
            if insn.mnemonic == 'bl':
                try:
                    target = int(insn.op_str.replace('#', ''), 16)
                    if target in self.functions:
                        self.call_graph[current_func].add(target)
                        self.reverse_call_graph[target].add(current_func)
                        self.functions[current_func].calls.append(target)
                        self.functions[target].callers.append(current_func)
                except:
                    pass
            
            # BLX Rx = 间接调用（虚函数等）
            elif insn.mnemonic == 'blx' and not insn.op_str.startswith('#'):
                # 标记为有间接调用
                pass
        
        total_edges = sum(len(callees) for callees in self.call_graph.values())
        logger.info(f"  调用边: {total_edges}")
    
    def _compute_reachability(self):
        """计算可达性"""
        logger.info("\n[4/5] 计算可达性")
        
        # 入口点: Reset handler + 所有非默认中断处理程序
        entry_points = set()
        
        for handler in self.interrupt_handlers:
            if not handler.is_default and handler.handler_address != 0:
                entry_points.add(handler.handler_address)
        
        # BFS遍历调用图
        visited = set()
        queue = list(entry_points)
        
        while queue:
            func_addr = queue.pop(0)
            if func_addr in visited:
                continue
            
            visited.add(func_addr)
            
            if func_addr in self.functions:
                self.functions[func_addr].is_reachable = True
            
            for callee in self.call_graph.get(func_addr, []):
                if callee not in visited:
                    queue.append(callee)
        
        reachable = sum(1 for f in self.functions.values() if f.is_reachable)
        unreachable = len(self.functions) - reachable
        
        logger.info(f"  可达函数: {reachable}")
        logger.info(f"  不可达函数: {unreachable}")
        
        if unreachable > 0:
            unreachable_funcs = [f for f in self.functions.values() if not f.is_reachable]
            logger.info(f"  不可达函数示例:")
            for f in unreachable_funcs[:5]:
                logger.info(f"    0x{f.address:08X}: {f.name}")
    
    def _infer_state_machines(self):
        """推断状态机"""
        logger.info("\n[5/5] 状态机推断")
        
        # 查找switch-case模式
        # 1. TBB/TBH指令
        # 2. 连续的CMP + 条件跳转
        
        state_candidates = []
        
        for i, insn in enumerate(self.instructions):
            # 查找TBB/TBH (跳转表)
            if insn.mnemonic in ['tbb', 'tbh']:
                # 往前找状态变量
                for j in range(max(0, i-10), i):
                    prev = self.instructions[j]
                    if prev.mnemonic in ['ldr', 'ldrb'] and 'r' in prev.op_str.lower():
                        state_candidates.append({
                            'type': 'jump_table',
                            'switch_pc': insn.address,
                            'load_pc': prev.address
                        })
                        break
            
            # 查找连续CMP模式
            if insn.mnemonic == 'cmp' and i + 1 < len(self.instructions):
                next_insn = self.instructions[i + 1]
                if next_insn.mnemonic in ['beq', 'bne', 'beq.w', 'bne.w']:
                    # 检查是否有多个连续的cmp-beq
                    consecutive = 1
                    for k in range(i + 2, min(i + 20, len(self.instructions)), 2):
                        if k + 1 < len(self.instructions):
                            i1 = self.instructions[k]
                            i2 = self.instructions[k + 1]
                            if i1.mnemonic == 'cmp' and i2.mnemonic in ['beq', 'bne', 'beq.w', 'bne.w']:
                                consecutive += 1
                            else:
                                break
                    
                    if consecutive >= 3:
                        state_candidates.append({
                            'type': 'cmp_chain',
                            'switch_pc': insn.address,
                            'states': consecutive
                        })
        
        # 创建状态机对象
        for candidate in state_candidates[:10]:  # 限制数量
            sm = StateMachine(
                state_variable_addr=0,
                state_variable_name=f"state_{candidate['switch_pc']:08X}",
                switch_pc=candidate['switch_pc']
            )
            self.state_machines.append(sm)
        
        logger.info(f"  发现状态机模式: {len(self.state_machines)}个")
    
    def _compute_call_depth(self) -> Dict[int, int]:
        """计算调用深度"""
        depth = {}
        
        def dfs(func_addr: int, current_depth: int, visited: Set[int]):
            if func_addr in visited:
                return
            
            visited.add(func_addr)
            depth[func_addr] = max(depth.get(func_addr, 0), current_depth)
            
            for callee in self.call_graph.get(func_addr, []):
                dfs(callee, current_depth + 1, visited.copy())
        
        # 从每个入口点开始
        for handler in self.interrupt_handlers:
            if not handler.is_default:
                dfs(handler.handler_address, 0, set())
        
        return depth
    
    # ================================================================
    # ⭐ RTOS 检测
    # ================================================================
    
    # RTOS特征符号
    RTOS_SIGNATURES = {
        'freertos': [
            'xTaskCreate', 'vTaskStartScheduler', 'xQueueCreate', 
            'xSemaphoreCreateMutex', 'vTaskDelay', 'pvPortMalloc',
            'xTaskGetCurrentTaskHandle', 'uxTaskGetStackHighWaterMark'
        ],
        'riot': [
            'thread_create', 'thread_sleep', 'mutex_lock', 'mutex_unlock',
            'msg_send', 'msg_receive', 'xtimer_sleep', 'shell_run',
            'gnrc_netif', 'auto_init'
        ],
        'zephyr': [
            'k_thread_create', 'k_sleep', 'k_mutex_lock', 'k_sem_take',
            'k_msgq_put', 'k_msgq_get', 'k_work_submit', 'k_timer_start',
            'sys_slist_append', 'z_thread_entry'
        ],
        'mbed': [
            'Thread', 'Mutex', 'Semaphore', 'Queue', 'Mail',
            'wait_ms', 'ThisThread', 'rtos_idle_loop', 'osKernelStart'
        ],
        'chibios': [
            'chThdCreateStatic', 'chSysInit', 'chMtxLock', 'chSemWait',
            'chMBFetch', 'chThdSleepMilliseconds', 'chVTSet'
        ],
        'rtthread': [
            'rt_thread_create', 'rt_thread_startup', 'rt_mutex_create',
            'rt_sem_create', 'rt_mq_create', 'rt_tick_get'
        ]
    }
    
    def _detect_rtos(self) -> RTOSInfo:
        """检测RTOS类型和关键函数"""
        logger.info("\n[7/8] RTOS检测")
        
        rtos_info = RTOSInfo()
        symbol_lower = {name.lower(): addr for name, addr in self.symbols.items()}
        
        best_match = None
        best_score = 0
        
        for rtos_type, signatures in self.RTOS_SIGNATURES.items():
            score = 0
            matched_funcs = []
            
            for sig in signatures:
                sig_lower = sig.lower()
                # 查找包含该签名的符号
                for sym_name, sym_addr in self.symbols.items():
                    if sig_lower in sym_name.lower():
                        score += 1
                        matched_funcs.append(sym_addr)
                        break
            
            if score > best_score:
                best_score = score
                best_match = rtos_type
                rtos_info.task_functions = matched_funcs
        
        if best_score >= 2:  # 至少匹配2个特征
            rtos_info.detected = True
            rtos_info.rtos_type = best_match
            rtos_info.confidence = min(best_score / 5.0, 1.0)
            
            logger.info(f"  ✅ 检测到RTOS: {best_match} (置信度: {rtos_info.confidence:.1%})")
            logger.info(f"  任务/线程函数: {len(rtos_info.task_functions)}个")
            
            # 提取调度器和同步原语函数
            for name, addr in self.symbols.items():
                name_lower = name.lower()
                if any(x in name_lower for x in ['scheduler', 'sched', 'dispatch', 'yield']):
                    rtos_info.scheduler_funcs.append(addr)
                elif any(x in name_lower for x in ['mutex', 'sem', 'lock', 'unlock']):
                    rtos_info.mutex_funcs.append(addr)
                elif any(x in name_lower for x in ['queue', 'msg', 'mail', 'mq']):
                    rtos_info.queue_funcs.append(addr)
        else:
            logger.info(f"  ℹ️ 未检测到已知RTOS (裸机固件)")
        
        return rtos_info
    
    # ================================================================
    # ⭐ 间接调用分析
    # ================================================================
    
    def _analyze_indirect_calls(self) -> List[IndirectCallInfo]:
        """分析间接调用（blx rX）"""
        logger.info("\n[8/8] 间接调用分析")
        
        indirect_calls = []
        
        if not HAS_CAPSTONE or not self.instructions:
            logger.warning("  无法进行间接调用分析（缺少Capstone或指令）")
            return indirect_calls
        
        # 查找所有blx rX指令
        for i, insn in enumerate(self.instructions):
            if insn.mnemonic in ['blx', 'bx']:
                op_str = insn.op_str.strip()
                
                # 检查是否是寄存器间接调用
                if op_str.startswith('r') and op_str[1:].isdigit():
                    call_info = IndirectCallInfo(
                        call_site=insn.address,
                        target_register=op_str
                    )
                    
                    # 回溯查找寄存器的来源
                    possible_targets = self._trace_register_source(i, op_str)
                    call_info.possible_targets = possible_targets
                    
                    # 确定所在函数
                    for func_addr, func_info in self.functions.items():
                        if func_addr <= insn.address < func_addr + func_info.size:
                            call_info.source_function = func_addr
                            break
                    
                    indirect_calls.append(call_info)
        
        logger.info(f"  发现间接调用: {len(indirect_calls)}个")
        
        # 统计可解析的间接调用
        resolved = sum(1 for c in indirect_calls if c.possible_targets)
        logger.info(f"  可解析目标: {resolved}个 ({resolved*100//max(1,len(indirect_calls))}%)")
        
        return indirect_calls
    
    def _trace_register_source(self, insn_idx: int, target_reg: str) -> List[int]:
        """回溯寄存器值来源"""
        possible_targets = []
        
        # 向后搜索最多50条指令
        search_range = min(insn_idx, 50)
        
        for i in range(insn_idx - 1, insn_idx - search_range - 1, -1):
            if i < 0:
                break
                
            insn = self.instructions[i]
            
            # ldr rX, [pc, #offset] - 从常量池加载
            if insn.mnemonic == 'ldr' and target_reg in insn.op_str:
                if 'pc' in insn.op_str.lower():
                    # 尝试解析PC相对加载
                    try:
                        # 简单的偏移解析
                        match = re.search(r'\[pc,\s*#(\d+)\]', insn.op_str)
                        if match:
                            offset = int(match.group(1))
                            pc_val = (insn.address + 4) & ~3  # Align
                            target_addr = self._read_word(pc_val + offset)
                            if target_addr and 0x08000000 <= target_addr < 0x08100000:
                                possible_targets.append(target_addr & ~1)
                    except:
                        pass
                    break
            
            # ldr rX, [rY, #offset] - 从内存加载
            elif insn.mnemonic == 'ldr' and insn.op_str.startswith(target_reg):
                # 可能是函数指针变量
                match = re.search(r'\[(r\d+),\s*#(\d+)\]', insn.op_str)
                if match:
                    # 记录可能的函数指针地址
                    break
            
            # mov rX, rY - 寄存器移动
            elif insn.mnemonic == 'mov' and insn.op_str.startswith(target_reg):
                parts = insn.op_str.split(',')
                if len(parts) == 2:
                    source_reg = parts[1].strip()
                    if source_reg.startswith('r'):
                        # 继续追踪源寄存器
                        target_reg = source_reg
            
            # 函数入口点（push）- 停止追踪
            elif insn.mnemonic == 'push':
                break
        
        return possible_targets
    
    def generate_interrupt_trigger_code(self) -> str:
        """生成中断触发C代码"""
        code = '''/*
 * Interrupt Trigger Generator
 * Auto-generated to maximize code coverage
 * 
 * Triggers all non-default interrupt handlers to execute
 * more code paths.
 */

#include "qemu/osdep.h"
#include "qemu/timer.h"
#include "hw/irq.h"

'''
        
        # 为每个非默认中断生成触发代码
        non_default = [h for h in self.interrupt_handlers 
                       if not h.is_default and h.handler_address != 0]
        
        code += f'''
/* Found {len(non_default)} non-default interrupt handlers */

typedef struct {{
    int irq_number;
    const char *name;
    uint64_t trigger_interval_ns;
}} InterruptTriggerConfig;

static const InterruptTriggerConfig g_interrupt_configs[] = {{
'''
        
        for handler in non_default[:30]:  # 限制数量
            interval = 10000000  # 10ms default
            
            # 根据类型调整间隔
            if 'TIM' in handler.handler_name or 'Timer' in handler.trigger_condition:
                interval = 1000000  # 1ms for timers
            elif 'USART' in handler.handler_name or 'UART' in handler.handler_name:
                interval = 5000000  # 5ms for UART
            elif 'SPI' in handler.handler_name:
                interval = 2000000  # 2ms for SPI
            
            code += f'    {{{handler.irq_number}, "{handler.handler_name}", {interval}ULL}},\n'
        
        code += '''    {-1, NULL, 0}  /* Sentinel */
};

static QEMUTimer *g_irq_timers[100];
static qemu_irq *g_nvic_irqs = NULL;

static void interrupt_trigger_callback(void *opaque)
{
    int idx = (int)(intptr_t)opaque;
    const InterruptTriggerConfig *cfg = &g_interrupt_configs[idx];
    
    if (cfg->irq_number >= 0 && g_nvic_irqs) {
        qemu_irq_pulse(g_nvic_irqs[cfg->irq_number]);
        
        /* Reschedule */
        timer_mod(g_irq_timers[idx],
                  qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + cfg->trigger_interval_ns);
    }
}

void init_interrupt_triggers(qemu_irq *nvic_irqs)
{
    g_nvic_irqs = nvic_irqs;
    
    for (int i = 0; g_interrupt_configs[i].irq_number >= 0; i++) {
        g_irq_timers[i] = timer_new_ns(QEMU_CLOCK_VIRTUAL,
                                        interrupt_trigger_callback,
                                        (void *)(intptr_t)i);
        
        /* Stagger the initial triggers */
        timer_mod(g_irq_timers[i],
                  qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + 
                  g_interrupt_configs[i].trigger_interval_ns + i * 100000);
    }
}

'''
        
        return code
    
    def get_uncovered_code_summary(self) -> Dict[str, Any]:
        """获取未覆盖代码摘要"""
        unreachable_funcs = [f for f in self.functions.values() if not f.is_reachable]
        interrupt_handlers = [h for h in self.interrupt_handlers if not h.is_default]
        
        # 估算未覆盖代码
        estimated_pcs = 0
        for func in unreachable_funcs:
            # 假设每个函数平均20条指令
            estimated_pcs += 20
        
        return {
            'unreachable_functions': len(unreachable_funcs),
            'interrupt_handlers': len(interrupt_handlers),
            'state_machines': len(self.state_machines),
            'estimated_uncovered_pcs': estimated_pcs,
            'top_unreachable': [
                {'address': f'0x{f.address:08X}', 'name': f.name}
                for f in unreachable_funcs[:10]
            ],
            'interrupt_handler_addresses': [
                {'irq': h.irq_number, 'address': f'0x{h.handler_address:08X}', 
                 'name': h.handler_name, 'trigger': h.trigger_condition}
                for h in interrupt_handlers[:20]
            ]
        }


def analyze_code(firmware_path: str) -> CallGraphAnalysisResult:
    """便捷函数"""
    analyzer = AdvancedCodeAnalyzer(firmware_path)
    return analyzer.analyze_all()


if __name__ == '__main__':
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python advanced_code_analysis.py <firmware.elf>")
        sys.exit(1)
    
    analyzer = AdvancedCodeAnalyzer(sys.argv[1])
    result = analyzer.analyze_all()
    
    print("\n" + "=" * 60)
    print("分析结果摘要")
    print("=" * 60)
    
    print(f"\n函数总数: {len(result.functions)}")
    print(f"不可达函数: {len(result.unreachable_functions)}")
    print(f"中断处理程序: {len(result.interrupt_handlers)}")
    print(f"状态机模式: {len(result.state_machines)}")
    
    print("\n非默认中断处理程序:")
    for h in result.interrupt_handlers[:15]:
        if not h.is_default and h.handler_address != 0:
            print(f"  IRQ{h.irq_number:3d}: 0x{h.handler_address:08X} ({h.handler_name})")
    
    # 生成中断触发代码
    code = analyzer.generate_interrupt_trigger_code()
    print(f"\n生成中断触发代码: {len(code)} 字节")
    
    summary = analyzer.get_uncovered_code_summary()
    print(f"\n预估可增加的PC: {summary['estimated_uncovered_pcs']}")


