
#!/usr/bin/env python3
"""
高级行为分析器模块
负责提取时序、概率、中断、数据通路、初始化和环境约束信息
"""

import logging
import re
from typing import Dict, List, Optional, Set, Tuple, Any
from dataclasses import dataclass, field
from collections import defaultdict, Counter

try:
    import capstone
    from capstone import CS_ARCH_ARM, CS_ARCH_ARM64
    HAS_CAPSTONE = True
except ImportError:
    HAS_CAPSTONE = False

logger = logging.getLogger(__name__)

@dataclass
class DelayStats:
    """延迟统计信息 (3.1)"""
    event_type: str  # 'write_to_irq', 'write_to_status_change'
    median_ms: Optional[float] = None
    p75_ms: Optional[float] = None
    max_ms: Optional[float] = None
    sample_count: int = 0
    # 静态分析预估值
    estimated_delay_ms: Optional[float] = None

@dataclass
class ProbabilisticBehavior:
    """概率行为 (3.2)"""
    offset: int
    mask: int
    value: int
    probability: float
    behavior_type: str  # 'random_ready', 'occasional_error', 'timeout'

@dataclass
class IRQMapping:
    """中断映射 (4.1)"""
    irq_number: int
    irq_line: Optional[int] = None
    trigger_condition: Dict[str, Any] = field(default_factory=dict)
    isr_function: Optional[str] = None
    vector_table_offset: Optional[int] = None

@dataclass
class FIFODefinition:
    """FIFO定义 (5.1)"""
    offset: int
    depth_estimate: int
    element_size: int  # 1, 2, 4 bytes
    behavior: str  # 'push_on_write', 'pop_on_read'
    status_offset: Optional[int] = None
    full_flag_mask: Optional[int] = None
    empty_flag_mask: Optional[int] = None

@dataclass
class DMADescriptorPattern:
    """DMA描述符模式 (5.2)"""
    descriptor_ptr_reg: int
    status_reg: int
    control_reg: Optional[int] = None
    descriptor_layout: Dict[str, int] = field(default_factory=dict)  # {'off_ptr': 0, 'off_len': 4}
    completion_irq: Optional[int] = None

@dataclass
class InitSequence:
    """初始化序列 (6.1)"""
    sequence: List[Dict[str, Any]]  # [{'offset': 0x00, 'value': 0x123, 'delay_ms': 0}]
    function_name: Optional[str] = None
    confidence: float = 1.0

@dataclass
class ClockDomain:
    """时钟域 (7.1)"""
    name: str
    source: str  # 'HSI', 'HSE', 'PLL', 'APB1', 'APB2'
    frequency_hz: Optional[int] = None
    prescaler: Optional[int] = None

@dataclass
class MemoryRegion:
    """内存区域 (7.2)"""
    name: str
    start: int
    size: int
    type: str  # 'FLASH', 'SRAM', 'PERIPHERAL', 'RESERVED'
    readable: bool = True
    writable: bool = False
    executable: bool = False

@dataclass
class AdvancedBehaviorInfo:
    """高级行为信息汇总"""
    base_address: int
    # 3. 时序与概率
    delay_stats: Dict[str, DelayStats] = field(default_factory=dict)
    probabilistic_behaviors: List[ProbabilisticBehavior] = field(default_factory=list)
    # 4. 事件与中断
    irq_mappings: List[IRQMapping] = field(default_factory=list)
    # 5. 数据通路
    fifo_definitions: List[FIFODefinition] = field(default_factory=list)
    dma_descriptor_patterns: List[DMADescriptorPattern] = field(default_factory=list)
    # 6. 初始化与配置
    init_sequences: List[InitSequence] = field(default_factory=list)
    # 7. 环境与约束
    clock_domain: Optional[ClockDomain] = None
    memory_regions: List[MemoryRegion] = field(default_factory=list)

class AdvancedBehaviorAnalyzer:
    """
    高级行为分析器
    处理时序、概率、中断、数据通路、初始化和环境约束信息
    """
    
    def __init__(self, elf_analyzer=None):
        self.elf_analyzer = elf_analyzer
        self.vector_table = {}
        self.isr_functions = {}
        self.clock_configs = {}
        
    def analyze_advanced_behaviors(self, peripheral_candidate, instructions: List,
                                 register_accesses: List, behavior_semantics) -> AdvancedBehaviorInfo:
        """
        分析高级行为信息
        
        Args:
            peripheral_candidate: 外设候选
            instructions: 指令列表
            register_accesses: 寄存器访问记录
            behavior_semantics: 基础行为语义
        
        Returns:
            AdvancedBehaviorInfo: 高级行为信息
        """
        logger.info(f"Analyzing advanced behaviors for peripheral at 0x{peripheral_candidate.base_address:08x}")
        
        info = AdvancedBehaviorInfo(base_address=peripheral_candidate.base_address)
        
        # 3. 时序与概率分析（静态预估）
        info.delay_stats = self._analyze_delay_stats_static(
            peripheral_candidate, instructions, register_accesses
        )
        info.probabilistic_behaviors = self._analyze_probabilistic_behaviors_static(
            peripheral_candidate, behavior_semantics
        )
        
        # 4. 中断映射分析
        info.irq_mappings = self._analyze_irq_mappings(
            peripheral_candidate, instructions, register_accesses
        )
        
        # 5. 数据通路分析
        info.fifo_definitions = self._analyze_fifo_definitions(
            peripheral_candidate, behavior_semantics, register_accesses
        )
        info.dma_descriptor_patterns = self._analyze_dma_patterns(
            peripheral_candidate, instructions, register_accesses
        )
        
        # 6. 初始化序列分析
        info.init_sequences = self._analyze_init_sequences(
            peripheral_candidate, instructions, register_accesses
        )
        
        # 7. 环境约束分析
        info.clock_domain = self._analyze_clock_domain(
            peripheral_candidate, instructions
        )
        info.memory_regions = self._get_memory_regions()
        
        return info
    
    def _analyze_delay_stats_static(self, peripheral_candidate, instructions: List,
                                   register_accesses: List) -> Dict[str, DelayStats]:
        """
        静态分析延迟统计 (3.1)
        基于指令序列和循环估算延迟
        """
        logger.info("Analyzing delay statistics (static estimation)")
        delay_stats = {}
        
        # 查找写操作到状态检查的延迟
        for access in register_accesses:
            if (access.base_address == peripheral_candidate.base_address and 
                access.access_type == 'write'):
                
                # 查找后续的状态检查
                status_checks = self._find_subsequent_status_checks(
                    instructions, access.instruction_addr, peripheral_candidate.base_address
                )
                
                for check in status_checks:
                    delay_key = f"write_0x{access.offset:02x}_to_status_check"
                    if delay_key not in delay_stats:
                        # 基于指令数量估算延迟
                        instruction_count = abs(check['addr'] - access.instruction_addr) // 4
                        estimated_delay = self._estimate_delay_from_instructions(instruction_count)
                        
                        delay_stats[delay_key] = DelayStats(
                            event_type=delay_key,
                            estimated_delay_ms=estimated_delay,
                            sample_count=1
                        )
                        
                        logger.debug(f"  Estimated delay for {delay_key}: {estimated_delay}ms")
        
        # 查找写操作到中断的延迟
        irq_delays = self._estimate_write_to_irq_delays(
            peripheral_candidate, instructions, register_accesses
        )
        delay_stats.update(irq_delays)
        
        return delay_stats
    
    def _analyze_probabilistic_behaviors_static(self, peripheral_candidate, 
                                              behavior_semantics) -> List[ProbabilisticBehavior]:
        """
        静态分析概率行为 (3.2)
        基于访问模式推断可能的概率行为
        """
        logger.info("Analyzing probabilistic behaviors (static inference)")
        behaviors = []
        
        if not behavior_semantics or not behavior_semantics.access_patterns:
            return behaviors
        
        for offset, pattern in behavior_semantics.access_patterns.items():
            # 状态寄存器可能有概率行为
            if pattern.register_type == 'status' and pattern.read_count > 5:
                # 基于读取频率推断可能的概率行为
                if pattern.read_count > pattern.write_count * 3:
                    # 频繁读取可能表示等待随机事件
                    behavior = ProbabilisticBehavior(
                        offset=offset,
                        mask=0x01,  # 假设最低位是状态位
                        value=1,
                        probability=0.1,  # 默认10%概率
                        behavior_type='random_ready'
                    )
                    behaviors.append(behavior)
                    
                    logger.debug(f"  Inferred probabilistic behavior at 0x{offset:02x}: random_ready")
        
        return behaviors
    
    def _analyze_irq_mappings(self, peripheral_candidate, instructions: List,
                             register_accesses: List) -> List[IRQMapping]:
        """
        分析中断映射 (4.1)
        从向量表和ISR函数分析中断映射
        """
        logger.info("Analyzing IRQ mappings")
        mappings = []
        
        # 1. 解析向量表
        vector_table = self._parse_vector_table()
        
        # 2. 查找ISR函数
        isr_functions = self._find_isr_functions()
        
        # 3. 关联外设访问与中断
        for access in register_accesses:
            if access.base_address == peripheral_candidate.base_address:
                # 查找访问后的中断相关操作
                irq_ops = self._find_irq_operations_near_access(instructions, access)
                
                for irq_op in irq_ops:
                    if irq_op['irq_number'] in vector_table:
                        mapping = IRQMapping(
                            irq_number=irq_op['irq_number'],
                            irq_line=irq_op['irq_number'],
                            trigger_condition={
                                'type': 'on_write',
                                'offset': access.offset,
                                'mask': 0xFF,  # 默认全字节
                                'value': 1
                            },
                            isr_function=vector_table.get(irq_op['irq_number']),
                            vector_table_offset=irq_op['irq_number'] * 4
                        )
                        mappings.append(mapping)
                        
                        logger.debug(f"  Found IRQ mapping: IRQ{irq_op['irq_number']} -> "
                                   f"write 0x{access.offset:02x}")
        
        return mappings
    
    def _analyze_fifo_definitions(self, peripheral_candidate, behavior_semantics,
                                 register_accesses: List) -> List[FIFODefinition]:
        """
        分析FIFO定义 (5.1)
        基于访问模式识别FIFO行为
        """
        logger.info("Analyzing FIFO definitions")
        fifos = []
        
        if not behavior_semantics or not behavior_semantics.access_patterns:
            return fifos
        
        for offset, pattern in behavior_semantics.access_patterns.items():
            # 频繁访问的数据寄存器可能是FIFO
            total_accesses = pattern.read_count + pattern.write_count
            if total_accesses > 10:  # 频繁访问阈值
                
                # 查找关联的状态寄存器
                status_offset = self._find_fifo_status_register(
                    offset, behavior_semantics.access_patterns
                )
                
                # 估算FIFO深度（基于连续访问模式）
                depth_estimate = self._estimate_fifo_depth(
                    peripheral_candidate.base_address, offset, register_accesses
                )
                
                # 确定FIFO行为
                if pattern.write_count > pattern.read_count:
                    behavior = 'push_on_write'
                else:
                    behavior = 'pop_on_read'
                
                fifo = FIFODefinition(
                    offset=offset,
                    depth_estimate=depth_estimate,
                    element_size=4,  # 默认4字节
                    behavior=behavior,
                    status_offset=status_offset,
                    full_flag_mask=0x02,  # 假设bit1是满标志
                    empty_flag_mask=0x01  # 假设bit0是空标志
                )
                fifos.append(fifo)
                
                logger.debug(f"  Found FIFO at 0x{offset:02x}: {behavior}, depth~{depth_estimate}")
        
        return fifos
    
    def _analyze_dma_patterns(self, peripheral_candidate, instructions: List,
                             register_accesses: List) -> List[DMADescriptorPattern]:
        """
        分析DMA描述符模式 (5.2)
        识别DMA相关的寄存器配置模式
        """
        logger.info("Analyzing DMA descriptor patterns")
        patterns = []
        
        # 查找DMA相关的函数和寄存器访问
        dma_accesses = []
        for access in register_accesses:
            if (access.base_address == peripheral_candidate.base_address and
                access.function_name):
                
                func_lower = access.function_name.lower()
                if any(keyword in func_lower for keyword in ['dma', 'transfer', 'descriptor']):
                    dma_accesses.append(access)
        
        if len(dma_accesses) >= 3:  # 至少需要3个寄存器（指针、长度、控制）
            # 分析DMA寄存器布局
            offsets = sorted([access.offset for access in dma_accesses])
            
            # 假设第一个是描述符指针，第二个是状态，第三个是控制
            if len(offsets) >= 2:
                pattern = DMADescriptorPattern(
                    descriptor_ptr_reg=offsets[0],
                    status_reg=offsets[1],
                    control_reg=offsets[2] if len(offsets) > 2 else None,
                    descriptor_layout={
                        'off_ptr': 0,
                        'off_len': 4,
                        'off_ctrl': 8
                    }
                )
                
                # 查找关联的中断
                completion_irq = self._find_dma_completion_irq(
                    peripheral_candidate, instructions, dma_accesses
                )
                if completion_irq:
                    pattern.completion_irq = completion_irq
                
                patterns.append(pattern)
                
                logger.debug(f"  Found DMA pattern: ptr=0x{pattern.descriptor_ptr_reg:02x}, "
                           f"status=0x{pattern.status_reg:02x}")
        
        return patterns
    
    def _analyze_init_sequences(self, peripheral_candidate, instructions: List,
                               register_accesses: List) -> List[InitSequence]:
        """
        分析初始化序列 (6.1)
        识别外设初始化的寄存器配置序列
        """
        logger.info("Analyzing initialization sequences")
        sequences = []
        
        # 查找初始化相关的函数
        init_functions = set()
        for access in register_accesses:
            if (access.base_address == peripheral_candidate.base_address and
                access.function_name):
                
                func_lower = access.function_name.lower()
                if any(keyword in func_lower for keyword in ['init', 'config', 'setup', 'enable']):
                    init_functions.add(access.function_name)
        
        # 分析每个初始化函数的写序列
        for func_name in init_functions:
            func_accesses = [
                access for access in register_accesses
                if (access.base_address == peripheral_candidate.base_address and
                    access.function_name == func_name and
                    access.access_type == 'write')
            ]
            
            if len(func_accesses) >= 2:  # 至少2个写操作
                # 按指令地址排序
                func_accesses.sort(key=lambda x: x.instruction_addr)
                
                # 提取写序列
                sequence_steps = []
                for access in func_accesses:
                    # 尝试从指令中提取写入值
                    value = self._extract_write_value_from_access(access, instructions)
                    
                    step = {
                        'offset': access.offset,
                        'value': value if value is not None else 0,
                        'delay_ms': 0  # 静态分析无法确定延迟
                    }
                    sequence_steps.append(step)
                
                sequence = InitSequence(
                    sequence=sequence_steps,
                    function_name=func_name,
                    confidence=0.8
                )
                sequences.append(sequence)
                
                logger.debug(f"  Found init sequence in {func_name}: {len(sequence_steps)} steps")
        
        return sequences
    
    def _analyze_clock_domain(self, peripheral_candidate, instructions: List) -> Optional[ClockDomain]:
        """
        分析时钟域 (7.1)
        基于外设基址推断时钟域
        """
        logger.info("Analyzing clock domain")
        
        base_addr = peripheral_candidate.base_address
        
        # ARM Cortex-M常见外设时钟域映射
        clock_mappings = {
            # APB1 (通常42MHz)
            (0x40000000, 0x40007FFF): ('APB1', 42000000),
            # APB2 (通常84MHz)  
            (0x40010000, 0x40016FFF): ('APB2', 84000000),
            # AHB1 (通常168MHz)
            (0x40020000, 0x4007FFFF): ('AHB1', 168000000),
            # AHB2
            (0x50000000, 0x5007FFFF): ('AHB2', 168000000),
        }
        
        for (start, end), (domain, freq) in clock_mappings.items():
            if start <= base_addr <= end:
                clock_domain = ClockDomain(
                    name=f"{domain}_CLK",
                    source=domain,
                    frequency_hz=freq
                )
                
                logger.debug(f"  Inferred clock domain: {domain} @ {freq}Hz")
                return clock_domain
        
        # 默认时钟域
        return ClockDomain(
            name="UNKNOWN_CLK",
            source="UNKNOWN",
            frequency_hz=None
        )
    
    def _get_memory_regions(self) -> List[MemoryRegion]:
        """
        获取内存区域信息 (7.2)
        从ELF分析器获取内存布局
        """
        logger.info("Getting memory regions")
        regions = []
        
        if self.elf_analyzer and hasattr(self.elf_analyzer, 'memory_regions'):
            for region in self.elf_analyzer.memory_regions:
                memory_region = MemoryRegion(
                    name=region.name,
                    start=region.start,
                    size=region.end - region.start + 1,
                    type=region.type.upper(),
                    readable=region.readable,
                    writable=region.writable,
                    executable=region.executable
                )
                regions.append(memory_region)
        
        # 添加常见的ARM Cortex-M内存区域
        if not regions:
            regions = [
                MemoryRegion(
                    name="FLASH",
                    start=0x08000000,
                    size=0x100000,  # 1MB
                    type="FLASH",
                    readable=True,
                    writable=False,
                    executable=True
                ),
                MemoryRegion(
                    name="SRAM",
                    start=0x20000000,
                    size=0x20000,  # 128KB
                    type="SRAM",
                    readable=True,
                    writable=True,
                    executable=False
                ),
                MemoryRegion(
                    name="PERIPHERAL",
                    start=0x40000000,
                    size=0x20000000,  # 512MB
                    type="PERIPHERAL",
                    readable=True,
                    writable=True,
                    executable=False
                )
            ]
        
        logger.debug(f"  Found {len(regions)} memory regions")
        return regions
    
    # === 辅助方法 ===
    
    def _find_subsequent_status_checks(self, instructions: List, write_addr: int,
                                     base_address: int) -> List[Dict]:
        """查找写操作后的状态检查"""
        checks = []
        
        # 在写操作后的200条指令内查找状态检查
        for insn in instructions:
            if (insn.address > write_addr and 
                insn.address < write_addr + 200 * 4):
                
                # 检查是否是状态检查指令
                if self._is_status_check_instruction(insn, base_address):
                    checks.append({
                        'addr': insn.address,
                        'instruction': f"{insn.mnemonic} {insn.op_str}",
                        'type': 'status_check'
                    })
        
        return checks
    
    def _is_status_check_instruction(self, insn, base_address: int) -> bool:
        """检查是否是状态检查指令"""
        try:
            # 检查是否是读取指令
            if insn.mnemonic.lower() in ['ldr', 'ldrb', 'ldrh']:
                # 检查是否访问外设地址
                for operand in insn.operands:
                    if hasattr(operand, 'mem') and operand.mem:
                        if operand.mem.base != 0:
                            continue
                        addr = operand.mem.disp
                        if abs(addr - base_address) < 0x1000:  # 4KB范围内
                            return True
        except:
            pass
        return False
    
    def _estimate_delay_from_instructions(self, instruction_count: int) -> float:
        """基于指令数量估算延迟"""
        # 假设每条指令1个时钟周期，72MHz时钟
        cycles = instruction_count
        clock_freq = 72000000  # 72MHz
        delay_seconds = cycles / clock_freq
        return delay_seconds * 1000  # 转换为毫秒
    
    def _estimate_write_to_irq_delays(self, peripheral_candidate, instructions: List,
                                    register_accesses: List) -> Dict[str, DelayStats]:
        """估算写操作到中断的延迟"""
        delays = {}
        
        # 查找写操作后的中断使能
        for access in register_accesses:
            if (access.base_address == peripheral_candidate.base_address and 
                access.access_type == 'write'):
                
                # 查找后续的中断相关指令
                irq_ops = self._find_irq_operations_near_access(instructions, access)
                
                for irq_op in irq_ops:
                    delay_key = f"write_0x{access.offset:02x}_to_irq"
                    instruction_count = abs(irq_op['addr'] - access.instruction_addr) // 4
                    estimated_delay = self._estimate_delay_from_instructions(instruction_count)
                    
                    delays[delay_key] = DelayStats(
                        event_type=delay_key,
                        estimated_delay_ms=estimated_delay,
                        sample_count=1
                    )
        
        return delays
    
    def _parse_vector_table(self) -> Dict[int, str]:
        """解析向量表"""
        vector_table = {}
        
        if not self.elf_analyzer or not self.elf_analyzer.elf_info:
            return vector_table
        
        # 查找向量表相关的符号
        symbols = self.elf_analyzer.elf_info.symbols
        for name, info in symbols.items():
            if 'handler' in name.lower() or 'isr' in name.lower():
                # 尝试从符号名推断中断号
                irq_num = self._extract_irq_number_from_symbol(name)
                if irq_num is not None:
                    vector_table[irq_num] = name
        
        return vector_table
    
    def _find_isr_functions(self) -> Dict[str, Dict]:
        """查找ISR函数"""
        isr_functions = {}
        
        if not self.elf_analyzer or not self.elf_analyzer.elf_info:
            return isr_functions
        
        symbols = self.elf_analyzer.elf_info.symbols
        for name, info in symbols.items():
            if (info['type'] == 'STT_FUNC' and 
                ('handler' in name.lower() or 'isr' in name.lower())):
                isr_functions[name] = info
        
        return isr_functions
    
    def _find_irq_operations_near_access(self, instructions: List, access) -> List[Dict]:
        """查找访问附近的中断操作"""
        irq_ops = []
        
        # NVIC基址
        nvic_base = 0xE000E000
        
        # 在访问前后100条指令内查找NVIC操作
        for insn in instructions:
            if abs(insn.address - access.instruction_addr) < 100 * 4:
                # 检查是否访问NVIC寄存器
                for operand in insn.operands:
                    if hasattr(operand, 'mem') and operand.mem:
                        addr = operand.mem.disp
                        if nvic_base <= addr < nvic_base + 0x1000:
                            irq_number = self._extract_irq_from_nvic_addr(addr)
                            if irq_number is not None:
                                irq_ops.append({
                                    'addr': insn.address,
                                    'irq_number': irq_number,
                                    'operation': insn.mnemonic
                                })
        
        return irq_ops
    
    def _find_fifo_status_register(self, data_offset: int, access_patterns: Dict) -> Optional[int]:
        """查找FIFO的状态寄存器"""
        # 查找附近的状态寄存器
        for offset, pattern in access_patterns.items():
            if (offset != data_offset and 
                pattern.register_type == 'status' and
                abs(offset - data_offset) <= 0x10):  # 16字节范围内
                return offset
        return None
    
    def _estimate_fifo_depth(self, base_address: int, offset: int, 
                           register_accesses: List) -> int:
        """估算FIFO深度"""
        # 统计连续访问的最大次数
        consecutive_accesses = []
        current_count = 0
        last_addr = None
        
        for access in register_accesses:
            if (access.base_address == base_address and 
                access.offset == offset):
                
                if last_addr and abs(access.instruction_addr - last_addr) < 50:
                    current_count += 1
                else:
                    if current_count > 0:
                        consecutive_accesses.append(current_count)
                    current_count = 1
                
                last_addr = access.instruction_addr
        
        if current_count > 0:
            consecutive_accesses.append(current_count)
        
        # 返回最大连续访问次数作为深度估计
        return max(consecutive_accesses) if consecutive_accesses else 16
    
    def _find_dma_completion_irq(self, peripheral_candidate, instructions: List,
                               dma_accesses: List) -> Optional[int]:
        """查找DMA完成中断"""
        # 在DMA访问附近查找中断操作
        for access in dma_accesses:
            irq_ops = self._find_irq_operations_near_access(instructions, access)
            if irq_ops:
                return irq_ops[0]['irq_number']
        return None
    
    def _extract_write_value_from_access(self, access, instructions: List) -> Optional[int]:
        """从访问记录中提取写入值"""
        # 查找访问指令
        for insn in instructions:
            if insn.address == access.instruction_addr:
                # 尝试从指令中提取立即数
                for operand in insn.operands:
                    if operand.type in [capstone.arm.ARM_OP_IMM, capstone.arm64.ARM64_OP_IMM]:
                        return operand.imm
        return None
    
    def _extract_irq_number_from_symbol(self, symbol_name: str) -> Optional[int]:
        """从符号名提取中断号"""
        # 尝试从符号名中提取数字
        import re
        matches = re.findall(r'\d+', symbol_name)
        if matches:
            return int(matches[-1])  # 取最后一个数字
        return None
    
    def _extract_irq_from_nvic_addr(self, nvic_addr: int) -> Optional[int]:
        """从NVIC地址提取中断号"""
        nvic_base = 0xE000E000
        relative_addr = nvic_addr - nvic_base
        
        # NVIC ISER (Interrupt Set Enable Register)
        if 0x100 <= relative_addr < 0x120:
            reg_index = (relative_addr - 0x100) // 4
            return reg_index * 32  # 粗略估计
        
        return None
    
    def export_advanced_behaviors(self, advanced_info: AdvancedBehaviorInfo, output_path: str):
        """导出高级行为信息到JSON"""
        import json
        
        export_data = {
            'base_address': f"0x{advanced_info.base_address:08x}",
            
            # 3. 时序与概率
            'timing': {},
            'probabilities': [],
            
            # 4. 事件与中断
            'irqs': [],
            
            # 5. 数据通路
            'fifo': [],
            'dma': [],
            
            # 6. 初始化与配置
            'init_sequence': [],
            
            # 7. 环境与约束
            'clock': {},
            'memory_map': []
        }
        
        # 导出延迟统计
        for event_type, delay_stats in advanced_info.delay_stats.items():
            export_data['timing'][event_type] = {
                'median_ms': delay_stats.median_ms,
                'p75_ms': delay_stats.p75_ms,
                'max_ms': delay_stats.max_ms,
                'estimated_ms': delay_stats.estimated_delay_ms
            }
        
        # 导出概率行为
        for prob_behavior in advanced_info.probabilistic_behaviors:
            export_data['probabilities'].append({
                'offset': f"0x{prob_behavior.offset:02x}",
                'mask': f"0x{prob_behavior.mask:02x}",
                'value': prob_behavior.value,
                'prob': prob_behavior.probability,
                'type': prob_behavior.behavior_type
            })
        
        # 导出中断映射
        for irq_mapping in advanced_info.irq_mappings:
            export_data['irqs'].append({
                'line': irq_mapping.irq_number,
                'trigger': irq_mapping.trigger_condition,
                'isr_function': irq_mapping.isr_function
            })
        
        # 导出FIFO定义
        for fifo_def in advanced_info.fifo_definitions:
            export_data['fifo'].append({
                'offset': f"0x{fifo_def.offset:02x}",
                'depth': fifo_def.depth_estimate,
                'elem_size': fifo_def.element_size,
                'behavior': fifo_def.behavior,
                'status_offset': f"0x{fifo_def.status_offset:02x}" if fifo_def.status_offset else None
            })
        
        # 导出DMA模式
        for dma_pattern in advanced_info.dma_descriptor_patterns:
            export_data['dma'].append({
                'descr_ptr_reg': f"0x{dma_pattern.descriptor_ptr_reg:02x}",
                'status_reg': f"0x{dma_pattern.status_reg:02x}",
                'descr_layout': dma_pattern.descriptor_layout,
                'completion_irq': dma_pattern.completion_irq
            })
        
        # 导出初始化序列
        for init_seq in advanced_info.init_sequences:
            sequence_data = []
            for step in init_seq.sequence:
                sequence_data.append({
                    'offset': f"0x{step['offset']:02x}",
                    'value': f"0x{step['value']:x}" if isinstance(step['value'], int) else step['value']
                })
            
            export_data['init_sequence'].append({
                'function': init_seq.function_name,
                'sequence': sequence_data,
                'confidence': init_seq.confidence
            })
        
        # 导出时钟域
        if advanced_info.clock_domain:
            export_data['clock'] = {
                'src': advanced_info.clock_domain.source,
                'freq_hz': advanced_info.clock_domain.frequency_hz
            }
        
        # 导出内存区域
        for region in advanced_info.memory_regions:
            export_data['memory_map'].append({
                'name': region.name,
                'start': f"0x{region.start:08x}",
                'size': f"0x{region.size:x}",
                'type': region.type
            })
        
        # 保存到文件
        with open(output_path, 'w') as f:
            json.dump(export_data, f, indent=2)
        
        logger.info(f"Exported advanced behavior info to {output_path}")
        return export_data
