
#!/usr/bin/env python3
"""
行为语义提取器模块
负责从静态分析结果中提取寄存器访问模式、位域签名和抽象原语
"""

import logging
from typing import Dict, List, Optional, Set, Tuple, Any
from dataclasses import dataclass, field
from collections import defaultdict, Counter
import re

try:
    import capstone
    from capstone import CS_ARCH_ARM, CS_ARCH_ARM64
    HAS_CAPSTONE = True
except ImportError:
    HAS_CAPSTONE = False

logger = logging.getLogger(__name__)

@dataclass
class AccessPattern:
    """寄存器访问模式"""
    offset: int
    read_count: int = 0
    write_count: int = 0
    read_after_write_count: int = 0
    common_values: List[int] = field(default_factory=list)
    read_after_write_rate: float = 0.0
    register_type: Optional[str] = None  # 'data', 'status', 'control'

@dataclass
class BitfieldSignature:
    """位域签名"""
    offset: int
    mask: int
    meaning: str  # 'flag', 'enable', 'clear-on-read', etc.
    behavior: str  # 'poll_flag', 'enable_bit', 'status_bit', etc.
    usage_count: int = 0
    associated_instructions: List[str] = field(default_factory=list)

@dataclass
class BehaviorPrimitive:
    """行为原语"""
    type: str  # 'wait_clear', 'wait_set', 'irq_on_write', 'init_sequence', 'fifo_push', 'dma_start'
    offset: int
    mask: Optional[int] = None
    timeout_ms: Optional[int] = None
    parameters: Dict[str, Any] = field(default_factory=dict)
    evidence: List[str] = field(default_factory=list)
    confidence: float = 1.0

@dataclass
class BehaviorSemantics:
    """完整的行为语义"""
    base_address: int
    access_patterns: Dict[int, AccessPattern]
    bitfield_signatures: Dict[int, List[BitfieldSignature]]
    primitives: List[BehaviorPrimitive]
    peripheral_behavior_type: Optional[str] = None  # 'polling_device', 'interrupt_driven', 'dma_capable'

class BehaviorSemanticExtractor:
    """
    行为语义提取器
    从静态分析结果中提取高级行为语义
    """
    
    def __init__(self, elf_analyzer=None):
        self.elf_analyzer = elf_analyzer
        self.instruction_cache = {}
        self.loop_patterns = []
        self.init_sequences = []
        
    def extract_behavior_semantics(self, peripheral_candidate, instructions: List, 
                                  register_accesses: List) -> BehaviorSemantics:
        """
        提取完整的行为语义
        
        Args:
            peripheral_candidate: 外设候选对象
            instructions: 指令列表
            register_accesses: 寄存器访问记录列表
        
        Returns:
            BehaviorSemantics: 完整的行为语义
        """
        logger.info(f"Extracting behavior semantics for peripheral at 0x{peripheral_candidate.base_address:08x}")
        
        # 步骤1: 提取访问模式
        access_patterns = self._extract_access_patterns(peripheral_candidate, register_accesses)
        
        # 步骤2: 提取位域签名
        bitfield_signatures = self._extract_bitfield_signatures(
            peripheral_candidate, instructions, register_accesses
        )
        
        # 步骤3: 提取行为原语
        primitives = self._extract_behavior_primitives(
            peripheral_candidate, instructions, register_accesses, access_patterns
        )
        
        # 步骤4: 推断外设行为类型
        behavior_type = self._infer_peripheral_behavior_type(
            access_patterns, bitfield_signatures, primitives
        )
        
        return BehaviorSemantics(
            base_address=peripheral_candidate.base_address,
            access_patterns=access_patterns,
            bitfield_signatures=bitfield_signatures,
            primitives=primitives,
            peripheral_behavior_type=behavior_type
        )
    
    def _extract_access_patterns(self, peripheral_candidate, 
                                register_accesses: List) -> Dict[int, AccessPattern]:
        """
        提取寄存器访问模式 (2.1)
        
        统计每个寄存器的：
        - 读写次数
        - 读后写比率
        - 常见值
        - 寄存器类型推断
        """
        logger.info("Extracting access patterns")
        patterns = {}
        
        # 按偏移分组访问记录
        offset_accesses = defaultdict(list)
        for access in register_accesses:
            if access.base_address == peripheral_candidate.base_address:
                offset_accesses[access.offset].append(access)
        
        # 分析每个偏移的访问模式
        for offset, accesses in offset_accesses.items():
            pattern = AccessPattern(offset=offset)
            
            # 统计读写次数
            reads = [a for a in accesses if a.access_type == 'read']
            writes = [a for a in accesses if a.access_type == 'write']
            pattern.read_count = len(reads)
            pattern.write_count = len(writes)
            
            # 分析读后写模式
            pattern.read_after_write_count = self._count_read_after_write(accesses)
            if pattern.write_count > 0:
                pattern.read_after_write_rate = pattern.read_after_write_count / pattern.write_count
            
            # 提取常见值（需要动态分析或更深入的静态分析）
            pattern.common_values = self._extract_common_values(accesses)
            
            # 推断寄存器类型
            pattern.register_type = self._infer_register_type(pattern)
            
            patterns[offset] = pattern
            
            logger.debug(f"  Offset 0x{offset:02x}: R={pattern.read_count}, W={pattern.write_count}, "
                        f"RaW={pattern.read_after_write_rate:.2f}, Type={pattern.register_type}")
        
        return patterns
    
    def _extract_bitfield_signatures(self, peripheral_candidate, instructions: List,
                                    register_accesses: List) -> Dict[int, List[BitfieldSignature]]:
        """
        提取位域签名 (2.2)
        
        识别：
        - 位操作模式（AND, OR, TST等）
        - 常见掩码
        - 位域语义
        """
        logger.info("Extracting bitfield signatures")
        signatures = defaultdict(list)
        
        # 分析每个访问点的位操作
        for access in register_accesses:
            if access.base_address != peripheral_candidate.base_address:
                continue
            
            # 查找访问点附近的位操作指令
            bit_ops = self._find_nearby_bit_operations(
                instructions, access.instruction_addr, access.offset
            )
            
            for op_info in bit_ops:
                # 检查是否已存在相似的签名
                existing = self._find_existing_signature(
                    signatures[access.offset], op_info['mask']
                )
                
                if existing:
                    existing.usage_count += 1
                    existing.associated_instructions.append(op_info['instruction'])
                else:
                    # 创建新的位域签名
                    signature = BitfieldSignature(
                        offset=access.offset,
                        mask=op_info['mask'],
                        meaning=self._infer_bitfield_meaning(op_info),
                        behavior=self._infer_bitfield_behavior(op_info),
                        usage_count=1,
                        associated_instructions=[op_info['instruction']]
                    )
                    signatures[access.offset].append(signature)
        
        # 按使用频率排序
        for offset in signatures:
            signatures[offset].sort(key=lambda s: s.usage_count, reverse=True)
            
            # 日志输出
            for sig in signatures[offset][:3]:  # 显示前3个最常用的
                logger.debug(f"  Offset 0x{offset:02x}: Mask=0x{sig.mask:02x}, "
                            f"Meaning={sig.meaning}, Behavior={sig.behavior}, "
                            f"Count={sig.usage_count}")
        
        return dict(signatures)
    
    def _extract_behavior_primitives(self, peripheral_candidate, instructions: List,
                                    register_accesses: List, 
                                    access_patterns: Dict[int, AccessPattern]) -> List[BehaviorPrimitive]:
        """
        提取行为原语 (2.3)
        
        识别：
        - wait_clear/wait_set（轮询模式）
        - irq_on_write（中断触发）
        - init_sequence（初始化序列）
        - fifo_push/pop（FIFO操作）
        - dma_start（DMA启动）
        """
        logger.info("Extracting behavior primitives")
        primitives = []
        
        # 1. 检测轮询模式 (wait_clear/wait_set)
        polling_primitives = self._detect_polling_patterns(
            peripheral_candidate, instructions, register_accesses
        )
        primitives.extend(polling_primitives)
        
        # 2. 检测中断触发模式
        irq_primitives = self._detect_irq_patterns(
            peripheral_candidate, instructions, register_accesses
        )
        primitives.extend(irq_primitives)
        
        # 3. 检测初始化序列
        init_primitives = self._detect_init_sequences(
            peripheral_candidate, register_accesses, access_patterns
        )
        primitives.extend(init_primitives)
        
        # 4. 检测FIFO操作
        fifo_primitives = self._detect_fifo_patterns(
            peripheral_candidate, register_accesses, access_patterns
        )
        primitives.extend(fifo_primitives)
        
        # 5. 检测DMA操作
        dma_primitives = self._detect_dma_patterns(
            peripheral_candidate, instructions, register_accesses
        )
        primitives.extend(dma_primitives)
        
        # 按置信度排序
        primitives.sort(key=lambda p: p.confidence, reverse=True)
        
        # 日志输出
        for prim in primitives[:5]:  # 显示前5个
            logger.debug(f"  Primitive: {prim.type} @ 0x{prim.offset:02x}, "
                        f"Mask=0x{prim.mask:02x} if prim.mask else 'N/A', "
                        f"Confidence={prim.confidence:.2f}")
        
        return primitives
    
    # === 辅助方法 ===
    
    def _count_read_after_write(self, accesses: List) -> int:
        """统计读后写次数"""
        count = 0
        last_write_addr = None
        
        for access in accesses:
            if access.access_type == 'write':
                last_write_addr = access.instruction_addr
            elif access.access_type == 'read' and last_write_addr:
                # 检查读是否紧跟在写之后（100条指令内）
                if abs(access.instruction_addr - last_write_addr) < 100 * 4:
                    count += 1
        
        return count
    
    def _extract_common_values(self, accesses: List) -> List[int]:
        """提取常见值（静态分析中的立即数）"""
        values = []
        
        for access in accesses:
            # 从证据链中提取立即数值
            if hasattr(access, 'evidence_chain'):
                for evidence in access.evidence_chain:
                    # 使用正则表达式提取立即数
                    if hasattr(evidence, 'instruction'):
                        imm_matches = re.findall(r'#(0x[\da-fA-F]+|\d+)', evidence.instruction)
                        for match in imm_matches:
                            try:
                                value = int(match, 16) if match.startswith('0x') else int(match)
                                if 0 <= value <= 0xFFFFFFFF:  # 合理范围
                                    values.append(value)
                            except:
                                pass
        
        # 返回最常见的值
        if values:
            value_counts = Counter(values)
            return [v for v, _ in value_counts.most_common(5)]
        
        return []
    
    def _infer_register_type(self, pattern: AccessPattern) -> str:
        """推断寄存器类型"""
        # 基于访问模式推断
        if pattern.read_count > pattern.write_count * 3:
            return 'status'  # 频繁读取，可能是状态寄存器
        elif pattern.write_count > pattern.read_count * 2:
            return 'control'  # 频繁写入，可能是控制寄存器
        elif pattern.read_after_write_rate > 0.7:
            return 'data'  # 读后写模式，可能是数据寄存器
        else:
            return 'unknown'
    
    def _find_nearby_bit_operations(self, instructions: List, addr: int, 
                                   offset: int) -> List[Dict]:
        """查找附近的位操作指令"""
        bit_ops = []
        search_range = 20  # 搜索前后20条指令
        
        # 查找指令索引
        target_idx = None
        for i, insn in enumerate(instructions):
            if insn.address == addr:
                target_idx = i
                break
        
        if target_idx is None:
            return bit_ops
        
        # 搜索范围
        start_idx = max(0, target_idx - search_range)
        end_idx = min(len(instructions), target_idx + search_range + 1)
        
        for i in range(start_idx, end_idx):
            insn = instructions[i]
            op_info = self._analyze_bit_operation(insn)
            if op_info:
                bit_ops.append(op_info)
        
        return bit_ops
    
    def _analyze_bit_operation(self, insn) -> Optional[Dict]:
        """分析位操作指令"""
        try:
            mnemonic = insn.mnemonic.lower()
            
            # 位操作指令
            bit_ops = ['and', 'orr', 'eor', 'bic', 'tst', 'ands', 'orrs', 'eors', 'bics']
            
            if mnemonic in bit_ops:
                # 提取掩码（立即数）
                for operand in insn.operands:
                    if operand.type in [capstone.arm.ARM_OP_IMM, capstone.arm64.ARM64_OP_IMM]:
                        return {
                            'instruction': f"{insn.mnemonic} {insn.op_str}",
                            'mnemonic': mnemonic,
                            'mask': operand.imm,
                            'address': insn.address
                        }
        except:
            pass
        
        return None
    
    def _find_existing_signature(self, signatures: List[BitfieldSignature], 
                                mask: int) -> Optional[BitfieldSignature]:
        """查找已存在的相同掩码签名"""
        for sig in signatures:
            if sig.mask == mask:
                return sig
        return None
    
    def _infer_bitfield_meaning(self, op_info: Dict) -> str:
        """推断位域含义"""
        mask = op_info['mask']
        mnemonic = op_info['mnemonic']
        
        # 基于掩码和操作推断
        if mask == 0x01:
            return 'flag'  # 单个位，可能是标志
        elif mask in [0x80, 0x8000, 0x80000000]:
            return 'sign_bit'  # 符号位
        elif mnemonic == 'tst':
            return 'test_flag'  # 测试标志
        elif mnemonic in ['orr', 'orrs']:
            return 'enable'  # 使能位
        elif mnemonic in ['bic', 'bics']:
            return 'clear'  # 清除位
        else:
            return 'unknown'
    
    def _infer_bitfield_behavior(self, op_info: Dict) -> str:
        """推断位域行为"""
        mnemonic = op_info['mnemonic']
        
        if mnemonic == 'tst':
            return 'poll_flag'  # 轮询标志
        elif mnemonic in ['orr', 'orrs']:
            return 'set_bit'  # 设置位
        elif mnemonic in ['bic', 'bics']:
            return 'clear_bit'  # 清除位
        elif mnemonic in ['and', 'ands']:
            return 'mask_field'  # 掩码字段
        else:
            return 'unknown'
    
    def _detect_polling_patterns(self, peripheral_candidate, instructions: List,
                                register_accesses: List) -> List[BehaviorPrimitive]:
        """检测轮询模式"""
        primitives = []
        
        # 查找循环中的寄存器读取
        for i, insn in enumerate(instructions):
            if self._is_loop_instruction(insn):
                # 查找循环体中的外设访问
                loop_accesses = self._find_loop_body_accesses(
                    instructions, i, register_accesses, peripheral_candidate.base_address
                )
                
                for access in loop_accesses:
                    # 查找相关的位测试
                    bit_test = self._find_associated_bit_test(instructions, access)
                    if bit_test:
                        primitive = BehaviorPrimitive(
                            type='wait_clear' if bit_test['polarity'] == 'clear' else 'wait_set',
                            offset=access.offset,
                            mask=bit_test['mask'],
                            timeout_ms=200,  # 默认超时
                            evidence=[f"Loop at 0x{insn.address:08x}", 
                                     f"Test at 0x{bit_test['addr']:08x}"],
                            confidence=0.8
                        )
                        primitives.append(primitive)
        
        return primitives
    
    def _detect_irq_patterns(self, peripheral_candidate, instructions: List,
                            register_accesses: List) -> List[BehaviorPrimitive]:
        """检测中断触发模式"""
        primitives = []
        
        # 查找写操作后的中断相关指令
        for access in register_accesses:
            if (access.base_address == peripheral_candidate.base_address and 
                access.access_type == 'write'):
                
                # 查找附近的中断使能/触发指令
                irq_ops = self._find_nearby_irq_operations(instructions, access.instruction_addr)
                
                if irq_ops:
                    primitive = BehaviorPrimitive(
                        type='irq_on_write',
                        offset=access.offset,
                        mask=0xFF,  # 默认全字节
                        parameters={'irq_number': irq_ops.get('irq_number')},
                        evidence=[f"Write at 0x{access.instruction_addr:08x}",
                                 f"IRQ op at 0x{irq_ops['addr']:08x}"],
                        confidence=0.7
                    )
                    primitives.append(primitive)
        
        return primitives
    
    def _detect_init_sequences(self, peripheral_candidate, register_accesses: List,
                              access_patterns: Dict[int, AccessPattern]) -> List[BehaviorPrimitive]:
        """检测初始化序列"""
        primitives = []
        
        # 查找连续的写操作序列
        write_sequences = self._find_write_sequences(register_accesses, peripheral_candidate.base_address)
        
        for seq in write_sequences:
            if len(seq) >= 3:  # 至少3个连续写操作
                primitive = BehaviorPrimitive(
                    type='init_sequence',
                    offset=seq[0].offset,
                    parameters={
                        'sequence_length': len(seq),
                        'offsets': [a.offset for a in seq]
                    },
                    evidence=[f"Sequential writes: {len(seq)} operations"],
                    confidence=0.75
                )
                primitives.append(primitive)
        
        return primitives
    
    def _detect_fifo_patterns(self, peripheral_candidate, register_accesses: List,
                             access_patterns: Dict[int, AccessPattern]) -> List[BehaviorPrimitive]:
        """检测FIFO操作模式"""
        primitives = []
        
        # 查找重复访问同一偏移的模式（FIFO数据寄存器）
        for offset, pattern in access_patterns.items():
            if pattern.read_count + pattern.write_count > 10:  # 频繁访问
                # 检查是否有状态检查模式
                status_offset = self._find_associated_status_register(
                    offset, access_patterns, register_accesses
                )
                
                if status_offset is not None:
                    primitive_type = 'fifo_push' if pattern.write_count > pattern.read_count else 'fifo_pop'
                    primitive = BehaviorPrimitive(
                        type=primitive_type,
                        offset=offset,
                        parameters={
                            'status_offset': status_offset,
                            'access_count': pattern.read_count + pattern.write_count
                        },
                        evidence=[f"Data register at 0x{offset:02x}",
                                 f"Status register at 0x{status_offset:02x}"],
                        confidence=0.65
                    )
                    primitives.append(primitive)
        
        return primitives
    
    def _detect_dma_patterns(self, peripheral_candidate, instructions: List,
                            register_accesses: List) -> List[BehaviorPrimitive]:
        """检测DMA操作模式"""
        primitives = []
        
        # 查找DMA相关的寄存器配置序列
        dma_keywords = ['dma', 'channel', 'transfer', 'burst']
        
        for access in register_accesses:
            if access.base_address == peripheral_candidate.base_address:
                # 检查函数名是否包含DMA相关关键词
                if access.function_name:
                    func_lower = access.function_name.lower()
                    if any(keyword in func_lower for keyword in dma_keywords):
                        primitive = BehaviorPrimitive(
                            type='dma_start',
                            offset=access.offset,
                            parameters={'function': access.function_name},
                            evidence=[f"DMA-related function: {access.function_name}"],
                            confidence=0.6
                        )
                        primitives.append(primitive)
                        break
        
        return primitives
    
    def _infer_peripheral_behavior_type(self, access_patterns: Dict[int, AccessPattern],
                                       bitfield_signatures: Dict[int, List[BitfieldSignature]],
                                       primitives: List[BehaviorPrimitive]) -> str:
        """推断外设行为类型"""
        # 基于原语类型推断
        primitive_types = [p.type for p in primitives]
        
        if any('wait_' in t for t in primitive_types):
            return 'polling_device'
        elif any('irq_' in t for t in primitive_types):
            return 'interrupt_driven'
        elif any('dma_' in t for t in primitive_types):
            return 'dma_capable'
        
        # 基于访问模式推断
        total_reads = sum(p.read_count for p in access_patterns.values())
        total_writes = sum(p.write_count for p in access_patterns.values())
        
        if total_reads > total_writes * 2:
            return 'polling_device'
        else:
            return 'unknown'
    
    # === 循环检测辅助方法 ===
    
    def _is_loop_instruction(self, insn) -> bool:
        """检查是否是循环相关指令"""
        try:
            mnemonic = insn.mnemonic.lower()
            # 条件跳转指令（可能形成循环）
            return mnemonic in ['beq', 'bne', 'blt', 'bgt', 'ble', 'bge', 'b', 'cbz', 'cbnz']
        except:
            return False
    
    def _find_loop_body_accesses(self, instructions: List, loop_idx: int,
                                register_accesses: List, base_address: int) -> List:
        """查找循环体中的外设访问"""
        loop_accesses = []
        loop_insn = instructions[loop_idx]
        
        # 简单启发式：查找跳转目标前的访问
        for access in register_accesses:
            if (access.base_address == base_address and
                abs(access.instruction_addr - loop_insn.address) < 100):  # 100字节范围内
                loop_accesses.append(access)
        
        return loop_accesses
    
    def _find_associated_bit_test(self, instructions: List, access) -> Optional[Dict]:
        """查找关联的位测试"""
        # 查找访问后的TST指令
        for insn in instructions:
            if (insn.address > access.instruction_addr and 
                insn.address < access.instruction_addr + 20):  # 20字节内
                
                if insn.mnemonic.lower() == 'tst':
                    # 提取测试掩码
                    for operand in insn.operands:
                        if operand.type in [capstone.arm.ARM_OP_IMM, capstone.arm64.ARM64_OP_IMM]:
                            return {
                                'addr': insn.address,
                                'mask': operand.imm,
                                'polarity': 'clear'  # 默认等待清零
                            }
        
        return None
    
    def _find_nearby_irq_operations(self, instructions: List, addr: int) -> Optional[Dict]:
        """查找附近的中断操作"""
        # 简化实现：查找NVIC相关地址
        nvic_base = 0xE000E000
        
        for insn in instructions:
            if abs(insn.address - addr) < 100:  # 100字节范围
                # 检查是否访问NVIC寄存器
                for operand in insn.operands:
                    if hasattr(operand, 'mem') and operand.mem:
                        mem_addr = operand.mem.disp
                        if nvic_base <= mem_addr < nvic_base + 0x1000:
                            return {
                                'addr': insn.address,
                                'irq_number': (mem_addr - nvic_base) // 4
                            }
        
        return None
    
    def _find_write_sequences(self, register_accesses: List, base_address: int) -> List[List]:
        """查找连续写操作序列"""
        sequences = []
        current_seq = []
        last_addr = None
        
        for access in register_accesses:
            if (access.base_address == base_address and 
                access.access_type == 'write'):
                
                # 检查是否连续（100字节内）
                if last_addr and abs(access.instruction_addr - last_addr) > 100:
                    if len(current_seq) >= 3:
                        sequences.append(current_seq)
                    current_seq = []
                
                current_seq.append(access)
                last_addr = access.instruction_addr
        
        # 添加最后一个序列
        if len(current_seq) >= 3:
            sequences.append(current_seq)
        
        return sequences
    
    def _find_associated_status_register(self, data_offset: int, 
                                        access_patterns: Dict[int, AccessPattern],
                                        register_accesses: List) -> Optional[int]:
        """查找关联的状态寄存器"""
        # 查找在数据访问前被读取的寄存器（可能是状态寄存器）
        for offset, pattern in access_patterns.items():
            if offset != data_offset and pattern.register_type == 'status':
                return offset
        
        return None
    
    def export_behavior_semantics(self, semantics: BehaviorSemantics, output_path: str):
        """导出行为语义到JSON"""
        export_data = {
            'base_address': f"0x{semantics.base_address:08x}",
            'peripheral_behavior_type': semantics.peripheral_behavior_type,
            'access_patterns': {},
            'bitfield_signatures': {},
            'primitives': []
        }
        
        # 导出访问模式
        for offset, pattern in semantics.access_patterns.items():
            export_data['access_patterns'][f"0x{offset:02x}"] = {
                'reads': pattern.read_count,
                'writes': pattern.write_count,
                'read_after_write': pattern.read_after_write_rate,
                'common_values': pattern.common_values,
                'register_type': pattern.register_type
            }
        
        # 导出位域签名
        for offset, signatures in semantics.bitfield_signatures.items():
            export_data['bitfield_signatures'][f"0x{offset:02x}"] = [
                {
                    'mask': f"0x{sig.mask:02x}",
                    'meaning': sig.meaning,
                    'behavior': sig.behavior,
                    'usage_count': sig.usage_count
                }
                for sig in signatures[:3]  # 只导出前3个最重要的
            ]
        
        # 导出原语
        for primitive in semantics.primitives[:10]:  # 只导出前10个最重要的
            prim_data = {
                'type': primitive.type,
                'offset': f"0x{primitive.offset:02x}",
                'confidence': round(primitive.confidence, 2)
            }
            
            if primitive.mask is not None:
                prim_data['mask'] = f"0x{primitive.mask:02x}"
            if primitive.timeout_ms is not None:
                prim_data['timeout_ms'] = primitive.timeout_ms
            if primitive.parameters:
                prim_data['parameters'] = primitive.parameters
            
            export_data['primitives'].append(prim_data)
        
        # 保存到文件
        with open(output_path, 'w') as f:
            json.dump(export_data, f, indent=2)
        
        logger.info(f"Exported behavior semantics to {output_path}")
        return export_data
