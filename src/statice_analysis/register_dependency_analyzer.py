#!/usr/bin/env python3
"""
寄存器依赖关系分析器
分析寄存器之间的依赖关系和访问顺序
"""

import logging
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass
from collections import defaultdict
from enum import Enum

logger = logging.getLogger(__name__)

class DependencyType(Enum):
    """依赖类型"""
    PREREQUISITE = "prerequisite"  # A必须在B之前访问
    SEQUENCE = "sequence"  # A和B通常按顺序访问
    MUTUAL_EXCLUSIVE = "mutual_exclusive"  # A和B互斥
    CONDITIONAL = "conditional"  # B的访问取决于A的值
    
@dataclass
class RegisterDependency:
    """寄存器依赖关系"""
    from_offset: int
    to_offset: int
    dependency_type: DependencyType
    confidence: float  # 0-1
    description: str

@dataclass
class AccessSequence:
    """访问序列"""
    sequence: List[int]  # 偏移列表
    frequency: int  # 出现频率
    purpose: str  # init, read, write, etc.

class RegisterDependencyAnalyzer:
    """
    寄存器依赖分析器
    
    功能:
    1. 分析初始化序列（哪些寄存器必须先配置）
    2. 检测读写依赖（读取前必须写入）
    3. 识别条件访问（基于状态寄存器的条件访问）
    4. 发现访问模式（常见的寄存器访问顺序）
    """
    
    def __init__(self):
        self.known_patterns = self._load_known_patterns()
        
    def analyze_dependencies(self, peripheral_data: Dict) -> Tuple[List[RegisterDependency], List[AccessSequence]]:
        """
        分析外设寄存器的依赖关系
        
        Args:
            peripheral_data: 外设数据
            
        Returns:
            (依赖关系列表, 访问序列列表)
        """
        if 'registers' not in peripheral_data:
            return [], []
        
        logger.info(f"分析外设 {peripheral_data.get('base_address', '?')} 的寄存器依赖")
        
        # 收集所有寄存器的访问信息
        register_info = self._collect_register_info(peripheral_data['registers'])
        
        # 分析依赖关系
        dependencies = []
        
        # 1. 分析初始化依赖
        init_deps = self._analyze_init_dependencies(register_info, peripheral_data)
        dependencies.extend(init_deps)
        
        # 2. 分析读写依赖
        rw_deps = self._analyze_read_write_dependencies(register_info)
        dependencies.extend(rw_deps)
        
        # 3. 分析条件依赖
        cond_deps = self._analyze_conditional_dependencies(register_info)
        dependencies.extend(cond_deps)
        
        # 4. 分析访问序列
        sequences = self._extract_access_sequences(peripheral_data)
        
        logger.info(f"发现{len(dependencies)}个依赖关系，{len(sequences)}个访问序列")
        
        return dependencies, sequences
    
    def _collect_register_info(self, registers: Dict) -> Dict[int, Dict]:
        """收集寄存器信息"""
        info = {}
        
        for offset_str, reg_data in registers.items():
            offset = int(offset_str, 16) if isinstance(offset_str, str) else offset_str
            
            info[offset] = {
                'read_count': reg_data.get('read_count', 0),
                'write_count': reg_data.get('write_count', 0),
                'access_type': reg_data.get('access_type', 'unknown'),
                'purpose': reg_data.get('inferred_purpose', 'unknown'),
                'instructions': reg_data.get('instructions', []),
                'access_pcs': reg_data.get('access_pcs', [])
            }
        
        return info
    
    def _analyze_init_dependencies(self, register_info: Dict[int, Dict], peripheral_data: Dict) -> List[RegisterDependency]:
        """
        分析初始化依赖
        
        规则:
        1. 使能寄存器通常最先访问
        2. 配置寄存器在使能之后
        3. 数据寄存器最后访问
        """
        dependencies = []
        peripheral_type = peripheral_data.get('peripheral_type', 'UNKNOWN')
        
        # 识别使能寄存器（通常在offset 0x00或专门的CR寄存器）
        enable_regs = []
        config_regs = []
        data_regs = []
        
        for offset, info in register_info.items():
            purpose = info['purpose']
            
            if 'enable' in purpose.lower() or 'control' in purpose.lower():
                if offset == 0x00:
                    enable_regs.append(offset)
                else:
                    config_regs.append(offset)
            elif 'config' in purpose.lower():
                config_regs.append(offset)
            elif 'data' in purpose.lower():
                data_regs.append(offset)
        
        # 建立依赖关系
        # 使能寄存器 -> 配置寄存器
        for enable_reg in enable_regs:
            for config_reg in config_regs:
                dependencies.append(RegisterDependency(
                    from_offset=enable_reg,
                    to_offset=config_reg,
                    dependency_type=DependencyType.PREREQUISITE,
                    confidence=0.8,
                    description=f"控制寄存器 0x{enable_reg:02x} 必须在配置寄存器 0x{config_reg:02x} 之前设置"
                ))
        
        # 配置寄存器 -> 数据寄存器
        for config_reg in config_regs:
            for data_reg in data_regs:
                dependencies.append(RegisterDependency(
                    from_offset=config_reg,
                    to_offset=data_reg,
                    dependency_type=DependencyType.PREREQUISITE,
                    confidence=0.7,
                    description=f"配置寄存器 0x{config_reg:02x} 应该在数据寄存器 0x{data_reg:02x} 之前设置"
                ))
        
        return dependencies
    
    def _analyze_read_write_dependencies(self, register_info: Dict[int, Dict]) -> List[RegisterDependency]:
        """
        分析读写依赖
        
        规则:
        1. 数据寄存器：写入后才能读取
        2. 状态寄存器：写入配置后才能读取状态
        """
        dependencies = []
        
        for offset, info in register_info.items():
            access_type = info['access_type']
            
            # 读写寄存器：如果有写入，通常写在读之前
            if access_type == 'read_write':
                if info['write_count'] > 0 and info['read_count'] > 0:
                    # 这是一个读写都存在的寄存器
                    # 检查是否是数据寄存器
                    if 'data' in info['purpose'].lower():
                        dependencies.append(RegisterDependency(
                            from_offset=offset,
                            to_offset=offset,
                            dependency_type=DependencyType.SEQUENCE,
                            confidence=0.6,
                            description=f"寄存器 0x{offset:02x} 通常先写后读（数据传输）"
                        ))
        
        # 检测成对的控制-状态寄存器
        control_regs = [off for off, info in register_info.items() 
                       if info['access_type'] == 'write_only' or 'control' in info['purpose'].lower()]
        status_regs = [off for off, info in register_info.items() 
                      if info['access_type'] == 'read_only' or 'status' in info['purpose'].lower()]
        
        # 如果控制寄存器和状态寄存器相邻，建立依赖
        for ctrl_reg in control_regs:
            for status_reg in status_regs:
                if abs(ctrl_reg - status_reg) <= 0x10:  # 相邻（<16字节）
                    dependencies.append(RegisterDependency(
                        from_offset=ctrl_reg,
                        to_offset=status_reg,
                        dependency_type=DependencyType.SEQUENCE,
                        confidence=0.7,
                        description=f"控制寄存器 0x{ctrl_reg:02x} 之后检查状态寄存器 0x{status_reg:02x}"
                    ))
        
        return dependencies
    
    def _analyze_conditional_dependencies(self, register_info: Dict[int, Dict]) -> List[RegisterDependency]:
        """
        分析条件依赖
        
        基于指令分析检测条件访问
        """
        dependencies = []
        
        # 寻找可能的条件访问模式
        # 通常表现为：读取状态寄存器 -> 基于结果访问其他寄存器
        
        status_regs = [off for off, info in register_info.items() 
                      if 'status' in info['purpose'].lower() or info['access_type'] == 'read_only']
        
        for status_reg in status_regs:
            # 检查其他寄存器的访问是否可能依赖这个状态寄存器
            for offset, info in register_info.items():
                if offset == status_reg:
                    continue
                
                # 如果这个寄存器的访问次数远少于状态寄存器，可能是条件访问
                status_accesses = register_info[status_reg]['read_count']
                this_accesses = info['read_count'] + info['write_count']
                
                if status_accesses > 0 and this_accesses < status_accesses * 0.5:
                    # 这个寄存器的访问可能依赖状态检查
                    dependencies.append(RegisterDependency(
                        from_offset=status_reg,
                        to_offset=offset,
                        dependency_type=DependencyType.CONDITIONAL,
                        confidence=0.5,
                        description=f"寄存器 0x{offset:02x} 的访问可能依赖状态寄存器 0x{status_reg:02x}"
                    ))
        
        return dependencies
    
    def _extract_access_sequences(self, peripheral_data: Dict) -> List[AccessSequence]:
        """
        提取常见的访问序列
        
        从指令或访问PC中推断访问顺序
        """
        sequences = []
        
        # 如果有初始化序列信息（来自高级分析）
        if 'advanced' in peripheral_data and 'init_sequence' in peripheral_data['advanced']:
            init_seq_data = peripheral_data['advanced']['init_sequence']
            if 'steps' in init_seq_data:
                steps = init_seq_data['steps']
                offsets = [step.get('offset') for step in steps if 'offset' in step]
                if offsets:
                    sequences.append(AccessSequence(
                        sequence=offsets,
                        frequency=1,
                        purpose='initialization'
                    ))
        
        # 尝试从寄存器偏移推断典型序列
        registers = peripheral_data.get('registers', {})
        sorted_offsets = sorted([int(off, 16) if isinstance(off, str) else off 
                                for off in registers.keys()])
        
        if len(sorted_offsets) >= 3:
            # 检测常见模式
            
            # 模式1: 顺序访问（0x00, 0x04, 0x08...）
            if self._is_sequential_pattern(sorted_offsets):
                sequences.append(AccessSequence(
                    sequence=sorted_offsets[:5],  # 前5个
                    frequency=1,
                    purpose='sequential_config'
                ))
            
            # 模式2: 配置-启动-读取模式
            if 0x00 in sorted_offsets:  # 控制寄存器
                config_seq = [0x00]
                # 添加其他配置寄存器
                config_seq.extend([off for off in sorted_offsets 
                                  if off > 0x00 and off < 0x20])
                if len(config_seq) >= 2:
                    sequences.append(AccessSequence(
                        sequence=config_seq,
                        frequency=1,
                        purpose='configuration'
                    ))
        
        return sequences
    
    def _is_sequential_pattern(self, offsets: List[int]) -> bool:
        """检查是否是顺序模式"""
        if len(offsets) < 3:
            return False
        
        # 检查是否以固定步长递增
        diffs = [offsets[i+1] - offsets[i] for i in range(len(offsets)-1)]
        
        # 如果大部分差值相同（例如都是4字节）
        from collections import Counter
        diff_counter = Counter(diffs)
        most_common_diff, count = diff_counter.most_common(1)[0]
        
        return count >= len(diffs) * 0.7  # 70%以上相同差值
    
    def _load_known_patterns(self) -> Dict:
        """
        加载已知的寄存器访问模式
        
        包括常见外设的典型访问序列
        """
        return {
            'UART_init': [0x08, 0x0C, 0x00, 0x04],  # 配置波特率、格式、使能
            'GPIO_init': [0x00, 0x04, 0x08],  # 模式、输出类型、速度
            'SPI_init': [0x00, 0x04, 0x08, 0x10],  # 控制、配置、波特率、使能
        }
    
    def export_dependency_graph(self, dependencies: List[RegisterDependency], base_address: str) -> str:
        """
        导出依赖图（文本格式）
        """
        doc = f"寄存器依赖图 - 外设 @ {base_address}\n"
        doc += "=" * 60 + "\n\n"
        
        # 按依赖类型分组
        by_type = defaultdict(list)
        for dep in dependencies:
            by_type[dep.dependency_type].append(dep)
        
        for dep_type, deps in by_type.items():
            doc += f"{dep_type.value.upper()}:\n"
            doc += "-" * 60 + "\n"
            
            for dep in deps:
                doc += f"  0x{dep.from_offset:02x} -> 0x{dep.to_offset:02x} "
                doc += f"(置信度: {dep.confidence:.2f})\n"
                doc += f"    {dep.description}\n"
            
            doc += "\n"
        
        return doc
    
    def export_sequence_doc(self, sequences: List[AccessSequence], base_address: str) -> str:
        """导出访问序列文档"""
        doc = f"访问序列 - 外设 @ {base_address}\n"
        doc += "=" * 60 + "\n\n"
        
        for i, seq in enumerate(sequences, 1):
            doc += f"序列 {i}: {seq.purpose}\n"
            doc += f"  {'  ->  '.join(f'0x{off:02x}' for off in seq.sequence)}\n"
            doc += f"  频率: {seq.frequency}\n\n"
        
        return doc


