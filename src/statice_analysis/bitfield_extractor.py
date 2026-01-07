#!/usr/bin/env python3
"""
位域信息提取器
分析寄存器位域，识别特殊含义的位
"""

import logging
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass
from collections import defaultdict, Counter

logger = logging.getLogger(__name__)

@dataclass
class BitfieldInfo:
    """位域信息"""
    bit_range: Tuple[int, int]  # (起始位, 结束位)
    purpose: str  # enable, status, config, data, flag, etc.
    common_values: List[int]  # 该位域的常见值
    access_pattern: str  # read_only, write_only, read_write
    significance: float  # 重要性得分 (0-1)

@dataclass
class RegisterBitfields:
    """寄存器的所有位域"""
    offset: int
    bitfields: List[BitfieldInfo]
    register_purpose: str  # control, status, data, config
    
class BitfieldExtractor:
    """
    位域提取器
    
    功能:
    1. 分析写入的值，识别位模式
    2. 检测常用的位操作（set/clear/toggle）
    3. 识别特殊位域（使能位、状态位等）
    4. 推断位域用途
    """
    
    def __init__(self):
        # 常见位域模式
        self.common_patterns = {
            'enable_bit': [0x1, 0x0],  # 使能/禁用
            'status_flags': [0x1, 0x2, 0x4, 0x8, 0x10],  # 状态标志
            'interrupt_flags': [0x1, 0x2, 0x4, 0x8],  # 中断标志
        }
        
    def extract_bitfields(self, peripheral_data: Dict) -> Dict[int, RegisterBitfields]:
        """
        提取外设所有寄存器的位域信息
        
        Args:
            peripheral_data: 外设数据，包含registers字典
            
        Returns:
            寄存器偏移 -> 位域信息的映射
        """
        if 'registers' not in peripheral_data:
            return {}
        
        logger.info(f"提取外设 {peripheral_data.get('base_address', '?')} 的位域信息")
        
        bitfields_map = {}
        
        for offset_str, reg_data in peripheral_data['registers'].items():
            offset = int(offset_str, 16) if isinstance(offset_str, str) else offset_str
            
            # 提取这个寄存器的位域
            bitfields = self._extract_register_bitfields(offset, reg_data, peripheral_data)
            
            if bitfields:
                bitfields_map[offset] = bitfields
        
        return bitfields_map
    
    def _extract_register_bitfields(self, offset: int, reg_data: Dict, peripheral_data: Dict) -> Optional[RegisterBitfields]:
        """提取单个寄存器的位域"""
        
        # 从访问模式推断寄存器用途
        access_type = reg_data.get('access_type', 'read_write')
        inferred_purpose = reg_data.get('inferred_purpose', 'general_purpose')
        
        # 确定寄存器用途
        reg_purpose = self._determine_register_purpose(access_type, inferred_purpose, reg_data)
        
        # 提取位域
        bitfields = []
        
        # 方法1: 基于写入值分析位域
        if 'example_values' in reg_data and reg_data['example_values']:
            bitfields.extend(self._analyze_write_values(reg_data['example_values'], access_type))
        
        # 方法2: 基于寄存器类型推断典型位域
        bitfields.extend(self._infer_typical_bitfields(offset, reg_purpose, peripheral_data))
        
        # 方法3: 基于指令分析位操作
        if 'instructions' in reg_data and reg_data['instructions']:
            bitfields.extend(self._analyze_bit_operations(reg_data['instructions']))
        
        if not bitfields:
            return None
        
        # 去重和合并位域
        bitfields = self._merge_overlapping_bitfields(bitfields)
        
        return RegisterBitfields(
            offset=offset,
            bitfields=bitfields,
            register_purpose=reg_purpose
        )
    
    def _determine_register_purpose(self, access_type: str, inferred_purpose: str, reg_data: Dict) -> str:
        """确定寄存器用途"""
        
        # 优先使用推断的用途
        if 'control' in inferred_purpose or 'config' in inferred_purpose:
            return 'control'
        elif 'status' in inferred_purpose:
            return 'status'
        elif 'data' in inferred_purpose:
            return 'data'
        
        # 否则基于访问类型
        if access_type == 'read_only':
            return 'status'
        elif access_type == 'write_only':
            return 'control'
        else:
            return 'config'
    
    def _analyze_write_values(self, value_strs: List[str], access_type: str) -> List[BitfieldInfo]:
        """
        分析写入值，识别位域模式
        """
        bitfields = []
        
        # 转换字符串为整数
        values = []
        for v_str in value_strs:
            try:
                if isinstance(v_str, str):
                    v = int(v_str, 16) if v_str.startswith('0x') else int(v_str)
                else:
                    v = int(v_str)
                values.append(v)
            except:
                continue
        
        if not values:
            return bitfields
        
        # 分析位模式
        # 1. 单比特位
        single_bit_fields = self._find_single_bit_fields(values)
        bitfields.extend(single_bit_fields)
        
        # 2. 多比特位域
        multi_bit_fields = self._find_multi_bit_fields(values)
        bitfields.extend(multi_bit_fields)
        
        return bitfields
    
    def _find_single_bit_fields(self, values: List[int]) -> List[BitfieldInfo]:
        """查找单比特位域"""
        bitfields = []
        
        # 统计每个位被设置的频率
        bit_usage = Counter()
        for value in values:
            for bit in range(32):
                if value & (1 << bit):
                    bit_usage[bit] += 1
        
        # 识别常用的单比特位
        total_values = len(values)
        for bit, count in bit_usage.items():
            frequency = count / total_values
            
            # 如果这个位经常被设置或清除，它可能是重要的
            if frequency > 0.3:  # 在30%以上的值中被设置
                purpose = self._infer_single_bit_purpose(bit, frequency)
                
                bitfields.append(BitfieldInfo(
                    bit_range=(bit, bit),
                    purpose=purpose,
                    common_values=[0, 1],
                    access_pattern='write',
                    significance=frequency
                ))
        
        return bitfields
    
    def _find_multi_bit_fields(self, values: List[int]) -> List[BitfieldInfo]:
        """查找多比特位域"""
        bitfields = []
        
        # 尝试识别连续的位域
        # 例如: bits[7:4] 用于配置
        
        # 分析值的分布
        value_counter = Counter(values)
        
        # 如果值的数量很少，可能是枚举类型
        if len(value_counter) <= 8:
            # 尝试找到覆盖这些值的最小位域
            max_value = max(values) if values else 0
            if max_value > 0:
                # 计算需要的位数
                num_bits = max_value.bit_length()
                
                # 检查是否是特定位域
                bitfields.append(BitfieldInfo(
                    bit_range=(0, num_bits - 1),
                    purpose='enum_config',
                    common_values=sorted(value_counter.keys())[:5],
                    access_pattern='write',
                    significance=0.7
                ))
        
        return bitfields
    
    def _infer_single_bit_purpose(self, bit: int, frequency: float) -> str:
        """推断单比特位的用途"""
        
        # 位0通常是使能位
        if bit == 0:
            return 'enable_bit'
        
        # 位1-7可能是配置位或状态位
        elif 1 <= bit <= 7:
            if frequency > 0.8:
                return 'config_bit'
            else:
                return 'flag_bit'
        
        # 位8-15可能是状态位或中断位
        elif 8 <= bit <= 15:
            return 'status_or_interrupt_bit'
        
        # 更高位可能是扩展配置
        else:
            return 'extended_config_bit'
    
    def _infer_typical_bitfields(self, offset: int, reg_purpose: str, peripheral_data: Dict) -> List[BitfieldInfo]:
        """
        基于寄存器类型推断典型位域
        """
        bitfields = []
        peripheral_type = peripheral_data.get('peripheral_type', 'UNKNOWN')
        
        # GPIO寄存器的典型位域
        if peripheral_type == 'GPIO':
            if reg_purpose == 'control' and offset == 0x00:
                # GPIO模式寄存器：每2位控制一个引脚
                for pin in range(8):  # 假设8个引脚
                    bitfields.append(BitfieldInfo(
                        bit_range=(pin*2, pin*2+1),
                        purpose=f'pin{pin}_mode',
                        common_values=[0, 1, 2, 3],  # 输入/输出/复用/模拟
                        access_pattern='write',
                        significance=0.8
                    ))
            elif offset == 0x0C:  # 输入数据寄存器
                for pin in range(16):
                    bitfields.append(BitfieldInfo(
                        bit_range=(pin, pin),
                        purpose=f'pin{pin}_input',
                        common_values=[0, 1],
                        access_pattern='read',
                        significance=0.6
                    ))
        
        # UART寄存器的典型位域
        elif peripheral_type == 'UART':
            if offset == 0x00:  # 数据寄存器
                bitfields.append(BitfieldInfo(
                    bit_range=(0, 7),
                    purpose='data_byte',
                    common_values=[],
                    access_pattern='read_write',
                    significance=1.0
                ))
            elif offset == 0x04:  # 状态寄存器
                bitfields.extend([
                    BitfieldInfo(
                        bit_range=(0, 0),
                        purpose='tx_empty',
                        common_values=[0, 1],
                        access_pattern='read',
                        significance=0.9
                    ),
                    BitfieldInfo(
                        bit_range=(1, 1),
                        purpose='rx_not_empty',
                        common_values=[0, 1],
                        access_pattern='read',
                        significance=0.9
                    ),
                ])
        
        # 控制寄存器的通用位域
        elif reg_purpose == 'control':
            bitfields.extend([
                BitfieldInfo(
                    bit_range=(0, 0),
                    purpose='enable',
                    common_values=[0, 1],
                    access_pattern='write',
                    significance=0.9
                ),
                BitfieldInfo(
                    bit_range=(1, 1),
                    purpose='reset_or_start',
                    common_values=[0, 1],
                    access_pattern='write',
                    significance=0.7
                ),
            ])
        
        # 状态寄存器的通用位域
        elif reg_purpose == 'status':
            for bit in range(8):
                bitfields.append(BitfieldInfo(
                    bit_range=(bit, bit),
                    purpose=f'status_flag_{bit}',
                    common_values=[0, 1],
                    access_pattern='read',
                    significance=0.5
                ))
        
        return bitfields
    
    def _analyze_bit_operations(self, instructions: List[str]) -> List[BitfieldInfo]:
        """
        分析指令中的位操作
        
        识别:
        - ORR/BIC 指令 (设置/清除位)
        - AND 指令 (测试位)
        - LSL/LSR 指令 (位移操作)
        """
        bitfields = []
        
        for instr_str in instructions:
            if not isinstance(instr_str, str):
                continue
            
            # 检测位设置操作 (ORR)
            if 'orr' in instr_str.lower():
                # 尝试提取立即数
                if '#' in instr_str:
                    try:
                        imm_str = instr_str.split('#')[1].split(',')[0].strip()
                        imm = int(imm_str, 16) if 'x' in imm_str else int(imm_str)
                        
                        # 检查是否是单比特
                        if imm & (imm - 1) == 0:  # 2的幂
                            bit = (imm.bit_length() - 1)
                            bitfields.append(BitfieldInfo(
                                bit_range=(bit, bit),
                                purpose='set_bit',
                                common_values=[1],
                                access_pattern='write',
                                significance=0.8
                            ))
                    except:
                        pass
            
            # 检测位清除操作 (BIC)
            elif 'bic' in instr_str.lower():
                # 类似ORR的处理
                pass
        
        return bitfields
    
    def _merge_overlapping_bitfields(self, bitfields: List[BitfieldInfo]) -> List[BitfieldInfo]:
        """合并重叠的位域"""
        if not bitfields:
            return []
        
        # 按起始位排序
        sorted_fields = sorted(bitfields, key=lambda x: x.bit_range[0])
        
        merged = [sorted_fields[0]]
        
        for current in sorted_fields[1:]:
            last = merged[-1]
            
            # 检查是否重叠
            if current.bit_range[0] <= last.bit_range[1]:
                # 重叠，选择更重要的那个
                if current.significance > last.significance:
                    merged[-1] = current
                # 否则忽略current
            else:
                # 不重叠，直接添加
                merged.append(current)
        
        return merged
    
    def export_bitfield_doc(self, bitfields_map: Dict[int, RegisterBitfields], base_address: str) -> str:
        """
        导出位域文档
        
        生成人类可读的位域说明
        """
        doc = f"位域文档 - 外设 @ {base_address}\n"
        doc += "=" * 60 + "\n\n"
        
        for offset, reg_bitfields in sorted(bitfields_map.items()):
            doc += f"寄存器 @ +0x{offset:02x} ({reg_bitfields.register_purpose})\n"
            doc += "-" * 60 + "\n"
            
            for bf in reg_bitfields.bitfields:
                bit_str = f"[{bf.bit_range[0]}]" if bf.bit_range[0] == bf.bit_range[1] else f"[{bf.bit_range[1]}:{bf.bit_range[0]}]"
                doc += f"  {bit_str:8} {bf.purpose:25} ({bf.access_pattern})\n"
                if bf.common_values:
                    doc += f"           常见值: {', '.join(f'0x{v:x}' for v in bf.common_values)}\n"
            
            doc += "\n"
        
        return doc

