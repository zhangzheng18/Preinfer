#!/usr/bin/env python3
"""
外设特定推断规则
包含各种常见外设的识别和推断规则
"""

import logging
from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass

logger = logging.getLogger(__name__)

@dataclass
class PeripheralRule:
    """外设识别规则"""
    peripheral_type: str
    confidence_boost: float  # 匹配此规则时的置信度提升
    offset_patterns: List[int]  # 典型偏移列表
    register_purposes: Dict[int, str]  # 偏移 -> 用途
    bitfield_hints: Dict[int, List[Tuple[int, int, str]]]  # 偏移 -> [(bit_start, bit_end, purpose)]
    access_pattern_hints: Dict[int, str]  # 偏移 -> 访问类型（read/write/rw）
    initialization_sequence: List[int]  # 典型初始化序列

class PeripheralRules:
    """
    外设规则库
    
    包含各种MCU常见外设的识别和推断规则
    """
    
    def __init__(self):
        self.rules = self._load_all_rules()
        
    def match_peripheral_type(self, peripheral_data: Dict) -> Tuple[str, float]:
        """
        匹配外设类型
        
        Args:
            peripheral_data: 外设数据
            
        Returns:
            (外设类型, 置信度)
        """
        registers = peripheral_data.get('registers', {})
        if not registers:
            return 'UNKNOWN', 0.0
        
        # 提取偏移列表
        offsets = set()
        for offset_str in registers.keys():
            try:
                offset = int(offset_str, 16) if isinstance(offset_str, str) else offset_str
                offsets.add(offset)
            except:
                continue
        
        if not offsets:
            return 'UNKNOWN', 0.0
        
        # 尝试匹配每个规则
        best_match = ('UNKNOWN', 0.0)
        
        for rule in self.rules:
            confidence = self._calculate_match_confidence(rule, offsets, registers)
            if confidence > best_match[1]:
                best_match = (rule.peripheral_type, confidence)
        
        return best_match
    
    def _calculate_match_confidence(self, rule: PeripheralRule, offsets: Set[int], registers: Dict) -> float:
        """计算规则匹配置信度"""
        
        # 检查偏移模式匹配度
        rule_offsets = set(rule.offset_patterns)
        matching_offsets = offsets & rule_offsets
        
        if not rule_offsets:
            offset_score = 0.0
        else:
            offset_score = len(matching_offsets) / len(rule_offsets)
        
        # 检查访问模式匹配度
        access_score = 0.0
        if rule.access_pattern_hints:
            matched = 0
            for offset, expected_access in rule.access_pattern_hints.items():
                offset_str = f"0x{offset:02x}"
                if offset_str in registers:
                    actual_access = registers[offset_str].get('access_type', '')
                    if expected_access in actual_access or actual_access in expected_access:
                        matched += 1
            access_score = matched / len(rule.access_pattern_hints) if rule.access_pattern_hints else 0
        
        # 综合得分
        confidence = offset_score * 0.7 + access_score * 0.3
        
        return confidence * rule.confidence_boost
    
    def apply_rules(self, peripheral_data: Dict, peripheral_type: str) -> Dict:
        """
        应用规则增强外设数据
        
        Args:
            peripheral_data: 外设数据
            peripheral_type: 识别的外设类型
            
        Returns:
            增强后的外设数据
        """
        # 找到对应的规则
        rule = next((r for r in self.rules if r.peripheral_type == peripheral_type), None)
        if not rule:
            return peripheral_data
        
        registers = peripheral_data.get('registers', {})
        
        # 应用寄存器用途推断
        for offset, purpose in rule.register_purposes.items():
            offset_str = f"0x{offset:02x}"
            if offset_str in registers:
                # 如果已有推断且不太准确，替换为规则推断
                current_purpose = registers[offset_str].get('inferred_purpose', '')
                if 'general' in current_purpose or not current_purpose:
                    registers[offset_str]['inferred_purpose'] = purpose
                    registers[offset_str]['rule_based'] = True
        
        # 添加位域提示
        if 'bitfield_hints' not in peripheral_data:
            peripheral_data['bitfield_hints'] = {}
        peripheral_data['bitfield_hints'].update(rule.bitfield_hints)
        
        # 添加初始化序列提示
        if rule.initialization_sequence:
            if 'init_sequence_hint' not in peripheral_data:
                peripheral_data['init_sequence_hint'] = rule.initialization_sequence
        
        return peripheral_data
    
    def _load_all_rules(self) -> List[PeripheralRule]:
        """加载所有外设规则"""
        rules = []
        
        # GPIO规则
        rules.append(self._gpio_rule())
        
        # UART规则
        rules.append(self._uart_rule())
        
        # SPI规则
        rules.append(self._spi_rule())
        
        # I2C规则
        rules.append(self._i2c_rule())
        
        # Timer规则
        rules.append(self._timer_rule())
        
        # ADC规则
        rules.append(self._adc_rule())
        
        # DMA规则
        rules.append(self._dma_rule())
        
        # RCC (时钟控制) 规则
        rules.append(self._rcc_rule())
        
        return rules
    
    def _gpio_rule(self) -> PeripheralRule:
        """GPIO外设规则"""
        return PeripheralRule(
            peripheral_type='GPIO',
            confidence_boost=1.0,
            offset_patterns=[0x00, 0x04, 0x08, 0x0C, 0x10, 0x14, 0x18, 0x1C],
            register_purposes={
                0x00: 'mode_register',
                0x04: 'output_type_register',
                0x08: 'output_speed_register',
                0x0C: 'pull_up_down_register',
                0x10: 'input_data_register',
                0x14: 'output_data_register',
                0x18: 'bit_set_reset_register',
                0x1C: 'lock_register',
            },
            bitfield_hints={
                0x00: [(0, 1, 'pin0_mode'), (2, 3, 'pin1_mode')],  # 每2位一个引脚
                0x10: [(i, i, f'pin{i}_input') for i in range(16)],
                0x14: [(i, i, f'pin{i}_output') for i in range(16)],
            },
            access_pattern_hints={
                0x00: 'write',
                0x10: 'read',
                0x14: 'read_write',
            },
            initialization_sequence=[0x00, 0x04, 0x08, 0x0C]
        )
    
    def _uart_rule(self) -> PeripheralRule:
        """UART外设规则"""
        return PeripheralRule(
            peripheral_type='UART',
            confidence_boost=1.0,
            offset_patterns=[0x00, 0x04, 0x08, 0x0C, 0x10],
            register_purposes={
                0x00: 'data_register',
                0x04: 'status_register',
                0x08: 'control_register1',
                0x0C: 'control_register2',
                0x10: 'baud_rate_register',
            },
            bitfield_hints={
                0x04: [
                    (0, 0, 'tx_empty'),
                    (1, 1, 'rx_not_empty'),
                    (6, 6, 'tx_complete'),
                ],
                0x08: [
                    (0, 0, 'uart_enable'),
                    (2, 2, 'tx_enable'),
                    (3, 3, 'rx_enable'),
                ],
            },
            access_pattern_hints={
                0x00: 'read_write',
                0x04: 'read',
                0x08: 'write',
            },
            initialization_sequence=[0x10, 0x0C, 0x08]
        )
    
    def _spi_rule(self) -> PeripheralRule:
        """SPI外设规则"""
        return PeripheralRule(
            peripheral_type='SPI',
            confidence_boost=1.0,
            offset_patterns=[0x00, 0x04, 0x08, 0x0C],
            register_purposes={
                0x00: 'control_register1',
                0x04: 'control_register2',
                0x08: 'status_register',
                0x0C: 'data_register',
            },
            bitfield_hints={
                0x00: [
                    (0, 0, 'clock_phase'),
                    (1, 1, 'clock_polarity'),
                    (2, 2, 'master_select'),
                    (3, 5, 'baud_rate'),
                    (6, 6, 'spi_enable'),
                ],
                0x08: [
                    (0, 0, 'rx_buffer_not_empty'),
                    (1, 1, 'tx_buffer_empty'),
                    (7, 7, 'busy'),
                ],
            },
            access_pattern_hints={
                0x00: 'write',
                0x08: 'read',
                0x0C: 'read_write',
            },
            initialization_sequence=[0x00, 0x04]
        )
    
    def _i2c_rule(self) -> PeripheralRule:
        """I2C外设规则"""
        return PeripheralRule(
            peripheral_type='I2C',
            confidence_boost=1.0,
            offset_patterns=[0x00, 0x04, 0x08, 0x0C, 0x10],
            register_purposes={
                0x00: 'control_register1',
                0x04: 'control_register2',
                0x08: 'own_address_register',
                0x0C: 'data_register',
                0x10: 'status_register1',
                0x14: 'status_register2',
                0x18: 'clock_control_register',
            },
            bitfield_hints={
                0x00: [
                    (0, 0, 'i2c_enable'),
                    (8, 8, 'start'),
                    (9, 9, 'stop'),
                    (10, 10, 'ack'),
                ],
                0x10: [
                    (0, 0, 'start_bit'),
                    (1, 1, 'addr_sent'),
                    (2, 2, 'byte_transfer_finished'),
                    (7, 7, 'tx_empty'),
                ],
            },
            access_pattern_hints={
                0x00: 'write',
                0x0C: 'read_write',
                0x10: 'read',
            },
            initialization_sequence=[0x18, 0x08, 0x00]
        )
    
    def _timer_rule(self) -> PeripheralRule:
        """Timer外设规则"""
        return PeripheralRule(
            peripheral_type='TIMER',
            confidence_boost=0.9,
            offset_patterns=[0x00, 0x04, 0x08, 0x0C, 0x10, 0x24, 0x28, 0x2C],
            register_purposes={
                0x00: 'control_register1',
                0x04: 'control_register2',
                0x08: 'slave_mode_control',
                0x0C: 'dma_interrupt_enable',
                0x10: 'status_register',
                0x24: 'counter_register',
                0x28: 'prescaler',
                0x2C: 'auto_reload_register',
            },
            bitfield_hints={
                0x00: [
                    (0, 0, 'counter_enable'),
                    (1, 1, 'update_disable'),
                    (2, 2, 'update_request_source'),
                    (3, 3, 'one_pulse_mode'),
                ],
                0x10: [
                    (0, 0, 'update_interrupt_flag'),
                    (1, 1, 'cc1_interrupt_flag'),
                ],
            },
            access_pattern_hints={
                0x00: 'write',
                0x10: 'read',
                0x24: 'read_write',
            },
            initialization_sequence=[0x28, 0x2C, 0x00]
        )
    
    def _adc_rule(self) -> PeripheralRule:
        """ADC外设规则"""
        return PeripheralRule(
            peripheral_type='ADC',
            confidence_boost=0.9,
            offset_patterns=[0x00, 0x04, 0x08, 0x0C, 0x4C],
            register_purposes={
                0x00: 'status_register',
                0x04: 'control_register1',
                0x08: 'control_register2',
                0x0C: 'sample_time_register1',
                0x10: 'sample_time_register2',
                0x4C: 'data_register',
            },
            bitfield_hints={
                0x00: [
                    (1, 1, 'end_of_conversion'),
                    (4, 4, 'start_of_conversion'),
                ],
                0x08: [
                    (0, 0, 'adc_on'),
                    (1, 1, 'continuous_conversion'),
                    (22, 22, 'start_conversion'),
                ],
            },
            access_pattern_hints={
                0x00: 'read',
                0x04: 'write',
                0x4C: 'read',
            },
            initialization_sequence=[0x0C, 0x04, 0x08]
        )
    
    def _dma_rule(self) -> PeripheralRule:
        """DMA外设规则"""
        return PeripheralRule(
            peripheral_type='DMA',
            confidence_boost=0.9,
            offset_patterns=[0x08, 0x0C, 0x10, 0x14, 0x18],
            register_purposes={
                0x08: 'channel_config_register',
                0x0C: 'number_of_data',
                0x10: 'peripheral_address',
                0x14: 'memory_address',
            },
            bitfield_hints={
                0x08: [
                    (0, 0, 'channel_enable'),
                    (1, 1, 'transfer_complete_interrupt'),
                    (4, 5, 'data_transfer_direction'),
                    (7, 7, 'memory_increment'),
                ],
            },
            access_pattern_hints={
                0x08: 'write',
                0x0C: 'write',
                0x10: 'write',
                0x14: 'write',
            },
            initialization_sequence=[0x10, 0x14, 0x0C, 0x08]
        )
    
    def _rcc_rule(self) -> PeripheralRule:
        """RCC (复位和时钟控制) 规则"""
        return PeripheralRule(
            peripheral_type='RCC',
            confidence_boost=1.0,
            offset_patterns=[0x00, 0x04, 0x08, 0x0C, 0x10, 0x14, 0x18, 0x1C, 0x20],
            register_purposes={
                0x00: 'clock_control_register',
                0x04: 'pll_config_register',
                0x08: 'clock_config_register',
                0x0C: 'clock_interrupt_register',
                0x10: 'ahb_peripheral_reset',
                0x14: 'apb1_peripheral_reset',
                0x18: 'apb2_peripheral_reset',
                0x1C: 'ahb_peripheral_clock_enable',
                0x20: 'apb1_peripheral_clock_enable',
            },
            bitfield_hints={
                0x00: [
                    (0, 0, 'hsi_on'),
                    (1, 1, 'hsi_ready'),
                    (16, 16, 'hse_on'),
                    (17, 17, 'hse_ready'),
                    (24, 24, 'pll_on'),
                    (25, 25, 'pll_ready'),
                ],
                0x08: [
                    (0, 1, 'system_clock_switch'),
                    (4, 7, 'ahb_prescaler'),
                    (10, 12, 'apb1_prescaler'),
                    (13, 15, 'apb2_prescaler'),
                ],
            },
            access_pattern_hints={
                0x00: 'write',
                0x08: 'write',
                0x1C: 'write',
            },
            initialization_sequence=[0x00, 0x04, 0x08, 0x1C, 0x20]
        )
    
    def get_rule(self, peripheral_type: str) -> Optional[PeripheralRule]:
        """获取指定类型的规则"""
        return next((r for r in self.rules if r.peripheral_type == peripheral_type), None)
    
    def list_supported_peripherals(self) -> List[str]:
        """列出支持的所有外设类型"""
        return [rule.peripheral_type for rule in self.rules]


