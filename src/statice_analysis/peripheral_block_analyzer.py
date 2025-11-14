"""
Enhanced Peripheral Address Analyzer

This module enhances peripheral detection by:
1. Identifying peripheral base addresses (not just individual register addresses)
2. Determining peripheral address ranges
3. Grouping related MMIO accesses into peripheral blocks
4. Using known peripheral databases to infer complete address ranges

Key improvements:
- Base address detection using alignment and clustering
- Range inference from known peripheral databases
- Conservative range estimation for unknown peripherals
"""

import sys
from pathlib import Path
from typing import Dict, List, Set, Tuple, Optional
from dataclasses import dataclass

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from peripheral_modeling.known_peripherals_db import lookup_peripheral, ALL_PERIPHERALS


@dataclass
class PeripheralBlock:
    """Represents a complete peripheral with base address and range"""
    base_addr: int
    size: int
    peripheral_type: str
    name: str
    accessed_offsets: Set[int]  # Offsets actually accessed by firmware
    confidence: str  # 'high', 'medium', 'low'
    
    def get_end_addr(self) -> int:
        return self.base_addr + self.size
    
    def contains(self, addr: int) -> bool:
        return self.base_addr <= addr < self.get_end_addr()


class PeripheralBlockAnalyzer:
    """
    Analyzes MMIO addresses to identify complete peripheral blocks
    """
    
    # Common peripheral sizes for different MCU families
    PERIPHERAL_SIZES = {
        'STM32': {
            'USART': 0x400,
            'UART': 0x400,
            'SPI': 0x400,
            'I2C': 0x400,
            'TIMER': 0x400,
            'ADC': 0x400,
            'DMA': 0x400,
            'GPIO': 0x400,
            'CAN': 0x400,
            'PWM': 0x400,
            'DEFAULT': 0x400
        },
        'SAM3X': {
            'USART': 0x200,
            'UART': 0x200,
            'SPI': 0x100,
            'TWI': 0x100,
            'SSC': 0x400,
            'TC': 0x100,  # Timer Counter
            'PWM': 0x400,
            'ADC': 0x200,
            'DACC': 0x100,
            'DMAC': 0x400,
            'PIOA': 0x200,
            'PIOB': 0x200,
            'PIOC': 0x200,
            'PIOD': 0x200,
            'PMC': 0x200,
            'EEFC': 0x200,
            'WDT': 0x10,
            'RTC': 0x100,
            'RTT': 0x20,
            'DEFAULT': 0x200
        },
        'LPC': {
            'UART': 0x1000,
            'TIMER': 0x1000,
            'PWM': 0x1000,
            'DEFAULT': 0x1000
        },
        'DEFAULT': {
            'DEFAULT': 0x400  # Conservative default
        }
    }
    
    def __init__(self, mcu_family: str = 'DEFAULT'):
        self.mcu_family = mcu_family
        self.size_table = self.PERIPHERAL_SIZES.get(mcu_family, self.PERIPHERAL_SIZES['DEFAULT'])
    
    def analyze_addresses(self, mmio_addresses: List[int]) -> List[PeripheralBlock]:
        """
        Analyze a list of MMIO addresses and identify peripheral blocks
        
        Returns:
            List of PeripheralBlock objects with inferred ranges
        """
        if not mmio_addresses:
            return []
        
        # Sort addresses
        sorted_addrs = sorted(set(mmio_addresses))
        
        # ⭐ 特殊处理：识别系统外设密集区域（多个小型外设）
        system_periph_blocks = self._identify_system_peripheral_regions(sorted_addrs)
        
        # 从地址列表中移除已处理的系统外设地址
        remaining_addrs = [addr for addr in sorted_addrs 
                          if not any(block.contains(addr) for block in system_periph_blocks)]
        
        # Group remaining addresses into clusters (potential peripherals)
        clusters = self._cluster_addresses(remaining_addrs)
        
        # Convert clusters to peripheral blocks
        blocks = list(system_periph_blocks)  # Start with system peripherals
        for cluster_addrs in clusters:
            block = self._create_peripheral_block(cluster_addrs)
            if block:
                blocks.append(block)
        
        return blocks
    
    def _identify_system_peripheral_regions(self, addresses: List[int]) -> List[PeripheralBlock]:
        """
        识别系统外设密集区域（如SAM3X的0x400E1Axx区域）
        
        特征：
        - 多个小型外设（16-256字节）
        - 密集分布在一个小区域内（通常256字节内）
        - 地址间隔小（0x10-0x40）
        
        已知模式：
        - SAM3X: 0x400E1A00-0x400E1AFF (RSTC, SUPC, RTT, WDT, RTC, GPBR)
        - STM32: 0xE000E000-0xE000EFFF (NVIC, SCB, SysTick)
        """
        system_blocks = []
        
        # 定义已知的系统外设密集区域
        SYSTEM_REGIONS = [
            # (region_base, region_size, standard_periph_size, name_prefix)
            (0x400E1A00, 0x100, 0x10, "SAM3X_SYS"),  # SAM3X system peripherals
            (0x400E1800, 0x200, 0x200, "SAM3X_PIO"), # SAM3X PIO controllers
            (0xE000E000, 0x1000, 0x100, "ARM_SYS"),  # ARM system peripherals
        ]
        
        for region_base, region_size, periph_size, name_prefix in SYSTEM_REGIONS:
            region_end = region_base + region_size
            
            # 找到在这个区域内的所有地址
            addrs_in_region = [addr for addr in addresses 
                              if region_base <= addr < region_end]
            
            if not addrs_in_region:
                continue
            
            # 为每个地址创建小型外设块
            # 按periph_size对齐
            bases_seen = set()
            for addr in addrs_in_region:
                # 计算这个地址所属的外设基址
                periph_base = (addr // periph_size) * periph_size
                
                # 确保在区域范围内
                if region_base <= periph_base < region_end:
                    if periph_base not in bases_seen:
                        bases_seen.add(periph_base)
                        
                        # 创建小型外设块
                        offset_in_region = periph_base - region_base
                        block = PeripheralBlock(
                            base_addr=periph_base,
                            size=periph_size,
                            peripheral_type='SYSTEM',
                            name=f'{name_prefix}_{hex(offset_in_region)[2:].upper()}',
                            accessed_offsets={addr - periph_base for addr in addrs_in_region
                                             if periph_base <= addr < periph_base + periph_size},
                            confidence='high'  # 基于已知模式，高置信度
                        )
                        system_blocks.append(block)
        
        return system_blocks
    
    def _cluster_addresses(self, addresses: List[int], max_gap: int = 0x100) -> List[List[int]]:
        """
        Cluster addresses that are close together into groups
        """
        if not addresses:
            return []
        
        clusters = []
        current_cluster = [addresses[0]]
        
        for addr in addresses[1:]:
            if addr - current_cluster[-1] <= max_gap:
                current_cluster.append(addr)
            else:
                clusters.append(current_cluster)
                current_cluster = [addr]
        
        clusters.append(current_cluster)
        return clusters
    
    def _infer_base_address(self, addresses: List[int]) -> int:
        """
        Infer the base address of a peripheral from accessed addresses
        
        Strategy:
        1. Try common alignment boundaries (0x400, 0x200, 0x100, 0x1000)
        2. Use the lowest address aligned to the boundary
        """
        min_addr = min(addresses)
        
        # Try different alignment boundaries (most common first)
        for alignment in [0x1000, 0x400, 0x200, 0x100, 0x40]:
            base = (min_addr // alignment) * alignment
            if base <= min_addr:
                return base
        
        return min_addr
    
    def _create_peripheral_block(self, addresses: List[int]) -> Optional[PeripheralBlock]:
        """
        Create a PeripheralBlock from a cluster of addresses
        """
        if not addresses:
            return None
        
        # Infer base address
        base_addr = self._infer_base_address(addresses)
        
        # Try to identify peripheral from known database
        peripheral_info = lookup_peripheral(hex(base_addr))
        
        if peripheral_info:
            # Known peripheral - use database info
            peripheral_type = peripheral_info['type']
            name = peripheral_info.get('name', peripheral_type)
            family = peripheral_info.get('family', self.mcu_family)
            
            # Get size from size table
            size = self._get_peripheral_size(peripheral_type, family)
            confidence = 'high'
        else:
            # Unknown peripheral - try to infer type and size
            peripheral_type = 'UNKNOWN'
            name = f'PERIPH_{hex(base_addr)}'
            
            # Infer size from accessed addresses
            max_offset = max(addr - base_addr for addr in addresses)
            size = self._round_up_size(max_offset + 4)  # +4 for register size
            confidence = 'low'
        
        # Calculate accessed offsets
        accessed_offsets = set(addr - base_addr for addr in addresses)
        
        return PeripheralBlock(
            base_addr=base_addr,
            size=size,
            peripheral_type=peripheral_type,
            name=name,
            accessed_offsets=accessed_offsets,
            confidence=confidence
        )
    
    def _get_peripheral_size(self, peripheral_type: str, family: str = None) -> int:
        """
        Get the standard size for a peripheral type
        """
        # Try family-specific size table first
        if family and family in self.PERIPHERAL_SIZES:
            size_table = self.PERIPHERAL_SIZES[family]
            if peripheral_type in size_table:
                return size_table[peripheral_type]
            return size_table['DEFAULT']
        
        # Fall back to current MCU family
        if peripheral_type in self.size_table:
            return self.size_table[peripheral_type]
        
        return self.size_table['DEFAULT']
    
    def _round_up_size(self, size: int) -> int:
        """
        Round up size to a reasonable peripheral size
        """
        # Round up to next power of 2 or standard size
        for std_size in [0x10, 0x20, 0x40, 0x100, 0x200, 0x400, 0x1000]:
            if size <= std_size:
                return std_size
        return 0x1000  # Max reasonable peripheral size
    
    def merge_overlapping_blocks(self, blocks: List[PeripheralBlock]) -> List[PeripheralBlock]:
        """
        Merge overlapping peripheral blocks
        """
        if not blocks:
            return []
        
        # Sort by base address
        sorted_blocks = sorted(blocks, key=lambda b: b.base_addr)
        
        merged = [sorted_blocks[0]]
        
        for block in sorted_blocks[1:]:
            last = merged[-1]
            
            # Check for overlap
            if block.base_addr < last.get_end_addr():
                # Overlapping - merge
                if block.confidence == 'high' and last.confidence != 'high':
                    # Prefer high confidence block
                    merged[-1] = block
                elif block.confidence == last.confidence:
                    # Same confidence - extend range
                    new_end = max(last.get_end_addr(), block.get_end_addr())
                    last.size = new_end - last.base_addr
                    last.accessed_offsets.update(
                        offset + (block.base_addr - last.base_addr) 
                        for offset in block.accessed_offsets
                    )
            else:
                # No overlap - add new block
                merged.append(block)
        
        return merged


def enhance_peripheral_analysis(mmio_addresses: List[int], mcu_family: str = 'SAM3X') -> Dict:
    """
    Enhanced peripheral analysis with base addresses and ranges
    
    Args:
        mmio_addresses: List of MMIO addresses accessed by firmware
        mcu_family: MCU family (e.g., 'SAM3X', 'STM32', 'LPC')
    
    Returns:
        Dictionary with peripheral blocks and metadata
    """
    analyzer = PeripheralBlockAnalyzer(mcu_family)
    
    # Analyze addresses to get peripheral blocks
    blocks = analyzer.analyze_addresses(mmio_addresses)
    
    # Merge overlapping blocks
    blocks = analyzer.merge_overlapping_blocks(blocks)
    
    # Convert to dictionary format
    result = {
        'peripheral_blocks': [
            {
                'base_addr': hex(block.base_addr),
                'base_addr_int': block.base_addr,
                'size': block.size,
                'end_addr': hex(block.get_end_addr()),
                'type': block.peripheral_type,
                'name': block.name,
                'accessed_offsets': sorted(block.accessed_offsets),
                'accessed_addresses': [hex(block.base_addr + off) for off in sorted(block.accessed_offsets)],
                'confidence': block.confidence
            }
            for block in blocks
        ],
        'total_blocks': len(blocks),
        'coverage': {
            'high_confidence': sum(1 for b in blocks if b.confidence == 'high'),
            'medium_confidence': sum(1 for b in blocks if b.confidence == 'medium'),
            'low_confidence': sum(1 for b in blocks if b.confidence == 'low')
        }
    }
    
    return result


if __name__ == '__main__':
    # Test with SAM3X addresses
    test_addresses = [
        0x400e0600,  # UART base
        0x400e0620,  # UART + 0x20
        0x400e0a00,  # EEFC0 base
        0x400e0a04,  # EEFC0 + 0x04
        0x40094000,  # PWM base
        0x40094004,  # PWM + 0x04
        0x400c8000,  # ADC base
        0x400c8010,  # ADC + 0x10
    ]
    
    result = enhance_peripheral_analysis(test_addresses, 'SAM3X')
    
    print("Enhanced Peripheral Analysis Results:")
    print(f"Total blocks: {result['total_blocks']}")
    print(f"Coverage: {result['coverage']}")
    print("\nPeripheral Blocks:")
    for block in result['peripheral_blocks']:
        print(f"\n  {block['name']} ({block['type']})")
        print(f"    Base: {block['base_addr']}, Size: {hex(block['size'])}, End: {block['end_addr']}")
        print(f"    Confidence: {block['confidence']}")
        print(f"    Accessed offsets: {[hex(off) for off in block['accessed_offsets'][:5]]}...")

