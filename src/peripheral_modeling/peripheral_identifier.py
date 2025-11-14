#!/usr/bin/env python3
"""
Peripheral Identifier - Clusters MMIO addresses and identifies peripheral types
"""

import json
from pathlib import Path
from typing import List, Dict, Optional, Set
from dataclasses import dataclass
import logging

@dataclass
class PeripheralCandidate:
    """Represents a candidate peripheral"""
    name: str
    base_address: int
    size: int
    type: str
    confidence: float
    addresses: List[int]
    registers: Dict[int, Dict]  # offset -> register info
    source: str  # 'knowledge_base', 'clustered', 'isolated'
    
    def to_dict(self) -> Dict:
        return {
            'name': self.name,
            'base_address': hex(self.base_address),
            'size': hex(self.size),
            'type': self.type,
            'confidence': self.confidence,
            'addresses': [hex(a) for a in self.addresses],
            'registers': {hex(k): v for k, v in self.registers.items()},
            'source': self.source
        }


class PeripheralIdentifier:
    """Identifies and clusters peripherals from MMIO addresses"""
    
    def __init__(self, architecture: str, variant: str = "Unknown"):
        self.architecture = architecture.upper()
        self.variant = variant
        self.logger = logging.getLogger('PeripheralIdentifier')
        
        # Load knowledge base
        self.knowledge_base = self._load_knowledge_base()
        
        # Clustering parameters
        self.cluster_distance = 0x1000  # 4KB clustering window
        self.min_peripheral_size = 0x100  # 256 bytes minimum
        self.max_peripheral_size = 0x10000  # 64KB maximum ⭐ 增大以覆盖大型外设集群
    
    def _load_knowledge_base(self) -> Dict:
        """Load peripheral knowledge base"""
        kb_path = Path(__file__).parent.parent.parent / 'knowledge_base' / f'{self.architecture.lower()}_peripherals.json'
        
        if kb_path.exists():
            with open(kb_path, 'r') as f:
                kb = json.load(f)
                self.logger.info(f"Loaded knowledge base: {len(kb.get('peripherals', []))} peripherals")
                return kb
        else:
            self.logger.warning(f"Knowledge base not found: {kb_path}")
            return {'peripherals': []}
    
    def identify_peripherals(self, mmio_addresses: List[Dict]) -> List[Dict]:
        """
        Identify peripherals from MMIO addresses
        
        Args:
            mmio_addresses: List of MMIO address dictionaries
        
        Returns:
            List of identified peripheral dictionaries
        """
        self.logger.info(f"Identifying peripherals from {len(mmio_addresses)} MMIO addresses")
        
        # Extract unique addresses
        unique_addresses = sorted(set(addr['address'] for addr in mmio_addresses))
        
        # Two-tier clustering approach
        peripherals = []
        
        # Tier 1: Knowledge-based clustering
        kb_peripherals, remaining_addresses = self._knowledge_based_clustering(unique_addresses)
        peripherals.extend(kb_peripherals)
        self.logger.info(f"Knowledge-based clustering: {len(kb_peripherals)} peripherals, {len(remaining_addresses)} remaining addresses")
        
        # Tier 2: Distance-based clustering
        distance_peripherals = self._distance_based_clustering(remaining_addresses)
        peripherals.extend(distance_peripherals)
        self.logger.info(f"Distance-based clustering: {len(distance_peripherals)} peripherals")
        
        # Sort by base address
        peripherals.sort(key=lambda p: p['base_address'] if isinstance(p['base_address'], int) else int(p['base_address'], 16))
        
        self.logger.info(f"Total identified peripherals: {len(peripherals)}")
        
        return peripherals
    
    def _knowledge_based_clustering(self, addresses: List[int]) -> tuple[List[Dict], List[int]]:
        """
        Cluster addresses using knowledge base
        
        Returns:
            (identified_peripherals, remaining_addresses)
        """
        identified = []
        used_addresses = set()
        
        # Check each address against knowledge base
        for kb_peripheral in self.knowledge_base.get('peripherals', []):
            base = int(kb_peripheral['base_address'], 16) if isinstance(kb_peripheral['base_address'], str) else kb_peripheral['base_address']
            size = int(kb_peripheral['size'], 16) if isinstance(kb_peripheral['size'], str) else kb_peripheral['size']
            end = base + size
            
            # Find addresses in this peripheral's range
            matching_addresses = [addr for addr in addresses if base <= addr < end]
            
            if matching_addresses:
                # Create peripheral candidate
                candidate = {
                    'name': kb_peripheral['name'],
                    'base_address': hex(base),
                    'size': hex(size),
                    'type': kb_peripheral.get('type', 'UNKNOWN'),
                    'confidence': 0.95,  # High confidence from knowledge base
                    'addresses': [hex(a) for a in matching_addresses],
                    'registers': self._extract_register_info(matching_addresses, base),
                    'source': 'knowledge_base',
                    'vendor_info': kb_peripheral.get('vendor_info', {})
                }
                
                identified.append(candidate)
                used_addresses.update(matching_addresses)
        
        # Remaining addresses
        remaining = [addr for addr in addresses if addr not in used_addresses]
        
        return identified, remaining
    
    def _distance_based_clustering(self, addresses: List[int]) -> List[Dict]:
        """
        Cluster remaining addresses by distance
        """
        if not addresses:
            return []
        
        clusters = []
        current_cluster = [addresses[0]]
        
        for addr in addresses[1:]:
            # Check if address is within clustering distance of current cluster
            if addr - current_cluster[-1] <= self.cluster_distance:
                current_cluster.append(addr)
            else:
                # Finalize current cluster
                if current_cluster:
                    clusters.append(current_cluster)
                # Start new cluster
                current_cluster = [addr]
        
        # Don't forget the last cluster
        if current_cluster:
            clusters.append(current_cluster)
        
        # Convert clusters to peripheral candidates
        peripherals = []
        for i, cluster in enumerate(clusters):
            base_address = min(cluster)
            max_address = max(cluster)
            
            # Calculate size (round up to nearest power of 2 or minimum size)
            size = max(max_address - base_address + 0x100, self.min_peripheral_size)
            size = min(size, self.max_peripheral_size)
            
            # Infer type from address range
            peripheral_type = self._infer_peripheral_type(base_address)
            
            candidate = {
                'name': f'PERIPH_{i}_{hex(base_address)}',
                'base_address': hex(base_address),
                'size': hex(size),
                'type': peripheral_type,
                'confidence': 0.6,  # Medium confidence from clustering
                'addresses': [hex(a) for a in cluster],
                'registers': self._extract_register_info(cluster, base_address),
                'source': 'clustered'
            }
            
            peripherals.append(candidate)
        
        return peripherals
    
    def _infer_peripheral_type(self, base_address: int) -> str:
        """
        Infer peripheral type from address range heuristics
        """
        # STM32 address ranges
        if self.architecture == 'ARM' and 'STM32' in self.variant.upper():
            if 0x40000000 <= base_address < 0x40008000:
                return 'APB1_PERIPHERAL'
            elif 0x40010000 <= base_address < 0x40018000:
                return 'APB2_PERIPHERAL'
            elif 0x40020000 <= base_address < 0x40030000:
                return 'AHB1_PERIPHERAL'
            elif 0x48000000 <= base_address < 0x50000000:
                return 'AHB2_PERIPHERAL'
            elif 0x50000000 <= base_address < 0x60000000:
                return 'AHB3_PERIPHERAL'
        
        # SAM3X address ranges
        elif self.architecture == 'ARM' and 'SAM3X' in self.variant.upper():
            if 0x40000000 <= base_address < 0x40100000:
                return 'PERIPHERAL'
            elif 0x400E0000 <= base_address < 0x400E2000:
                return 'SYSTEM_PERIPHERAL'
        
        # K64F address ranges
        elif self.architecture == 'ARM' and 'K64F' in self.variant.upper():
            if 0x40000000 <= base_address < 0x40100000:
                return 'AIPS_PERIPHERAL'
        
        # MAX32 address ranges
        elif self.architecture == 'ARM' and 'MAX32' in self.variant.upper():
            if 0x40000000 <= base_address < 0x40100000:
                return 'APB_PERIPHERAL'
        
        return 'UNKNOWN'
    
    def _extract_register_info(self, addresses: List[int], base_address: int) -> Dict[int, Dict]:
        """Extract register information from addresses"""
        registers = {}
        
        for addr in addresses:
            offset = addr - base_address
            registers[offset] = {
                'address': hex(addr),
                'offset': hex(offset),
                'access': 'RW',  # Default, can be refined later
                'name': f'REG_{offset:04X}'
            }
        
        return registers


# Example usage
if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    
    # Test with sample MMIO addresses
    sample_addresses = [
        {'address': 0x40011000, 'type': 'pc_relative', 'confidence': 0.9},
        {'address': 0x40011004, 'type': 'pc_relative', 'confidence': 0.9},
        {'address': 0x40011008, 'type': 'register_access', 'confidence': 0.8},
        {'address': 0x40013800, 'type': 'pc_relative', 'confidence': 0.9},
        {'address': 0x40020000, 'type': 'pc_relative', 'confidence': 0.9},
    ]
    
    identifier = PeripheralIdentifier('ARM', 'STM32F4')
    peripherals = identifier.identify_peripherals(sample_addresses)
    
    print(f"\nIdentified {len(peripherals)} peripherals:")
    for p in peripherals:
        print(f"  {p['name']}: {p['type']} @ {p['base_address']} (size: {p['size']})")
