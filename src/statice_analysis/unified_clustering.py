
#!/usr/bin/env python3
"""
统一聚类模块
合并improved_clustering和smart_clustering的优点，提供统一接口
"""

import logging
from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from collections import defaultdict, Counter

logger = logging.getLogger(__name__)

@dataclass
class RegisterAccess:
    """寄存器访问记录"""
    base_address: int
    offset: int
    access_type: str  # 'read', 'write'
    access_size: int  # 1, 2, 4, 8 bytes
    instruction_addr: int
    function_name: Optional[str] = None
    evidence_chain: List = field(default_factory=list)
    discovery_method: str = 'unknown'

@dataclass
class OffsetStats:
    """偏移统计信息"""
    offset: int
    read_count: int
    write_count: int
    instructions: List[str]

@dataclass
class PeripheralCandidate:
    """外设候选信息"""
    base_address: int
    size: int
    offset_stats: Dict[int, OffsetStats]
    refs: List[str]
    instructions: List[str]
    peripheral_type_hint: Optional[str] = None
    confidence: float = 1.0
    cluster_method: str = 'unified'

@dataclass
class ClusterMetrics:
    """聚类质量指标"""
    cohesion: float  # 内聚度
    separation: float  # 分离度
    offset_consistency: float  # 偏移一致性
    access_pattern_consistency: float  # 访问模式一致性
    
    def quality_score(self) -> float:
        """计算综合质量得分"""
        return (self.cohesion * 0.3 + 
                self.separation * 0.2 + 
                self.offset_consistency * 0.3 + 
                self.access_pattern_consistency * 0.2)


class UnifiedClustering:
    """
    统一聚类器
    
    整合了improved_clustering的规则聚类和smart_clustering的外设识别功能
    提供简单、可靠、准确的聚类方案
    """
    
    def __init__(self, elf_analyzer=None):
        """
        初始化
        
        Args:
            elf_analyzer: ELF分析器（可选，用于高级功能）
        """
        self.elf_analyzer = elf_analyzer
        self.min_cluster_size = 1  # 最小聚类大小（改为1，保留单次访问的外设）
        self.max_offset_range = 0x10000  # 最大偏移范围（64KB，更宽松）
        self.alignment_check = False  # 禁用严格对齐检查（某些外设非4字节对齐）
        self.irq_bindings = {}  # mmio_base -> irq_number
        self.enable_normalization = False  # 禁用地址归一化（防止错误合并）
        
    def cluster_register_accesses(self, accesses: List[RegisterAccess]) -> List[PeripheralCandidate]:
        """
        聚类寄存器访问 - 统一接口
        
        Args:
            accesses: 寄存器访问列表
            
        Returns:
            外设候选列表
        """
        if not accesses:
            return []
        
        logger.info(f"开始统一聚类，输入{len(accesses)}个访问")
        
        # 步骤1: 预过滤 - 移除明显的错误访问
        valid_accesses = self._pre_filter_accesses(accesses)
        logger.info(f"预过滤后剩余{len(valid_accesses)}个有效访问")
        
        # 步骤2: 地址归一化
        normalized_accesses = self._normalize_addresses(valid_accesses)
        
        # 步骤3: 初步聚类
        initial_clusters = self._initial_clustering(normalized_accesses)
        logger.info(f"初步聚类得到{len(initial_clusters)}个簇")
        
        # 步骤4: 验证和修正
        validated_clusters = self._validate_and_fix_clusters(initial_clusters)
        logger.info(f"验证后剩余{len(validated_clusters)}个有效簇")
        
        # 步骤5: 优化聚类
        optimized_clusters = self._optimize_clusters(validated_clusters)
        logger.info(f"优化后得到{len(optimized_clusters)}个最终簇")
        
        # 步骤6: 转换为外设候选
        candidates = self._clusters_to_candidates(optimized_clusters)
        
        # 步骤7: 外设类型推断（来自smart_clustering的功能）
        candidates = self._infer_peripheral_types(candidates)
        
        return candidates
    
    def _pre_filter_accesses(self, accesses: List[RegisterAccess]) -> List[RegisterAccess]:
        """
        预过滤访问，移除明显错误
        
        注意: 这里只做最基本的过滤，避免过度过滤导致丢失外设
        详细的外设过滤在 enhanced_basic_parser._should_skip_peripheral() 中完成
        """
        filtered = []
        
        for access in accesses:
            # 获取完整地址
            full_addr = access.base_address + access.offset if hasattr(access, 'offset') else access.base_address
            
            # 规则1: 4字节对齐检查（可选，默认禁用）
            if self.alignment_check and (full_addr % 4 != 0):
                logger.debug(f"跳过未对齐地址: {full_addr:#x}")
                continue
            
            # 规则2: 只过滤明显错误的偏移（负数）
            # 不再过滤大偏移，让后续阶段处理
            if hasattr(access, 'offset'):
                if access.offset < 0:
                    logger.debug(f"跳过负偏移: base={access.base_address:#x}, offset={access.offset:#x}")
                    continue
            
            # 不在这里过滤地址范围，让 enhanced_basic_parser 统一处理
            # 避免重复过滤导致丢失外设
            
            filtered.append(access)
        
        logger.debug(f"预过滤: {len(accesses)} -> {len(filtered)} 访问")
        return filtered
    
    def _normalize_addresses(self, accesses: List[RegisterAccess]) -> List[RegisterAccess]:
        """
        地址归一化，对齐到外设边界
        
        注意: 地址归一化可能导致不同外设被错误合并
        默认禁用，除非明确启用
        """
        if not self.enable_normalization:
            # 归一化被禁用，直接返回原始访问
            logger.debug("地址归一化已禁用，保留原始基址")
            return accesses
        
        normalized = []
        
        for access in accesses:
            base = access.base_address
            offset = access.offset if hasattr(access, 'offset') else 0
            
            # 尝试对齐到典型的外设边界
            aligned_base = self._align_to_peripheral_boundary(base)
            
            if aligned_base != base:
                new_offset = (base - aligned_base) + offset
                if 0 <= new_offset <= self.max_offset_range:
                    logger.debug(f"地址归一化: {base:#x} -> {aligned_base:#x}, 新偏移: {new_offset:#x}")
                    access.base_address = aligned_base
                    if hasattr(access, 'offset'):
                        access.offset = new_offset
            
            normalized.append(access)
        
        return normalized
    
    def _align_to_peripheral_boundary(self, addr: int) -> int:
        """将地址对齐到外设边界"""
        # 尝试1KB对齐
        aligned_1k = (addr // 0x400) * 0x400
        if abs(addr - aligned_1k) <= 0x100:
            return aligned_1k
        
        # 尝试4KB对齐
        aligned_4k = (addr // 0x1000) * 0x1000
        if abs(addr - aligned_4k) <= 0x400:
            return aligned_4k
        
        return addr
    
    def _initial_clustering(self, accesses: List[RegisterAccess]) -> Dict[int, List[RegisterAccess]]:
        """初步聚类 - 基于基址分组"""
        clusters = defaultdict(list)
        
        for access in accesses:
            clusters[access.base_address].append(access)
        
        # 移除单个访问的聚类
        clusters = {base: access_list 
                   for base, access_list in clusters.items() 
                   if len(access_list) >= self.min_cluster_size}
        
        return clusters
    
    def _validate_and_fix_clusters(self, clusters: Dict[int, List[RegisterAccess]]) -> Dict[int, List[RegisterAccess]]:
        """验证和修正聚类"""
        validated = {}
        
        for base, access_list in clusters.items():
            # 提取所有偏移
            offsets = [a.offset for a in access_list if hasattr(a, 'offset')]
            
            # 如果没有偏移信息，也保留这个聚类
            if not offsets:
                if len(access_list) >= self.min_cluster_size:
                    validated[base] = access_list
                continue
            
            # 移除负偏移
            valid_offsets = [o for o in offsets if o >= 0]
            if len(valid_offsets) < len(offsets):
                logger.warning(f"外设 {base:#x}: 移除了 {len(offsets) - len(valid_offsets)} 个负偏移访问")
                access_list = [a for a in access_list 
                             if not hasattr(a, 'offset') or a.offset >= 0]
            
            # 检查偏移范围（放宽到64KB）
            if valid_offsets:
                max_offset = max(valid_offsets)
                if max_offset > self.max_offset_range:
                    logger.warning(f"外设 {base:#x}: 最大偏移 {max_offset:#x} 超过限制 {self.max_offset_range:#x}")
                    # 不再自动分裂，而是保留整个簇
                    # 让后续分析决定如何处理
            
            # 保留有效簇（最小聚类大小降为1）
            if len(access_list) >= self.min_cluster_size:
                validated[base] = access_list
            else:
                logger.debug(f"外设 {base:#x}: 访问次数 {len(access_list)} < {self.min_cluster_size}，被过滤")
        
        return validated
    
    def _split_large_cluster(self, base: int, access_list: List[RegisterAccess]) -> Dict[int, List[RegisterAccess]]:
        """分裂大簇"""
        sub_clusters = defaultdict(list)
        
        for access in access_list:
            offset = access.offset if hasattr(access, 'offset') else 0
            
            # 按照4KB块分组
            block_base = base + (offset // 0x1000) * 0x1000
            block_offset = offset % 0x1000
            
            new_access = access
            new_access.base_address = block_base
            if hasattr(new_access, 'offset'):
                new_access.offset = block_offset
            
            sub_clusters[block_base].append(new_access)
        
        return {base: accesses for base, accesses in sub_clusters.items() 
                if len(accesses) >= self.min_cluster_size}
    
    def _optimize_clusters(self, clusters: Dict[int, List[RegisterAccess]]) -> Dict[int, List[RegisterAccess]]:
        """
        优化聚类，智能合并相邻小簇
        
        ⚠️  MCU固件特点：小而精致，聚类必须非常保守！
        
        保守合并策略：
        1. 同一个1KB范围内 (<= 0x400) 且访问密集 → 可能是同一外设的寄存器
        2. 1KB-4KB范围 (0x400 - 0x1000) → 谨慎判断（可能是GPIO多端口）
        3. > 4KB → 不合并（很可能是不同外设）
        
        误合并检测：
        - 合并后偏移跨度 > 4KB → 拒绝（避免误合并）
        - 访问密度过低 → 拒绝（稀疏访问可能是多个外设）
        
        例如：
          ✅ 0x40020000 + 0x40020400 (GPIO-A + GPIO-B, 同组外设)
          ❌ 0x40020000 + 0x40024000 (GPIO + UART, 不同外设)
        """
        if not clusters:
            return {}
        
        sorted_bases = sorted(clusters.keys())
        merged_groups = []  # [(base, [accesses])]
        
        i = 0
        while i < len(sorted_bases):
            # 开始一个新的合并组
            group_base = sorted_bases[i]
            group_accesses = list(clusters[group_base])
            
            # 计算当前组的统计信息
            group_offsets = [a.offset for a in group_accesses if hasattr(a, 'offset')]
            group_min_offset = min(group_offsets) if group_offsets else 0
            group_max_offset = max(group_offsets) if group_offsets else 0
            group_span = group_max_offset - group_min_offset
            
            # 尝试连续合并后续的簇
            j = i + 1
            while j < len(sorted_bases):
                next_base = sorted_bases[j]
                next_accesses = clusters[next_base]
                
                # 计算与当前组最后一个基址的距离
                prev_base = sorted_bases[j-1]
                distance = next_base - prev_base
                
                # === 保守合并决策 ===
                should_merge = False
                merge_reason = ""
                
                # 规则1: 非常接近 (<= 1KB) → 可能是同一外设的连续寄存器
                if distance <= 0x400:
                    # 计算合并后的总跨度
                    test_merged = group_accesses + list(next_accesses)
                    test_offsets = [a.offset for a in test_merged if hasattr(a, 'offset')]
                    
                    if test_offsets:
                        merged_span = max(test_offsets) - min(test_offsets)
                        # 只有合并后跨度仍 <= 4KB 才合并
                        if merged_span <= 0x1000:
                            should_merge = True
                            merge_reason = f"极近距离({distance:#x})"
                
                # 规则2: 1KB-4KB 范围 → 需要额外证据
                elif distance <= 0x1000:
                    # 检查是否在已知的外设块模式内（例如GPIO的多端口）
                    # 特征：等间距、相同访问模式
                    test_merged = group_accesses + list(next_accesses)
                    test_offsets = [a.offset for a in test_merged if hasattr(a, 'offset')]
                    
                    if test_offsets:
                        merged_span = max(test_offsets) - min(test_offsets)
                        access_density = len(test_offsets) / (merged_span + 1) if merged_span > 0 else 1.0
                        
                        # 只有密度足够高（> 0.01，即每100字节至少1个访问）才合并
                        if merged_span <= 0x1000 and access_density > 0.01:
                            should_merge = True
                            merge_reason = f"中距离({distance:#x})+高密度({access_density:.3f})"
                        else:
                            logger.debug(f"❌ 拒绝合并: {group_base:#x} + {next_base:#x} (密度过低: {access_density:.3f})")
                
                # 规则3: 同一个4KB对齐块内 → 强制合并（寄存器块内必然同一外设）
                elif (group_base & ~0xFFF) == (next_base & ~0xFFF):
                    test_merged = group_accesses + list(next_accesses)
                    if self._should_merge(group_base, test_merged):
                        should_merge = True
                        merge_reason = "同一4KB块"
                
                if should_merge:
                    # 最终检查：偏移范围是否合理
                    if self._should_merge(group_base, test_merged):
                        group_accesses = test_merged
                        # 更新组的统计信息
                        group_offsets = [a.offset for a in group_accesses if hasattr(a, 'offset')]
                        group_min_offset = min(group_offsets) if group_offsets else 0
                        group_max_offset = max(group_offsets) if group_offsets else 0
                        group_span = group_max_offset - group_min_offset
                        
                        logger.debug(f"✅ 合并外设: {group_base:#x} + {next_base:#x} (距离:{distance:#x}, 原因:{merge_reason})")
                        j += 1
                        continue
                    else:
                        logger.debug(f"❌ 停止合并: {group_base:#x} + {next_base:#x} (偏移范围超限)")
                        break
                else:
                    logger.debug(f"⏸️  停止合并: {prev_base:#x} → {next_base:#x} (距离{distance:#x}太远)")
                    break
            
            # 保存这个合并组
            merged_groups.append((group_base, group_accesses))
            i = j  # 跳到下一个未处理的簇
        
        # 转换回字典
        optimized = {base: accesses for base, accesses in merged_groups}
        
        logger.info(f"聚类优化: {len(clusters)} 个初始簇 → {len(optimized)} 个最终外设 (保守策略)")
        return optimized
    
    def _should_merge(self, base: int, merged_accesses: List[RegisterAccess]) -> bool:
        """判断是否应该合并"""
        offsets = [a.offset for a in merged_accesses if hasattr(a, 'offset')]
        if not offsets:
            return True
        
        max_offset = max(offsets)
        return max_offset <= self.max_offset_range
    
    def _clusters_to_candidates(self, clusters: Dict[int, List[RegisterAccess]]) -> List[PeripheralCandidate]:
        """
        将聚类转换为外设候选
        
        ⭐ 关键修改：
        现在 RegisterAccess.base_address 存储的是实际的MMIO地址（如0xE000ED28），
        而不是原始基地址+偏移。
        
        因此需要重新计算：
        1. 找到簇中最小的地址作为基地址
        2. 所有其他地址相对于基地址计算偏移
        """
        candidates = []
        
        for base, access_list in clusters.items():
            # ⭐ 重新计算基地址：簇中最小的地址
            all_addresses = [a.base_address for a in access_list]
            cluster_base_address = min(all_addresses)
            
            # 统计偏移
            offset_stats_dict = defaultdict(lambda: {'read': 0, 'write': 0, 'instructions': []})
            
            for access in access_list:
                # ⭐ 计算相对于簇基地址的偏移
                offset = access.base_address - cluster_base_address
                access_type = access.access_type if hasattr(access, 'access_type') else 'unknown'
                
                if access_type == 'read':
                    offset_stats_dict[offset]['read'] += 1
                elif access_type == 'write':
                    offset_stats_dict[offset]['write'] += 1
                
                # 记录指令
                if hasattr(access, 'evidence_chain') and access.evidence_chain:
                    offset_stats_dict[offset]['instructions'].extend(access.evidence_chain[:2])
            
            # 转换为OffsetStats
            offset_stats = {}
            for offset, stats in offset_stats_dict.items():
                offset_stats[offset] = OffsetStats(
                    offset=offset,
                    read_count=stats['read'],
                    write_count=stats['write'],
                    instructions=stats['instructions'][:5]
                )
            
            # 计算外设大小
            if offset_stats:
                max_offset = max(offset_stats.keys())
                min_size = max_offset + 0x100  # 至少加256字节余量
                # 向上取整到合理的页大小
                if min_size <= 0x400:
                    size = 0x400  # 1KB
                elif min_size <= 0x1000:
                    size = 0x1000  # 4KB
                else:
                    size = ((min_size + 0xFFF) & ~0xFFF)  # 对齐到4KB
                size = min(size, 0x10000)  # 最大64KB
            else:
                size = 0x400
            
            # 创建候选 ⭐ 使用重新计算的基地址
            candidate = PeripheralCandidate(
                base_address=cluster_base_address,
                size=size,
                offset_stats=offset_stats,
                refs=[],
                instructions=[],
                peripheral_type_hint=None,
                confidence=1.0,
                cluster_method='unified'
            )
            
            candidates.append(candidate)
        
        logger.info(f"生成{len(candidates)}个外设候选")
        return candidates
    
    def _infer_peripheral_types(self, candidates: List[PeripheralCandidate]) -> List[PeripheralCandidate]:
        """
        推断外设类型
        
        基于偏移模式的简单推断（来自smart_clustering的功能）
        """
        for candidate in candidates:
            offsets = set(candidate.offset_stats.keys())
            
            # GPIO模式
            if {0x00, 0x04, 0x08, 0x0C} <= offsets:
                candidate.peripheral_type_hint = 'GPIO'
                candidate.confidence *= 1.2
            
            # UART模式
            elif {0x00, 0x04} <= offsets and len(offsets) <= 6:
                candidate.peripheral_type_hint = 'UART'
                candidate.confidence *= 1.15
            
            # Timer模式
            elif {0x00, 0x24, 0x28} <= offsets:
                candidate.peripheral_type_hint = 'TIMER'
                candidate.confidence *= 1.1
        
        return candidates
    
    def evaluate_cluster_quality(self, clusters: Dict[int, List[RegisterAccess]]) -> Dict[int, ClusterMetrics]:
        """
        评估聚类质量
        
        返回每个聚类的质量指标
        """
        metrics = {}
        
        for base, access_list in clusters.items():
            cohesion = self._calculate_cohesion(access_list)
            separation = self._calculate_separation(base, clusters)
            offset_consistency = self._calculate_offset_consistency(access_list)
            pattern_consistency = self._calculate_pattern_consistency(access_list)
            
            metrics[base] = ClusterMetrics(
                cohesion=cohesion,
                separation=separation,
                offset_consistency=offset_consistency,
                access_pattern_consistency=pattern_consistency
            )
        
        return metrics
    
    def _calculate_cohesion(self, access_list: List[RegisterAccess]) -> float:
        """计算簇内聚度"""
        if len(access_list) < 2:
            return 1.0
        
        offsets = [a.offset for a in access_list if hasattr(a, 'offset')]
        if not offsets:
            return 1.0
        
        offset_range = max(offsets) - min(offsets) if len(offsets) > 1 else 0
        cohesion = 1.0 - min(offset_range / self.max_offset_range, 1.0)
        
        return cohesion
    
    def _calculate_separation(self, base: int, all_clusters: Dict[int, List[RegisterAccess]]) -> float:
        """计算簇分离度"""
        other_bases = [b for b in all_clusters.keys() if b != base]
        if not other_bases:
            return 1.0
        
        min_distance = min(abs(base - other) for other in other_bases)
        separation = min(min_distance / 0x1000, 1.0)
        
        return separation
    
    def _calculate_offset_consistency(self, access_list: List[RegisterAccess]) -> float:
        """计算偏移一致性"""
        offsets = [a.offset for a in access_list if hasattr(a, 'offset')]
        if not offsets:
            return 1.0
        
        negative_ratio = sum(1 for o in offsets if o < 0) / len(offsets)
        large_ratio = sum(1 for o in offsets if o > self.max_offset_range) / len(offsets)
        
        consistency = 1.0 - negative_ratio - large_ratio
        return max(consistency, 0.0)
    
    def _calculate_pattern_consistency(self, access_list: List[RegisterAccess]) -> float:
        """计算访问模式一致性"""
        read_count = sum(1 for a in access_list 
                        if hasattr(a, 'access_type') and a.access_type == 'read')
        write_count = sum(1 for a in access_list 
                         if hasattr(a, 'access_type') and a.access_type == 'write')
        
        if read_count + write_count == 0:
            return 1.0
        
        # 理想情况下，读写都应该存在
        if read_count > 0 and write_count > 0:
            consistency = 1.0
        elif read_count == 0 or write_count == 0:
            consistency = 0.7
        else:
            consistency = 0.5
        
        return consistency

