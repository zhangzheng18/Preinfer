#!/usr/bin/env python3
"""
基于静态分析的外设代码生成和QEMU集成 - 使用src/现有模块

完整流程:
1. 静态分析固件 (src/static_analysis + src/peripheral_modeling)
2. 生成外设C代码 (src/qemu_integration/enhanced_qemu_peripheral_generator_v24.py)
3. 适配板型 (src/soc_integration/board_template_manager.py + dynamic_board_adapter.py)
4. 更新QEMU构建
5. 编译并测试

这个脚本整合了src/下所有现有的功能模块！
"""

import sys
import os
import json
import subprocess
import time
import logging
from pathlib import Path
from typing import Dict, List, Optional

# 添加src到路径
PROJECT_ROOT = Path(__file__).parent
sys.path.insert(0, str(PROJECT_ROOT / 'src'))

# 导入现有的src模块
from static_analysis.elf_analyzer import ELFAnalyzer
from static_analysis.enhanced_basic_parser import EnhancedBasicParser
from arch_detection.arch_detector import ArchDetector
from peripheral_modeling.peripheral_identifier import PeripheralIdentifier
from peripheral_modeling.known_peripherals_db import lookup_peripheral
from peripheral_modeling.peripheral_templates import (
    get_template_for_type,
    UART_TEMPLATE,
    GPIO_TEMPLATE,
    SPI_TEMPLATE,
    GENERIC_TEMPLATE
)

from qemu_integration.enhanced_qemu_peripheral_generator_v24 import EnhancedQEMUPeripheralGenerator
from qemu_integration.phase1_improved_generator import Phase1ImprovedGenerator
from qemu_integration.safe_board_generator import SafeBoardGenerator
from qemu_integration.enhanced_board_generator import (  # ⭐ NEW: 使用平衡策略的板型生成器
    generate_enhanced_board_code,
    save_and_integrate_board
)
from qemu_integration.hybrid_peripheral_generator import HybridPeripheralGenerator  # ⭐ BEST: 混合策略
from soc_integration.board_template_manager import BoardTemplateManager
from soc_integration.dynamic_board_adapter import DynamicBoardAdapter
from static_analysis.empty_interrupt_detector import EmptyInterruptDetector
from static_analysis.peripheral_block_analyzer import PeripheralBlockAnalyzer  # ⭐ NEW: 外设块分析器

logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger(__name__)

class StaticAnalysisBasedCodeGen:
    """
    基于静态分析的代码生成完整流程
    
    核心思想: 充分利用src/下已有的所有模块
    """
    
    def __init__(self, qemu_path: str = None):
        self.qemu_path = Path(qemu_path or "/home/zhangzheng/new/qemu")
        self.project_root = PROJECT_ROOT
        self.output_dir = self.project_root / "generated"
        self.output_dir.mkdir(exist_ok=True)
        
        # 初始化现有模块
        # ⭐ BEST: 混合策略生成器（精确模板 + 智能通用外设）
        self.hybrid_generator = HybridPeripheralGenerator(str(self.qemu_path))
        self.peripheral_analyzer = PeripheralBlockAnalyzer()
        
        # 保留旧版本作为备份
        self.periph_generator = Phase1ImprovedGenerator()
        self.periph_generator_v24 = EnhancedQEMUPeripheralGenerator()
        self.board_manager = BoardTemplateManager(str(self.qemu_path))
        self.board_adapter = DynamicBoardAdapter(str(self.qemu_path))
        
        self.results = []
        
    def process_firmware(self, firmware_path: Path) -> Dict:
        """处理单个固件的完整流程"""
        logger.info("\n" + "="*80)
        logger.info(f"🎯 处理固件: {firmware_path.name}")
        logger.info("="*80)
        
        result = {
            'firmware': firmware_path.name,
            'success': False,
            'error': None
        }
        
        try:
            # Step 1: 静态分析 (使用src/现有模块)
            logger.info("\n📊 Step 1: 静态分析固件 (使用src/模块)")
            analysis_result = self._run_static_analysis(firmware_path)
            
            if not analysis_result['success']:
                result['error'] = analysis_result.get('error', 'Static analysis failed')
                return result
            
            result.update({
                'architecture': analysis_result['architecture'],
                'mmio_count': analysis_result['mmio_count'],
                'peripheral_count': analysis_result['peripheral_count']
            })
            
            logger.info(f"   ✅ 识别: {result['peripheral_count']}个外设, "
                       f"{result['mmio_count']}个MMIO")
            
            # 保存分析结果 (供后续步骤使用)
            analysis_json = self.output_dir / f"{firmware_path.stem}_comprehensive.json"
            self._save_analysis_result(analysis_result, analysis_json)
            
            # ⭐ Step 2: 外设块分析（增强的聚类分析）
            logger.info("\n🔬 Step 2: 外设块分析 (PeripheralBlockAnalyzer)")
            mmio_addresses = analysis_result.get('raw_mmio_addresses', [])
            peripheral_blocks = self.peripheral_analyzer.analyze_addresses(mmio_addresses)
            
            logger.info(f"   ✅ 识别: {len(peripheral_blocks)}个外设块")
            
            # 统计置信度
            confidence_counts = {'high': 0, 'medium': 0, 'low': 0}
            for block in peripheral_blocks:
                confidence_counts[block.confidence] += 1
            
            logger.info(f"   📊 置信度: high={confidence_counts['high']}, "
                       f"medium={confidence_counts['medium']}, low={confidence_counts['low']}")
            
            # ⭐ Step 3: 生成混合板型（精确模板 + 智能通用外设）
            logger.info("\n🏗️  Step 3: 生成混合板型 (HybridPeripheralGenerator)")
            
            board_name = f"netduinoplus2_enhanced_{firmware_path.stem.replace('-', '_')}"
            
            hybrid_result = self.hybrid_generator.generate_hybrid_board(
                firmware_path=firmware_path,
                peripheral_blocks=peripheral_blocks,
                analysis_result=analysis_result,
                board_name=board_name
            )
            
            if not hybrid_result['success']:
                result['error'] = f"Hybrid board generation failed: {hybrid_result.get('error')}"
                return result
            
            board_name = hybrid_result['board_name']
            result['board_name'] = board_name
            result['board_file'] = hybrid_result.get('board_file')
            result['template_peripherals'] = hybrid_result['template_peripherals']
            result['smart_peripherals'] = hybrid_result['smart_peripherals']
            
            logger.info(f"   ✅ 板型: {board_name}")
            logger.info(f"   ✅ 外设块: {len(peripheral_blocks)}个")
            logger.info(f"   ✅ 混合策略: {hybrid_result['template_peripherals']}个模板 + {hybrid_result['smart_peripherals']}个智能")
            
            # Step 4: 更新QEMU构建配置
            logger.info("\n⚙️  Step 4: 更新QEMU构建配置")
            # 更新meson.build以包含新生成的板型
            self._update_board_meson_build(board_name)
            logger.info(f"   ✅ meson.build已更新")
            
            # Step 5: 编译QEMU
            logger.info("\n🔨 Step 5: 编译QEMU")
            if not self._build_qemu():
                result['error'] = 'QEMU build failed'
                return result
            logger.info(f"   ✅ QEMU编译成功")
            
            # Step 6: 运行测试
            logger.info("\n🚀 Step 6: 运行仿真测试")
            
            # 使用生成的板型（包含平衡策略的enhanced_smart_periph.c）
            logger.info(f"   使用板型: {board_name}")
            logger.info(f"   平衡策略: 0x00000001 (minimal ready state)")
            
            test_result = self._run_qemu_test(
                firmware_path,
                board_name
            )
            
            if test_result['success']:
                result['success'] = True
                result['test_result'] = test_result
                logger.info(f"   ✅ 仿真成功!")
                logger.info(f"      - Trace长度: {test_result.get('trace_length', 0)}")
                logger.info(f"      - 唯一PC: {test_result.get('unique_pcs', 0)}")
                logger.info(f"      - PC范围: {test_result.get('pc_range', 0)} bytes")
            else:
                result['error'] = test_result.get('error', 'Unknown')
                logger.info(f"   ❌ 仿真失败: {result['error']}")
            
        except Exception as e:
            result['error'] = str(e)
            logger.error(f"❌ 处理失败: {e}")
            import traceback
            traceback.print_exc()
        
        return result
    
    def _run_static_analysis(self, firmware_path: Path) -> Dict:
        """
        运行静态分析 - 使用src/下的现有模块
        
        使用的模块:
        - src/arch_detection/arch_detector.py
        - src/static_analysis/enhanced_basic_parser.py
        - src/peripheral_modeling/peripheral_identifier.py
        - src/peripheral_modeling/known_peripherals_db.py
        - src/static_analysis/empty_interrupt_detector.py (新增)
        """
        try:
            # 0. 空中断检测 (EmptyInterruptDetector) - 新增!
            logger.info(f"   检测空中断...")
            empty_irq_detector = EmptyInterruptDetector(str(firmware_path))
            empty_irq_result = empty_irq_detector.detect()
            
            empty_interrupt_names = set()
            empty_irq_numbers = []  # 新增: 提取IRQ号
            
            if empty_irq_result['success']:
                empty_interrupt_names = set(
                    irq.name for irq in empty_irq_result['empty_interrupts']
                )
                # 提取IRQ号（只包含外部中断，不包含系统异常）
                empty_irq_numbers = [
                    irq.irq_number 
                    for irq in empty_irq_result['empty_interrupts'] 
                    if irq.irq_number is not None
                ]
                logger.info(f"   空中断: {len(empty_interrupt_names)}个 - {list(empty_interrupt_names)[:5]}...")
                logger.info(f"   空中断IRQ: {len(empty_irq_numbers)}个 - {empty_irq_numbers[:5]}...")
            
            # 1. 架构检测 (ArchDetector)
            arch_detector = ArchDetector(str(firmware_path))
            arch_name, arch_config = arch_detector.detect()
            
            if not arch_name or not arch_config:
                return {'success': False, 'error': 'Architecture detection failed'}
            
            logger.info(f"   架构: {arch_name}")
            logger.info(f"   CPU: {arch_config.cpu_type}")
            logger.info(f"   Flash: 0x{arch_config.flash_base:08X}, {arch_config.flash_size} bytes")
            logger.info(f"   RAM: 0x{arch_config.ram_base:08X}, {arch_config.ram_size} bytes")
            
            # 2. MMIO地址提取 (EnhancedBasicParser)
            parser = EnhancedBasicParser(str(firmware_path))
            candidates = parser.extract_peripheral_candidates()
            
            # 提取所有MMIO地址
            mmio_addresses = []
            for candidate in candidates:
                base = candidate.base_address
                mmio_addresses.append(base)
                # 也包括识别的所有偏移地址 (从offset_stats获取)
                if hasattr(candidate, 'offset_stats'):
                    for offset in candidate.offset_stats.keys():
                        mmio_addresses.append(base + offset)
            
            mmio_addresses = list(set(mmio_addresses))  # 去重
            logger.info(f"   MMIO地址: {len(mmio_addresses)}个")
            
            # 3. 外设识别和聚类 (PeripheralIdentifier)
            identifier = PeripheralIdentifier(architecture=arch_name)
            
            # 将MMIO地址转换为PeripheralIdentifier需要的格式
            mmio_addr_list = [
                {'address': addr, 'access_type': 'rw'}
                for addr in mmio_addresses
            ]
            
            peripherals_result = identifier.identify_peripherals(mmio_addr_list)
            
            # identify_peripherals 返回的是列表，不是字典
            if isinstance(peripherals_result, list):
                clusters = peripherals_result
            else:
                clusters = peripherals_result.get('clusters', [])
            
            logger.info(f"   外设聚类: {len(clusters)}个")
            
            # 4. 使用known_peripherals_db增强识别
            enhanced_peripherals = []
            for cluster in clusters:
                base_addr = cluster.get('base_address', 0)
                
                # 标准化地址格式
                if isinstance(base_addr, str):
                    base_addr_hex = base_addr if base_addr.startswith('0x') else f'0x{base_addr}'
                    base_addr_int = int(base_addr_hex, 16)
                else:
                    base_addr_int = base_addr
                    base_addr_hex = f'0x{base_addr:08X}'
                
                # 查询已知外设数据库
                known_info = lookup_peripheral(base_addr_hex)
                
                periph = {
                    'name': known_info['name'] if known_info else f'PERIPH_{base_addr_int:08X}',
                    'type': known_info['type'] if known_info else cluster.get('type', 'UNKNOWN'),  # 使用'type'而不是'peripheral_type'
                    'base_address': base_addr_hex,
                    'size': cluster.get('size', 0x1000),
                    'addresses': cluster.get('addresses', []),
                    'registers': {}
                }
                
                # 构建寄存器信息
                for addr_info in cluster.get('addresses', []):
                    # 处理不同的地址格式
                    if isinstance(addr_info, int):
                        addr = addr_info
                        access_type = 'rw'
                    elif isinstance(addr_info, str):
                        addr = int(addr_info, 16) if addr_info.startswith('0x') else int(addr_info)
                        access_type = 'rw'
                    elif isinstance(addr_info, dict):
                        addr = addr_info.get('address', 0)
                        access_type = addr_info.get('access_type', 'rw')
                    else:
                        continue
                    
                    offset = addr - base_addr_int
                    if 0 <= offset < 0x10000:  # 合理的偏移范围
                        periph['registers'][f'0x{offset:02X}'] = {
                            'offset': f'0x{offset:02X}',
                            'name': f'REG_{offset:04X}',
                            'access_type': access_type
                        }
                
                enhanced_peripherals.append(periph)
            
            # 构建完整的分析结果 (兼容EnhancedQEMUPeripheralGenerator的输入格式)
            result = {
                'success': True,
                'firmware_path': str(firmware_path),
                'architecture': arch_name,
                'cpu_type': arch_config.cpu_type or 'cortex-m3',
                'entry_point': arch_detector.elf_info.get('entry', 0),
                'flash_base': arch_config.flash_base,
                'flash_size': arch_config.flash_size,
                'ram_base': arch_config.ram_base,
                'ram_size': arch_config.ram_size,
                'mmio_count': len(mmio_addresses),
                'peripheral_count': len(enhanced_peripherals),
                'clustered_peripherals': enhanced_peripherals,  # 关键字段!
                'raw_mmio_addresses': mmio_addresses,
                'empty_interrupts': empty_interrupt_names,  # 空中断名称
                'empty_irq_numbers': empty_irq_numbers  # 新增: 空中断IRQ号
            }
            
            return result
            
        except Exception as e:
            logger.error(f"   静态分析失败: {e}")
            import traceback
            traceback.print_exc()
            return {'success': False, 'error': str(e)}
    
    def _save_analysis_result(self, analysis: Dict, output_file: Path):
        """保存分析结果为JSON (供EnhancedQEMUPeripheralGenerator使用)"""
        # 转换set为list (JSON不支持set)
        analysis_copy = analysis.copy()
        if 'empty_interrupts' in analysis_copy and isinstance(analysis_copy['empty_interrupts'], set):
            analysis_copy['empty_interrupts'] = list(analysis_copy['empty_interrupts'])
        
        with open(output_file, 'w') as f:
            json.dump(analysis_copy, f, indent=2)
        logger.info(f"   💾 分析结果: {output_file.name}")
    
    def _prepare_board_config(self, analysis: Dict) -> Dict:
        """
        准备板型配置 (供DynamicBoardAdapter使用)
        
        根据架构选择合适的基础板型
        """
        arch_name = analysis['architecture']
        
        # 根据架构选择板型
        if 'STM32F4' in arch_name:
            base_board = 'netduinoplus2'
            soc_file = 'hw/arm/stm32f405_soc.c'
        elif 'STM32F1' in arch_name:
            base_board = 'stm32vldiscovery'
            soc_file = 'hw/arm/stm32f100_soc.c'
        elif 'SAM3' in arch_name:
            # SAM3系列使用通用ARM Cortex-M板型
            base_board = 'netduinoplus2'  # 使用STM32F4作为基础
            soc_file = 'hw/arm/stm32f405_soc.c'
            logger.info(f"   ⚠️  SAM3使用通用ARM板型 (netduinoplus2)")
        else:
            # 默认使用STM32F4板型
            base_board = 'netduinoplus2'
            soc_file = 'hw/arm/stm32f405_soc.c'
            logger.info(f"   ⚠️  未知架构，使用默认板型 (netduinoplus2)")
        
        board_config = {
            'base_board': base_board,
            'soc_file': soc_file,
            'similarity_score': 85.0,  # 基于静态分析的配置
            'adjustments': {
                'flash_base': analysis['flash_base'],
                'flash_size': analysis['flash_size'],
                'flash_size_kb': analysis['flash_size'] // 1024,  # KB单位
                'sram_base': analysis['ram_base'],  # DynamicBoardAdapter使用sram_base
                'sram_size': analysis['ram_size'],
                'sram_size_kb': analysis['ram_size'] // 1024,  # KB单位
                'ram_base': analysis['ram_base'],   # 也保留ram_base以兼容
                'ram_size': analysis['ram_size']
            },
            'special_regions': []
        }
        
        return board_config
    
    def _update_board_meson_build(self, board_name: str):
        """更新QEMU的meson.build文件以包含新生成的板型"""
        arm_meson = self.qemu_path / "hw" / "arm" / "meson.build"
        
        if not arm_meson.exists():
            logger.warning(f"   ⚠️  未找到: {arm_meson}")
            return
        
        content = arm_meson.read_text()
        
        # 检查是否已经包含了这个板型
        board_c_file = f"{board_name}.c"
        if board_c_file in content:
            logger.info(f"   ℹ️  板型已在meson.build中: {board_c_file}")
            return
        
        # 在arm_ss.add行之前添加新板型
        if "arm_ss.add(when: 'CONFIG_NETDUINOPLUS2'" in content:
            # 在netduinoplus2之后添加
            new_line = f"arm_ss.add(when: 'CONFIG_NETDUINOPLUS2', if_true: files('{board_c_file}'))\n"
            content = content.replace(
                "arm_ss.add(when: 'CONFIG_NETDUINOPLUS2', if_true: files('netduinoplus2.c'))",
                f"arm_ss.add(when: 'CONFIG_NETDUINOPLUS2', if_true: files('netduinoplus2.c'))\n{new_line}"
            )
            
            arm_meson.write_text(content)
            logger.info(f"   ✅ 已添加板型到meson.build: {board_c_file}")
        else:
            logger.warning(f"   ⚠️  无法找到合适的位置添加板型")
    
    def _update_meson_build(self, generated_files: List[Dict]):
        """更新QEMU的meson.build文件"""
        # 更新hw/misc/meson.build
        misc_meson = self.qemu_path / "hw" / "misc" / "meson.build"
        
        if not misc_meson.exists():
            logger.warning(f"   ⚠️  未找到: {misc_meson}")
            return
        
        content = misc_meson.read_text()
        
        # 收集需要添加的文件
        files_to_add = []
        for file_info in generated_files:
            c_file = Path(file_info['c_file']).name
            if c_file not in content:
                files_to_add.append(c_file)
        
        if not files_to_add:
            logger.info(f"   所有文件已在meson.build中")
            return
        
        # 在文件末尾添加一个独立的system_ss.add调用
        files_list = ', '.join([f"'{f}'" for f in files_to_add])
        addition = f"\n# Auto-generated peripheral devices\nsystem_ss.add(files({files_list}))\n"
        
        content += addition
        misc_meson.write_text(content)
        
        logger.info(f"   添加了 {len(files_to_add)} 个文件到meson.build")
    
    def _build_qemu(self) -> bool:
        """编译QEMU"""
        build_dir = self.qemu_path / "build"
        
        try:
            # 检查是否需要配置
            if not (build_dir / "build.ninja").exists():
                logger.info("   配置QEMU构建...")
                subprocess.run(
                    ["meson", "setup", "build"],
                    cwd=self.qemu_path,
                    check=True,
                    capture_output=True
                )
            
            # 编译
            logger.info("   编译中 (这可能需要几分钟)...")
            result = subprocess.run(
                ["ninja", "-C", "build"],
                cwd=self.qemu_path,
                capture_output=True,
                timeout=600
            )
            
            return result.returncode == 0
            
        except subprocess.TimeoutExpired:
            logger.error("   编译超时")
            return False
        except Exception as e:
            logger.error(f"   编译失败: {e}")
            return False
    
    def _run_qemu_test(self, firmware_path: Path, board_name: str) -> Dict:
        """运行QEMU测试并收集trace"""
        qemu_binary = self.qemu_path / "build" / "qemu-system-arm"
        
        if not qemu_binary.exists():
            return {'success': False, 'error': 'QEMU binary not found'}
        
        # 生成trace日志
        trace_log = self.output_dir / f"{firmware_path.stem}_trace.log"
        
        # ⭐ 优化的QEMU参数
        qemu_cmd = [
            str(qemu_binary),
            "-M", board_name,
            "-kernel", str(firmware_path),
            "-d", "exec",  # 移除nochain以提升性能
            "-D", str(trace_log),
            # ❌ 移除-icount：它会显著降低性能，不是必需的
            "-nographic",  # 无图形界面（必要）
            "-serial", "none"  # 禁用串口（避免输出干扰）
        ]
        
        try:
            # 运行QEMU (60秒超时)
            proc = subprocess.Popen(
                qemu_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            time.sleep(60)
            proc.terminate()
            proc.wait(timeout=60)  # 从2秒增加到60秒
            
            # 分析trace
            if trace_log.exists():
                trace_analysis = self._analyze_trace(trace_log)
                return {
                    'success': True,
                    **trace_analysis
                }
            else:
                return {'success': False, 'error': 'No trace generated'}
                
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _analyze_trace(self, trace_file: Path) -> Dict:
        """分析trace日志"""
        import re
        
        pcs = []
        pattern = re.compile(r'Trace \d+: 0x[0-9a-fA-F]+ \[[0-9a-fA-F]+/([0-9a-fA-F]+)/')
        
        with open(trace_file) as f:
            for line in f:
                match = pattern.search(line)
                if match:
                    pc = int(match.group(1), 16)
                    pcs.append(pc)
        
        if not pcs:
            return {
                'trace_length': 0,
                'unique_pcs': 0,
                'pc_range': 0
            }
        
        unique_pcs = len(set(pcs))
        pc_range = max(pcs) - min(pcs)
        
        # 质量评估
        if len(pcs) >= 500 and unique_pcs >= 50 and pc_range >= 2048:
            quality = 'high'
        elif len(pcs) >= 100 and unique_pcs >= 10:
            quality = 'medium'
        else:
            quality = 'low'
        
        return {
            'trace_length': len(pcs),
            'unique_pcs': unique_pcs,
            'pc_range': pc_range,
            'start_pc': pcs[0],
            'end_pc': pcs[-1],
            'quality': quality
        }
    
    def process_batch(self, firmware_dir: Path, limit: int = 10):
        """批量处理固件"""
        logger.info("\n" + "╔"+ "="*78 + "╗")
        logger.info("║" + " "*10 + "基于静态分析的代码生成+QEMU集成 (使用src/模块)" + " "*16 + "║")
        logger.info("╚"+ "="*78 + "╝\n")
        
        firmwares = list(firmware_dir.rglob("*.elf"))[:limit]
        logger.info(f"找到 {len(firmwares)} 个固件\n")
        
        for i, firmware in enumerate(firmwares, 1):
            logger.info(f"\n[{i}/{len(firmwares)}] " + "─"*70)
            result = self.process_firmware(firmware)
            self.results.append(result)
            time.sleep(1)
        
        self._print_summary()
    
    def _print_summary(self):
        """打印统计"""
        logger.info("\n" + "╔"+ "="*78 + "╗")
        logger.info("║" + " "*30 + "测试汇总" + " "*40 + "║")
        logger.info("╚"+ "="*78 + "╝\n")
        
        total = len(self.results)
        success = sum(1 for r in self.results if r['success'])
        
        logger.info(f"总测试数: {total}")
        logger.info(f"成功: {success}/{total} ({success/total*100:.1f}%)")
        
        if success > 0:
            logger.info(f"\n✅ 成功固件:")
            for r in self.results:
                if r['success']:
                    quality = r.get('test_result', {}).get('quality', 'unknown')
                    logger.info(f"  • {r['firmware']} ({quality})")
        
        failed = [r for r in self.results if not r['success']]
        if failed:
            logger.info(f"\n❌ 失败固件:")
            for r in failed:
                logger.info(f"  • {r['firmware']}: {r['error']}")


def main():
    """命令行入口"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='基于静态分析的代码生成+QEMU集成 (使用src/现有模块)'
    )
    parser.add_argument('firmware', type=Path, 
                        help='固件文件或目录')
    parser.add_argument('-n', '--limit', type=int, default=5,
                        help='批量处理时的数量限制')
    parser.add_argument('--qemu', type=str, 
                        default='/home/zhangzheng/new/qemu',
                        help='QEMU源码路径')
    
    args = parser.parse_args()
    
    pipeline = StaticAnalysisBasedCodeGen(qemu_path=args.qemu)
    
    if args.firmware.is_dir():
        pipeline.process_batch(args.firmware, args.limit)
    else:
        result = pipeline.process_firmware(args.firmware)
        if result['success']:
            logger.info("\n🎉 处理成功！")
        else:
            logger.error(f"\n❌ 处理失败: {result['error']}")


if __name__ == '__main__':
    main()

