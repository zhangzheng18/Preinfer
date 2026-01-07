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

⭐ 关键修复 (2025-11-14):
- 修复了USART轮询死循环问题 (qemu/hw/char/stm32f2xx_usart.c)
- 在USART复位时预填充换行符，让固件能处理"空命令"后继续执行
- 详细说明见: USART_POLLING_FIX_SUMMARY.md
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
from src.qemu_integration.unified_board_generator import (  # ⭐ BEST: 统一板级生成器 (协议注入)
    BoardGenerationConfig,
    UnifiedBoardGenerator,
    generate_board_for_firmware
)
from qemu_integration.hybrid_peripheral_generator import HybridPeripheralGenerator  # ⭐ BEST: 混合策略
from qemu_integration.adaptive_peripheral_strategy import (  # ⭐ NEW: 自适应外设策略
    AdaptivePeripheralAnalyzer,
    AdaptiveStrategy,
    PeripheralConfig,
    PeripheralType,
    analyze_and_suggest
)
from qemu_integration.timeout_bypass_strategy import (  # ⭐ NEW: 超时绕过策略
    TimeoutBypassManager,
    TimeoutBypassConfig,
    BypassAction
)
from qemu_integration.peripheral_strategy_manager import (  # ⭐ NEW: 外设策略管理器
    PeripheralStrategyManager,
    StrategyLevel,
    PeripheralStrategyResult,
    analyze_firmware_strategy
)
from soc_integration.board_template_manager import BoardTemplateManager
from soc_integration.dynamic_board_adapter import DynamicBoardAdapter
from static_analysis.empty_interrupt_detector import EmptyInterruptDetector
from static_analysis.peripheral_block_analyzer import PeripheralBlockAnalyzer  # ⭐ NEW: 外设块分析器
from static_analysis.timer_interrupt_analyzer import TimerInterruptAnalyzer  # ⭐ NEW: 定时器中断分析器
from static_analysis.loop_condition_analyzer import LoopConditionAnalyzer  # ⭐ NEW: 循环条件分析器
from static_analysis.hal_tick_analyzer import HALTickAnalyzer  # ⭐ NEW: HAL tick分析器
from static_analysis.advanced_mmio_detector import AdvancedMMIODetector  # ⭐ NEW: 高级MMIO检测器
from static_analysis.polling_loop_analyzer import PollingLoopAnalyzer  # ⭐ NEW: 轮询循环分析
from static_analysis.deep_mmio_analyzer import DeepMMIOAnalyzer  # ⭐ NEW: 深度MMIO分析
from static_analysis.execution_optimizer import ExecutionOptimizer  # ⭐ NEW: 执行优化器
from static_analysis.comprehensive_firmware_analyzer import ComprehensiveFirmwareAnalyzer  # ⭐ NEW: 综合分析
from static_analysis.advanced_code_analysis import AdvancedCodeAnalyzer  # ⭐ NEW: 高级代码分析
from qemu_integration.smart_peripheral_generator import (  # ⭐ NEW: 智能外设生成
    SmartPeripheralGenerator, UwTickDetector
)
from qemu_integration.targeted_peripheral_generator import TargetedPeripheralGenerator  # ⭐ NEW: 针对性外设
from qemu_integration.enhanced_board_code_injector import EnhancedBoardCodeInjector  # ⭐ NEW: 板型代码注入

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
        
        # ⭐ NEW: 自适应外设策略和超时绕过
        self.adaptive_strategy = AdaptiveStrategy(level=AdaptiveStrategy.MODERATE)
        self.timeout_bypass_manager = TimeoutBypassManager(TimeoutBypassConfig(
            pc_stuck_threshold=5000,
            mmio_stuck_threshold=10000
        ))
        
        # ⭐ NEW: 统一的外设策略管理器
        self.strategy_level = StrategyLevel.MODERATE  # 默认中等策略
        self.strategy_manager: Optional[PeripheralStrategyManager] = None
        
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
                'machine_type': analysis_result.get('machine_type', 'ARM'),
                'mmio_count': analysis_result['mmio_count'],
                'peripheral_count': analysis_result['peripheral_count']
            })
            
            logger.info(f"   ✅ 识别: {result['peripheral_count']}个外设, "
                       f"{result['mmio_count']}个MMIO")
            
            # 保存分析结果 (供后续步骤使用)
            analysis_json = self.output_dir / f"{firmware_path.stem}_comprehensive.json"
            self._save_analysis_result(analysis_result, analysis_json)
            
            # ⭐ 检查是否是非 ARM 架构 (RISC-V / MIPS)
            machine_type = analysis_result.get('machine_type', 'ARM')
            if machine_type != 'ARM':
                logger.info(f"\n🔀 检测到非ARM架构: {machine_type}")
                return self._process_non_arm_firmware(firmware_path, analysis_result, result)
            
            # ⭐ Step 2: 外设块分析（增强的聚类分析）
            logger.info("\n🔬 Step 2: 外设块分析 (PeripheralBlockAnalyzer)")
            mmio_addresses = analysis_result.get('raw_mmio_addresses', [])
            
            # ⭐ CRITICAL: 使用正确的MCU family进行外设识别
            mcu_family = analysis_result.get('architecture', 'DEFAULT')
            self.peripheral_analyzer = PeripheralBlockAnalyzer(mcu_family)
            logger.info(f"   📊 MCU family: {mcu_family}")
            
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
            
            # ⭐ 修复: 确保板型名称只包含合法的C标识符字符
            import re
            safe_name = re.sub(r'[^a-zA-Z0-9_]', '_', firmware_path.stem)
            board_name = f"netduinoplus2_enhanced_{safe_name}"
            
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
            
            # ⭐ Step 3.5: 使用统一板级生成器增强板型（协议注入、CRC绕过等）
            logger.info("\n🚀 Step 3.5: 应用统一板级优化 (协议注入、时序控制)")
            try:
                # ⭐ 根据检测到的架构设置 Flash 基址
                detected_arch = analysis_result.get('architecture', 'STM32F4')
                flash_base = analysis_result.get('flash_base', 0x08000000)
                flash_size = analysis_result.get('flash_size', 0x100000)
                sram_base = analysis_result.get('ram_base', 0x20000000)
                sram_size = analysis_result.get('ram_size', 0x20000)
                
                # 选择正确的 CPU 类型
                cpu_type = analysis_result.get('cpu_type', 'cortex-m4')
                
                logger.info(f"   架构: {detected_arch}, Flash: 0x{flash_base:08X}, CPU: {cpu_type}")
                
                unified_config = BoardGenerationConfig(
                    board_name=board_name,
                    firmware_path=str(firmware_path),
                    base_soc="STM32F405_SOC",  # 基础 SoC 模板
                    flash_base=flash_base,
                    flash_size=flash_size,
                    sram_base=sram_base,
                    sram_size=sram_size,
                    cpu_type=cpu_type
                )
                unified_gen = UnifiedBoardGenerator(unified_config)
                unified_gen.analyze_firmware()
                unified_code = unified_gen.generate_board_file()
                
                # 获取生成器使用的实际机器名称（小写）
                actual_machine_name = unified_gen._sanitize_name(board_name)
                
                # 覆盖生成的板级文件 - 使用原始 board_name 作为文件名
                # 这样可以与现有的 meson.build 条目兼容
                board_file_path = self.qemu_path / "hw" / "arm" / f"{board_name}.c"
                with open(board_file_path, 'w') as f:
                    f.write(unified_code)
                
                # 注意：QEMU机器名使用小写，但文件名保持原样
                # 我们需要在 DEFINE_MACHINE 中使用小写名称
                result['board_file'] = str(board_file_path)
                result['qemu_machine_name'] = actual_machine_name  # 记录实际的机器名
                logger.info(f"   ✅ 协议类型: {unified_config.detected_protocol}")
                logger.info(f"   ✅ uwTick地址: 0x{unified_config.uwtick_address:08X}")
                logger.info(f"   ✅ QEMU机器名: {actual_machine_name}")
                logger.info(f"   ✅ 已应用协议注入优化")
            except Exception as e:
                logger.warning(f"   ⚠️  统一板级优化失败，使用混合板型: {e}")
            
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
            
            # 使用生成的板型（包含USART轮询修复和协议注入）
            # 使用实际的QEMU机器名称（小写）
            qemu_machine = result.get('qemu_machine_name', board_name.lower().replace('-', '_'))
            logger.info(f"   使用板型: {qemu_machine}")
            logger.info(f"   USART轮询修复: 已自动注入SMART-USART2 (10次轮询触发)")
            logger.info(f"   协议注入: Modbus RTU 命令帧")
            logger.info(f"   测试时长: 600秒 (完整测试)")
            
            test_result = self._run_qemu_test(
                firmware_path,
                qemu_machine
            )
            
            if test_result['success']:
                result['success'] = True
                result['test_result'] = test_result
                logger.info(f"   ✅ Firmware正常运行!")
                logger.info(f"      - Trace长度: {test_result.get('trace_length', 0):,}")
                logger.info(f"      - 唯一PC: {test_result.get('unique_pcs', 0)}")
                logger.info(f"      - PC范围: {test_result.get('pc_range', 0)} bytes")
                
                # 针对CNC/grbl类firmware的特别说明
                if test_result.get('trace_length', 0) > 1000:
                    logger.info(f"      💡 Firmware循环等待串口输入 (正常行为，如grbl CNC控制器)")
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
            
            # ⭐ 获取机器类型 (ARM, RISC-V, MIPS)
            elf_machine = arch_detector.elf_info.get('machine', 'ARM')
            if 'RISC-V' in elf_machine:
                machine_type = 'RISCV'
            elif 'MIPS' in elf_machine:
                machine_type = 'MIPS'
            else:
                machine_type = 'ARM'
            
            logger.info(f"   架构: {arch_name} (机器类型: {machine_type})")
            logger.info(f"   CPU: {arch_config.cpu_type}")
            logger.info(f"   Flash: 0x{arch_config.flash_base:08X}, {arch_config.flash_size} bytes")
            logger.info(f"   RAM: 0x{arch_config.ram_base:08X}, {arch_config.ram_size} bytes")
            
            # 2. MMIO地址提取 (使用高级MMIO检测器 + EnhancedBasicParser)
            logger.info(f"   高级MMIO地址检测...")
            
            # 2a. 使用高级MMIO检测器 (支持复杂的间接地址访问)
            mmio_detector = AdvancedMMIODetector(str(firmware_path), arch_name)
            advanced_mmio = mmio_detector.detect_all_mmio()
            logger.info(f"   高级检测器: {len(advanced_mmio)}个地址")
            
            # 获取检测统计
            mmio_stats = mmio_detector.get_statistics()
            logger.info(f"   检测方法统计: {mmio_stats['by_method']}")
            
            # 2b. 使用EnhancedBasicParser作为补充
            try:
                parser = EnhancedBasicParser(str(firmware_path))
                candidates = parser.extract_peripheral_candidates()
                
                parser_mmio = []
                for candidate in candidates:
                    base = candidate.base_address
                    parser_mmio.append(base)
                    if hasattr(candidate, 'offset_stats'):
                        for offset in candidate.offset_stats.keys():
                            parser_mmio.append(base + offset)
                
                logger.info(f"   基础解析器: {len(parser_mmio)}个地址")
            except Exception as e:
                logger.warning(f"   基础解析器失败: {e}")
                parser_mmio = []
            
            # 2c. 合并两种方法的结果
            mmio_addresses = list(set(advanced_mmio + parser_mmio))
            logger.info(f"   合并后MMIO地址: {len(mmio_addresses)}个")
            
            # 2d. 深度MMIO分析 - 识别寄存器级别访问模式
            logger.info(f"   深度MMIO分析...")
            try:
                deep_analyzer = DeepMMIOAnalyzer(str(firmware_path))
                deep_profiles = deep_analyzer.analyze()
                deep_summary = deep_analyzer.get_summary()
                logger.info(f"   深度分析: {deep_summary['total_accesses']}次访问, "
                           f"{deep_summary['peripheral_count']}个外设")
                logger.info(f"   访问类型: read={deep_summary['by_type'].get('read', 0)}, "
                           f"write={deep_summary['by_type'].get('write', 0)}, "
                           f"rmw={deep_summary['by_type'].get('rmw', 0)}")
            except Exception as e:
                logger.warning(f"   深度分析失败: {e}")
                deep_profiles = {}
            
            # 2e. 轮询循环分析 - 识别可能导致PC停滞的循环
            logger.info(f"   轮询循环分析...")
            try:
                polling_analyzer = PollingLoopAnalyzer(str(firmware_path))
                polling_loops = polling_analyzer.analyze()
                polling_summary = polling_analyzer.get_summary()
                high_severity = polling_analyzer.get_high_severity_loops()
                
                logger.info(f"   发现轮询循环: {polling_summary['total_loops']}个 "
                           f"(高={polling_summary['by_severity'].get('high', 0)}, "
                           f"中={polling_summary['by_severity'].get('medium', 0)})")
                
                if high_severity:
                    logger.warning(f"   ⚠️ 高严重度轮询循环 (可能导致PC停滞):")
                    for loop in high_severity[:3]:
                        logger.warning(f"      0x{loop.loop_start:08X} - 0x{loop.loop_end:08X}")
            except Exception as e:
                logger.warning(f"   轮询分析失败: {e}")
                polling_loops = []
                high_severity = []
            
            # 2f. 执行优化分析 - 生成多种提升唯一PC的策略
            logger.info(f"   执行优化分析...")
            try:
                exec_optimizer = ExecutionOptimizer(str(firmware_path))
                opt_strategies = exec_optimizer.analyze_all()
                opt_summary = exec_optimizer.get_summary()
                
                logger.info(f"   优化策略: {opt_summary['strategies']}个, "
                           f"预估PC增益: +{opt_summary['estimated_pc_gain']}")
                
                if opt_summary['top_strategies']:
                    logger.info(f"   Top策略:")
                    for name, priority, gain in opt_summary['top_strategies'][:3]:
                        logger.info(f"      - {name} (优先级={priority}, 增益=+{gain})")
            except Exception as e:
                logger.warning(f"   执行优化分析失败: {e}")
                opt_strategies = []
            
            # 2g. uwTick地址检测 - 用于HAL超时支持
            logger.info(f"   uwTick地址检测...")
            try:
                uwtick_detector = UwTickDetector(str(firmware_path))
                uwtick_addr = uwtick_detector.detect()
                if uwtick_addr:
                    logger.info(f"   ✅ uwTick地址: 0x{uwtick_addr:08X}")
                else:
                    logger.info(f"   ⚠️ 未检测到uwTick")
            except Exception as e:
                logger.warning(f"   uwTick检测失败: {e}")
                uwtick_addr = None
            
            # 2h. 综合固件分析 - 深度MMIO检测、虚函数表、轮询模式
            logger.info(f"   综合固件分析...")
            comprehensive_result = None
            try:
                comprehensive_analyzer = ComprehensiveFirmwareAnalyzer(str(firmware_path))
                comprehensive_result = comprehensive_analyzer.analyze_all()
                
                mmio_count = comprehensive_result['mmio_addresses']['total']
                vtable_count = comprehensive_result['vtable_calls']['total']
                polling_count = comprehensive_result['polling_patterns']['total']
                periph_count = comprehensive_result['peripherals']['total']
                
                logger.info(f"   ✅ 综合分析完成:")
                logger.info(f"      MMIO地址: {mmio_count}个")
                logger.info(f"      虚函数调用: {vtable_count}个")
                logger.info(f"      轮询模式: {polling_count}个")
                logger.info(f"      外设配置: {periph_count}个")
                
                # 显示按类型分布
                by_type = comprehensive_result['mmio_addresses']['by_type']
                logger.info(f"      MMIO类型分布: {by_type}")
                
                # 显示轮询类型分布
                poll_types = comprehensive_result['polling_patterns']['by_type']
                logger.info(f"      轮询类型分布: {poll_types}")
                
                # 合并MMIO地址到主列表
                for mmio_detail in comprehensive_result['mmio_addresses']['details']:
                    addr = int(mmio_detail['address'].replace('0x', ''), 16)
                    if addr not in mmio_addresses:
                        mmio_addresses.append(addr)
                
                logger.info(f"      合并后MMIO总数: {len(mmio_addresses)}个")
                
            except Exception as e:
                logger.warning(f"   综合分析失败: {e}")
                import traceback
                traceback.print_exc()
            
            # 2i. 高级代码分析 - 调用图、中断向量表、状态机
            logger.info(f"   高级代码分析...")
            code_analysis_result = None
            try:
                code_analyzer = AdvancedCodeAnalyzer(str(firmware_path))
                code_analysis_result = code_analyzer.analyze_all()
                
                total_funcs = len(code_analysis_result.functions)
                unreachable = len(code_analysis_result.unreachable_functions)
                irq_handlers = len([h for h in code_analysis_result.interrupt_handlers 
                                   if not h.is_default and h.handler_address != 0])
                state_machines = len(code_analysis_result.state_machines)
                
                logger.info(f"   ✅ 高级代码分析完成:")
                logger.info(f"      函数总数: {total_funcs}")
                logger.info(f"      不可达函数: {unreachable} ({unreachable*100//max(1,total_funcs)}%)")
                logger.info(f"      中断处理程序: {irq_handlers}个")
                logger.info(f"      状态机模式: {state_machines}个")
                
                # 显示中断处理程序
                if irq_handlers > 0:
                    logger.info(f"      关键中断处理程序:")
                    for h in code_analysis_result.interrupt_handlers[:5]:
                        if not h.is_default and h.handler_address != 0:
                            logger.info(f"        IRQ{h.irq_number}: 0x{h.handler_address:08X} ({h.handler_name})")
                
            except Exception as e:
                logger.warning(f"   高级代码分析失败: {e}")
                import traceback
                traceback.print_exc()
            
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
            
            # ⭐ NEW: 自适应外设分析 (AdaptivePeripheralAnalyzer)
            logger.info(f"   自适应外设分析...")
            adaptive_analyzer = AdaptivePeripheralAnalyzer(str(firmware_path))
            adaptive_result = adaptive_analyzer.analyze_firmware()
            
            logger.info(f"   自适应外设: {len(adaptive_result['peripherals'])}个")
            logger.info(f"   建议: {len(adaptive_result['recommendations'])}条")
            
            # ⭐ NEW: 定时器中断分析 (TimerInterruptAnalyzer)
            logger.info(f"   定时器中断分析...")
            timer_analyzer = TimerInterruptAnalyzer(str(firmware_path))
            timer_result = timer_analyzer.analyze()
            
            timer_configs = timer_result.get('timer_configs', {})
            peripheral_irq_configs = timer_result.get('peripheral_irq_configs', {})
            
            # 统计有实际handler的定时器
            real_timer_handlers = [
                name for name, cfg in timer_configs.items() 
                if cfg.get('has_real_handler', False)
            ]
            logger.info(f"   定时器: {len(timer_configs)}个, 有实际handler: {len(real_timer_handlers)}个")
            if real_timer_handlers:
                logger.info(f"   有效定时器: {real_timer_handlers}")
            
            # ⭐ NEW: 循环条件分析 (LoopConditionAnalyzer)
            logger.info(f"   循环条件分析...")
            loop_analyzer = LoopConditionAnalyzer(str(firmware_path))
            loop_result = loop_analyzer.analyze()
            
            error_handler_patches = loop_analyzer.get_error_handler_patches()
            exit_conditions = loop_result.get('exit_conditions', [])
            
            infinite_loops = loop_result.get('summary', {}).get('infinite_loops', 0)
            logger.info(f"   循环: {loop_result.get('summary', {}).get('total_loops', 0)}个")
            logger.info(f"   错误处理函数: {loop_result.get('summary', {}).get('total_error_handlers', 0)}个")
            logger.info(f"   无限循环补丁: {len(error_handler_patches)}个")
            if exit_conditions:
                logger.info(f"   退出条件建议: {len(exit_conditions)}个")
            
            # ⭐ NEW: HAL tick分析 - 检测uwTick地址用于解决超时循环问题
            logger.info(f"   HAL tick分析...")
            hal_tick_analyzer = HALTickAnalyzer(str(firmware_path))
            tick_info = hal_tick_analyzer.analyze()
            if 'uwTick_addr' in tick_info:
                logger.info(f"   ⭐ uwTick @ 0x{tick_info['uwTick_addr']:08X} (用于HAL超时支持)")
            else:
                logger.info(f"   未找到uwTick变量")
            
            # ⭐ 使用外设地址进行更精确的 MCU 类型检测
            from src.peripheral_modeling.known_peripherals_db import detect_mcu_family_from_addresses
            mmio_hex_addrs = [f'0x{addr:08X}' if isinstance(addr, int) else addr for addr in mmio_addresses]
            detected_mcu_family = detect_mcu_family_from_addresses(mmio_hex_addrs)
            logger.info(f"   ⭐ 检测到 MCU 类型: {detected_mcu_family} (基于外设地址)")
            
            # 构建完整的分析结果 (兼容EnhancedQEMUPeripheralGenerator的输入格式)
            # 使用更精确的 MCU 类型替代通用的 arch_name
            # ⭐ 对于非 ARM 架构，使用原始的 arch_name
            final_arch = detected_mcu_family if machine_type == 'ARM' else arch_name
            result = {
                'success': True,
                'firmware_path': str(firmware_path),
                'architecture': final_arch,  # 使用精确的 MCU 类型
                'mcu_family': final_arch,    # 额外的字段
                'machine_type': machine_type,  # ⭐ NEW: 机器类型 (ARM, RISCV, MIPS)
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
                'empty_irq_numbers': empty_irq_numbers,  # 空中断IRQ号
                # ⭐ NEW: 自适应外设和定时器中断分析结果
                'adaptive_peripherals': adaptive_result['peripherals'],
                'adaptive_recommendations': adaptive_result['recommendations'],
                'timer_configs': timer_configs,
                'peripheral_irq_configs': peripheral_irq_configs,
                'real_timer_handlers': real_timer_handlers,
                # ⭐ NEW: 循环条件分析结果
                'error_handler_patches': error_handler_patches,  # Error Handler跳过补丁
                'exit_conditions': exit_conditions,  # 循环退出条件建议
                # ⭐ NEW: HAL tick分析结果
                'tick_info': tick_info  # uwTick地址和相关信息
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
    
    def _process_non_arm_firmware(self, firmware_path: Path, analysis_result: Dict, result: Dict) -> Dict:
        """
        处理非ARM架构固件 (RISC-V, MIPS)
        
        使用系统安装的QEMU进行仿真，不需要编译自定义板型
        """
        machine_type = analysis_result.get('machine_type', 'RISCV')
        arch_name = analysis_result.get('architecture', 'Unknown')
        cpu_type = analysis_result.get('cpu_type', 'rv32')
        entry_point = analysis_result.get('entry_point', 0)
        
        logger.info(f"   架构: {arch_name}")
        logger.info(f"   CPU: {cpu_type}")
        logger.info(f"   入口点: 0x{entry_point:08X}")
        
        # 选择 QEMU 二进制文件和机器类型
        if machine_type == 'RISCV':
            qemu_binary = self.qemu_path / "build" / "qemu-system-riscv32"
            # GD32VF103 和 CH32V307 都是 RISC-V 嵌入式 MCU
            # 使用 sifive_e 作为最接近的模拟
            qemu_machine = 'sifive_e'
            qemu_cpu = 'sifive-e31'  # RV32IMAC
        elif machine_type == 'MIPS':
            qemu_binary = self.qemu_path / "build" / "qemu-system-mipsel"
            qemu_machine = 'malta'
            qemu_cpu = 'P5600'  # MIPS32r5
        else:
            result['error'] = f'Unsupported machine type: {machine_type}'
            return result
        
        # 检查 QEMU 是否存在
        if not Path(qemu_binary).exists():
            result['error'] = f'{machine_type} QEMU not found: {qemu_binary}'
            logger.error(f"   ❌ {result['error']}")
            return result
        
        # 转换为字符串
        qemu_binary = str(qemu_binary)
        
        logger.info(f"   QEMU: {qemu_binary}")
        logger.info(f"   机器: {qemu_machine}")
        logger.info(f"   CPU: {qemu_cpu}")
        
        # 运行测试
        logger.info("\n🚀 运行仿真测试 (系统QEMU)")
        
        test_result = self._run_non_arm_qemu_test(
            firmware_path=firmware_path,
            qemu_binary=qemu_binary,
            machine=qemu_machine,
            cpu=qemu_cpu,
            machine_type=machine_type,
            analysis_result=analysis_result
        )
        
        if test_result['success']:
            result['success'] = True
            result['unique_pcs'] = test_result.get('unique_pcs', 0)
            result['total_instructions'] = test_result.get('total_instructions', 0)
            logger.info(f"\n   📊 PC执行统计:")
            logger.info(f"      总执行次数: {test_result.get('total_instructions', 0)}")
            logger.info(f"      唯一PC数量: {test_result.get('unique_pcs', 0)}")
        else:
            result['error'] = test_result.get('error', 'QEMU test failed')
            logger.error(f"   ❌ 仿真失败: {result['error']}")
        
        return result
    
    def _run_non_arm_qemu_test(self, firmware_path: Path, qemu_binary: str, 
                               machine: str, cpu: str, machine_type: str,
                               analysis_result: Dict) -> Dict:
        """运行非ARM架构的QEMU测试"""
        import re
        
        trace_log = self.output_dir / f"{firmware_path.stem}_trace.log"
        
        # 清空日志文件
        try:
            with open(trace_log, 'w') as f:
                pass
        except Exception as e:
            return {'success': False, 'error': f'清空日志失败: {e}'}
        
        # 构建 QEMU 命令
        flash_base = analysis_result.get('flash_base', 0x08000000)
        
        if machine_type == 'RISCV':
            # RISC-V: 使用 virt 机器 + device loader 加载 ELF
            # virt 机器的 RAM 在 0x80000000，可以正确加载 GD32VF103 固件
            qemu_cmd = [
                qemu_binary,
                "-M", "virt",  # 使用 virt 虚拟机，更灵活
                "-cpu", cpu,
                "-device", f"loader,file={firmware_path}",  # 使用 device loader
                "-d", "exec",
                "-D", str(trace_log),
                "-nographic",
                "-serial", "none"
            ]
        elif machine_type == 'MIPS':
            # MIPS: malta 板使用 -kernel
            qemu_cmd = [
                qemu_binary,
                "-M", machine,
                "-cpu", cpu,
                "-kernel", str(firmware_path),
                "-d", "exec",
                "-D", str(trace_log),
                "-nographic",
                "-serial", "none"
            ]
        else:
            return {'success': False, 'error': f'Unsupported machine type: {machine_type}'}
        
        logger.info(f"   QEMU命令: {' '.join(qemu_cmd[:6])}...")
        
        proc = None
        try:
            proc = subprocess.Popen(
                qemu_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # 等待 180 秒收集 trace (RISC-V/MIPS 固件通常执行较快)
            import time
            logger.info(f"   运行测试 (180秒)...")
            time.sleep(180)
            
            # 终止进程
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=2)
            
            # 读取 stderr 输出
            stderr_output = proc.stderr.read() if proc.stderr else ""
            if stderr_output and 'fatal' in stderr_output.lower():
                logger.warning(f"   ⚠️ QEMU 警告: {stderr_output[:200]}")
            
            # 分析 trace
            if trace_log.exists() and trace_log.stat().st_size > 0:
                unique_pcs = set()
                total_instructions = 0
                
                # RISC-V/MIPS trace 格式: Trace N: 0x... [XXXXXXXX/PC/...]
                # PC 是第二个斜杠分隔的字段
                pattern = re.compile(r'Trace \d+:.*\[[0-9a-fA-F]+/([0-9a-fA-F]+)/')
                
                with open(trace_log, 'r') as f:
                    for line in f:
                        if 'Trace' in line:
                            match = pattern.search(line)
                            if match:
                                pc = int(match.group(1), 16)
                                unique_pcs.add(pc)
                                total_instructions += 1
                
                # 过滤有效的 PC (排除启动代码 0x1000 等)
                valid_pcs = {pc for pc in unique_pcs if pc > 0x10000}
                
                return {
                    'success': True,
                    'unique_pcs': len(valid_pcs) if valid_pcs else len(unique_pcs),
                    'total_instructions': total_instructions,
                    'all_pcs': len(unique_pcs)  # 包括启动代码
                }
            else:
                return {'success': False, 'error': 'No trace generated'}
                
        except Exception as e:
            return {'success': False, 'error': str(e)}
        finally:
            if proc and proc.poll() is None:
                proc.kill()
    
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
        elif 'K64F' in arch_name or 'MK64F' in arch_name or 'MKL' in arch_name:
            # Kinetis/NXP系列 - Flash从0x00000000开始
            # 使用通用ARM板型但调整内存布局
            base_board = 'netduinoplus2'
            soc_file = 'hw/arm/stm32f405_soc.c'
            logger.info(f"   ⚠️  Kinetis MCU检测到 - Flash: 0x00000000")
            logger.info(f"   ⚠️  注意: QEMU STM32板型可能不完全兼容Kinetis外设")
        elif 'LPC' in arch_name:
            # NXP LPC系列
            base_board = 'netduinoplus2'
            soc_file = 'hw/arm/stm32f405_soc.c'
            logger.info(f"   ⚠️  LPC MCU使用通用ARM板型")
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
        # ========== 新增：主动清空日志文件 ==========
        try:
            # 截断文件为0字节（覆盖旧内容）
            with open(trace_log, 'w') as f:
                pass
        except Exception as e:
            logger.warning(f"清空日志文件失败: {e}")
            return {'success': False, 'error': f'清空日志失败: {e}'}
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
        
        proc = None
        stderr_thread = None
        try:
            # 运行QEMU并收集trace
            # ⭐ 实时输出stderr（包含USART调试信息）
            proc = subprocess.Popen(
                qemu_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                bufsize=1,  # 行缓冲
                text=True   # 文本模式
            )
            
            # ⭐ 启动线程实时输出stderr
            import threading
            def stream_stderr():
                try:
                    for line in iter(proc.stderr.readline, ''):
                        if line:
                            logger.info(f"   [QEMU] {line.rstrip()}")
                except:
                    pass
            
            stderr_thread = threading.Thread(target=stream_stderr, daemon=True)
            stderr_thread.start()
            
            # ⭐ 等待60秒收集trace（足够收集初始化和部分运行时行为）
            time.sleep(180)
            
            # 优雅终止进程
            if proc.poll() is None:  # 进程仍在运行
                proc.terminate()
                
                # 等待进程退出（最多5秒）
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    # 如果5秒内没有退出，强制杀死
                    logger.warning("   ⚠️  QEMU进程未及时退出，强制终止")
                    proc.kill()
                    proc.wait(timeout=2)  # 再等待2秒确保进程已终止
            
            # 等待stderr线程完成
            if stderr_thread:
                stderr_thread.join(timeout=1)
            
            # 读取剩余的stderr输出
            try:
                remaining_stderr = proc.stderr.read()
                if remaining_stderr:
                    for line in remaining_stderr.splitlines():
                        if line.strip():
                            logger.info(f"   [QEMU] {line}")
            except:
                pass
            
            # 分析trace（即使进程被强制终止，trace文件也应该已生成）
            if trace_log.exists() and trace_log.stat().st_size > 0:
                trace_analysis = self._analyze_trace(trace_log)
                
                # ⭐ 分析最后执行的PC，检测死循环
                pcs = []
                import re
                pattern = re.compile(r'Trace \d+: 0x[0-9a-fA-F]+ \[[0-9a-fA-F]+/([0-9a-fA-F]+)/')
                with open(trace_log) as f:
                    for line in f:
                        m = pattern.search(line)
                        if m:
                            pcs.append(int(m.group(1), 16))
                
                if len(pcs) > 100:
                    from collections import Counter
                    last_100 = pcs[-100:]
                    pc_counts = Counter(last_100)
                    most_common = pc_counts.most_common(5)
                    logger.info(f"   📊 最后100个PC中最频繁的:")
                    for pc, count in most_common:
                        logger.info(f"      0x{pc:08x}: {count}次 ({count}%)")
                    
                    # ⭐ 改进的死循环检测：检查连续重复模式
                    # 真正的死循环：某个PC连续出现多次（>10次）
                    # 正常循环：PC分布相对均匀（如打印字符串循环）
                    consecutive_repeats = []
                    current_pc = None
                    repeat_count = 0
                    for pc in last_100:
                        if pc == current_pc:
                            repeat_count += 1
                        else:
                            if repeat_count > 10:  # 连续重复超过10次
                                consecutive_repeats.append((current_pc, repeat_count))
                            current_pc = pc
                            repeat_count = 1
                    
                    if consecutive_repeats:
                        logger.warning(f"   ⚠️  检测到紧密死循环（连续重复模式）:")
                        for pc, count in consecutive_repeats[:3]:  # 只显示前3个
                            logger.warning(f"      0x{pc:08x}: 连续{count}次")
                    elif most_common and most_common[0][1] > 50:
                        logger.warning(f"   ⚠️  检测到可能的死循环 @ 0x{most_common[0][0]:08x} (占比{most_common[0][1]}%)")
                    else:
                        logger.info(f"   ✅ 未检测到死循环（PC分布正常，可能是正常的执行循环）")
                
                return {
                    'success': True,
                    **trace_analysis
                }
            else:
                return {'success': False, 'error': 'No trace generated or trace file is empty'}
                
        except subprocess.TimeoutExpired:
            # 如果进程管理超时，尝试强制杀死并检查trace
            logger.warning("   ⚠️  进程终止超时，强制杀死")
            if proc is not None:
                try:
                    proc.kill()
                    proc.wait(timeout=2)
                except:
                    pass
            
            # 即使进程管理失败，只要trace文件存在就认为成功
            if trace_log.exists() and trace_log.stat().st_size > 0:
                trace_analysis = self._analyze_trace(trace_log)
                return {
                    'success': True,
                    **trace_analysis
                }
            else:
                return {'success': False, 'error': 'Process timeout and no trace generated'}
                
        except Exception as e:
            # 其他异常：尝试清理进程并返回错误
            if proc is not None:
                try:
                    if proc.poll() is None:
                        proc.terminate()
                        proc.wait(timeout=2)
                except:
                    try:
                        proc.kill()
                    except:
                        pass
            
            return {'success': False, 'error': str(e)}
    
    def _analyze_trace(self, trace_file: Path) -> Dict:
        """分析trace日志并统计唯一PC"""
        import re
        from collections import Counter
        
        pcs = []
        pattern = re.compile(r'Trace \d+: 0x[0-9a-fA-F]+ \[[0-9a-fA-F]+/([0-9a-fA-F]+)/')
        
        with open(trace_file) as f:
            for line in f:
                match = pattern.search(line)
                if match:
                    pc = int(match.group(1), 16)
                    pcs.append(pc)
        
        if not pcs:
            logger.warning("   ⚠️  没有捕获到任何PC (trace为空)")
            return {
                'trace_length': 0,
                'unique_pcs': 0,
                'pc_range': 0
            }
        
        # ⭐ 统计唯一PC
        unique_pc_set = set(pcs)
        unique_pcs = len(unique_pc_set)
        pc_range = max(pcs) - min(pcs)
        
        # ⭐ 输出唯一PC统计
        logger.info(f"\n   📊 PC执行统计:")
        logger.info(f"      总执行次数: {len(pcs)}")
        logger.info(f"      唯一PC数量: {unique_pcs}")
        logger.info(f"      PC覆盖范围: 0x{min(pcs):08X} - 0x{max(pcs):08X} ({pc_range} bytes)")
        
        # ⭐ PC分布分析
        pc_counter = Counter(pcs)
        most_executed = pc_counter.most_common(10)
        logger.info(f"      最频繁执行的PC (Top 10):")
        for pc, count in most_executed:
            percentage = count / len(pcs) * 100
            logger.info(f"        0x{pc:08X}: {count}次 ({percentage:.1f}%)")
        
        # ⭐ 按地址区间分析 (Flash vs RAM vs Handler)
        flash_pcs = [pc for pc in unique_pc_set if 0x08000000 <= pc < 0x08100000]
        ram_pcs = [pc for pc in unique_pc_set if 0x20000000 <= pc < 0x20100000]
        handler_pcs = [pc for pc in unique_pc_set if 0xFFFF0000 <= pc]
        
        logger.info(f"      PC区域分布:")
        logger.info(f"        Flash (0x08xxxxxx): {len(flash_pcs)} 唯一PC")
        logger.info(f"        RAM   (0x20xxxxxx): {len(ram_pcs)} 唯一PC")
        if handler_pcs:
            logger.info(f"        Handler (0xFFFFxxxx): {len(handler_pcs)} 唯一PC")
        
        # 质量评估
        if len(pcs) >= 500 and unique_pcs >= 50 and pc_range >= 2048:
            quality = 'high'
            logger.info(f"   ✅ 执行质量: 高 (良好的代码覆盖率)")
        elif len(pcs) >= 100 and unique_pcs >= 10:
            quality = 'medium'
            logger.info(f"   ⚠️  执行质量: 中等")
        else:
            quality = 'low'
            logger.warning(f"   ❌ 执行质量: 低 (可能陷入死循环或执行失败)")
        
        return {
            'trace_length': len(pcs),
            'unique_pcs': unique_pcs,
            'pc_range': pc_range,
            'start_pc': pcs[0],
            'end_pc': pcs[-1],
            'quality': quality,
            'flash_coverage': len(flash_pcs),
            'ram_coverage': len(ram_pcs),
            'most_executed': [(hex(pc), count) for pc, count in most_executed[:5]]
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
        
        # ⭐ NEW: Print adaptive peripheral analysis summary
        logger.info(f"\n" + "─"*78)
        logger.info("⭐ 自适应外设分析总结:")
        logger.info("─"*78)
        
        for r in self.results:
            if r.get('success') and r.get('test_result'):
                logger.info(f"\n固件: {r['firmware']}")
                
                # 打印超时绕过统计
                bypass_stats = self.timeout_bypass_manager.get_statistics()
                logger.info(f"  超时绕过统计:")
                logger.info(f"    - 总MMIO访问: {bypass_stats['total_accesses']}")
                logger.info(f"    - 唯一访问模式: {bypass_stats['unique_access_patterns']}")
                logger.info(f"    - 尝试绕过: {bypass_stats['bypasses_attempted']}")
                logger.info(f"    - 成功绕过: {bypass_stats['successful_bypasses']}")
        
        logger.info(f"\n" + "─"*78)
        logger.info("💡 覆盖率提升建议:")
        logger.info("  1. 启用Timer中断可执行更多运动控制代码")
        logger.info("  2. 使用超时绕过策略自动处理卡住的外设")
        logger.info("  3. 检查未执行的中断处理程序并配置相应IRQ")
        logger.info("─"*78)


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

