#!/usr/bin/env python3
"""
MCU主板模板管理器

功能：
1. 保留原始QEMU主板文件作为模板
2. 基于固件分析结果动态生成适配版本
3. 自动修改SOC配置（RAM/Flash大小、外设列表）
4. 版本管理，避免覆盖原始文件

设计原则：
- 原始模板在 qemu/hw/arm/*.c.template
- 生成的适配版本在 qemu/hw/arm/*.c (编译用)
- 每次运行根据固件需求重新生成
"""

import os
import re
import json
import shutil
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass


@dataclass
class BoardTemplate:
    """主板模板配置"""
    name: str                    # 模板名称 (如 netduinoplus2)
    soc_type: str                # SOC类型 (如 STM32F405_SOC)
    soc_header: str              # SOC头文件
    original_file: str           # 原始.c文件路径
    template_file: str           # 模板文件路径
    
    # 默认配置
    default_flash_size: int      # KB
    default_sram_size: int       # KB
    default_cpu: str             # CPU型号
    
    # 可配置参数标记
    configurable_params: List[str] = None  # ['FLASH_SIZE', 'SRAM_SIZE', 'CPU']


# 已知主板模板库
BOARD_TEMPLATES = {
    'netduinoplus2': BoardTemplate(
        name='netduinoplus2',
        soc_type='TYPE_STM32F405_SOC',
        soc_header='hw/arm/stm32f405_soc.h',
        original_file='hw/arm/netduinoplus2.c',
        template_file='hw/arm/netduinoplus2.c.template',
        default_flash_size=1024,
        default_sram_size=192,
        default_cpu='cortex-m4',
        configurable_params=['FLASH_SIZE', 'SRAM_SIZE']
    ),
    'stm32vldiscovery': BoardTemplate(
        name='stm32vldiscovery',
        soc_type='TYPE_STM32F100_SOC',
        soc_header='hw/arm/stm32f100_soc.h',
        original_file='hw/arm/stm32vldiscovery.c',
        template_file='hw/arm/stm32vldiscovery.c.template',
        default_flash_size=128,
        default_sram_size=8,
        default_cpu='cortex-m3',
        configurable_params=['FLASH_SIZE', 'SRAM_SIZE']
    ),
}


class BoardTemplateManager:
    """主板模板管理器"""
    
    def __init__(self, qemu_path: str = "/home/zhangzheng/new/qemu"):
        self.qemu_path = Path(qemu_path)
        self.hw_arm_path = self.qemu_path / "hw" / "arm"
        self.templates_backed_up = False
        
    def backup_original_files(self):
        """备份原始文件为模板（只执行一次）"""
        if self.templates_backed_up or (self.hw_arm_path / "netduinoplus2.c.template").exists():
            print("ℹ️  原始模板已存在，跳过备份")
            return
        
        print("📦 备份原始主板文件为模板...")
        
        for board_name, template in BOARD_TEMPLATES.items():
            original = self.hw_arm_path / template.original_file.replace('hw/arm/', '')
            template_file = self.hw_arm_path / f"{board_name}.c.template"
            
            if original.exists() and not template_file.exists():
                shutil.copy2(original, template_file)
                print(f"  ✅ {board_name}.c → {board_name}.c.template")
        
        self.templates_backed_up = True
        print("✅ 模板备份完成！")
    
    def generate_adapted_board(
        self,
        base_template: str,
        firmware_analysis: Dict,
        output_name: Optional[str] = None
    ) -> str:
        """
        基于分析结果生成适配的主板文件
        
        Args:
            base_template: 基础模板名称 (如 'netduinoplus2')
            firmware_analysis: 固件分析结果
            output_name: 输出文件名（None则使用base_template）
        
        Returns:
            生成的主板文件路径
        """
        if base_template not in BOARD_TEMPLATES:
            raise ValueError(f"Unknown template: {base_template}")
        
        template = BOARD_TEMPLATES[base_template]
        output_name = output_name or base_template
        
        print(f"\n🔧 生成适配主板: {output_name}")
        print(f"  基础模板: {base_template}")
        
        # 读取模板内容
        template_path = self.hw_arm_path / f"{base_template}.c.template"
        if not template_path.exists():
            # 如果模板不存在，使用原始文件
            template_path = self.hw_arm_path / f"{base_template}.c"
        
        with open(template_path, 'r') as f:
            content = f.read()
        
        # 提取固件需求
        required_flash = firmware_analysis.get('flash_size_kb', template.default_flash_size)
        required_sram = firmware_analysis.get('sram_size_kb', template.default_sram_size)
        required_cpu = firmware_analysis.get('cpu_type', template.default_cpu)
        
        print(f"  固件需求:")
        print(f"    Flash: {required_flash}KB")
        print(f"    SRAM: {required_sram}KB")
        print(f"    CPU: {required_cpu}")
        
        # 应用适配（当前只修改注释，因为Flash/SRAM在SOC层）
        # 主要是为了文档和后续扩展
        adapted_content = self._adapt_board_content(
            content,
            template,
            required_flash,
            required_sram,
            required_cpu,
            firmware_analysis
        )
        
        # 写入适配后的文件
        output_path = self.hw_arm_path / f"{output_name}.c"
        with open(output_path, 'w') as f:
            f.write(adapted_content)
        
        print(f"  ✅ 生成: {output_path}")
        
        return str(output_path)
    
    def _adapt_board_content(
        self,
        content: str,
        template: BoardTemplate,
        flash_kb: int,
        sram_kb: int,
        cpu: str,
        analysis: Dict
    ) -> str:
        """适配主板内容"""
        
        # 添加自动生成标记
        header_comment = f"""/*
 * Auto-adapted from {template.name} template
 * Generated for firmware: {analysis.get('firmware_name', 'unknown')}
 * Detected MCU: {analysis.get('detected_variant', 'unknown')}
 * 
 * Resource requirements:
 *   Flash: {flash_kb}KB (template: {template.default_flash_size}KB)
 *   SRAM: {sram_kb}KB (template: {template.default_sram_size}KB)
 *   CPU: {cpu} (template: {template.default_cpu})
 * 
 * This file is auto-generated. Do not edit manually.
 * Template: {template.template_file}
 */

"""
        
        # 如果已有auto-adapted标记，替换
        if '* Auto-adapted from' in content:
            content = re.sub(
                r'/\*\n \* Auto-adapted from.*?\*/\n\n',
                '',
                content,
                flags=re.DOTALL
            )
        
        # 在第一个#include之前插入
        content = re.sub(
            r'(#include\s+"qemu/osdep\.h")',
            header_comment + r'\1',
            content,
            count=1
        )
        
        # 如果有CPU类型检查，可以修改valid_cpu_types
        if cpu != template.default_cpu:
            # 尝试修改CPU验证
            content = re.sub(
                r'ARM_CPU_TYPE_NAME\("cortex-m\d"\)',
                f'ARM_CPU_TYPE_NAME("{cpu}")',
                content
            )
        
        return content
    
    def generate_adapted_soc(
        self,
        base_soc: str,
        firmware_analysis: Dict,
        peripherals: List[Dict]
    ) -> str:
        """
        生成适配的SOC文件
        
        这是关键：修改SOC的RAM/Flash大小和外设列表
        
        Args:
            base_soc: 基础SOC类型 (如 'stm32f405_soc')
            firmware_analysis: 固件分析结果
            peripherals: 外设列表
        
        Returns:
            生成的SOC文件路径
        """
        print(f"\n🔧 生成适配SOC: {base_soc}")
        
        # SOC文件路径
        soc_c_path = self.hw_arm_path / f"{base_soc}.c"
        soc_h_path = self.qemu_path / "include" / "hw" / "arm" / f"{base_soc}.h"
        
        # 使用.backup文件作为template（优先级最高）
        soc_c_backup = self.hw_arm_path / f"{base_soc}.c.backup"
        soc_h_backup = self.qemu_path / "include" / "hw" / "arm" / f"{base_soc}.h.backup"
        soc_c_template = self.hw_arm_path / f"{base_soc}.c.template"
        soc_h_template = self.qemu_path / "include" / "hw" / "arm" / f"{base_soc}.h.template"
        
        # 优先使用.backup（最干净），其次是.template，最后是当前文件
        if soc_c_backup.exists():
            # 使用backup作为template
            if not soc_c_template.exists() or soc_c_backup.stat().st_mtime < soc_c_template.stat().st_mtime:
                shutil.copy2(soc_c_backup, soc_c_template)
                print(f"  📦 使用backup作为template: {base_soc}.c.backup → {base_soc}.c.template")
        elif not soc_c_template.exists() and soc_c_path.exists():
            shutil.copy2(soc_c_path, soc_c_template)
            print(f"  📦 备份: {base_soc}.c → {base_soc}.c.template")
        
        if soc_h_backup.exists():
            if not soc_h_template.exists() or soc_h_backup.stat().st_mtime < soc_h_template.stat().st_mtime:
                shutil.copy2(soc_h_backup, soc_h_template)
                print(f"  📦 使用backup作为template: {base_soc}.h.backup → {base_soc}.h.template")
        elif not soc_h_template.exists() and soc_h_path.exists():
            shutil.copy2(soc_h_path, soc_h_template)
            print(f"  📦 备份: {base_soc}.h → {base_soc}.h.template")
        
        # 读取模板
        with open(soc_c_template, 'r') as f:
            soc_c_content = f.read()
        with open(soc_h_template, 'r') as f:
            soc_h_content = f.read()
        
        # 修改头文件（RAM/Flash大小和Base地址）
        required_flash = firmware_analysis.get('flash_size_kb', 1024) * 1024
        required_sram = firmware_analysis.get('sram_size_kb', 128) * 1024
        flash_base = firmware_analysis.get('flash_base', 0x08000000)
        sram_base = firmware_analysis.get('sram_base', 0x20000000)
        
        print(f"  修改资源配置:")
        print(f"    Flash: {required_flash//1024}KB @ 0x{flash_base:08x}")
        print(f"    SRAM: {required_sram//1024}KB @ 0x{sram_base:08x}")
        
        # 替换FLASH_SIZE定义
        soc_h_content = re.sub(
            r'#define FLASH_SIZE \(.*?\)',
            f'#define FLASH_SIZE ({required_flash})',
            soc_h_content
        )
        
        # 替换SRAM_SIZE定义
        soc_h_content = re.sub(
            r'#define SRAM_SIZE \(.*?\)',
            f'#define SRAM_SIZE ({required_sram})',
            soc_h_content
        )
        
        # 🆕 替换Flash base地址
        if flash_base != 0x08000000:
            print(f"  ⚠️  非标准Flash base: 0x{flash_base:08x}")
            # 在SOC C文件中修改Flash内存区域的base地址
            soc_c_content = re.sub(
                r'(memory_region_add_subregion\(system_memory,\s*)0x08000000',
                rf'\g<1>0x{flash_base:08x}',
                soc_c_content
            )
        
        # 🆕 替换SRAM base地址  
        if sram_base != 0x20000000:
            print(f"  ⚠️  非标准SRAM base: 0x{sram_base:08x}")
            soc_c_content = re.sub(
                r'(memory_region_add_subregion\(system_memory,\s*)0x20000000',
                rf'\g<1>0x{sram_base:08x}',
                soc_c_content
            )
        
        # 写入适配后的文件
        with open(soc_c_path, 'w') as f:
            f.write(soc_c_content)
        with open(soc_h_path, 'w') as f:
            f.write(soc_h_content)
        
        print(f"  ✅ 已更新: {soc_c_path}")
        print(f"  ✅ 已更新: {soc_h_path}")
        
        return str(soc_c_path)
    
    def restore_original_files(self):
        """恢复原始文件（从模板）"""
        print("\n♻️  恢复原始文件...")
        
        for board_name, template in BOARD_TEMPLATES.items():
            template_file = self.hw_arm_path / f"{board_name}.c.template"
            original = self.hw_arm_path / f"{board_name}.c"
            
            if template_file.exists():
                shutil.copy2(template_file, original)
                print(f"  ✅ 恢复: {board_name}.c")
        
        # 恢复SOC文件
        for soc_name in ['stm32f405_soc', 'stm32f100_soc']:
            for ext in ['.c', '.h']:
                if ext == '.h':
                    template_path = self.qemu_path / "include" / "hw" / "arm" / f"{soc_name}{ext}.template"
                    original_path = self.qemu_path / "include" / "hw" / "arm" / f"{soc_name}{ext}"
                else:
                    template_path = self.hw_arm_path / f"{soc_name}{ext}.template"
                    original_path = self.hw_arm_path / f"{soc_name}{ext}"
                
                if template_path.exists():
                    shutil.copy2(template_path, original_path)
                    print(f"  ✅ 恢复: {soc_name}{ext}")
        
        print("✅ 恢复完成！")
    
    def list_templates(self):
        """列出所有可用模板"""
        print("\n📋 可用主板模板:")
        print()
        for name, template in BOARD_TEMPLATES.items():
            print(f"  {name}")
            print(f"    SOC: {template.soc_type}")
            print(f"    Flash: {template.default_flash_size}KB")
            print(f"    SRAM: {template.default_sram_size}KB")
            print(f"    CPU: {template.default_cpu}")
            print()


def select_best_template(firmware_analysis: Dict) -> str:
    """
    基于固件分析结果选择最佳模板
    
    Args:
        firmware_analysis: 固件分析结果（包含detected_variant, flash_size_kb等）
    
    Returns:
        最佳模板名称
    """
    variant = firmware_analysis.get('detected_variant', '')
    flash_kb = firmware_analysis.get('flash_size_kb', 128)
    sram_kb = firmware_analysis.get('sram_size_kb', 20)
    cpu = firmware_analysis.get('cpu_type', 'cortex-m3')
    
    print(f"\n🔍 选择最佳模板:")
    print(f"  固件版型: {variant}")
    print(f"  Flash需求: {flash_kb}KB")
    print(f"  SRAM需求: {sram_kb}KB")
    print(f"  CPU: {cpu}")
    
    # 匹配规则
    if 'F103' in variant or 'F1' in variant:
        # STM32F1系列
        if sram_kb <= 8:
            selected = 'stm32vldiscovery'
        else:
            # F1但需要更多RAM，用F4的machine但后续会适配
            selected = 'netduinoplus2'
            print("  ⚠️  F1固件但RAM需求>8KB，使用netduinoplus2并适配")
    elif 'F4' in variant or flash_kb > 256:
        # STM32F4系列
        selected = 'netduinoplus2'
    elif 'SAM3' in variant:
        # SAM3系列暂时也用netduinoplus2（RAM足够）
        selected = 'netduinoplus2'
        print("  ⚠️  SAM3固件，使用netduinoplus2作为fallback")
    else:
        # 默认
        selected = 'netduinoplus2' if sram_kb > 20 else 'stm32vldiscovery'
    
    print(f"  ✅ 选择模板: {selected}")
    return selected


# 命令行接口
if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='MCU主板模板管理器')
    parser.add_argument('action', choices=['backup', 'restore', 'list', 'adapt'],
                       help='操作: backup(备份), restore(恢复), list(列表), adapt(适配)')
    parser.add_argument('--analysis', help='固件分析结果JSON文件（adapt时需要）')
    parser.add_argument('--template', help='基础模板名称')
    parser.add_argument('--qemu-path', default='/home/zhangzheng/new/qemu',
                       help='QEMU路径')
    
    args = parser.parse_args()
    
    manager = BoardTemplateManager(args.qemu_path)
    
    if args.action == 'backup':
        manager.backup_original_files()
    
    elif args.action == 'restore':
        manager.restore_original_files()
    
    elif args.action == 'list':
        manager.list_templates()
    
    elif args.action == 'adapt':
        if not args.analysis:
            print("错误: --analysis 参数必需")
            exit(1)
        
        # 读取分析结果
        with open(args.analysis, 'r') as f:
            analysis = json.load(f)
        
        # 选择模板
        template = args.template or select_best_template(analysis)
        
        # 生成适配主板
        manager.generate_adapted_board(template, analysis)
        
        # 生成适配SOC
        if 'F405' in template or 'netduino' in template:
            manager.generate_adapted_soc('stm32f405_soc', analysis, [])
        elif 'F100' in template or 'vldiscovery' in template:
            manager.generate_adapted_soc('stm32f100_soc', analysis, [])
        
        print("\n✅ 主板适配完成！")

