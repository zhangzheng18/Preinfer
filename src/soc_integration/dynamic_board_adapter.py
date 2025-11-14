#!/usr/bin/env python3
"""
动态板子适配器
根据板子配置和固件分析结果，动态调整QEMU板子
"""

import re
import json
import shutil
from pathlib import Path
from typing import Dict, List


class DynamicBoardAdapter:
    """动态板子适配器"""
    
    def __init__(self, qemu_path: str):
        self.qemu_path = Path(qemu_path)
        self.hw_arm_path = self.qemu_path / "hw" / "arm"
        self.backup_path = self.qemu_path / "backups"
        self.backup_path.mkdir(exist_ok=True)
    
    def adapt_board(self, board_config: Dict, peripherals: List[Dict] = None) -> bool:
        """
        动态适配板子
        
        Args:
            board_config: 板子配置（来自board_similarity_matcher）
            peripherals: 提取的外设列表
        
        Returns:
            bool: 成功返回True
        """
        print(f"\n{'='*70}")
        print(f"  动态板子适配")
        print(f"{'='*70}\n")
        
        soc_file = board_config['soc_file']
        soc_path = self.qemu_path / soc_file
        
        if not soc_path.exists():
            print(f"❌ SOC文件不存在: {soc_path}")
            return False
        
        print(f"基础板子: {board_config['base_board']}")
        print(f"SOC文件: {soc_file}")
        print(f"相似度: {board_config['similarity_score']:.1f}/100\n")
        
        # 1. 备份原始文件
        self._backup_file(soc_path)
        
        # ⭐ 1.5. 修改头文件中的基址定义（关键！）
        soc_header = soc_path.with_suffix('.h')
        # 从soc_file路径推断头文件路径
        # hw/arm/stm32f405_soc.c -> include/hw/arm/stm32f405_soc.h
        if 'hw/arm' in str(soc_file):
            soc_name = soc_path.stem  # stm32f405_soc
            soc_header = self.qemu_path / 'include' / 'hw' / 'arm' / f'{soc_name}.h'
        
        if soc_header.exists():
            self._adjust_soc_header(soc_header, board_config['adjustments'])
        else:
            print(f"⚠️  未找到头文件: {soc_header}")
        
        # 2. 加载模板
        template_path = soc_path.with_suffix('.c.template')
        if not template_path.exists():
            # 如果没有template，从backup创建
            backup_path = self.backup_path / soc_path.name
            if backup_path.exists():
                shutil.copy2(backup_path, template_path)
            else:
                shutil.copy2(soc_path, template_path)
        
        with open(template_path, 'r') as f:
            content = f.read()
        
        # 3. 调整Flash/RAM配置
        content = self._adjust_memory(content, board_config['adjustments'])
        
        # 4. 添加特殊内存区域
        content = self._add_special_regions(content, board_config['special_regions'])
        
        # 5. ⭐ 添加VTOR初始化代码（向量表设置）
        content = self._add_vtor_initialization(content, board_config['adjustments'])
        
        # 6. 写回
        with open(soc_path, 'w') as f:
            f.write(content)
        
        print(f"✅ 板子适配完成")
        self._print_adjustments(board_config['adjustments'])
        
        return True
    
    def _backup_file(self, file_path: Path):
        """备份文件"""
        backup_file = self.backup_path / file_path.name
        if not backup_file.exists():
            shutil.copy2(file_path, backup_file)
            print(f"  📦 备份: {file_path.name} → backups/")
    
    def _adjust_soc_header(self, header_path: Path, adjustments: Dict):
        """
        ⭐ 修改SOC头文件中的基址定义
        
        这是关键步骤：修改 FLASH_BASE_ADDRESS 和 SRAM_BASE_ADDRESS
        """
        self._backup_file(header_path)
        
        with open(header_path, 'r') as f:
            content = f.read()
        
        flash_base = adjustments['flash_base']
        sram_base = adjustments['sram_base']
        
        # 替换 FLASH_BASE_ADDRESS
        # 匹配: #define FLASH_BASE_ADDRESS 0x08000000
        old_content = content
        content = re.sub(
            r'(#define\s+FLASH_BASE_ADDRESS\s+)0x[0-9A-Fa-f]+',
            rf'\g<1>{hex(flash_base)}',
            content
        )
        
        if content != old_content:
            print(f"  ⭐ 修改头文件 Flash 基址: {hex(flash_base)}")
        
        # 替换 SRAM_BASE_ADDRESS (如果存在)
        old_content = content
        content = re.sub(
            r'(#define\s+SRAM_BASE_ADDRESS\s+)0x[0-9A-Fa-f]+',
            rf'\g<1>{hex(sram_base)}',
            content
        )
        
        if content != old_content:
            print(f"  ⭐ 修改头文件 SRAM 基址: {hex(sram_base)}")
        
        # 写回
        with open(header_path, 'w') as f:
            f.write(content)
    
    def _adjust_memory(self, content: str, adjustments: Dict) -> str:
        """调整内存配置"""
        print(f"调整内存配置:")
        
        flash_size = adjustments['flash_size_kb'] * 1024
        sram_size = adjustments['sram_size_kb'] * 1024
        flash_base = adjustments['flash_base']
        sram_base = adjustments['sram_base']
        
        # ⭐ 关键修复：确保Flash大小足够大（至少1MB）
        min_flash_size = 1024 * 1024  # 1MB
        if flash_size < min_flash_size:
            print(f"  ⚠️  Flash大小 {flash_size//1024}KB 太小，扩展到 {min_flash_size//1024}KB")
            flash_size = min_flash_size
        
        # 替换Flash大小
        # 查找类似: #define FLASH_SIZE (1024 * 1024) 或 0x100000
        content = re.sub(
            r'(#define\s+FLASH_SIZE\s+)(?:\(\s*\d+\s*\*\s*1024\s*\)|0x[0-9A-Fa-f]+)',
            rf'\g<1>({flash_size})',
            content
        )
        
        # ⭐ 关键：替换 memory_region_init_rom 中的Flash大小
        # 匹配: memory_region_init_rom(flash, ..., flash_size, ...)
        #      或 memory_region_init_rom(&s->flash, ..., 0x100000, ...)
        old_content = content
        content = re.sub(
            r'(memory_region_init_rom\s*\([^,]+,\s*[^,]+,\s*[^,]+,\s*)(?:\d+|0x[0-9A-Fa-f]+|flash_size)',
            rf'\g<1>{flash_size}',
            content
        )
        
        if content != old_content:
            print(f"  ⭐ 修改Flash初始化大小: {flash_size//1024}KB")
        
        # 也替换直接使用的Flash大小字面量（向后兼容）
        content = re.sub(
            r'(memory_region_init_rom.*?flash.*?,\s*)0x[0-9A-Fa-f]+',
            rf'\g<1>{hex(flash_size)}',
            content
        )
        
        # 替换SRAM大小
        content = re.sub(
            r'(#define\s+SRAM_SIZE\s+)(?:\(\s*\d+\s*\*\s*1024\s*\)|0x[0-9A-Fa-f]+)',
            rf'\g<1>({sram_size})',
            content
        )
        
        content = re.sub(
            r'(memory_region_init_ram.*?sram.*?,\s*)0x[0-9A-Fa-f]+',
            rf'\g<1>{hex(sram_size)}',
            content
        )
        
        # 替换基址（如果不同）
        # Flash基址 - 改进版：匹配所有可能的格式
        # 可能的格式: memory_region_add_subregion(system_memory, 0, flash)
        #           memory_region_add_subregion(system_memory, 0x08000000, &s->flash)
        #           memory_region_add_subregion(system_memory, FLASH_BASE_ADDRESS, ...)
        
        # 先尝试匹配常见的数字格式
        old_content = content
        content = re.sub(
            r'(memory_region_add_subregion\s*\([^,]+,\s*)(?:0x[0-9A-Fa-f]+|0)(\s*,\s*[^,]*flash[^)]*\))',
            rf'\g<1>{hex(flash_base)}\g<2>',
            content,
            flags=re.IGNORECASE
        )
        
        if content != old_content:
            print(f"  ⭐ 修改C代码 Flash 基址: {hex(flash_base)}")
        
        # SRAM基址 - 同样改进（修复：不保留旧地址）
        old_content = content
        content = re.sub(
            r'(memory_region_add_subregion\s*\([^,]+,\s*)(0x[12][0-9A-Fa-f]{7})(\s*,\s*[^,]*(?:sram|ram)[^)]*\))',
            rf'\g<1>{hex(sram_base)}\g<3>',  # ⭐ 修复：使用\g<3>而不是\g<2>
            content,
            flags=re.IGNORECASE
        )
        
        if content != old_content:
            print(f"  ⭐ 修改C代码 SRAM 基址: {hex(sram_base)}")
        
        print(f"  Flash: {flash_size//1024}KB @ {hex(flash_base)}")
        print(f"  SRAM: {sram_size//1024}KB @ {hex(sram_base)}")
        
        return content
    
    def _add_vtor_initialization(self, content: str, adjustments: Dict) -> str:
        """
        ⭐ 添加VTOR（向量表偏移寄存器）初始化代码
        
        ARM Cortex-M的向量表基址由VTOR控制，需要在CPU初始化后设置
        """
        flash_base = adjustments['flash_base']
        
        # 如果Flash不在0x0或0x08000000，需要设置VTOR
        if flash_base not in [0x0, 0x08000000]:
            print(f"  ⭐ 添加VTOR初始化代码: {hex(flash_base)}")
            
            # 查找CPU初始化或realize函数
            # 模式1: 查找 armv7m_load_kernel 调用
            if 'armv7m_load_kernel' in content or 'arm_load_kernel' in content:
                # 在 armv7m_load_kernel 之后添加VTOR设置
                vtor_code = f"""
    
    /* ⭐ PerAuto: 设置向量表偏移（VTOR）以支持非标准Flash基址 */
    {{
        CPUState *cpu_state = CPU(armv7m);
        CPUARMState *env = &ARM_CPU(cpu_state)->env;
        /* 设置VTOR到Flash基址 */
        env->v7m.vecbase[false] = {hex(flash_base)};  /* Non-secure VTOR */
        env->v7m.vecbase[true] = {hex(flash_base)};   /* Secure VTOR (for ARMv8-M) */
    }}
"""
                # 在realize函数结尾或armv7m_load_kernel之后插入
                patterns = [
                    (r'(armv7m_load_kernel\([^)]+\);)', rf'\g<1>{vtor_code}'),
                    (r'(arm_load_kernel\([^)]+\);)', rf'\g<1>{vtor_code}')
                ]
                
                for pattern, replacement in patterns:
                    old_content = content
                    content = re.sub(pattern, replacement, content)
                    if content != old_content:
                        print(f"    ✅ VTOR代码已注入到kernel load之后")
                        break
            
            # 模式2: 直接在realize函数结尾添加
            elif '_realize' in content or '_init' in content:
                # 查找realize函数的结尾
                vtor_code = f"""
    
    /* ⭐ PerAuto: 设置向量表偏移（VTOR）以支持非标准Flash基址 */
    if (cpu && ARM_CPU(cpu)->env.v7m.cpu) {{
        CPUARMState *env = &ARM_CPU(cpu)->env;
        env->v7m.vecbase[false] = {hex(flash_base)};
        env->v7m.vecbase[true] = {hex(flash_base)};
    }}
"""
                # 在realize函数结尾插入（在最后的}之前）
                # 这个比较通用，但可能不准确
                print(f"    ⚠️  未找到armv7m_load_kernel，VTOR可能需要手动设置")
        
        return content
    
    def _add_special_regions(self, content: str, special_regions: List[str]) -> str:
        """添加特殊内存区域"""
        if not special_regions:
            return content
        
        print(f"\n添加特殊内存区域:")
        
        # 检查是否已添加
        if '/* Special Memory Regions */' in content:
            print(f"  ℹ️  特殊内存区域已存在")
            return content
        
        # 定义各种特殊区域
        region_defs = {
            'stm32_system_memory': (0x1FFF0000, 0x8000, 'System Memory'),
            'stm32_option_bytes': (0x1FFFC000, 0x10, 'Option Bytes'),
            'boot_memory': (0x00000000, 0x20000, 'Boot Memory'),
            'internal_rom': (0x00100000, 0x40000, 'Internal ROM'),
            'arm_system_control': (0xE000E000, 0x1000, 'ARM SCB'),
        }
        
        region_code = "\n    /* Special Memory Regions (auto-added) */\n"
        for region in special_regions:
            if region in region_defs:
                addr, size, desc = region_defs[region]
                region_code += f'    create_unimplemented_device("{region}", {hex(addr)}, {hex(size)}); /* {desc} */\n'
                print(f"  + {desc}: {hex(addr)}, {size} bytes")
        
        # 插入到realize函数中
        # 查找合适的插入点
        patterns = [
            r'(    /\* Peripherals)',
            r'(    /\* USART)',
            r'(    /\* ADC)',
        ]
        
        inserted = False
        for pattern in patterns:
            if re.search(pattern, content):
                content = re.sub(pattern, region_code + r'\1', content, count=1)
                inserted = True
                break
        
        if not inserted:
            print(f"  ⚠️  未找到插入点")
        
        return content
    
    def _print_adjustments(self, adjustments: Dict):
        """打印调整摘要"""
        print(f"\n调整摘要:")
        print(f"  Flash: {adjustments['flash_size_kb']}KB @ {hex(adjustments['flash_base'])}")
        print(f"  SRAM: {adjustments['sram_size_kb']}KB @ {hex(adjustments['sram_base'])}")
        print()


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='动态板子适配器')
    parser.add_argument('--config', required=True, help='板子配置JSON')
    parser.add_argument('--qemu-path', required=True, help='QEMU源码路径')
    
    args = parser.parse_args()
    
    # 加载配置
    with open(args.config, 'r') as f:
        board_config = json.load(f)
    
    # 执行适配
    adapter = DynamicBoardAdapter(args.qemu_path)
    success = adapter.adapt_board(board_config)
    
    return 0 if success else 1


if __name__ == '__main__':
    exit(main())

