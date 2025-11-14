#!/usr/bin/env python3
"""
MCU架构检测器

自动检测固件的目标架构（STM32F1/F4, SAM3, AVR等）并推荐QEMU配置
"""

import subprocess
import json
import re
from pathlib import Path
from typing import Dict, Optional, Tuple
from dataclasses import dataclass


@dataclass
class ArchConfig:
    """架构配置"""
    name: str                    # 架构名称
    qemu_machine: str            # QEMU machine类型
    cpu_type: Optional[str]      # CPU类型
    ram_base: int                # RAM基址
    ram_size: int                # RAM大小
    flash_base: int              # Flash基址
    flash_size: int              # Flash大小
    peripheral_base: int         # 外设基址
    supported: bool = True       # 是否支持


# 已知架构配置库
ARCH_DATABASE = {
    'STM32F103': ArchConfig(
        name='STM32F103 (Cortex-M3)',
        qemu_machine='netduinoplus2',
        cpu_type='cortex-m3',
        ram_base=0x20000000,
        ram_size=20 * 1024,
        flash_base=0x08000000,
        flash_size=128 * 1024,
        peripheral_base=0x40000000,
        supported=True
    ),
    'STM32F4': ArchConfig(
        name='STM32F4xx (Cortex-M4)',
        qemu_machine='netduinoplus2',  # 或 stm32vldiscovery
        cpu_type='cortex-m4',
        ram_base=0x20000000,
        ram_size=192 * 1024,
        flash_base=0x08000000,
        flash_size=1024 * 1024,
        peripheral_base=0x40000000,
        supported=True
    ),
    'SAM3X': ArchConfig(
        name='SAM3X (Cortex-M3, Arduino Due)',
        qemu_machine='stm32vldiscovery',  # Fallback: 使用STM32F1的Cortex-M3机器
        cpu_type='cortex-m3',
        ram_base=0x20000000,
        ram_size=96 * 1024,
        flash_base=0x00080000,  # 注意！SAM3的Flash在不同地址
        flash_size=512 * 1024,
        peripheral_base=0x40000000,
        supported=True  # 使用fallback机器尝试运行
    ),
    'AVR': ArchConfig(
        name='AVR (Arduino Uno/Mega)',
        qemu_machine='arduino-uno',
        cpu_type=None,
        ram_base=0x0100,
        ram_size=2 * 1024,
        flash_base=0x0000,
        flash_size=32 * 1024,
        peripheral_base=0x0000,
        supported=False  # 需要特殊处理
    ),
    'GENERIC_CORTEX_M3': ArchConfig(
        name='Generic Cortex-M3',
        qemu_machine='lm3s6965evb',
        cpu_type='cortex-m3',
        ram_base=0x20000000,
        ram_size=64 * 1024,
        flash_base=0x00000000,
        flash_size=256 * 1024,
        peripheral_base=0x40000000,
        supported=True
    ),
    'GENERIC_CORTEX_M4': ArchConfig(
        name='Generic Cortex-M4',
        qemu_machine='netduinoplus2',
        cpu_type='cortex-m4',
        ram_base=0x20000000,
        ram_size=128 * 1024,
        flash_base=0x08000000,
        flash_size=512 * 1024,
        peripheral_base=0x40000000,
        supported=True
    ),
}


class ArchDetector:
    """架构检测器"""
    
    def __init__(self, firmware_path: str):
        self.firmware_path = Path(firmware_path)
        self.elf_info = {}
        self.detected_arch = None
        self.config = None
    
    def detect(self) -> Tuple[str, ArchConfig]:
        """
        检测固件架构
        
        Returns:
            (arch_name, arch_config)
        """
        # 1. 读取ELF信息
        self._read_elf_info()
        
        # 2. 基于入口地址和machine推断架构
        arch_name = self._infer_arch()
        
        # 3. 获取配置
        if arch_name in ARCH_DATABASE:
            self.config = ARCH_DATABASE[arch_name]
        else:
            # 使用通用配置
            self.config = self._create_generic_config()
        
        self.detected_arch = arch_name
        return arch_name, self.config
    
    def _read_elf_info(self):
        """读取ELF文件信息"""
        try:
            # 读取ELF header
            result = subprocess.run(
                ['readelf', '-h', str(self.firmware_path)],
                capture_output=True,
                text=True,
                check=True
            )
            
            lines = result.stdout.split('\n')
            for line in lines:
                if 'Entry point address:' in line:
                    addr = line.split(':')[1].strip()
                    self.elf_info['entry_point'] = int(addr, 16)
                elif 'Machine:' in line:
                    machine = line.split(':')[1].strip()
                    self.elf_info['machine'] = machine
                elif 'Class:' in line:
                    elf_class = line.split(':')[1].strip()
                    self.elf_info['class'] = elf_class
            
            # 读取sections（找Flash和RAM）
            result = subprocess.run(
                ['readelf', '-S', str(self.firmware_path)],
                capture_output=True,
                text=True,
                check=True
            )
            
            self.elf_info['sections'] = self._parse_sections(result.stdout)
            
        except Exception as e:
            print(f"Warning: Failed to read ELF info: {e}")
            self.elf_info = {
                'entry_point': 0x08000000,
                'machine': 'ARM',
                'sections': {}
            }
    
    def _parse_sections(self, readelf_output: str) -> Dict:
        """解析ELF sections"""
        sections = {}
        
        # 查找 .text, .data, .bss sections
        for line in readelf_output.split('\n'):
            if re.search(r'\s+\.(text|data|bss|rodata|isr_vector)', line):
                parts = line.split()
                if len(parts) >= 5:
                    section_name = parts[1]
                    try:
                        addr = int(parts[3], 16) if parts[3] != '0' else 0
                        size = int(parts[5], 16)
                        sections[section_name] = {'addr': addr, 'size': size}
                    except:
                        pass
        
        return sections
    
    def _infer_arch(self) -> str:
        """基于入口地址和sections推断架构"""
        entry = self.elf_info.get('entry_point', 0)
        machine = self.elf_info.get('machine', '')
        
        print(f"[ArchDetector] Entry: 0x{entry:08x}, Machine: {machine}")
        
        # 首先检查Machine字段 - RISC-V和MIPS优先判断
        if 'RISC-V' in machine or 'riscv' in machine.lower():
            return 'RISCV'  # 返回特殊标记
        elif 'MIPS' in machine or 'mips' in machine.lower():
            return 'MIPS'  # 返回特殊标记
        
        # 规则1: 入口地址在0x08000000 → STM32系列
        if 0x08000000 <= entry < 0x08100000:
            # 进一步区分F1/F4
            flash_size = self._estimate_flash_size()
            if flash_size > 256 * 1024:
                return 'STM32F4'
            else:
                return 'STM32F103'
        
        # 规则2: 入口地址在0x00080000 → SAM3系列
        elif 0x00080000 <= entry < 0x00100000:
            return 'SAM3X'
        
        # 规则3: 入口地址在0x00000000 → Generic Cortex-M或AVR
        elif entry < 0x00010000:
            if 'ARM' in machine:
                return 'GENERIC_CORTEX_M3'
            else:
                return 'AVR'
        
        # 规则4: 其他Cortex-M (0x20000000附近是RAM)
        elif 0x20000000 <= entry < 0x30000000:
            return 'GENERIC_CORTEX_M4'
        
        # 默认：根据machine推断（但排除非ARM架构）
        if 'ARM' in machine or 'Cortex' in machine:
            return 'GENERIC_CORTEX_M3'
        elif 'AVR' in machine:
            return 'AVR'
        else:
            # 未知架构，保守返回UNKNOWN而不是默认ARM
            return 'UNKNOWN'
    
    def _estimate_flash_size(self) -> int:
        """估算Flash大小"""
        sections = self.elf_info.get('sections', {})
        
        max_addr = 0
        for sec_name, sec_info in sections.items():
            if sec_name in ['.text', '.rodata', '.isr_vector']:
                end_addr = sec_info['addr'] + sec_info['size']
                max_addr = max(max_addr, end_addr)
        
        if max_addr > 0x08000000:
            flash_used = max_addr - 0x08000000
            # 向上取整到常见Flash大小
            if flash_used > 512 * 1024:
                return 1024 * 1024
            elif flash_used > 256 * 1024:
                return 512 * 1024
            elif flash_used > 128 * 1024:
                return 256 * 1024
            else:
                return 128 * 1024
        
        return 128 * 1024  # 默认
    
    def _create_generic_config(self) -> ArchConfig:
        """为未知架构创建通用配置"""
        entry = self.elf_info.get('entry_point', 0x08000000)
        
        # 基于入口地址推断
        if entry >= 0x08000000:
            flash_base = 0x08000000
            ram_base = 0x20000000
        elif entry >= 0x00080000:
            flash_base = 0x00080000
            ram_base = 0x20000000
        else:
            flash_base = 0x00000000
            ram_base = 0x20000000
        
        return ArchConfig(
            name='Generic ARM Cortex-M',
            qemu_machine='netduinoplus2',
            cpu_type='cortex-m4',
            ram_base=ram_base,
            ram_size=128 * 1024,
            flash_base=flash_base,
            flash_size=512 * 1024,
            peripheral_base=0x40000000,
            supported=True
        )
    
    def get_qemu_args(self) -> list:
        """获取QEMU参数"""
        if not self.config:
            self.detect()
        
        args = [
            '-M', self.config.qemu_machine,
            '-kernel', str(self.firmware_path),
            '-nographic',
        ]
        
        # 如果指定了CPU类型
        if self.config.cpu_type:
            args.extend(['-cpu', self.config.cpu_type])
        
        return args
    
    def generate_report(self) -> Dict:
        """生成检测报告"""
        if not self.config:
            self.detect()
        
        return {
            'firmware': str(self.firmware_path),
            'detected_arch': self.detected_arch,
            'elf_info': self.elf_info,
            'config': {
                'name': self.config.name,
                'qemu_machine': self.config.qemu_machine,
                'cpu_type': self.config.cpu_type,
                'ram': f'0x{self.config.ram_base:08x} ({self.config.ram_size // 1024}KB)',
                'flash': f'0x{self.config.flash_base:08x} ({self.config.flash_size // 1024}KB)',
                'peripheral': f'0x{self.config.peripheral_base:08x}',
                'supported': self.config.supported
            },
            'qemu_args': self.get_qemu_args()
        }


def detect_firmware_arch(firmware_path: str, verbose: bool = False) -> Tuple[str, ArchConfig]:
    """
    快捷函数：检测固件架构
    
    Args:
        firmware_path: 固件路径
        verbose: 是否输出详细信息
    
    Returns:
        (arch_name, arch_config)
    """
    detector = ArchDetector(firmware_path)
    arch_name, config = detector.detect()
    
    if verbose:
        report = detector.generate_report()
        print("\n=== 架构检测报告 ===")
        print(json.dumps(report, indent=2, ensure_ascii=False))
    
    return arch_name, config


# 测试代码
if __name__ == '__main__':
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python3 arch_detector.py <firmware.elf>")
        sys.exit(1)
    
    firmware = sys.argv[1]
    detect_firmware_arch(firmware, verbose=True)

