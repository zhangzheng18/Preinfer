#!/usr/bin/env python3
"""
空中断检测器

检测固件中的空中断处理函数（默认Handler）
这些中断如果被触发会导致固件卡死

检测方法:
1. 解析中断向量表（IVT）
2. 识别默认Handler（死循环）
3. 标记哪些中断是空的
"""

import struct
import logging
from typing import Dict, List, Set, Optional, Tuple
from pathlib import Path
from dataclasses import dataclass
from elftools.elf.elffile import ELFFile

logger = logging.getLogger(__name__)


@dataclass
class InterruptInfo:
    """中断信息"""
    index: int              # 中断索引
    name: str              # 中断名称
    handler_address: int   # 处理函数地址
    is_empty: bool         # 是否是空中断
    is_default: bool       # 是否是默认Handler
    irq_number: Optional[int] = None  # IRQ号（对于外部中断）


class EmptyInterruptDetector:
    """空中断检测器"""
    
    # ARM Cortex-M中断向量表名称（SAM3X为例）
    CORTEX_M_VECTOR_NAMES = [
        "Initial_SP", "Reset", "NMI", "HardFault",
        "MemManage", "BusFault", "UsageFault", "Reserved",
        "Reserved", "Reserved", "Reserved", "SVC",
        "DebugMon", "Reserved", "PendSV", "SysTick",
        # 外部中断 (IRQ0-47)
        "SUPC", "RSTC", "RTC", "RTT", "WDT",
        "PMC", "EFC0", "EFC1", "UART", "SMC",
        "SDRAMC", "PIOA", "PIOB", "PIOC", "PIOD",
        "PIOE", "PIOF", "USART0", "USART1", "USART2",
        "USART3", "HSMCI", "TWI0", "TWI1", "SPI0",
        "SPI1", "SSC", "TC0", "TC1", "TC2",
        "TC3", "TC4", "TC5", "TC6", "TC7",
        "TC8", "PWM", "ADC", "DACC", "DMAC",
        "UOTGHS", "TRNG", "EMAC", "CAN0", "CAN1"
    ]
    
    def __init__(self, firmware_path: str):
        self.firmware_path = Path(firmware_path)
        self.elf = None
        self.code_section = None
        self.ivt_base = None
        
    def detect(self) -> Dict:
        """
        检测空中断
        
        Returns:
            {
                'success': bool,
                'interrupts': List[InterruptInfo],
                'empty_interrupts': List[InterruptInfo],
                'default_handler_address': int,
                'statistics': Dict
            }
        """
        logger.info("🔍 检测空中断处理函数...")
        
        try:
            # 1. 加载ELF文件
            with open(self.firmware_path, 'rb') as f:
                self.elf = ELFFile(f)
                
                # 2. 找到.text section
                self.code_section = self.elf.get_section_by_name('.text')
                if not self.code_section:
                    return {'success': False, 'error': 'No .text section'}
                
                self.ivt_base = self.code_section['sh_addr']
                
                # 3. 解析中断向量表
                interrupts = self._parse_interrupt_vector_table()
                
                # 4. 识别默认Handler
                default_handler = self._identify_default_handler(interrupts)
                
                # 5. 标记空中断
                empty_interrupts = [irq for irq in interrupts if irq.is_empty]
                
                # 6. 统计
                statistics = {
                    'total_interrupts': len(interrupts),
                    'empty_interrupts': len(empty_interrupts),
                    'implemented_interrupts': len(interrupts) - len(empty_interrupts),
                    'default_handler_address': default_handler
                }
                
                logger.info(f"   总中断数: {statistics['total_interrupts']}")
                logger.info(f"   空中断数: {statistics['empty_interrupts']}")
                logger.info(f"   已实现: {statistics['implemented_interrupts']}")
                logger.info(f"   默认Handler: 0x{default_handler:08X}")
                
                return {
                    'success': True,
                    'interrupts': interrupts,
                    'empty_interrupts': empty_interrupts,
                    'default_handler_address': default_handler,
                    'statistics': statistics
                }
                
        except Exception as e:
            logger.error(f"❌ 空中断检测失败: {e}")
            import traceback
            logger.debug(traceback.format_exc())
            return {'success': False, 'error': str(e)}
    
    def _parse_interrupt_vector_table(self) -> List[InterruptInfo]:
        """解析中断向量表"""
        
        # 读取IVT数据
        ivt_data = self.code_section.data()[:256]  # 前64个向量
        vectors = struct.unpack('<64I', ivt_data)
        
        interrupts = []
        
        for i, addr in enumerate(vectors):
            if i == 0:
                # 跳过Initial SP
                continue
            
            # 清除Thumb模式位（最低位）
            handler_addr = addr & 0xFFFFFFFE
            
            # 获取中断名称
            if i < len(self.CORTEX_M_VECTOR_NAMES):
                name = self.CORTEX_M_VECTOR_NAMES[i]
            else:
                name = f"IRQ{i-16}"
            
            # 计算IRQ号（外部中断）
            irq_number = i - 16 if i >= 16 else None
            
            interrupts.append(InterruptInfo(
                index=i,
                name=name,
                handler_address=handler_addr,
                is_empty=False,  # 稍后标记
                is_default=False,
                irq_number=irq_number
            ))
        
        return interrupts
    
    def _identify_default_handler(self, interrupts: List[InterruptInfo]) -> int:
        """
        识别默认Handler
        
        默认Handler特征:
        1. 被多个中断向量指向
        2. 代码是死循环: b.n <self> (0xe7fe)
        """
        
        # 统计每个地址被引用的次数
        handler_counts = {}
        for irq in interrupts:
            addr = irq.handler_address
            if addr > 0:
                handler_counts[addr] = handler_counts.get(addr, 0) + 1
        
        # 找到被引用最多的地址
        if not handler_counts:
            return 0
        
        default_handler = max(handler_counts.items(), key=lambda x: x[1])[0]
        
        # 验证是否是死循环
        if self._is_infinite_loop(default_handler):
            # 标记所有指向默认Handler的中断为空中断
            for irq in interrupts:
                if irq.handler_address == default_handler:
                    irq.is_empty = True
                    irq.is_default = True
        
        return default_handler
    
    def _is_infinite_loop(self, address: int) -> bool:
        """
        检查地址处是否是死循环
        
        ARM Thumb死循环: b.n <self>
        机器码: 0xe7fe
        """
        try:
            # 计算在.text section中的偏移
            offset = address - self.ivt_base
            if offset < 0 or offset >= len(self.code_section.data()):
                return False
            
            # 读取2字节指令
            code = self.code_section.data()[offset:offset+2]
            if len(code) < 2:
                return False
            
            # 检查是否是 b.n <self> (0xe7fe)
            instruction = struct.unpack('<H', code)[0]
            return instruction == 0xe7fe
            
        except:
            return False
    
    def get_empty_interrupt_names(self) -> List[str]:
        """获取空中断的名称列表"""
        result = self.detect()
        if not result['success']:
            return []
        
        return [irq.name for irq in result['empty_interrupts']]
    
    def get_empty_irq_numbers(self) -> List[int]:
        """获取空中断的IRQ号列表（只包含外部中断）"""
        result = self.detect()
        if not result['success']:
            return []
        
        return [irq.irq_number for irq in result['empty_interrupts'] 
                if irq.irq_number is not None]
    
    def should_disable_interrupt(self, peripheral_name: str) -> bool:
        """
        判断某个外设的中断是否应该被禁用
        
        Args:
            peripheral_name: 外设名称 (如 'ADC', 'UART', 'SPI0')
        
        Returns:
            True if 该外设的中断是空的，应该禁用
        """
        empty_names = self.get_empty_interrupt_names()
        
        # 精确匹配
        if peripheral_name.upper() in empty_names:
            return True
        
        # 模糊匹配（处理USART0, SPI0等）
        for empty_name in empty_names:
            if peripheral_name.upper() in empty_name or empty_name in peripheral_name.upper():
                return True
        
        return False


def detect_empty_interrupts(firmware_path: str) -> Dict:
    """
    便捷函数：检测固件中的空中断
    
    Args:
        firmware_path: 固件路径
    
    Returns:
        检测结果字典
    """
    detector = EmptyInterruptDetector(firmware_path)
    return detector.detect()


if __name__ == '__main__':
    # 测试
    import sys
    
    if len(sys.argv) > 1:
        firmware = sys.argv[1]
    else:
        firmware = "database/unit_tests/ARDUINO-SAM3-PWM.elf"
    
    logging.basicConfig(level=logging.INFO, format='%(message)s')
    
    result = detect_empty_interrupts(firmware)
    
    if result['success']:
        print("\n空中断列表:")
        print("="*80)
        for irq in result['empty_interrupts']:
            irq_str = f"IRQ{irq.irq_number}" if irq.irq_number is not None else "N/A"
            print(f"  [{irq.index:2d}] {irq.name:15s} ({irq_str:6s}): 0x{irq.handler_address:08X}")

