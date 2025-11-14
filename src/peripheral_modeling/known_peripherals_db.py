#!/usr/bin/env python3
"""
已知外设地址数据库

基于常见MCU的外设地址映射，用于快速识别外设类型
"""

from typing import Dict, List, Optional

# STM32F4系列外设地址映射
STM32F4_PERIPHERALS = {
    # RCC (Reset and Clock Control)
    '0x40023800': {'type': 'RCC', 'name': 'RCC', 'family': 'STM32F4'},
    
    # GPIO
    '0x40020000': {'type': 'GPIO', 'name': 'GPIOA', 'family': 'STM32F4'},
    '0x40020400': {'type': 'GPIO', 'name': 'GPIOB', 'family': 'STM32F4'},
    '0x40020800': {'type': 'GPIO', 'name': 'GPIOC', 'family': 'STM32F4'},
    '0x40020C00': {'type': 'GPIO', 'name': 'GPIOD', 'family': 'STM32F4'},
    '0x40021000': {'type': 'GPIO', 'name': 'GPIOE', 'family': 'STM32F4'},
    '0x40021400': {'type': 'GPIO', 'name': 'GPIOF', 'family': 'STM32F4'},
    '0x40021800': {'type': 'GPIO', 'name': 'GPIOG', 'family': 'STM32F4'},
    '0x40021C00': {'type': 'GPIO', 'name': 'GPIOH', 'family': 'STM32F4'},
    '0x40022000': {'type': 'GPIO', 'name': 'GPIOI', 'family': 'STM32F4'},
    
    # USART/UART
    '0x40011000': {'type': 'UART', 'name': 'USART1', 'family': 'STM32F4'},
    '0x40004400': {'type': 'UART', 'name': 'USART2', 'family': 'STM32F4'},
    '0x40004800': {'type': 'UART', 'name': 'USART3', 'family': 'STM32F4'},
    '0x40004C00': {'type': 'UART', 'name': 'UART4', 'family': 'STM32F4'},
    '0x40005000': {'type': 'UART', 'name': 'UART5', 'family': 'STM32F4'},
    '0x40011400': {'type': 'UART', 'name': 'USART6', 'family': 'STM32F4'},
    
    # SPI
    '0x40013000': {'type': 'SPI', 'name': 'SPI1', 'family': 'STM32F4'},
    '0x40003800': {'type': 'SPI', 'name': 'SPI2', 'family': 'STM32F4'},
    '0x40003C00': {'type': 'SPI', 'name': 'SPI3', 'family': 'STM32F4'},
    '0x40013400': {'type': 'SPI', 'name': 'SPI4', 'family': 'STM32F4'},
    '0x40015000': {'type': 'SPI', 'name': 'SPI5', 'family': 'STM32F4'},
    '0x40015400': {'type': 'SPI', 'name': 'SPI6', 'family': 'STM32F4'},
    
    # I2C
    '0x40005400': {'type': 'I2C', 'name': 'I2C1', 'family': 'STM32F4'},
    '0x40005800': {'type': 'I2C', 'name': 'I2C2', 'family': 'STM32F4'},
    '0x40005C00': {'type': 'I2C', 'name': 'I2C3', 'family': 'STM32F4'},
    
    # Timers
    '0x40000000': {'type': 'TIMER', 'name': 'TIM2', 'family': 'STM32F4'},
    '0x40000400': {'type': 'TIMER', 'name': 'TIM3', 'family': 'STM32F4'},
    '0x40000800': {'type': 'TIMER', 'name': 'TIM4', 'family': 'STM32F4'},
    '0x40000C00': {'type': 'TIMER', 'name': 'TIM5', 'family': 'STM32F4'},
    '0x40001000': {'type': 'TIMER', 'name': 'TIM6', 'family': 'STM32F4'},
    '0x40001400': {'type': 'TIMER', 'name': 'TIM7', 'family': 'STM32F4'},
    '0x40010000': {'type': 'TIMER', 'name': 'TIM1', 'family': 'STM32F4'},
    '0x40010400': {'type': 'TIMER', 'name': 'TIM8', 'family': 'STM32F4'},
    '0x40014000': {'type': 'TIMER', 'name': 'TIM9', 'family': 'STM32F4'},
    '0x40014400': {'type': 'TIMER', 'name': 'TIM10', 'family': 'STM32F4'},
    '0x40014800': {'type': 'TIMER', 'name': 'TIM11', 'family': 'STM32F4'},
    
    # ADC
    '0x40012000': {'type': 'ADC', 'name': 'ADC1', 'family': 'STM32F4'},
    '0x40012100': {'type': 'ADC', 'name': 'ADC2', 'family': 'STM32F4'},
    '0x40012200': {'type': 'ADC', 'name': 'ADC3', 'family': 'STM32F4'},
    '0x40012300': {'type': 'ADC', 'name': 'ADC_Common', 'family': 'STM32F4'},
    
    # DMA
    '0x40026000': {'type': 'DMA', 'name': 'DMA1', 'family': 'STM32F4'},
    '0x40026400': {'type': 'DMA', 'name': 'DMA2', 'family': 'STM32F4'},
    
    # PWR
    '0x40007000': {'type': 'PWR', 'name': 'PWR', 'family': 'STM32F4'},
    
    # FLASH
    '0x40023C00': {'type': 'FLASH', 'name': 'FLASH', 'family': 'STM32F4'},
    
    # SYSCFG
    '0x40013800': {'type': 'SYSCFG', 'name': 'SYSCFG', 'family': 'STM32F4'},
    
    # EXTI
    '0x40013C00': {'type': 'EXTI', 'name': 'EXTI', 'family': 'STM32F4'},
    
    # CAN
    '0x40006400': {'type': 'CAN', 'name': 'CAN1', 'family': 'STM32F4'},
    '0x40006800': {'type': 'CAN', 'name': 'CAN2', 'family': 'STM32F4'},
}

# STM32F1系列（完整）
STM32F1_PERIPHERALS = {
    # RCC
    '0x40021000': {'type': 'RCC', 'name': 'RCC', 'family': 'STM32F1'},
    
    # GPIO (注意：F1和F4的GPIO地址不同)
    '0x40010800': {'type': 'GPIO', 'name': 'GPIOA', 'family': 'STM32F1'},
    '0x40010C00': {'type': 'GPIO', 'name': 'GPIOB', 'family': 'STM32F1'},
    '0x40011000': {'type': 'GPIO', 'name': 'GPIOC', 'family': 'STM32F1'},
    '0x40011400': {'type': 'GPIO', 'name': 'GPIOD', 'family': 'STM32F1'},
    '0x40011800': {'type': 'GPIO', 'name': 'GPIOE', 'family': 'STM32F1'},
    
    # USART/UART
    '0x40013800': {'type': 'UART', 'name': 'USART1', 'family': 'STM32F1'},
    '0x40004400': {'type': 'UART', 'name': 'USART2', 'family': 'STM32F1'},
    '0x40004800': {'type': 'UART', 'name': 'USART3', 'family': 'STM32F1'},
    
    # Timers
    '0x40012C00': {'type': 'TIMER', 'name': 'TIM1', 'family': 'STM32F1'},
    '0x40000000': {'type': 'TIMER', 'name': 'TIM2', 'family': 'STM32F1'},
    '0x40000400': {'type': 'TIMER', 'name': 'TIM3', 'family': 'STM32F1'},
    '0x40000800': {'type': 'TIMER', 'name': 'TIM4', 'family': 'STM32F1'},
    
    # Flash
    '0x40022000': {'type': 'FLASH', 'name': 'FLASH', 'family': 'STM32F1'},
}

# STM32F0系列（Cortex-M0）
STM32F0_PERIPHERALS = {
    '0x40021000': {'type': 'RCC', 'name': 'RCC', 'family': 'STM32F0'},
    '0x48000000': {'type': 'GPIO', 'name': 'GPIOA', 'family': 'STM32F0'},
    '0x48000400': {'type': 'GPIO', 'name': 'GPIOB', 'family': 'STM32F0'},
    '0x48000800': {'type': 'GPIO', 'name': 'GPIOC', 'family': 'STM32F0'},
    '0x40013800': {'type': 'UART', 'name': 'USART1', 'family': 'STM32F0'},
}

# STM32L4系列（低功耗）
STM32L4_PERIPHERALS = {
    '0x40021000': {'type': 'RCC', 'name': 'RCC', 'family': 'STM32L4'},
    '0x48000000': {'type': 'GPIO', 'name': 'GPIOA', 'family': 'STM32L4'},
    '0x48000400': {'type': 'GPIO', 'name': 'GPIOB', 'family': 'STM32L4'},
    '0x40013800': {'type': 'UART', 'name': 'USART1', 'family': 'STM32L4'},
}

# NXP LPC系列（常见于P2IM固件）
LPC_PERIPHERALS = {
    '0x400FC000': {'type': 'RCC', 'name': 'SYSCON', 'family': 'LPC'},
    '0x40028000': {'type': 'GPIO', 'name': 'GPIO0', 'family': 'LPC'},
    '0x4000C000': {'type': 'UART', 'name': 'UART0', 'family': 'LPC'},
}

# 通用外设地址检测（用于未知MCU）
# 基于常见的外设地址模式
GENERIC_PATTERNS = {
    # APB1总线（通常0x4000xxxx）
    'apb1_uart_range': (0x40000000, 0x40008000, 'UART'),
    'apb1_timer_range': (0x40000000, 0x40002000, 'TIMER'),
    
    # APB2总线（通常0x4001xxxx）
    'apb2_uart_range': (0x40010000, 0x40018000, 'UART'),
    'apb2_gpio_range': (0x40010000, 0x40018000, 'GPIO'),
    
    # AHB1总线（通常0x4002xxxx）
    'ahb1_gpio_range': (0x40020000, 0x40023000, 'GPIO'),
    'ahb1_rcc_range': (0x40023000, 0x40024000, 'RCC'),
    'ahb1_dma_range': (0x40026000, 0x40028000, 'DMA'),
}

# SAM3X系列完整外设映射 (Arduino Due使用的MCU)
SAM3X_COMPLETE_PERIPHERALS = {
    # System Controller
    '0x400e0400': {'type': 'PMC', 'name': 'PMC', 'family': 'SAM3X'},  # Power Management Controller
    '0x400e0600': {'type': 'UART', 'name': 'UART', 'family': 'SAM3X'},
    '0x400e0800': {'type': 'SMC', 'name': 'SMC', 'family': 'SAM3X'},  # Static Memory Controller
    '0x400e0a00': {'type': 'GPIO', 'name': 'PIOA', 'family': 'SAM3X'},  # Parallel I/O Controller A
    '0x400e0c00': {'type': 'GPIO', 'name': 'PIOB', 'family': 'SAM3X'},  # Parallel I/O Controller B
    '0x400e0e00': {'type': 'GPIO', 'name': 'PIOC', 'family': 'SAM3X'},  # Parallel I/O Controller C
    '0x400e1000': {'type': 'GPIO', 'name': 'PIOD', 'family': 'SAM3X'},  # Parallel I/O Controller D
    '0x400e1200': {'type': 'GPIO', 'name': 'PIOE', 'family': 'SAM3X'},  # Parallel I/O Controller E
    '0x400e1400': {'type': 'GPIO', 'name': 'PIOF', 'family': 'SAM3X'},  # Parallel I/O Controller F
    
    # USART
    '0x40098000': {'type': 'UART', 'name': 'USART0', 'family': 'SAM3X'},
    '0x4009c000': {'type': 'UART', 'name': 'USART1', 'family': 'SAM3X'},
    '0x400a0000': {'type': 'UART', 'name': 'USART2', 'family': 'SAM3X'},
    '0x400a4000': {'type': 'UART', 'name': 'USART3', 'family': 'SAM3X'},
    
    # TWI (I2C)
    '0x4008c000': {'type': 'I2C', 'name': 'TWI0', 'family': 'SAM3X'},
    '0x40090000': {'type': 'I2C', 'name': 'TWI1', 'family': 'SAM3X'},
    
    # SPI
    '0x40088000': {'type': 'SPI', 'name': 'SPI0', 'family': 'SAM3X'},
    
    # SSC (Synchronous Serial Controller) - 这是导致问题的外设！
    '0x40004000': {'type': 'SSC', 'name': 'SSC', 'family': 'SAM3X'},
    
    # TC (Timer Counter)
    '0x40080000': {'type': 'TIMER', 'name': 'TC0', 'family': 'SAM3X'},
    '0x40080040': {'type': 'TIMER', 'name': 'TC1', 'family': 'SAM3X'},
    '0x40080080': {'type': 'TIMER', 'name': 'TC2', 'family': 'SAM3X'},
    '0x40084000': {'type': 'TIMER', 'name': 'TC3', 'family': 'SAM3X'},
    '0x40084040': {'type': 'TIMER', 'name': 'TC4', 'family': 'SAM3X'},
    '0x40084080': {'type': 'TIMER', 'name': 'TC5', 'family': 'SAM3X'},
    '0x40088040': {'type': 'TIMER', 'name': 'TC7', 'family': 'SAM3X'},
    '0x40088080': {'type': 'TIMER', 'name': 'TC8', 'family': 'SAM3X'},
    
    # PWM
    '0x40094000': {'type': 'PWM', 'name': 'PWM', 'family': 'SAM3X'},
    
    # ADC (注意：与TC3共享地址空间，但ADC在0x40084000-0x400840FF范围)
    '0x400c8000': {'type': 'ADC', 'name': 'ADC', 'family': 'SAM3X'},  # 12-bit ADC
    
    # DACC
    '0x400b8000': {'type': 'DAC', 'name': 'DACC', 'family': 'SAM3X'},  # DAC Controller
    
    # DMAC
    '0x400c0000': {'type': 'DMA', 'name': 'DMAC', 'family': 'SAM3X'},  # DMA Controller
    
    # CAN
    '0x400b4000': {'type': 'CAN', 'name': 'CAN0', 'family': 'SAM3X'},
    '0x400b8000': {'type': 'CAN', 'name': 'CAN1', 'family': 'SAM3X'},
    
    # EMAC
    '0x400b0000': {'type': 'EMAC', 'name': 'EMAC', 'family': 'SAM3X'},  # Ethernet MAC
    
    # HSMCI
    '0x40000000': {'type': 'HSMCI', 'name': 'HSMCI', 'family': 'SAM3X'},  # High Speed Multimedia Card Interface
    
    # TRNG
    '0x400bc000': {'type': 'TRNG', 'name': 'TRNG', 'family': 'SAM3X'},  # True Random Number Generator
    
    # RTC
    '0x400e1a60': {'type': 'RTC', 'name': 'RTC', 'family': 'SAM3X'},
    '0x400e1a30': {'type': 'RTT', 'name': 'RTT', 'family': 'SAM3X'},  # Real-time Timer
    
    # WDT
    '0x400e1a50': {'type': 'WDT', 'name': 'WDT', 'family': 'SAM3X'},  # Watchdog Timer
    
    # EFC (Embedded Flash Controller)
    '0x400e0a00': {'type': 'FLASH', 'name': 'EFC0', 'family': 'SAM3X'},
    '0x400e0c00': {'type': 'FLASH', 'name': 'EFC1', 'family': 'SAM3X'},
    
    # RSTC
    '0x400e1a00': {'type': 'RSTC', 'name': 'RSTC', 'family': 'SAM3X'},  # Reset Controller
    
    # SUPC
    '0x400e1a10': {'type': 'SUPC', 'name': 'SUPC', 'family': 'SAM3X'},  # Supply Controller
    
    # UOTGHS
    '0x400ac000': {'type': 'USB', 'name': 'UOTGHS', 'family': 'SAM3X'},  # USB OTG High Speed
}

# 合并所有数据库（注意：优先级 STM32F4 > F1 > 其他）
# STM32F4是最常见的，所以优先
ALL_PERIPHERALS = {}
ALL_PERIPHERALS.update(STM32L4_PERIPHERALS)  # 最低优先级
ALL_PERIPHERALS.update(STM32F0_PERIPHERALS)
ALL_PERIPHERALS.update(LPC_PERIPHERALS)
ALL_PERIPHERALS.update(SAM3X_COMPLETE_PERIPHERALS)  # SAM3X完整映射
ALL_PERIPHERALS.update(STM32F1_PERIPHERALS)  # F1次优先
ALL_PERIPHERALS.update(STM32F4_PERIPHERALS)  # F4最高优先级（覆盖冲突地址）

def lookup_peripheral(address: str) -> dict:
    """
    根据地址查找外设信息
    
    Args:
        address: 外设基地址（如 '0x40023800' 或 '0x40023000'）
    
    Returns:
        外设信息字典，如果未找到返回None
    
    增强功能：
    - 精确匹配：优先查找完全匹配的地址
    - 范围匹配：如果精确匹配失败，尝试在外设地址范围内匹配
      例如：0x40023000 可以匹配到 0x40023800 (RCC)
    """
    # 规范化地址格式（转为小写，统一0x前缀）
    addr = address.lower()
    if not addr.startswith('0x'):
        addr = '0x' + addr
    
    # 数据库中的地址也统一转为小写进行比较
    addr_normalized = addr.upper().replace('X', 'x')  # 0x40023800
    
    # 1. 直接查找（精确匹配）
    if addr_normalized in ALL_PERIPHERALS:
        return ALL_PERIPHERALS[addr_normalized]
    
    # 2. 尝试不同的格式
    for db_addr, info in ALL_PERIPHERALS.items():
        if db_addr.lower() == addr.lower():
            return info
    
    # 3. ⭐ 范围匹配：检查地址是否在已知外设的范围内
    #    例如：0x40023000 应该匹配到 RCC (0x40023800)
    #    因为它们在同一个4KB块内 (0x40023000-0x40023FFF)
    try:
        query_addr = int(addr, 16)
        
        # 定义常见外设的大小（用于范围匹配）
        TYPICAL_PERIPH_SIZE = 0x1000  # 4KB，大多数外设的标准大小
        
        for db_addr_str, info in ALL_PERIPHERALS.items():
            db_addr = int(db_addr_str, 16)
            
            # 检查是否在同一个4KB块内
            # 例如：0x40023000 和 0x40023800 都在 0x40023000-0x40023FFF 范围内
            query_block = query_addr & ~(TYPICAL_PERIPH_SIZE - 1)  # 对齐到4KB边界
            db_block = db_addr & ~(TYPICAL_PERIPH_SIZE - 1)
            
            if query_block == db_block:
                # 在同一个块内，认为是同一个外设
                return info
        
    except (ValueError, AttributeError):
        pass
    
    return None

def identify_peripheral_type(address: str) -> str:
    """
    识别外设类型
    
    Args:
        address: 外设基地址
    
    Returns:
        外设类型字符串，如果未知返回'UNKNOWN'
    """
    info = lookup_peripheral(address)
    return info['type'] if info else 'UNKNOWN'

def get_peripheral_family(address: str) -> str:
    """
    获取外设所属芯片系列
    
    Args:
        address: 外设基地址
    
    Returns:
        芯片系列字符串，如果未知返回'UNKNOWN'
    """
    info = lookup_peripheral(address)
    return info['family'] if info else 'UNKNOWN'

def is_known_peripheral(address: str) -> bool:
    """
    检查是否为已知外设
    
    Args:
        address: 外设基地址
    
    Returns:
        True if known, False otherwise
    """
    return lookup_peripheral(address) is not None

def get_all_addresses() -> list:
    """获取所有已知外设地址列表"""
    return list(ALL_PERIPHERALS.keys())

def get_peripherals_by_type(peripheral_type: str) -> list:
    """
    根据类型获取所有外设
    
    Args:
        peripheral_type: 外设类型（如 'GPIO', 'UART'）
    
    Returns:
        外设信息列表
    """
    return [
        {'address': addr, **info}
        for addr, info in ALL_PERIPHERALS.items()
        if info['type'] == peripheral_type
    ]


def guess_peripheral_type_by_address(address: str) -> Optional[str]:
    """
    根据地址模式猜测外设类型（用于未知外设）
    
    Args:
        address: 外设地址
    
    Returns:
        猜测的外设类型，如果无法猜测返回None
    """
    try:
        addr = int(address.replace('0x', '').replace('0X', ''), 16)
    except:
        return None
    
    # 检查是否匹配通用模式
    for pattern_name, (start, end, ptype) in GENERIC_PATTERNS.items():
        if start <= addr < end:
            # 进一步细化判断
            if ptype == 'GPIO':
                # GPIO通常每个端口间隔0x400
                if (addr - start) % 0x400 == 0:
                    return 'GPIO'
            elif ptype == 'UART':
                # UART通常每个间隔0x400或0x1000
                return 'UART'
            elif ptype == 'RCC':
                return 'RCC'
            elif ptype == 'DMA':
                return 'DMA'
            elif ptype == 'TIMER':
                # Timer通常每个间隔0x400
                if (addr - start) % 0x400 == 0:
                    return 'TIMER'
    
    return None


def get_peripheral_info_enhanced(address: str) -> Dict:
    """
    增强的外设信息获取（优先查库，其次推断）
    
    Args:
        address: 外设地址
    
    Returns:
        外设信息字典
    """
    # 先查已知数据库
    info = lookup_peripheral(address)
    if info:
        return {'address': address, **info, 'source': 'database'}
    
    # 尝试推断
    guessed_type = guess_peripheral_type_by_address(address)
    if guessed_type:
        return {
            'address': address,
            'type': guessed_type,
            'name': f'{guessed_type}_{address[-4:]}',
            'family': 'UNKNOWN',
            'source': 'inference'
        }
    
    # 无法识别
    return {
        'address': address,
        'type': 'UNKNOWN',
        'name': f'PERIPHERAL_{address[-8:]}',
        'family': 'UNKNOWN',
        'source': 'unknown'
    }

# 示例用法
if __name__ == '__main__':
    # 测试
    test_addresses = ['0x40023800', '0x40020000', '0x40011000', '0x99999999']
    
    for addr in test_addresses:
        info = lookup_peripheral(addr)
        if info:
            print(f"{addr}: {info['name']} ({info['type']}) - {info['family']}")
        else:
            print(f"{addr}: Unknown peripheral")
    
    print(f"\n总计已知外设: {len(ALL_PERIPHERALS)} 个")
    print(f"GPIO数量: {len(get_peripherals_by_type('GPIO'))}")
    print(f"UART数量: {len(get_peripherals_by_type('UART'))}")

