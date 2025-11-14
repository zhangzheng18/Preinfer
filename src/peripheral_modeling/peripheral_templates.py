#!/usr/bin/env python3
"""
外设行为模板 - 为已知外设类型提供通用行为配置

这些模板定义了常见外设的典型行为，用于增强自动生成的外设模型
"""

from typing import Dict, List, Optional


# GPIO通用模板
GPIO_TEMPLATE = {
    'registers': {
        '0x00': {  # MODER - Mode register
            'name': 'MODER',
            'type': 'control',
            'access': 'rw',
            'description': 'GPIO port mode register',
            'reset_value': 0x00000000
        },
        '0x04': {  # OTYPER - Output type register
            'name': 'OTYPER',
            'type': 'control',
            'access': 'rw',
            'description': 'GPIO port output type register',
            'reset_value': 0x00000000
        },
        '0x08': {  # OSPEEDR - Output speed register
            'name': 'OSPEEDR',
            'type': 'control',
            'access': 'rw',
            'description': 'GPIO port output speed register',
            'reset_value': 0x00000000
        },
        '0x0C': {  # PUPDR - Pull-up/pull-down register
            'name': 'PUPDR',
            'type': 'control',
            'access': 'rw',
            'description': 'GPIO port pull-up/pull-down register',
            'reset_value': 0x00000000
        },
        '0x10': {  # IDR - Input data register
            'name': 'IDR',
            'type': 'status',
            'access': 'ro',
            'description': 'GPIO port input data register',
            'reset_value': 0x00000000,
            'volatile': True,
            # ✅ 关键：IDR需要返回模拟的输入值（避免轮询卡死）
            'default_read_value': 0x0000FFFF  # 假设所有引脚为高电平
        },
        '0x14': {  # ODR - Output data register
            'name': 'ODR',
            'type': 'control',
            'access': 'rw',
            'description': 'GPIO port output data register',
            'reset_value': 0x00000000
        },
        '0x18': {  # BSRR - Bit set/reset register
            'name': 'BSRR',
            'type': 'control',
            'access': 'wo',
            'description': 'GPIO port bit set/reset register'
        },
        '0x1C': {  # LCKR - Configuration lock register
            'name': 'LCKR',
            'type': 'control',
            'access': 'rw',
            'description': 'GPIO port configuration lock register',
            'reset_value': 0x00000000
        },
        '0x20': {  # AFRL - Alternate function low register
            'name': 'AFRL',
            'type': 'control',
            'access': 'rw',
            'description': 'GPIO alternate function low register',
            'reset_value': 0x00000000
        },
        '0x24': {  # AFRH - Alternate function high register
            'name': 'AFRH',
            'type': 'control',
            'access': 'rw',
            'description': 'GPIO alternate function high register',
            'reset_value': 0x00000000
        }
    }
}

# UART/USART通用模板
UART_TEMPLATE = {
    'registers': {
        '0x00': {  # SR - Status register
            'name': 'SR',
            'type': 'status',
            'access': 'rw',
            'description': 'Status register',
            'reset_value': 0x000000C0,  # TXE and TC bits set
            'status_bits': [5, 6, 7],  # RXNE, TC, TXE
            # ✅ TXE(bit7)和TC(bit6)应该始终为1（发送缓冲区空）
            'default_read_value': 0x000000C0
        },
        '0x04': {  # DR - Data register
            'name': 'DR',
            'type': 'data',
            'access': 'rw',
            'description': 'Data register',
            'reset_value': 0x00000000
        },
        '0x08': {  # BRR - Baud rate register
            'name': 'BRR',
            'type': 'config',
            'access': 'rw',
            'description': 'Baud rate register',
            'reset_value': 0x00000000
        },
        '0x0C': {  # CR1 - Control register 1
            'name': 'CR1',
            'type': 'control',
            'access': 'rw',
            'description': 'Control register 1',
            'reset_value': 0x00000000,
            'control_bits': [13, 3, 2]  # UE, TE, RE
        },
        '0x10': {  # CR2 - Control register 2
            'name': 'CR2',
            'type': 'control',
            'access': 'rw',
            'description': 'Control register 2',
            'reset_value': 0x00000000
        },
        '0x14': {  # CR3 - Control register 3
            'name': 'CR3',
            'type': 'control',
            'access': 'rw',
            'description': 'Control register 3',
            'reset_value': 0x00000000
        },
        '0x18': {  # GTPR - Guard time and prescaler register
            'name': 'GTPR',
            'type': 'config',
            'access': 'rw',
            'description': 'Guard time and prescaler register',
            'reset_value': 0x00000000
        }
    },
    'behaviors': {
        'auto_tx_ready': True,  # 自动设置TXE/TC为ready
        'echo_rx_data': False,  # 是否回显接收数据
        'support_irq': True,
        # ✅ 新增：TX缓冲区模拟
        'tx_buffer_enabled': True,
        'tx_buffer_size': 1,  # 1字节缓冲区（硬件FIFO）
        'tx_immediate_ready': True,  # 写入后立即就绪
        # ✅ 串口输出支持
        'enable_stdout': True,  # 输出到标准输出
        'output_prefix': '[UART] ',  # 输出前缀
        # ✅ 状态位自动管理
        'auto_set_txe': True,   # 写DR后自动设置TXE（发送寄存器空）
        'auto_set_tc': True,    # 传输完成后自动设置TC（传输完成）
        'rxne_always_clear': True  # RXNE始终清零（无接收数据）
    }
}

# RCC通用模板
RCC_TEMPLATE = {
    'registers': {
        '0x00': {  # CR - Clock control register
            'name': 'CR',
            'type': 'control',
            'access': 'rw',
            'description': 'Clock control register',
            'reset_value': 0x00000083,
            # ✅ 关键：控制位→状态位映射
            'control_status_pairs': [
                {'control_bit': 0, 'status_bit': 1, 'name': 'HSI'},    # HSION → HSIRDY
                {'control_bit': 16, 'status_bit': 17, 'name': 'HSE'},  # HSEON → HSERDY
                {'control_bit': 24, 'status_bit': 25, 'name': 'PLL'},  # PLLON → PLLRDY
                {'control_bit': 26, 'status_bit': 27, 'name': 'PLLI2S'} # PLLI2SON → PLLI2SRDY
            ]
        },
        '0x04': {  # PLLCFGR - PLL configuration register
            'name': 'PLLCFGR',
            'type': 'config',
            'access': 'rw',
            'description': 'PLL configuration register',
            'reset_value': 0x24003010
        },
        '0x08': {  # CFGR - Clock configuration register
            'name': 'CFGR',
            'type': 'control',
            'access': 'rw',
            'description': 'Clock configuration register',
            'reset_value': 0x00000000,
            # ✅ SWS（系统时钟切换状态）应该等于SW（系统时钟选择）
            'mirror_bits': {'source': [0, 1], 'target': [2, 3]}  # SW → SWS
        },
        '0x0C': {  # CIR - Clock interrupt register
            'name': 'CIR',
            'type': 'control',
            'access': 'rw',
            'description': 'Clock interrupt register',
            'reset_value': 0x00000000
        },
        '0x30': {  # AHB1ENR - AHB1 peripheral clock enable
            'name': 'AHB1ENR',
            'type': 'control',
            'access': 'rw',
            'description': 'AHB1 peripheral clock enable register',
            'reset_value': 0x00100000
        },
        '0x40': {  # APB1ENR - APB1 peripheral clock enable
            'name': 'APB1ENR',
            'type': 'control',
            'access': 'rw',
            'description': 'APB1 peripheral clock enable register',
            'reset_value': 0x00000000
        },
        '0x44': {  # APB2ENR - APB2 peripheral clock enable
            'name': 'APB2ENR',
            'type': 'control',
            'access': 'rw',
            'description': 'APB2 peripheral clock enable register',
            'reset_value': 0x00000000
        }
    },
    'behaviors': {
        'auto_ready': True,  # 时钟自动就绪（立即响应）
        'mirror_switch_status': True  # 自动镜像SW到SWS
    }
}

# Flash控制器模板
FLASH_TEMPLATE = {
    'registers': {
        '0x00': {  # ACR - Access control register
            'name': 'ACR',
            'type': 'control',
            'access': 'rw',
            'description': 'Flash access control register',
            'reset_value': 0x00000000
        },
        '0x04': {  # KEYR - Key register
            'name': 'KEYR',
            'type': 'control',
            'access': 'wo',
            'description': 'Flash key register'
        },
        '0x08': {  # OPTKEYR - Option key register
            'name': 'OPTKEYR',
            'type': 'control',
            'access': 'wo',
            'description': 'Flash option key register'
        },
        '0x0C': {  # SR - Status register
            'name': 'SR',
            'type': 'status',
            'access': 'rw',
            'description': 'Flash status register',
            'reset_value': 0x00000000,
            # ✅ BSY位（bit16）应该立即清零（操作完成）
            'default_read_value': 0x00000000  # BSY=0
        },
        '0x10': {  # CR - Control register
            'name': 'CR',
            'type': 'control',
            'access': 'rw',
            'description': 'Flash control register',
            'reset_value': 0x80000000
        }
    },
    'behaviors': {
        'instant_complete': True  # Flash操作立即完成
    }
}

# Timer通用模板
TIMER_TEMPLATE = {
    'registers': {
        '0x00': {  # CR1 - Control register 1
            'name': 'CR1',
            'type': 'control',
            'access': 'rw',
            'reset_value': 0x00000000
        },
        '0x10': {  # SR - Status register
            'name': 'SR',
            'type': 'status',
            'access': 'rw',
            'reset_value': 0x00000000
        },
        '0x24': {  # CNT - Counter
            'name': 'CNT',
            'type': 'data',
            'access': 'rw',
            'reset_value': 0x00000000,
            'volatile': True
        },
        '0x28': {  # PSC - Prescaler
            'name': 'PSC',
            'type': 'config',
            'access': 'rw',
            'reset_value': 0x00000000
        },
        '0x2C': {  # ARR - Auto-reload register
            'name': 'ARR',
            'type': 'config',
            'access': 'rw',
            'reset_value': 0x0000FFFF
        }
    }
}

# 所有模板映射
# PWR (Power Control) 通用模板
PWR_TEMPLATE = {
    'registers': {
        '0x00': {  # PWR_CR - Power control register
            'name': 'CR',
            'type': 'control',
            'access': 'rw',
            'description': 'PWR power control register',
            'reset_value': 0x00000000,
            # 关键位：
            # [14] VOS: Regulator voltage scaling output selection
            # [8] DBP: Disable backup domain write protection
            # [4] PVDE: Power voltage detector enable
            'control_bits': [14, 8, 4],
            'default_read_value': 0x00000000
        },
        '0x04': {  # PWR_CSR - Power control/status register
            'name': 'CSR',
            'type': 'status',
            'access': 'rw',
            'description': 'PWR power control/status register',
            'reset_value': 0x00000000,
            # 关键位：
            # [14] VOSRDY: Regulator voltage scaling output selection ready bit
            # [3] PVDO: PVD output
            'status_bits': [14, 3],
            'default_read_value': 0x00004000,  # VOSRDY=1 (立即就绪)
            'control_status_pairs': [
                {'control_reg': '0x00', 'control_bit': 14, 'status_bit': 14, 'name': 'VOS/VOSRDY'}
            ]
        }
    },
    'behaviors': {
        'immediate_ready': True,  # 所有状态位立即就绪
        'ignore_reserved_bits': True
    }
}

# SPI通用模板
SPI_TEMPLATE = {
    'registers': {
        '0x00': {  # CR1 - Control register 1
            'name': 'CR1',
            'type': 'control',
            'access': 'rw',
            'description': 'SPI control register 1',
            'reset_value': 0x00000000,
            'control_bits': [6, 2, 3]  # SPE, MSTR, SSM
        },
        '0x04': {  # CR2 - Control register 2
            'name': 'CR2',
            'type': 'control',
            'access': 'rw',
            'description': 'SPI control register 2',
            'reset_value': 0x00000000
        },
        '0x08': {  # SR - Status register
            'name': 'SR',
            'type': 'status',
            'access': 'ro',
            'description': 'SPI status register',
            'reset_value': 0x00000002,  # TXE=1
            # ✅ TXE(bit1)和RXNE(bit0)控制
            'default_read_value': 0x00000003,  # TXE=1, RXNE=1 (就绪)
            'status_bits': [0, 1, 7]  # RXNE, TXE, BSY
        },
        '0x0C': {  # DR - Data register
            'name': 'DR',
            'type': 'data',
            'access': 'rw',
            'description': 'SPI data register',
            'reset_value': 0x00000000
        }
    },
    'behaviors': {
        'auto_tx_ready': True,
        'instant_transfer': True,  # 立即完成传输
        'loopback_mode': False
    }
}

# I2C通用模板
I2C_TEMPLATE = {
    'registers': {
        '0x00': {  # CR1 - Control register 1
            'name': 'CR1',
            'type': 'control',
            'access': 'rw',
            'description': 'I2C control register 1',
            'reset_value': 0x00000000
        },
        '0x14': {  # SR1 - Status register 1
            'name': 'SR1',
            'type': 'status',
            'access': 'ro',
            'description': 'I2C status register 1',
            'reset_value': 0x00000000,
            # ✅ TXE(bit7)和BTF(bit2)就绪
            'default_read_value': 0x00000082,  # TXE=1
            'status_bits': [7, 6, 2, 1, 0]  # TXE, RXNE, BTF, ADDR, SB
        },
        '0x18': {  # SR2 - Status register 2
            'name': 'SR2',
            'type': 'status',
            'access': 'ro',
            'description': 'I2C status register 2',
            'reset_value': 0x00000000,
            'default_read_value': 0x00000000  # BUSY=0
        },
        '0x10': {  # DR - Data register
            'name': 'DR',
            'type': 'data',
            'access': 'rw',
            'description': 'I2C data register',
            'reset_value': 0x00000000
        }
    },
    'behaviors': {
        'auto_tx_ready': True,
        'instant_transfer': True
    }
}

# ADC通用模板
ADC_TEMPLATE = {
    'registers': {
        '0x00': {  # SR - Status register
            'name': 'SR',
            'type': 'status',
            'access': 'rw',
            'description': 'ADC status register',
            'reset_value': 0x00000000,
            # ✅ EOC(bit1)转换完成
            'default_read_value': 0x00000002,  # EOC=1
            'status_bits': [1, 4]  # EOC, STRT
        },
        '0x08': {  # CR2 - Control register 2
            'name': 'CR2',
            'type': 'control',
            'access': 'rw',
            'description': 'ADC control register 2',
            'reset_value': 0x00000000
        },
        '0x4C': {  # DR - Data register
            'name': 'DR',
            'type': 'data',
            'access': 'ro',
            'description': 'ADC regular data register',
            'reset_value': 0x00000000,
            'default_read_value': 0x00000800,  # 模拟值：中间值
            'volatile': True
        }
    },
    'behaviors': {
        'instant_conversion': True,  # 立即完成转换
        'fixed_value': 0x800  # 返回固定的模拟值
    }
}

# DMA通用模板
DMA_TEMPLATE = {
    'registers': {
        '0x00': {  # ISR - Interrupt status register
            'name': 'ISR',
            'type': 'status',
            'access': 'ro',
            'description': 'DMA interrupt status register',
            'reset_value': 0x00000000
        },
        '0x04': {  # IFCR - Interrupt flag clear register
            'name': 'IFCR',
            'type': 'control',
            'access': 'wo',
            'description': 'DMA interrupt flag clear register'
        }
    },
    'behaviors': {
        'instant_transfer': True  # DMA立即完成
    }
}

# ✅ 通用外设模板 (Fallback)
GENERIC_TEMPLATE = {
    'registers': {},
    'behaviors': {
        'status_ready_by_default': True,  # 状态寄存器默认就绪
        'data_register_returns_zero': False,  # 数据寄存器返回0
        'control_register_writable': True  # 控制寄存器可写
    }
}

PERIPHERAL_TEMPLATES = {
    'GPIO': GPIO_TEMPLATE,
    'UART': UART_TEMPLATE,
    'USART': UART_TEMPLATE,  # USART使用UART模板
    'RCC': RCC_TEMPLATE,
    'FLASH': FLASH_TEMPLATE,
    'TIMER': TIMER_TEMPLATE,
    'TIM': TIMER_TEMPLATE,  # TIM使用TIMER模板
    'PWR': PWR_TEMPLATE,
    'SPI': SPI_TEMPLATE,
    'I2C': I2C_TEMPLATE,
    'ADC': ADC_TEMPLATE,
    'DMA': DMA_TEMPLATE,
    'GENERIC': GENERIC_TEMPLATE,  # 通用模板
    'UNKNOWN': GENERIC_TEMPLATE   # 未知类型使用通用模板
}


def get_template_for_type(peripheral_type: str) -> Optional[Dict]:
    """
    获取外设类型对应的模板，如果未找到则返回通用模板
    
    Args:
        peripheral_type: 外设类型（如 'GPIO', 'UART'）
    
    Returns:
        模板字典，总是返回一个模板(至少是GENERIC)
    """
    # 标准化类型名称
    peripheral_type_upper = peripheral_type.upper() if peripheral_type else 'UNKNOWN'
    
    # 尝试直接匹配
    if peripheral_type_upper in PERIPHERAL_TEMPLATES:
        return PERIPHERAL_TEMPLATES[peripheral_type_upper]
    
    # 尝试模糊匹配 (例如 USART1 → USART → UART)
    for key in PERIPHERAL_TEMPLATES.keys():
        if key in peripheral_type_upper or peripheral_type_upper in key:
            return PERIPHERAL_TEMPLATES[key]
    
    # 返回通用模板作为fallback
    return GENERIC_TEMPLATE


def apply_template_to_peripheral(peripheral_data: Dict, template: Dict) -> Dict:
    """
    将模板应用到外设数据
    
    Args:
        peripheral_data: 从分析得到的外设数据
        template: 外设模板
    
    Returns:
        增强后的外设数据
    """
    # 合并寄存器信息（保留分析数据，补充模板数据）
    if 'registers' in template:
        for offset, template_reg in template['registers'].items():
            if offset not in peripheral_data.get('registers', {}):
                # 寄存器不存在，直接添加
                if 'registers' not in peripheral_data:
                    peripheral_data['registers'] = {}
                peripheral_data['registers'][offset] = template_reg
            else:
                # 寄存器存在，合并信息（保留分析数据优先）
                existing_reg = peripheral_data['registers'][offset]
                for key, value in template_reg.items():
                    if key not in existing_reg:
                        existing_reg[key] = value
    
    # 添加行为配置
    if 'behaviors' in template:
        peripheral_data['behaviors'] = peripheral_data.get('behaviors', {})
        peripheral_data['behaviors'].update(template['behaviors'])
    
    return peripheral_data


def enhance_peripheral_with_template(peripheral_data: Dict, peripheral_type: str) -> Dict:
    """
    使用模板增强外设数据
    
    Args:
        peripheral_data: 外设数据
        peripheral_type: 外设类型
    
    Returns:
        增强后的外设数据
    """
    template = get_template_for_type(peripheral_type)
    if template:
        peripheral_data = apply_template_to_peripheral(peripheral_data, template)
    
    return peripheral_data


# 示例用法
if __name__ == '__main__':
    # 测试GPIO模板
    print("GPIO模板寄存器:")
    for offset, reg in GPIO_TEMPLATE['registers'].items():
        print(f"  {offset}: {reg['name']} ({reg['type']}) - {reg.get('description', '')}")
    
    print(f"\nRCC控制位→状态位对:")
    for pair in RCC_TEMPLATE['registers']['0x00']['control_status_pairs']:
        print(f"  {pair['name']}: bit[{pair['control_bit']}] → bit[{pair['status_bit']}]")

