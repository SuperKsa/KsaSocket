# cython: language_level=3

import logging


class logger_color_format(logging.Formatter):
    COLORS = {
        'DEBUG': '\033[1;37m',  # 白色
        'INFO': '\033[1;32m',  # 绿色
        'WARNING': '\033[1;33m',  # 黄色
        'ERROR': '\033[1;31m',  # 红色
        'CRITICAL': '\033[1;41;37m',  # 红底白字（用于严重错误）
        'RESET': '\033[0m'  # 重置为默认颜色
    }

    def format(self, record):
        log_message = super().format(record)
        color = self.COLORS.get(record.levelname, self.COLORS['RESET'])
        return f"{color}{log_message}{self.COLORS['RESET']}"


def KsaLogger(mark:str='Ksa', level:int=logging.DEBUG):
    # 创建一个控制台处理器，将日志输出到控制台
    console_handler = logging.StreamHandler()

    # 将格式化器添加到处理器
    console_handler.setFormatter(logger_color_format('[%(asctime)s] [%(name)s - %(levelname)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S'))

    # 获取根记录器（root logger）并将控制台处理器添加到根记录器
    logger = logging.getLogger(mark)
    logger.addHandler(console_handler)

    # 设置日志级别
    logger.setLevel(logging.DEBUG)

    return logger