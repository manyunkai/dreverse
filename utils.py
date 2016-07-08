# -*-coding:utf-8 -*-
"""
Created on 2016-7-5

@author: Danny
DannyWork Project
"""

import time
import socket
import threading
import string
import random
import re
import platform
import logging
from hashlib import md5

from crypto import Crypto


# 连接测试请求数据

PING_SENDING_START = '---PING REQ START---'
PING_SENDING_DATA = '---PING REQ START---{0}---PING REQ END---'
PING_SENDING_PATTERN = '---PING REQ START---(\w+)---PING REQ END---'
# 连接测试回发数据
PING_RES_DATA = '---PING RES START---{0}---PING RES END---'
PING_RES_PATTERN = '---PING RES START---(\w+)---PING RES END---'
# 连接测试完成数据
PING_FINISH_PATTERN = '---PING FINISH START---(\w+)---PING FINISH END---'

# 数据传送
TRANSFER_PREPARE = '---TRANSFER PREPARE---'
TRANSFER_READY = '---TRANSFER READY---'
TRANSFER_START = '---TRANSFER START---'
TRANSFER_END = '---TRANSFER END---'
TRANSFER_PACK_DATA = '---TRANSFER START---{0}---TRANSFER END---'
TRANSFER_UNPACK_PATTERN = '---TRANSFER START---(.*)---TRANSFER END---'


ALLOWED_WORDS = string.ascii_letters + string.digits


def get_random_string(length=16):
    """
    获取随机字符串，包含 a-zA-z0-9

    :param length: 随机字符串长度
    :return: 得到的随机字符串
    """

    words = ALLOWED_WORDS * (length // 16 + 2)
    return ''.join(random.sample(words, length))


def get_random_md5():
    """
    返回随机生成的 32 位长度的 md5 字符串

    :return: str
    """

    random_str = ''.join([get_random_string(32), str(time.time())])
    return md5(random_str.encode('utf8')).hexdigest()


def get_python_version():
    """
    获取 Python 版本，返回 2 或者 3

    :return: str, 2 or 3
    """

    return platform.python_version().split('.')[0]


def generate_ping_data(encrypt_key=''):
    """
    生成 ping 数据

    :return: (plain_text, ping_data)
    """

    hello = get_random_md5()
    raw = PING_SENDING_DATA.format(Crypto(encrypt_key).encrypt(hello) if encrypt_key else hello).encode('utf8')
    return hello, raw


def parse_ping_data(data, encrypt_key=''):
    """
    解析 ping 数据

    :return: plain_text
    """

    if isinstance(data, bytes):
        data = data.decode('utf8')

    try:
        data = re.match(PING_SENDING_PATTERN, data).groups()[0]
    except (AttributeError, IndexError):
        data = None
    else:
        if encrypt_key:
            data = Crypto(encrypt_key).decrypt(data).decode()

    return data


def reply_ping_data(data):
    """
    回发 ping 数据

    :param data: plain_text
    :return: None
    """

    return PING_SENDING_DATA.format(data).encode('utf8')


def close_socket(sock):
    """
    关闭 socket 连接

    :param sock: socket Instance
    :return: None
    """

    try:
        sock.shutdown(socket.SHUT_RDWR)
        sock.close()
    except:
        pass


def ping_socket(sock, encrypt_key=''):
    """
    Socket 连接状态测试

    :param sock: socket instance.
    :param encrypt_key: 加密 key
    :return: True or False
    """

    hello, raw = generate_ping_data(encrypt_key)
    hello_back = ''

    try:
        sock.settimeout(3)
        sock.sendall(raw)
        hello_back = parse_ping_data(sock.recv(1024))
    except Exception as e:
        logger = logging.getLogger('Socket Pinger')
        logger.warning('Ping Error: {0}'.format(e))
    finally:
        sock.settimeout(socket.getdefaulttimeout())

    return hello == hello_back


def remove_item_from_deque(deque, item):
    """
    从 list 中删除元素

    :param deque: list object.
    :param item: item to be removed.
    :return: None
    """

    try:
        deque.remove(item)
    except ValueError:
        pass


def pack_data(data, encrypt_key=''):
    """
    封装数据包

    :param data: 原始数据
    :param encrypt_key: 加密 key
    :return: 封装后的数据
    """

    if encrypt_key:
        data = Crypto(encrypt_key).encrypt(data)

    return TRANSFER_PACK_DATA.format(data).encode('utf8')


def unpack_data(data, encrypt_key=''):
    """
    解析数据包

    :param data: 原始数据
    :param encrypt_key: 加密 key
    :return: 解析后的数据
    """

    if isinstance(data, bytes):
        data = data.decode('utf8')

    try:
        data = re.match(TRANSFER_UNPACK_PATTERN, data).groups()[0]
    except IndexError:
        raise ValueError('Unpack received data error.')

    if encrypt_key:
        data = Crypto(encrypt_key).decrypt(data)

    return data


class DataTransfer(threading.Thread):
    """
    数据传输线程
    """

    def __init__(self, sock_from, sock_to, secret='', direction='e2i'):
        super(DataTransfer, self).__init__()

        self.sock_from = sock_from
        self.sock_to = sock_to
        self.secret = secret

        self.direction = direction

        self.logger = logging.getLogger('Data Transferor')

    def get_data_from_external(self):
        """
        获取外部到内部的数据包
        从外部到内部的数据包需进行解包处理

        :return: 解析后的数据
        """

        transfer_start = TRANSFER_START.encode('utf8')
        transfer_end = TRANSFER_END.encode('utf8')

        raw = b'' if get_python_version() == '3' else ''
        data = b'' if get_python_version() == '3' else ''
        while True:
            frag = self.sock_from.recv(65536)
            if not raw and frag and not frag.startswith(transfer_start):
                raise ValueError('Bad data.')

            raw += frag

            raw_splited = raw.split(transfer_end)
            if len(raw_splited) > 1:
                for part in raw_splited[:-1]:
                    part += transfer_end
                    data += unpack_data(part, self.secret)
                raw = raw_splited[-1]

            if not raw:
                break
            elif raw.endswith(transfer_end):
                data += unpack_data(raw, self.secret)
                break
        return data

    def get_data_from_internal(self):
        """
        获取内部到外部的数据包

        :return: 解析后的数据
        """

        buff = self.sock_from.recv(65536)
        return buff

    def send_data(self, data):
        """
        发送数据

        :param data:
        :return:
        """

        self.sock_to.sendall(data)

    def run(self):
        count = 20
        try:
            while count:
                data = self.get_data_from_external() if self.direction == 'e2i' else self.get_data_from_internal()
                if self.direction == 'i2e':
                    # 如果是发送到远程主机的数据，则需进行封包处理
                    data = pack_data(data, self.secret)
                if get_python_version() == '3' and type(data) == str:
                    data = data.encode('utf8')
                self.send_data(data)
                if not data:
                    count -= 1
        except Exception as e:
            self.logger.warning('Exception: {0}, socket closed.'.format(e))
        else:
            self.logger.warning('Exception: Timeout, socket closed.')
        finally:
            close_socket(self.sock_from)
            close_socket(self.sock_to)


def start_data_transfer(internal_socket, external_socket, secret=''):
    """
    启动双向数据传输

    :param internal_socket: 本机 socket 对象
    :param external_socket: 远程 socket 对象
    :return: (l2r DataTransfer Thread Instance, r2l DataTransfer Thread Instance)
    """

    l2r = DataTransfer(internal_socket, external_socket, secret, 'i2e')
    l2r.start()

    r2l = DataTransfer(external_socket, internal_socket, secret, 'e2i')
    r2l.start()

    return l2r, r2l
