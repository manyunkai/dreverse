# -*-coding:utf-8 -*-
"""
Created on 2016-7-5

@author: Danny
DannyWork Project
"""

import socket
import threading
import time
import logging
import argparse

from utils import close_socket, parse_ping_data, reply_ping_data, get_python_version, start_data_transfer, \
    PING_SENDING_START, TRANSFER_PREPARE, TRANSFER_READY

if get_python_version() == '2':
    from exceptions import *


class ConnectionHold(threading.Thread):
    """
    连接保持与传输检测
    """

    socket = None
    secret = ''

    target_ip = None
    target_port = None

    socket_timeout = 120

    logger = None

    def __init__(self, socket, secret, target_ip, target_port, log_level=logging.INFO):
        super(ConnectionHold, self).__init__()

        self.socket = socket
        self.secret = secret

        self.target_ip = target_ip
        self.target_port = target_port

        self.logger = logging.getLogger('Connection Holder')
        self.logger.setLevel(log_level)

    def create_target_socket(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((self.target_ip, self.target_port))
        return sock

    def run(self):
        count = 20
        try:
            while count:
                data = self.socket.recv(1024)
                if not data:
                    count -= 1
                    continue

                if data.startswith(PING_SENDING_START.encode('utf8')):
                    # 解密 ping 数据
                    plain = parse_ping_data(data, self.secret)
                    # 将解密后的 ping 数据回发
                    self.socket.sendall(reply_ping_data(plain))
                    self.logger.debug('Received ping at {0}.'.format(self.socket))
                elif data.startswith(TRANSFER_PREPARE.encode('utf8')):
                    local_sock = self.create_target_socket()
                    self.socket.sendall(TRANSFER_READY.encode('utf8'))
                    tl, tr = start_data_transfer(local_sock, self.socket, self.secret)
                    self.logger.info('Ready to transfer data between {0} and {1}.'.format(self.socket, local_sock))
                    # tl.join()
                    break
                else:
                    # 接收到无效数据，关闭 socket
                    self.logger.warning('Invalid data received in {0}, closed.'.format(self.socket))
                    break
        except Exception as e:
            self.logger.warning('Error in ConnectionHold[{0}]: {1}, closed.'.format(self, e))
            close_socket(self.socket)
        self.logger.info('ConnectionHold thread for {0} quit.'.format(self.socket))


class RemoteConnect(threading.Thread):
    """
    控制并保持与远程端口的连接
    实例化时，需传入 pool 参数，为 deque object，请注意 deque 的 maxlen 决定所维护的最大连接数
    """

    # 连接配置
    ip = None
    port = None

    # 本地目标配置
    target_ip = None
    target_port = None

    # 默认维护的最大连接数
    default_max_connections = 5

    # 连接保持与传输检测线程
    holding_threads = None

    secret = ''

    log_level = None
    logger = None

    def __init__(self, ip, port, target_ip, target_port, secret='', max_connections=None, log_level=logging.INFO):
        super(RemoteConnect, self).__init__()

        self.ip = ip
        self.port = port
        self.target_ip = target_ip
        self.target_port = target_port
        self.default_max_connections = max_connections or self.default_max_connections
        self.holding_threads = []
        self.secret = secret

        self.log_level = log_level
        self.logger = logging.getLogger('Remote Connector')
        self.logger.setLevel(log_level)

    def create_new_socket(self):
        new_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        new_sock.settimeout(1)
        try:
            new_sock.connect((self.ip, self.port))
            # “握手”过程
            # 接受并解密 ping 数据
            plain = parse_ping_data(new_sock.recv(1024), self.secret)
            if not plain:
                raise ConnectionError('No data received, closed.')
            # 将解密后的 ping 数据回发
            new_sock.sendall(reply_ping_data(plain))
            plain = parse_ping_data(new_sock.recv(1024))
        except Exception as e:
            self.logger.warning('Socket create error: {0}'.format(e))
        else:
            if plain == 'READY':
                new_sock.settimeout(socket.getdefaulttimeout())
                return new_sock
            self.logger.warning('No reply in {0}, give up.'.format(new_sock))

    def start_holding_thread(self, socket):
        holding_thread = ConnectionHold(socket, self.secret, self.target_ip, self.target_port, log_level=self.log_level)
        holding_thread.start()
        return holding_thread

    def run(self):
        while True:
            # 连接保持与传输检测线程状态测试与重启
            for thread in self.holding_threads:
                if not thread.is_alive():
                    self.holding_threads.remove(thread)

            # 连接管理
            if len(self.holding_threads) < self.default_max_connections:
                new_sock = self.create_new_socket()
                if new_sock:
                    self.logger.info('Connection ready in {0}.'.format(new_sock))
                    self.holding_threads.append(self.start_holding_thread(new_sock))
                    continue

            time.sleep(5)


if __name__ == '__main__':
    # 参数解析
    parser = argparse.ArgumentParser()
    parser.add_argument('-l', '--local',
                        default='127.0.0.1:22',
                        type=str,
                        help="Local address to be connected. Default is 127.0.0.1:22.")
    parser.add_argument('-e', '--remote',
                        default='127.0.0.1:50067',
                        type=str,
                        help="Remote address to communicate with. Default is 127.0.0.1:50067.")
    parser.add_argument('--log-level',
                        default='INFO',
                        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                        type=str,
                        help="Log level. Default is DEBUG.")
    parser.add_argument('-s', '--secret',
                        default='nN31mnOq0ek4UBXxecl4WnLeCoYOfTQJ',
                        type=str,
                        help="Secret key for encryption.")
    parser.add_argument('-t', '--timeout',
                        default=120,
                        type=int,
                        help="Socket timeout, default is 120.")
    args = parser.parse_args()

    # 设置 socket 的默认超时时间
    socket.setdefaulttimeout(args.timeout)

    # 日志级别
    log_level = getattr(logging, args.log_level)
    # 设置日志级别及输出格式
    logging.basicConfig(level=log_level,
                        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    remote_ip, remote_port = args.remote.split(':')
    local_ip, local_port = args.local.split(':')
    t = RemoteConnect(remote_ip, int(remote_port), local_ip, int(local_port), secret=args.secret, log_level=log_level)
    t.start()
    t.join()
