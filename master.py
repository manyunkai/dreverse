# -*-coding:utf-8 -*-
"""
Created on 2016-7-5

@author: Danny
DannyWork Project
"""

import socket
import threading
import time
import argparse
import logging
from collections import deque

from utils import reply_ping_data, close_socket, ping_socket, get_python_version, start_data_transfer, \
    TRANSFER_PREPARE, TRANSFER_READY

if get_python_version() == '2':
    from exceptions import *


class LocalListen(threading.Thread):
    """
    本地端口监听管理
    """

    # 可用的远程连接 socket 池
    pool = None
    default_max_queued_connections = 5

    # 加密 key
    secret = ''

    # 日志
    logger = None

    def __init__(self, pool, ip, port, secret='', max_queued_connections=None, log_level=logging.INFO):
        threading.Thread.__init__(self)

        self.ip = ip
        self.port = port
        self.default_max_queued_connections = max_queued_connections or self.default_max_queued_connections
        self.pool = pool
        self.secret = secret

        self.logger = logging.getLogger('Local Listener')
        self.logger.setLevel(log_level)

    def run(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.ip, self.port))
        sock.listen(self.default_max_queued_connections)
        sock.setblocking(1)

        self.logger.info('Master is listening on internal: {0}:{1}'.format(self.ip, self.port))

        while True:
            client_sock, address = sock.accept()
            while True:
                # 从地址池中获取一个可用的远程通信 socket
                try:
                    remote_sock = self.pool.pop()
                except IndexError:
                    close_socket(client_sock)
                    break
                else:
                    try:
                        remote_sock.settimeout(1)
                        # 通知远程准备接收数据
                        remote_sock.sendall(TRANSFER_PREPARE.encode('utf8'))
                        # 等待远程准备就绪
                        data = remote_sock.recv(1024)
                        if not TRANSFER_READY.encode('utf8') == data:
                            raise ValueError('Wrong data received')
                    except Exception as e:
                        self.logger.info('Remote not ready({0}) at {1}, give up.'.format(e, client_sock))
                        close_socket(remote_sock)
                    else:
                        remote_sock.settimeout(socket.getdefaulttimeout())
                        start_data_transfer(client_sock, remote_sock, self.secret)
                        self.logger.info('Ready to transfer data between {0} and {1}.'.format(client_sock, remote_sock))
                        break


class RemoteListen(threading.Thread):
    """
    远程端口监听管理
    """

    default_max_queued_connections = 5
    max_free_connections = 10

    pool = None
    secret = ''

    logger = None

    def __init__(self, pool, ip, port, secret='', max_queued_connections=None,
                 max_free_connections=None, log_level=logging.INFO):
        threading.Thread.__init__(self)

        self.ip = ip
        self.port = port
        self.default_max_queued_connections = max_queued_connections or self.default_max_queued_connections
        self.max_free_connections = max_free_connections or self.max_free_connections
        self.pool = pool
        self.secret = secret

        self.logger = logging.getLogger('Remote Listener')
        self.logger.setLevel(log_level)

    def run(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.ip, self.port))
        sock.listen(self.default_max_queued_connections)
        sock.setblocking(1)

        self.logger.info('Master is listening on external: {0}:{1}'.format(self.ip, self.port))

        while True:
            client_sock, address = sock.accept()
            try:
                if len(self.pool) >= self.max_free_connections:
                    raise ConnectionError('Too many connections.')

                # “握手”
                if not ping_socket(client_sock, self.secret):
                    raise ConnectionError('Bad connection.')

                client_sock.sendall(reply_ping_data('READY'))
            except Exception as e:
                self.logger.warning('Connection established error: {0}'.format(e))
                close_socket(client_sock)
            else:
                self.pool.appendleft(client_sock)
                self.logger.info('CONNECTED: {0}. {1} free connections.'.format(address, len(self.pool)))


class ConnectionPing(threading.Thread):
    """
    保活测试
    """

    # 可用的远程连接 socket 池
    pool = None

    # 加密 key
    secret = ''

    logger = None

    def __init__(self, pool, secret='', log_level=logging.INFO):
        super(ConnectionPing, self).__init__()

        self.pool = pool
        self.secret = secret

        self.logger = logging.getLogger('ConnectionPing')
        self.logger.setLevel(log_level)

    def run(self):
        while True:
            try:
                sock = self.pool.pop()
            except IndexError:
                self.logger.warning('No connections.')
            else:
                if ping_socket(sock, self.secret):
                    self.pool.appendleft(sock)
                else:
                    self.logger.warning('Ping failed in {0}, give up. {1} left.'.format(sock, len(self.pool)))
                    close_socket(sock)
            time.sleep(5)


if __name__ == '__main__':
    # 参数解析
    parser = argparse.ArgumentParser()
    parser.add_argument('-l', '--local',
                        default='127.0.0.1:1081',
                        type=str,
                        help="Local address to be listening on. Default is 127.0.0.1:1081.")
    parser.add_argument('-e', '--remote',
                        default='0.0.0.0:50067',
                        type=str,
                        help="Remote address to be listening on. Default is 0.0.0.0:50067.")
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

    # AES 加密密钥
    secret = args.secret

    # 设置 socket 的默认超时时间
    socket.setdefaulttimeout(args.timeout)

    # 日志级别
    log_level = getattr(logging, args.log_level)
    # 设置日志级别及输出格式
    logging.basicConfig(level=log_level,
                        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    pool = deque()

    ip, port = args.remote.split(':')
    remote_listen_thread = RemoteListen(pool=pool, ip=ip, port=int(port), secret=secret, log_level=log_level)
    remote_listen_thread.setDaemon(True)
    remote_listen_thread.start()

    ip, port = args.local.split(':')
    local_listen_thread = LocalListen(pool=pool, ip=ip, port=int(port), secret=secret, log_level=log_level)
    local_listen_thread.setDaemon(True)
    local_listen_thread.start()

    ping_thread = ConnectionPing(pool=pool, secret=secret, log_level=log_level)
    ping_thread.setDaemon(True)
    ping_thread.start()
    ping_thread.join()
