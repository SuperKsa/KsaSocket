# cython: language_level=3

import logging
import socket
import threading
import time
import traceback
import zlib

from .KsaLogger import KsaLogger

cdef class KsaClient:
    cdef:
        str host
        int port
        int bufferSize  # 消息buffer大小
        object Socket
        bint isZip
        bint Connected

        bint Exit
        bint debug
        bint Nodelay

        object callbackMessage
        object calbackDisconnected
        object callbackConnectEd

        str bufferHead
        str bufferFooter
        bytes Protocol
        int ProtocolLen
        bint ProtocolConnectEd

        object logger


    def __init__(self, int bufferSize=1024, object callbackConnectEd=None, object callbackMessage=None, object calbackDisconnected=None, str bufferHead="", str bufferFooter="", bint msgZIP=False, bint debug=False, bint Nodelay=False, loglevel:int=logging.DEBUG):
        """

        :param callbackConnectEd:
        :param callbackMessage:
        :param calbackDisconnected:
        """
        self.logger = KsaLogger('KsaClient', loglevel)
        self.logger.info(f'初始化中')

        self.bufferSize = bufferSize  # 消息buffer大小
        self.callbackMessage = callbackMessage
        self.calbackDisconnected = calbackDisconnected
        self.callbackConnectEd = callbackConnectEd
        self.debug = debug
        self.Nodelay = Nodelay
        self.Exit = False
        self.Connected = False
        self.bufferHead = bufferHead
        self.bufferFooter = bufferFooter
        self.isZip = msgZIP
        self.Protocol = b"\t\fKsaSocket\f\t"
        self.ProtocolLen = len(self.Protocol)
        self.ProtocolConnectEd = False

    def connect(self, str ip='', int port=0, bint isZip=False):
        # 初始化客户端，设置服务器IP和端口
        self.host = ip
        self.port = port
        self.isZip = isZip
        self.Exit = False
        self.Connected = False
        # self.logger.debug('开始连接')
        # 连接到服务器
        try:
            Socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            if self.Nodelay:
                # 禁用Nagle算法
                Socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

            Socket.connect((self.host, self.port))
            Socket.settimeout(3)  # 设置超时时间为5秒

            self.Connected = True
            try:
                if self.callbackConnectEd is not None:
                    self.callbackConnectEd()
            except Exception as e:
                pass
            Socket.sendall(self.Protocol)  # 首次连接发送内部标志

            # 启动一个独立的线程用于持续接收数据
            threading.Thread(target=self._read_data, daemon=True).start()
            self.Socket = Socket

            self.logger.info(f'服务端连接成功 {self.host}:{self.port}')
            return True

        except Exception as e:
            # self.logger.debug(f"连接服务器时发生错误: {e}")
            pass

        return False

    def send(self, data=''):
        # 发送数据到服务器
        try:
            if self.Socket is not None:
                sendData = data.encode('utf-8')
                if self.isZip:
                    sendData = zlib.compress(sendData)
                self.Socket.sendall(sendData)
        except socket.error as e:
            # self.logger.debug(f'发送消息报错:{e}')
            if e.errno not in (socket.EWOULDBLOCK, 10035):
                self._Disconnected_(isCall=True)
        except Exception as e:
            pass

    def is_connected(self):
        return self.Connected

    def _debug(self, msg=None):
        if self.debug:
            print('【TCP-TCPClient】 ', msg)

    def _Disconnected_(self, isCall=False):

        if self.Socket is not None:
            self.Socket.close()
        self.Exit = True
        self.Connected = False
        if isCall:
            try:
                if self.calbackDisconnected is not None:
                    self.calbackDisconnected()
            except Exception as e:
                pass

    def _read_data(self):
        # 持续接收数据的函数
        self.logger.debug('消息线程 开始')
        Messages = ""
        isAdd = False
        while not self.Exit:
            if self.Socket is None:
                time.sleep(0.1)
                continue

            data = None
            # 从服务器接收数据
            try:

                data = self.Socket.recv(self.bufferSize)
                # 协议的处理 检测到协议标志时 标记协议连接成功
                if not self.ProtocolConnectEd:
                    if data[:self.ProtocolLen] == self.Protocol:
                        data = data[self.ProtocolLen:]
                        self.ProtocolConnectEd = True

                # if data is None or data == b"":
                #     self._Disconnected_(isCall=True)

            except socket.error as e:
                # self.logger.debug(f'读取消息报错：socket.error={e.errno} {e}')
                if e.errno and e.errno not in (socket.EWOULDBLOCK, 10035, 1038):
                    self._Disconnected_(isCall=True)
            except Exception as e:
                pass
            frame_start = time.time()
            if self.isZip:
                data = zlib.decompress(data)

            MsgList = []
            if data is not None and self.bufferHead and self.bufferFooter:
                # 解析消息 分割粘包
                try:
                    Messages += data.decode('utf-8')
                    if Messages:

                        while True:
                            index_start = Messages.find(self.bufferHead)
                            index_end = Messages.find(self.bufferFooter)
                            msgLen = len(Messages)
                            if msgLen <= 0:
                                break

                            # 整个字符只有包头尾字符 则直接重置
                            if msgLen == 2 and index_start != -1 and index_end != -1:
                                Messages = ''
                                break

                            # 存在包头 将消息重置到第一个包头的位置
                            if not isAdd and index_start >= 0:
                                if index_start > 0:
                                    Messages = Messages[index_start:]
                                    index_start = 0
                                isAdd = True  # 标记开始
                                # print(f'N={N} 存在包头 将消息重置到第一个包头的位置')
                                continue

                            # 添加模式
                            if isAdd:
                                # 再次检查第一位之后的字符是否存在包头
                                s = Messages[1:].find(self.bufferHead)
                                if s >= 0 and s < index_end:  # 存在包头 继续重置消息头部
                                    Messages = Messages[s + 1:]  # 这里必须+1 因为是从第二个字符查找包头
                                    continue

                                # 标准包尾 处理完成直接结束
                                if index_end == msgLen - 1:
                                    MsgList.append(Messages[1:-1])
                                    Messages = ''
                                    isAdd = False
                                    break

                                # 任意包尾
                                if index_end >= 0 and index_end > index_start:
                                    MsgList.append(Messages[index_start + 1:index_end])
                                    Messages = Messages[index_end - 1:]  # -1后退一个字符给头数据便于判断
                                    isAdd = False

                                # 没有包尾 退出
                                if index_end == -1:
                                    break
                            else:
                                # 没有包头 退出
                                if index_start == -1:
                                    break

                except Exception as e:
                    print('TCP客户端消息分割粘包错误：')
                    traceback.print_exc()
            else:
                try:
                    subMsg = data.decode('utf-8')
                    MsgList.append(subMsg)
                except Exception as e:
                    pass
            # 消息回调
            if len(MsgList) and self.callbackMessage is not None:
                for value in MsgList:
                    try:
                        self.callbackMessage(value)
                    except Exception as e:
                        pass
                MsgList = []

            data = None
            subMsg = ''
            MsgList = []
            # print(f'TCP客户端消息读取并回调耗时={round((time.time() - frame_start) * 1000)}ms')


    def close(self):
        # 关闭与服务器的连接
        try:
            self._Disconnected_(isCall=False)
        except Exception as e:
            # print(f"关闭连接时发生错误: {e}")
            pass