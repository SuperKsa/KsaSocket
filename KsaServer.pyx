# cython: language_level=3

import json
import logging
import os
import queue
import socket
import threading
import time
import traceback
import zlib

from .Csocket import Csocket
from .KsaCoder import KsaCoder
from .KsaLogger import KsaLogger
from .KsaRequestParse import KsaRequestParse, KsaRequestParse_HTTP_MIME

cdef class KsaServer:
    cdef:
        object Socket

        str __Host
        int __Port
        bint __Exit

        dict __STATIC  # 静态资源绑定 key=访问路径 value=文件目录地址
        dict __ROUTE_HTTP  # 路由列表 key=访问路径 value=回调函数
        dict __ROUTE_WebSocket

        object __TCP_onConnect
        object __TCP_onMessage
        object __TCP_onClose
        bint __TCP_ZIP
        dict __TCP_ClientListMap
        int __TCP_bufferSize
        bint __TCP_Nodelay
        str __TCP_bufferHead
        str __TCP_bufferFooter
        list __TCP_Threads
        int __TCP_listenNum
        bint __TCP_ReuseAddr
        object __TCP_SendQueueCommon

        dict __WebSocket_ClientListMap
        object __WebSocket_SendQueueCommon

        object logger


        bint __WS_ZIP

        object RequestParse


    def __init__(self, host: str = '0.0.0.0', port: int = 8000, listenNum=100, reuseAddr=False, loglevel:int=logging.DEBUG):
        """
        初始化KsaSocket服务
        :param host: 网卡地址
        :param port: 服务端口
        :param listenNum: 监听客户端数量
        :param reuseAddr: 是否复用端口
        """
        self.__TCP_ClientListMap = {}
        self.__WebSocket_ClientListMap = {}
        self.__STATIC = {}
        self.__ROUTE_HTTP = {}
        self.__ROUTE_WebSocket = {}


        self.logger = KsaLogger('KsaServer', loglevel)
        self.logger.info(f'初始化中')


        self.__STATIC = {}  # 静态资源绑定 key=访问路径 value=文件目录地址
        self.__ROUTE_HTTP = {}  # 路由列表 key=访问路径 value=回调函数
        self.__ROUTE_WebSocket = {}

        self.__TCP_onConnect = None
        self.__TCP_onMessage = None
        self.__TCP_onClose = None
        self.__TCP_ZIP = False
        self.__TCP_ClientListMap = {}
        self.__TCP_bufferSize = 1024
        self.__TCP_Nodelay = False
        self.__TCP_bufferHead = ''
        self.__TCP_bufferFooter = ''
        self.__TCP_Threads = []
        self.__TCP_listenNum = listenNum
        self.__TCP_ReuseAddr = reuseAddr

        self.__Host = host
        self.__Port = port
        self.__TCP_listenNum = listenNum
        self.__TCP_ReuseAddr = reuseAddr
        self.__Exit = False
        self.__TCP_SendQueueCommon = queue.Queue()
        self.__WebSocket_SendQueueCommon = queue.Queue()
        self.RequestParse = None

    def http(self, path: str = '', method: str = 'GET', dirs: str = None, onMessage:object=None):
        """
        绑定HTTP路由
        :param path: 访问路径
        :param method: 请求类型 GET, POST, TCP, WS, WSS
        :param callback: 回调函数 参数1=ClientSocket对象 参数2=消息内容
        :return:
        """

        if path:
            if dirs:
                dirs = dirs.rstrip('/')+'/'
            self.__ROUTE_HTTP[path] = {
                'path': path,
                'method': method,
                'dir': dirs,
                'onMessage': onMessage
            }
            if dirs:
                self.logger.info(f'绑定HTTP静态资源 {path} dirs={dirs}')
            else:
                self.logger.debug(f'绑定 http://{self.__Host}:{self.__Port}{path} method={method}')
            return True
        return False

    def ws(self, path: str = '', onConnect:object=None, onMessage:object=None, onClose:object=None, isZip:bool=False):
        """
        绑定WebSocket服务
        :param path: 绑定路径
        :param onConnect: 新连接回调 可选 参数:(客户端ID, 客户端对象, 消息)
        :param onMessage: 新消息回调 可选 参数:(客户端ID, 客户端对象, 消息)
        :param onClose: 连接关闭回调 可选 参数:(客户端ID, 客户端对象, 消息)
        :param isZip:是否启用zip压缩消息
        :return:
        """
        if onConnect is None and onMessage is None and onClose is None:
            return False
        if path:
            path = '/'+path.lstrip('/')
            self.__ROUTE_WebSocket[path] = {
                'path': path,
                'onConnect': onConnect,
                'onMessage': onMessage,
                'onClose': onClose,
                'isZip': isZip
            }
            self.logger.info(f'绑定WS服务 ws://{self.__Host}:{self.__Port}{path} isZip={isZip}')
            return True
        return False

    def tcp(self, bufferSize: int = 0, onConnect:object=None, onMessage:object=None, onClose:object=None, bufferHead:str="", bufferFooter:str="", isZip:bool=False, nodelay=False):
        """
        启用TCP服务
        :param bufferSize:
        :param onConnect:
        :param onMessage:
        :param onClose:
        :param isZip:
        :param nodelay:
        :return:
        """
        if onConnect is None and onMessage is None and onClose is None:
            return False
        self.logger.debug(repr(f'启用TCP服务 bufferSize={bufferSize} bufferHead={bufferHead} bufferFooter={bufferFooter} isZip={isZip} 禁用Nagle算法={nodelay}'))
        self.__TCP_onConnect = onConnect
        self.__TCP_onMessage = onMessage
        self.__TCP_onClose = onClose
        self.__TCP_ZIP = isZip
        self.__TCP_bufferSize = bufferSize
        self.__TCP_Nodelay = nodelay
        self.__TCP_bufferHead = bufferHead
        self.__TCP_bufferFooter = bufferFooter
        return False

    def __response_http(self, client_socket:socket.socket=None, CtSocket: Csocket = None, recv_time:float=0.):
        """
        响应 HTTP请求 包含HTTPS
        :param client_socket:
        :param ReqParse:
        :param CtSocket:
        :return:
        """
        headers = CtSocket.get_header()

        def get_header():
            hds = []
            for key, value in headers.items():
                hds.append(f"{key}: {value}")
            return "\r\n".join(hds)

        def set_header(key, value):
            headers[key] = value


        if self.RequestParse.staticDir:  # 静态资源文件请求
            if self.RequestParse.staticFile:
                staticFiles = [self.RequestParse.staticFile]
            else:
                staticFiles = ['index.html', 'index.htm', 'default.htm', 'default.html']

            for value in staticFiles:
                resource_file = os.path.join(self.RequestParse.staticDir, value)
                # 根据静态目录地址和文件组合需要返回的文件路径

                if os.path.isfile(resource_file):
                    set_header('Content-Type', KsaRequestParse_HTTP_MIME(value))
                    with open(resource_file, 'rb') as file:
                        file_content = file.read()
                        set_header('Content-Length', len(file_content))
                        response = f"HTTP/1.1 200 OK\r\n{get_header()}\r\n\r\n"

                        CtSocket.send(msg=response.encode('utf-8') + file_content)
                        CtSocket.close()
                        return

        if self.RequestParse.bindPath and self.RequestParse.method in ['GET', 'POST', 'PUT', 'PATCH', 'DELETE']:
            set_header('Content-Type', 'text/html; charset=utf-8')
            replyMessage = CtSocket.onMessage(self.RequestParse.Body, recv_time)
            if replyMessage is not None:

                if isinstance(replyMessage, dict) or isinstance(replyMessage, list):
                    replyMessage = json.dumps(replyMessage, ensure_ascii=False)
                    set_header('Content-Type', 'application/json; charset=utf-8')

                response = f"HTTP/1.1 200 OK\r\n{get_header()}; charset=utf-8\r\n\r\n".encode('utf-8')

                if isinstance(replyMessage, bytes):
                    response += replyMessage
                else:
                    response += replyMessage.encode('utf-8')
                CtSocket.send(msg=response)
                CtSocket.close()
                return

        CtSocket.send(msg=b"HTTP/1.1 404 NotFound\r\n")
        CtSocket.close()

    def __response_WebSocket(self, client_socket:socket.socket=None, CtSocket: Csocket = None):
        """
        响应 WebSocket 请求
        :param client_socket:
        :param CtSocket:
        :return:
        """
        # 设置为非阻塞模式
        client_socket.setblocking(False)
        clientID = CtSocket.clientID()
        self.__WebSocket_ClientListMap[clientID] = CtSocket
        self.logger.debug(f'WebSocket 连接 {clientID}')
        KsaCoder.send_Protocols(client_socket, CtSocket.Header().get('Sec-WebSocket-Key'))
        CtSocket.onConnect()
        # 循环处理 WebSocket 数据
        while not self.__Exit and CtSocket.connectEd():

            try:
                data = client_socket.recv(self.__TCP_bufferSize)
                recv_time = time.time()  # 读取到原始数据的时间
                if not data or data == b'' or data[0] == 0x88:
                    self.logger.error(f'WebSocket 断开 {clientID}')
                    CtSocket.close()
                    break
                if data:
                    # 消息回调给路由绑定函数
                    try:
                        message = KsaCoder.decode(data).decode('utf-8')
                        replyMessage = CtSocket.onMessage(message, recv_time)
                        if replyMessage is not None:
                            CtSocket.send(msg=replyMessage)
                    except Exception as e:
                        pass

            except  socket.error as e:
                if e.errno not in [10035]:
                    CtSocket.close()
                    self.logger.error(f'WebSocket 断开 {clientID}')
                    # traceback.print_exc()
                    break


            time.sleep(0.0001)
        CtSocket.close()

    def __response_TCP(self, client_socket:socket.socket=None, CtSocket: Csocket = None):
        # 设置为非阻塞模式
        client_socket.setblocking(False)
        clientID = CtSocket.clientID()

        self.__TCP_ClientListMap[clientID] = CtSocket
        self.logger.debug(f'TCP新连接 {clientID}')

        CtSocket.onConnect()

        while not self.__Exit and CtSocket.connectEd():
            try:
                # 接收数据
                data = client_socket.recv(self.__TCP_bufferSize)
                recv_time = time.time()  # 读取到原始数据的时间
                if not data or data == b'':
                    self.logger.debug(f'TCP客户端 断开 clientID={clientID}')
                    # 关闭客户端连接
                    CtSocket.close()
                    break

                if data:

                    if self.__TCP_ZIP:
                        data = zlib.decompress(data)
                    CtSocket.onMessage(data, recv_time)

            except socket.error as e:

                if e.errno not in (socket.EWOULDBLOCK, 10035):
                    self.logger.debug(f'TCP客户端 断开 clientID={clientID} socket.error={e.errno}')
                    # 关闭客户端连接
                    CtSocket.close()
                    break

            except Exception as e:
                print('TCP客户端消息读取报错 Exception clientID={clientID} ：', e)
            time.sleep(0.001)

    def __thread_handle(self, client_socket:socket.socket, addr):
        request = None
        recv_time = 0  # 原始数据读取时间
        try:
            request = client_socket.recv(1024)
            recv_time = time.time()
        except socket.error as e:

            # 处理非阻塞recv时的异常
            if e.errno in [11, 35, 10035]:
                # print('socket.error 没有数据可读')
                pass  # 没有数据可读
            else:
                print(f'socket.error e.errno={e.errno}')
                # client_socket.close()
                # return
                pass
        except Exception as e:
            # client_socket.close()
            # return
            pass

        Protocol = None
        if request is not None:
            if request == b"\t\fKsaSocket\f\t":
                Protocol = 'KSASocket'

            if request[:4] in [b'GET ', b'POST'] and request.find(b"HTTP/") >0:
                Protocol = 'HTTP'

        if not Protocol:
            client_socket.close()
            return


        CtSocket = Csocket(KSA=self, socket=client_socket, request=request, addr=addr)
        if Protocol == 'HTTP':

            self.RequestParse = KsaRequestParse(request)
            parseRes = self.RequestParse.parse(self.__ROUTE_HTTP, self.__ROUTE_WebSocket)



            if not parseRes:
                self.logger.error(f'错误的请求 {addr[0]}:{addr[1]} Protocol={self.RequestParse.Protocol} / {self.RequestParse.method} Path={self.RequestParse.Path}')
                # print('request', request)
                client_socket.close()
                return

            CtSocket._setCallbackEvent(self.RequestParse.onConnect, self.RequestParse.onMessage, self.RequestParse.onClose)
            CtSocket.set_RouteParse(Protocol=self.RequestParse.Protocol, Path=self.RequestParse.Path, UrlQuery=self.RequestParse.UrlQuery, method=self.RequestParse.method, Header=self.RequestParse.Header, Body=self.RequestParse.Body, GET=self.RequestParse.GET, POST=self.RequestParse.POST)

            if self.RequestParse.Protocol == 'HTTP':
                self.__response_http(client_socket=client_socket, CtSocket=CtSocket, recv_time=recv_time)

            elif self.RequestParse.Protocol == 'WebSocket':
                self.__response_WebSocket(client_socket=client_socket, CtSocket=CtSocket)
            else:
                client_socket.close()

        if Protocol == 'KSASocket':
            client_socket.sendall(b"\t\fKsaSocket\f\t")
            CtSocket._setCallbackEvent(onConnect=self.__TCP_onConnect, onMessage=self.__TCP_onMessage, onClose=self.__TCP_onClose)
            CtSocket.setMsgConfig(isZip=self.__TCP_ZIP, bufferHead=self.__TCP_bufferHead, bufferFooter=self.__TCP_bufferFooter)

            self.__response_TCP(client_socket=client_socket, CtSocket=CtSocket)

    def _listenClient(self):
        self.logger.info('TCP 客户端监听线程 启动')
        while not self.__Exit:
            if self.Socket is None:
                time.sleep(0.01)
                continue
            try:
                # 等待客户端连接
                client_socket, client_address = self.Socket.accept()

                # 处理每个连接的客户端的线程
                threading.Thread(target=self.__thread_handle, args=(client_socket, client_address,), daemon=True).start()

            except socket.error as e:
                # print('_listenClient socket.error', e.errno)
                pass
            except Exception as e:
                pass
            time.sleep(0.0001)
        self.logger.error('TCP 客户端监听线程 结束')

    def start(self):
        self.logger.info(f'启动中')
        # 创建TCP套接字
        Socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        Socket.setblocking(False)  # 设置非阻塞模式
        if self.__TCP_ReuseAddr:
            # 设置端口复用
            Socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)
        if self.__TCP_Nodelay:
            # 禁用Nagle算法
            Socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        try:
            # 绑定套接字到指定地址和端口
            Socket.bind((self.__Host, self.__Port))
            # 开始监听连接 参数是同时连接的客户端数量
            Socket.listen(self.__TCP_listenNum)
            # # 设置超时时间为10秒
            # Socket.settimeout(1)

            self.Socket = Socket
            ths = threading.Thread(target=self._listenClient, name='TCP客户端监听 线程', daemon=True)
            ths.start()
            self.__TCP_Threads.append(ths)

            ths = threading.Thread(target=self._Thread_TCP_SendQueue, name='TCP全局消息队列处理 线程', daemon=True)
            ths.start()
            self.__TCP_Threads.append(ths)

            ths = threading.Thread(target=self._Thread_WS_SendQueue, name='WS全局消息队列处理 线程', daemon=True)
            ths.start()
            self.__TCP_Threads.append(ths)

            if len(self.__ROUTE_HTTP):
                self.logger.info(f'HTTP服务 http://{self.__Host}:{self.__Port}')


            self.logger.info(f'启动成功：host={self.__Host}:{self.__Port} 端口复用={self.__TCP_ReuseAddr} 客户端容量={self.__TCP_listenNum}')
        except socket.error as e:
            self.close()
            self.logger.error(f'服务启动失败 host={self.__Host}:{self.__Port} e.errno={e.errno} 端口被占用了吗？')
            self.logger.error(e)
            traceback.print_exc()

        except Exception as e:
            self.close()
            self.logger.error(f'服务启动失败 host={self.__Host}:{self.__Port} 端口被占用了吗？')
            self.logger.error(e)
            traceback.print_exc()

    def _Thread_WS_SendQueue(self):
        self.logger.info('WebSocket 全局消息线程 启动')

        # testpos = []
        # for i in range(1920):
        #     testpos.append([1920, 1080, 1080, 1080, 1080])

        while not self.__Exit:
            if self.Socket is None:
                time.sleep(0.01)
                continue
            #
            # json_message = json.dumps({'action': 'LaserData', 'Mark': time.time(), 'FPS': 12, 'FrameIndex': 3, 'data': testpos}, ensure_ascii=False)
            # self.__TCP_SendQueueCommon.put(json_message)

            del_clients = []
            try:
                data = self.__WebSocket_SendQueueCommon.get()
                if data:
                    for CtSocket in self.__WebSocket_ClientListMap.values():
                        try:
                            res = CtSocket.send(msg=data)
                        except Exception as e:
                            del_clients.append(CtSocket.clientID())


            except Exception as e:
                # print('WebSocket 全局消息线程报错：', e)
                # traceback.print_exc()
                pass

            if len(del_clients):
                for clientID in del_clients:
                    self.client_close(clientID)

            time.sleep(0.001)

        self.logger.error('WebSocket 全局消息线程 结束')

    def _Thread_TCP_SendQueue(self):
        self.logger.info('TCP 全局消息线程 启动')

        # testpos = []
        # for i in range(1920):
        #     testpos.append([1920, 1080, 1080, 1080, 1080])

        while not self.__Exit:
            if self.Socket is None:
                time.sleep(0.01)
                continue
            #
            # json_message = json.dumps({'action': 'LaserData', 'Mark': time.time(), 'FPS': 12, 'FrameIndex': 3, 'data': testpos}, ensure_ascii=False)
            # self.__TCP_SendQueueCommon.put(json_message)

            del_clients = []
            try:
                data = self.__TCP_SendQueueCommon.get()
                if data:
                    for CtSocket in self.__TCP_ClientListMap.values():
                        try:
                            CtSocket.send(msg=data)
                        except Exception as e:
                            del_clients.append(CtSocket.clientID())

            except Exception as e:
                # print('TCP 全局消息线程报错：', e)
                # traceback.print_exc()
                pass

            if len(del_clients):
                for clientID in del_clients:
                    self.client_close(clientID)

            time.sleep(0.001)
        self.logger.error('TCP 全局消息线程 结束')

    def _clientMapRemove(self, clientID):
        """
        从缓存的全局客户端MAP中清理指定数据
        :param clientID:
        :return:
        """
        try:
            if self.__TCP_ClientListMap.__contains__(clientID):
                del self.__TCP_ClientListMap[clientID]
        except Exception as e:
            pass

        # 清理KSA WS 客户端
        try:
            if self.__WebSocket_ClientListMap.__contains__(clientID):
                del self.__WebSocket_ClientListMap[clientID]
        except Exception as e:
            pass

        # print(f'清理客户端 完成：clientID={clientID} TCP现有客户端={self.count_tcp_clients()} WS现有客户端={self.count_ws_clients()}')


    def client_close(self, clientID):
        """
        主动关闭客户端
        :param clientID:
        :return:
        """
        try:
            con = self.__TCP_ClientListMap.get(clientID)
            if con is not None:
                con.close()

            con = self.__WebSocket_ClientListMap.get(clientID)
            if con is not None:
                con.close()
        except Exception as e:
            pass


    def tcp_sendAll(self, data=None):
        """
        发送消息给所有TCP客户端
        :param data:
        :return:
        """
        # print('KsaSocket 发送消息给所有TCP客户端', data)
        self.__TCP_SendQueueCommon.put(data)

    def ws_sendAll(self, data=None):
        """
        发送消息给所有TCP客户端
        :param data:
        :return:
        """
        # print('KsaSocket 发送消息给所有TCP客户端', data)
        self.__WebSocket_SendQueueCommon.put(data)

    def close(self):
        """
        主动结束
        :return:
        """
        if not self.__Exit:
            self.logger.debug('结束中')
            if self.Socket is not None:
                self.Socket.close()
            self.__Exit = True
            for ths in self.__TCP_Threads:
                self.logger.debug(f'正在停止线程：{ths.name}')
                ths.join()
            self.logger.error('停止运行')

    def running(self):
        """
        服务是否运行中
        :return:
        """
        return not self.__Exit

    def count_tcp_clients(self):
        """
        返回TCP客户端数量
        :return:
        """
        return len(self.__TCP_ClientListMap)

    def count_ws_clients(self):
        """
        返回WS客户端数量
        :return:
        """
        return len(self.__WebSocket_ClientListMap)

    def count_clients(self):
        """
        返回已连接客户端数量
        :return:
        """
        return self.count_tcp_clients() + self.count_ws_clients()

