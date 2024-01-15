import base64
import hashlib
import json
import logging
import os
import queue
import socket
import struct
import threading
import time
import zlib
from urllib.parse import urlparse


class KsaWebSocket:
    @staticmethod
    def decode(data):
        """
        解码WSS帧
        :param data:
        :return:
        """
        if data[0] == 0x88:
            return None

        payload_len = data[1] & 0b1111111
        if payload_len == 0b1111110:
            mask = data[4:8]
            decoded = data[8:]
        elif payload_len == 0b1111111:
            mask = data[10:14]
            decoded = data[14:]
        else:
            mask = data[2:6]
            decoded = data[6:]
        return bytes(bytearray([decoded[i] ^ mask[i % 4] for i in range(len(decoded))]))

    @staticmethod
    def encode(msg_bytes, token=b"\x81"):
        """
        构造WSS消息
        :param msg_bytes:
        :param token:
        :return:
        """
        length = len(msg_bytes)
        if length <= 125:
            token += struct.pack("B", length)
        elif length <= 65535:
            token += struct.pack("!BH", 126, length)
        else:
            token += struct.pack("!BQ", 127, length)
        return token + msg_bytes

    @staticmethod
    def send_Protocols(client_socket, client_request):
        """
        向客户端发送wss升级协议
        :param client_socket:
        :param client_request:
        :return:
        """
        # 提取 WebSocket key
        key = client_request.split('Sec-WebSocket-Key: ')[1].split('\r\n')[0]
        response_key = base64.b64encode(hashlib.sha1((key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode('utf-8')).digest()).decode('utf-8')

        # 发送 WebSocket 握手响应
        response = "HTTP/1.1 101 Switching Protocols\r\n"
        response += "Upgrade: websocket\r\n"
        response += "Connection: Upgrade\r\n"
        response += f"Sec-WebSocket-Accept: {response_key}\r\n\r\n"
        client_socket.send(response.encode('utf-8'))


class KsaClientSocket:
    request = None
    _GET = {}
    _POST = {}
    _HEADER = {}
    _BODY = None
    _Path = None  # 内部变量
    Exit = False  # 客户端是否退出
    ip = None  # 客户端 IP
    port = None  # 客户端 端口
    clientID = ''  # 客户端ID IP:端口
    Protocol = 'TCP'  # 协议类型
    Path = ''  # HTTP 请求路径

    def __init__(self, socket, request: bytes = b'', addr=None):
        """
        客户端对象 回调到外部的socket对象
        :param socket:
        :param request:
        :param addr:
        """
        self.socket = socket
        self.request = request.decode('utf-8')
        self.ip = addr[0]
        self.port = addr[1]
        self.clientID = f'{addr[0]}:{addr[1]}'

    def _RouteParse(self, routeHTTP, routeWebSocket):
        """
        私有 路由解析
        :param routeHTTP: http路由
        :param routeWebSocket: WebSocket路由
        :return:
        """
        rParse = KsaRequestParse(self.request)
        self.requestObject = rParse
        res = rParse.parse(routeHTTP, routeWebSocket)
        self._HEADER = rParse.Header
        self._BODY = rParse.Body
        self._GET = rParse.GET
        self.Protocol = rParse.Protocol
        self.Path = rParse.Path
        self.Method = rParse.method

        return res

    def send(self, msg, iszip=False, isWebSocket=None, bufferHead='', bufferFooter=''):
        """
        客户端消息发送函数
        :param msg: 消息内容 支持：bytes、str、dict
        :param iszip:
        :param flags:
        :return:
        """
        if msg is not None:
            try:
                message = msg
                if isinstance(message, str) or isinstance(message, float) or isinstance(message, int):
                    message = msg.encode('utf-8')
                elif isinstance(message, dict) or isinstance(message, list):
                    message = json.dumps(msg, ensure_ascii=False).encode('utf-8')

                if message is not None and isinstance(message, bytes):
                    if isWebSocket:
                        message = KsaWebSocket.encode(message)

                    if iszip:
                        message = zlib.decompress(message)

                    # 包头包尾组合
                    sendMessage = b""
                    if bufferHead:
                        sendMessage += bufferHead.encode('utf-8')
                    sendMessage += message
                    if bufferFooter:
                        sendMessage += bufferFooter.encode('utf-8')
                    message = None

                    self.socket.sendall(sendMessage)
                    return True
            except Exception as e:
                return False
            return False

    def close(self):
        """
        主动断开客户端
        :return:
        """
        self.Exit = True
        return self.socket.close()

    def recv(self, buffersize, flags=None):
        return self.socket.recv(buffersize)

    def GET(self):
        """
        获取GET请求参数
        :return:
        """
        return self._GET

    def POST(self):
        """
        获取POST参数
        :return: dict
        """
        return self._POST

    def onMessage(self, msg=None):
        if self.requestObject.onMessage is not None:
            try:
                return self.requestObject.onMessage(self.clientID, self, msg)
            except Exception as e:
                pass

    def onConnect(self):
        if self.requestObject.onMessage is not None:
            try:
                return self.requestObject.onConnect(self.clientID, self, 'Connect')
            except Exception as e:
                pass

    def onClose(self):
        if self.requestObject.onMessage is not None:
            try:
                return self.requestObject.onClose(self.clientID, self, 'Close')
            except Exception as e:
                pass


class KsaRequestParse:
    Protocol = 'TCP'  # 请求协议类型 TCP、HTTP、HTTPS、WSS、WS等
    IsSSL = False
    IsZIP = False
    method = None
    Path = None
    onConnect = None
    onMessage = None
    onClose = None
    staticDir = None
    staticFile = None
    GET = None
    Body = None
    Header = None

    def __init__(self, req):
        """
        解析socket请求头
        :param req:
        """
        self.request = req

    def parse_qs(self, query_string, separator='&', assignment='=', array_syntax='[]', encoding='utf-8', errors='replace'):
        if not query_string:
            return None
        result_dict = {}
        # 将查询字符串分割成键值对
        pairs = query_string.split(separator)
        for pair in pairs:
            # 将每个键值对分割成键和值
            key, value = pair.split(assignment, 1)

            # 解码键和值
            key = key.decode(encoding, errors) if isinstance(key, bytes) else key
            value = value.decode(encoding, errors) if isinstance(value, bytes) else value

            # 检查键是否表示一个数组
            if array_syntax in key:
                key, _ = key.split(array_syntax, 1)
                # 初始化数组或追加到数组
                if key not in result_dict:
                    result_dict[key] = [value]
                else:
                    result_dict[key].append(value)
            else:
                result_dict[key] = value

        return result_dict

    def parse(self, HttpRouteMap: dict = None, WSMap: dict = None):
        """
        解析头信息
        :param RouteMap: 路径 绑定路由
        :param StaticMap: 静态资源 绑定路由
        :return:
        """
        if not self.request:
            return False

        lines = self.request.split('\r\n')

        # 解析请求行
        request_line = lines[0].split(' ')
        method, path, protocol = request_line
        self.Path = path

        if protocol[:4] == 'HTTP':
            self.Protocol = 'HTTP'
        elif protocol[:5] == 'HTTPS':
            self.Protocol = 'HTTPS'
            self.IsSSL = True

        if 'Sec-WebSocket-Key' in self.request and 'Upgrade: websocket' in self.request:
            self.Protocol = 'WebSocket'

        # 解析 URL
        parsed_url = urlparse(path)
        # 检查路由
        routeCheck = False
        if self.Protocol in ['HTTP', 'HTTPS'] and HttpRouteMap is not None:
            self.method = method
            for mth, p, dirs, onMessage in HttpRouteMap.values():
                if (parsed_url.path == p or parsed_url.path.find(p) == 0):
                    routeCheck = True
                    self.onMessage = onMessage
                    if dirs is not None:
                        self.staticDir = dirs
                        self.staticFile = parsed_url.path[len(dirs):]
                    break
        elif self.Protocol == 'WebSocket' and WSMap is not None:
            self.method = method
            for p, onConnect, onMessage, onClose, isZip in WSMap.values():
                if (parsed_url.path == p or parsed_url.path.find(p) == 0):
                    routeCheck = True
                    self.onMessage = onMessage
                    self.onConnect = onConnect
                    self.onClose = onClose
                    self.IsZIP = isZip
                    break

        # 路由检查不通过
        if not routeCheck:
            return False
        if self.Protocol in ['HTTP', 'HTTPS']:
            self.GET = {}
            get_query = self.parse_qs(parsed_url.query)
            if get_query is not None:
                self.GET = get_query

            self.Body = None
            self.Header = {}
            self.Header['method'] = method
            self.Header['path'] = parsed_url.path
            self.Header['protocol'] = protocol

            # 解析其他头部信息
            for line in lines[1:]:
                if not line:
                    break  # 头部结束
                key, value = line.split(': ', 1)
                self.Header[key] = value

            # 解析消息体
            if '' in lines:
                body_start = lines.index('') + 1
                self.Body = '\r\n'.join(lines[body_start:])

            # print('self.GET', self.GET)
            # print('self.Header', self.Header)
            # print('self.Body', self.Body)

        return True


class ColoredFormatter(logging.Formatter):
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


class KsaSocket:
    __Host = ''
    __Port = 0
    __Exit = False

    __STATIC = {}  # 静态资源绑定 key=访问路径 value=文件目录地址
    __ROUTE_HTTP = {}  # 路由列表 key=访问路径 value=回调函数
    __ROUTE_WebSocket = {}

    __TCP_onConnect = None
    __TCP_onMessage = None
    __TCP_onClose = None
    __TCP_ZIP = False
    __TCP_ClientListMap = {}
    __TCP_bufferSize = 1024
    __TCP_Nodelay = False
    __TCP_bufferHead = ''
    __TCP_bufferFooter = ''
    __TCP_Threads = []
    __TCP_listenNum = 100
    __TCP_ReuseAddr = False

    __WebSocket_ClientListMap = {}

    def __init__(self, host: str = '0.0.0.0', port: int = 8000, listenNum=100, reuseAddr=False):
        """
        初始化KsaSocket服务
        :param host: 网卡地址
        :param port: 服务端口
        :param listenNum: 监听客户端数量
        :param reuseAddr: 是否复用端口
        """
        self.__Host = host
        self.__Port = port
        self.__TCP_listenNum = listenNum
        self.__TCP_ReuseAddr = reuseAddr
        self.__Exit = False
        self.__TCP_SendQueueCommon = queue.Queue()

        self.__initLog__()
        self.logger.info(f'服务初始化：host={host}:{port}')

    def __initLog__(self):

        # 创建一个格式化器，用于自定义日志的输出格式
        formatter = ColoredFormatter('[%(asctime)s] [%(name)s - %(levelname)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

        # 创建一个控制台处理器，将日志输出到控制台
        console_handler = logging.StreamHandler()

        # 将格式化器添加到处理器
        console_handler.setFormatter(formatter)

        # 获取根记录器（root logger）并将控制台处理器添加到根记录器
        root_logger = logging.getLogger()
        root_logger.addHandler(console_handler)

        # 创建一个自定义的记录器
        logger = logging.getLogger('KsaSocket')

        # 设置日志级别
        logger.setLevel(logging.DEBUG)

        self.logger = logger

    def http(self, path: str = '', method: str = 'GET', dirs: str = None, onMessage=None):
        """
        绑定HTTP路由
        :param path: 访问路径
        :param method: 请求类型 GET, POST, TCP, WS, WSS
        :param callback: 回调函数 参数1=ClientSocket对象 参数2=消息内容
        :return:
        """
        if onMessage is None:
            return False

        if path:
            if path[0] != '/':
                path = '/' + path
            self.__ROUTE_HTTP[path] = (method, path, dirs, onMessage)
            return True
        return False

    def ws(self, path: str = '', onConnect=None, onMessage=None, onClose=None, isZip=False):
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
            if path[0] != '/':
                path = '/' + path
            self.__ROUTE_WebSocket[path] = (path, onConnect, onMessage, onClose, isZip)
            return True
        return False

    def tcp(self, bufferSize: int = 0, onConnect=None, onMessage=None, onClose=None, bufferHead="", bufferFooter="", isZip=False, nodelay=False):
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
        self.logger.info(repr(f'启用TCP服务 bufferSize={bufferSize} bufferHead={bufferHead} bufferFooter={bufferFooter} isZip={isZip} nodelay={nodelay}'))
        self.__TCP_onConnect = onConnect
        self.__TCP_onMessage = onMessage
        self.__TCP_onClose = onClose
        self.__TCP_ZIP = isZip
        self.__TCP_bufferSize = bufferSize
        self.__TCP_Nodelay = nodelay
        self.__TCP_bufferHead = bufferHead
        self.__TCP_bufferFooter = bufferFooter
        return False

    def __response_http(self, client_socket=None, CtSocket: KsaClientSocket = None):
        """
        响应 HTTP请求 包含HTTPS
        :param client_socket:
        :param ReqParse:
        :param CtSocket:
        :return:
        """
        if CtSocket.Method in ['GET', 'POST', 'PUT', 'PATCH', 'DELETE']:
            ContentType = 'text/html'
            replyMessage = CtSocket.onMessage(msg=CtSocket.requestObject.Body)
            if replyMessage is not None:
                if isinstance(replyMessage, dict) or isinstance(replyMessage, list):
                    replyMessage = json.dumps(replyMessage, ensure_ascii=False)
                    ContentType = 'application/json'

            response = f"HTTP/1.1 200 OK\nContent-Type: {ContentType}; charset=utf-8\n\n"

            if replyMessage is not None:
                response += replyMessage

            CtSocket.send(response)

        elif CtSocket.requestObject.staticDir and CtSocket.requestObject.staticFile:  # 静态资源文件请求
            # 根据静态目录地址和文件组合需要返回的文件路径
            resource_file = os.path.join(CtSocket.requestObject.staticDir, CtSocket.requestObject.staticFile)
            if os.path.exists(resource_file):
                with open(resource_file, 'rb') as file:
                    file_content = file.read()
                    response = f"HTTP/1.1 200 OK\r\nContent-Length: {len(file_content)}\r\n\r\n"
                    CtSocket.send(response.encode('utf-8') + file_content)
            else:
                self.logger.debug('404 文件不存在：', resource_file)
                response = "HTTP/1.1 404 Not Found\nContent-Type: text/plain; charset=utf-8\n\n文件不存在！"
                CtSocket.send(response)

        CtSocket.close()

    def __response_WebSocket(self, client_socket=None, CtSocket: KsaClientSocket = None):
        """
        响应 WebSocket 请求
        :param client_socket:
        :param CtSocket:
        :return:
        """
        # 设置为非阻塞模式
        client_socket.setblocking(False)
        self.__WebSocket_ClientListMap[CtSocket.clientID] = client_socket
        self.logger.debug(f'WebSocket 新连接 {CtSocket.clientID}')
        KsaWebSocket.send_Protocols(client_socket, CtSocket.request)
        CtSocket.onConnect()
        # 循环处理 WebSocket 数据
        while not self.__Exit and not CtSocket.Exit:
            try:
                data = client_socket.recv(2048)
                if data == b'' or data[0] == 0x88:
                    self.logger.warning('客户端断开')
                    CtSocket.onClose()
                    break
                if data is not None or data != b'':
                    message = KsaWebSocket.decode(data)
                    # 消息回调给路由绑定函数
                    try:
                        replyMessage = CtSocket.onMessage(msg=message)
                        if replyMessage is not None:
                            CtSocket.send(replyMessage, CtSocket.requestObject.IsZIP, isWebSocket=True)
                    except Exception as e:
                        pass

            except  socket.error as e:
                if e.errno not in [10035]:
                    self.logger.error('消息报错：', e)
                    CtSocket.onClose()

            time.sleep(0.0001)
        CtSocket.close()

    def __response_TCP(self, client_socket=None, CtSocket: KsaClientSocket = None):
        # 设置为非阻塞模式
        client_socket.setblocking(False)
        self.__TCP_ClientListMap[CtSocket.clientID] = CtSocket
        self.logger.debug(f'TCP新连接 {CtSocket.clientID}')

        CtSocket.onConnect()

        while not self.__Exit and not CtSocket.Exit:
            try:
                # 接收数据
                data = client_socket.recv(self.__TCP_bufferSize)
                if data:
                    if self.__TCP_ZIP:
                        data = zlib.decompress(data)

                    data = data.decode('utf-8')

                    if self.__TCP_onMessage is not None:
                        try:
                            self.__TCP_onMessage(CtSocket.clientID, data)
                        except Exception as e:
                            pass

            except socket.error as e:
                if e.errno not in (socket.EWOULDBLOCK, 10035):
                    self.logger.debug(f'TCP客户端 断开 IP={CtSocket.ip}:{CtSocket.port} socket.error={e.errno}')
                    # 关闭客户端连接
                    client_socket.close()
                    try:
                        del self.__TCP_ClientListMap[CtSocket.clientID]
                    except Exception as e:
                        pass

                    try:
                        self.__TCP_onClose(CtSocket.clientID)
                    except Exception as e:
                        pass
            time.sleep(0.001)

    def __thread_handle(self, client_socket, addr):
        self.logger.debug(f"新客户端请求 {addr[0]}:{addr[1]}")
        request = None

        try:
            request = client_socket.recv(1024)
        except BlockingIOError:
            client_socket.close()
            return

        CtSocket = KsaClientSocket(socket=client_socket, request=request, addr=addr)
        checkRes = CtSocket._RouteParse(self.__ROUTE_HTTP, self.__ROUTE_WebSocket)
        if not checkRes:
            self.logger.error(f'错误的请求 {addr[0]}:{addr[1]} Protocol={CtSocket.Protocol} / {CtSocket.Method} Protocol={CtSocket.Path}')
            # print('request', request)
            client_socket.close()
            return

        if CtSocket.Protocol in ['HTTP', 'HTTPS']:
            self.__response_http(client_socket=client_socket, CtSocket=CtSocket)

        elif CtSocket.Protocol == 'WebSocket':
            self.__response_WebSocket(client_socket=client_socket, CtSocket=CtSocket)

        elif CtSocket.Protocol == 'TCP':
            self.__response_TCP(client_socket=client_socket, CtSocket=CtSocket)

    def _listenClient(self):
        self.logger.debug('TCP 客户端监听线程 启动')
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
        self.logger.debug('TCP 客户端监听线程 结束')

    def start(self):
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

            self.Socket = Socket
            ths = threading.Thread(target=self._listenClient, daemon=True)
            ths.start()
            self.__TCP_Threads.append(ths)

            ths = threading.Thread(target=self._Thread_TCP_SendQueue, daemon=True)
            ths.start()
            self.__TCP_Threads.append(ths)
            self.logger.info(f'服务启动：host={self.__Host}:{self.__Port}')
        except socket.error as e:
            self.logger.error(f'服务启动失败 host={self.__Host}:{self.__Port} e.errno={e.errno} 端口被占用了吗？')
            self.close()
        except Exception as e:
            pass

    def _Thread_TCP_SendQueue(self):
        self.logger.debug('TCP 全局消息线程 启动')
        while not self.__Exit:
            if self.Socket is None:
                time.sleep(0.01)
                continue

            del_clients = []
            try:
                data = self.__TCP_SendQueueCommon.get(block=False)
                if data:
                    for clientID, socket in self.__TCP_ClientListMap.items():
                        # self._debug(f'发送数据给{addr} data={data}')
                        if self.__Exit:
                            break
                        socket.send(msg=data)

            except Exception as e:
                pass

            for clientID in del_clients:
                del self.__TCP_ClientListMap[clientID]

            time.sleep(0.0001)
        self.logger.debug('TCP 全局消息线程 结束')

        # server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # server.bind((self.__Host, self.__Port))
        # server.listen(5)
        # self.logger.info(f'服务启动：host={self.__Host} port={self.__Port} 阻塞运行中')
        #
        # while not self.__Exit:
        #     client_socket, addr = server.accept()
        #     # 处理每个连接的客户端的线程
        #     threading.Thread(target=self.__thread_handle, args=(client_socket, addr,), daemon=True).start()

    def close(self):
        """
        主动结束
        :return:
        """
        if not self.__Exit:
            self.logger.debug('结束中')
            self.__Exit = True
            for thread in self.__TCP_Threads:
                thread.join()
            self.logger.debug('停止运行')
    def running(self):
        """
        服务是否运行中
        :return:
        """
        return not self.__Exit