import base64
import hashlib
import json
import logging
import os
import queue
import re
import socket
import struct
import threading
import time
import zlib
from urllib.parse import urlparse

class WsSocket:
    @staticmethod
    def parseCheckPath(paths:str='', inverted=False):
        """
        生成检查路由 web访问时使用
        :param paths:
        :param inverted: 是否需要倒序
        :return:
        """
        pathArr = ['/']
        levelPath = ''
        for value in paths.strip('/').split('/'):
            value = '/'+value
            levelPath += value
            pathArr.append(levelPath)
        if inverted:
            return pathArr[::-1]  # 返回倒序数组
        else:
            return pathArr

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


class Csocket:
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
    _onConnect = None
    _onMessage = None
    _onClose = None
    SetHeader = {}

    def __init__(self, KSA, socket, request: bytes = b'', addr=None):
        """
        客户端对象 回调到外部的socket对象
        :param socket:
        :param request:
        :param addr:
        """
        self.KSA = KSA
        self.socket = socket
        if request is not None:
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
        self._POST = rParse.POST
        self.Protocol = rParse.Protocol
        self.Path = rParse.Path
        self.Method = rParse.method

        self._setCallbackEvent(rParse.onConnect, rParse.onMessage, rParse.onClose)

        return res

    def _setCallbackEvent(self, onConnect=None, onMessage=None, onClose=None):
        self._onConnect = onConnect
        self._onMessage = onMessage
        self._onClose = onClose

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
                        message = WsSocket.encode(message)

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

    def set_header(self, key, value):
        self.SetHeader[key] = value

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
        if self._onMessage is not None:
            try:
                return self._onMessage(self.clientID, self, msg)
            except Exception as e:
                pass

    def onConnect(self):
        if self._onConnect is not None:
            try:
                return self._onConnect(self.clientID, self, 'Connect')
            except Exception as e:
                pass

    def onClose(self):
        # 清理KSA TCP 客户端
        try:
            if self.KSA.__TCP_ClientListMap.__contains__(self.clientID):
                del self.KSA.__TCP_ClientListMap[self.clientID]
        except Exception as e:
            pass

        # 清理KSA WS 客户端
        try:
            if self.KSA.__WebSocket_ClientListMap.__contains__(self.clientID):
                del self.KSA.__WebSocket_ClientListMap[self.clientID]
        except Exception as e:
            pass

        if self._onClose is not None:
            # 触发回调函数
            try:
                return self._onClose(self.clientID, self, 'Close')
            except Exception as e:
                pass


class KsaRequestParse:
    Protocol = 'TCP'  # 请求协议类型 TCP、HTTP、HTTPS、WSS、WS等
    IsSSL = False
    IsZIP = False
    method = None
    Path = None  # URL路径 头始终带/
    url_path = None  # URL目录部分 头不带/ 尾始终带/
    url_file = None  # URL文件部分

    onConnect = None
    onMessage = None
    onClose = None
    staticDir = None
    staticFile = None
    GET = None
    POST = None
    Body = None
    Header = None
    bindPath = None



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

    def parse_form_data(self):
        request_header = self.request
        # 假设请求头中有Content-Type字段，指示为multipart/form-data
        content_type_match = re.search(r'Content-Type: multipart/form-data; boundary=(\S+)', request_header)

        if content_type_match:
            boundary = content_type_match.group(1)
            # 使用边界分割POST数据
            parts = request_header.split('--' + boundary)

            # 去除空白部分
            parts = [part.strip() for part in parts if part.strip()]

            # 解析每个部分的数据
            post_data_dict = {}
            for part in parts:
                # 假设每个部分的格式为Content-Disposition: form-data; name="key"
                disposition_match = re.search(r'Content-Disposition: form-data; name="(\S+)"', part)
                if disposition_match:
                    key = disposition_match.group(1)
                    # 假设数据是以两个换行符分割的
                    value = part.split('\r\n\r\n', 1)[1]
                    post_data_dict[key] = value
            self.POST = post_data_dict

    def parse_url_path_file(self, path):
        """
        解析请求地址中的路径与文件部分
        :param path:
        :return:
        """
        self.Path = '/' + path.lstrip('/')
        lastSp = path.rfind('/')  # 最后一个/的位置索引
        lastPath = path[lastSp:][1:]  # 最后一个/之后的路径
        firstPath = path[:lastSp]  # 最后一个/之前的路径
        isFileRoute = len(lastPath[lastPath.rfind('.'):]) > 1  # url是否存在文件名

        # print(f'self.Path={self.Path} firstPath={firstPath} lastPath={lastPath} isFileRoute={isFileRoute}')

        if isFileRoute:  # 如果当前url存在文件名
            self.url_path = firstPath
            self.url_file = lastPath
        else:  # 当前url不存在文件名 默认index
            self.url_path = path
            self.url_file = ''

        if self.url_path != '/':
            self.url_path = self.url_path.strip('/')+'/'

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


        if protocol[:4] != 'HTTP':
            return False

        self.Protocol = 'HTTP'
        if 'Sec-WebSocket-Key' in self.request and 'Upgrade: websocket' in self.request:
            self.Protocol = 'WebSocket'

        # 解析 URL
        parsed_url = urlparse(path)
        self.parse_url_path_file(parsed_url.path)

        # 检查路由
        if self.Protocol == 'HTTP' and HttpRouteMap is not None:
            self.method = method
            routeObj = HttpRouteMap.get(self.Path)
            if routeObj is not None:
                # print(f'请求路径={parsed_url.path} 路由路径={p} staticFile={staticFile}')
                route_onMessage = routeObj.get('onMessage')
                route_dir = routeObj.get('dir')
                if route_onMessage is not None:
                    self.bindPath = routeObj.get('path')
                    self.onMessage = route_onMessage

                if route_dir is not None:
                    self.staticDir = route_dir


            # 未找到路由时 从绑定的静态目录路由中查找静态文件
            if not self.onMessage and not self.staticDir:
                for routePath in WsSocket.parseCheckPath(self.Path, inverted=True):
                    routeObj = HttpRouteMap.get(routePath)
                    if not routeObj:
                        continue

                    route_dir = routeObj.get('dir')
                    # 从路由中找到祖先级静态路径
                    if route_dir is not None:
                        self.staticDir = route_dir
                        break

            if self.staticDir:
                lastSp = self.Path.rfind('/') # 最后一个/的位置索引
                lastPath = self.Path[lastSp:][1:] # 最后一个/之后的路径
                firstPath = self.Path[:lastSp] # 最后一个/之前的路径
                isFileRoute = len(lastPath[lastPath.rfind('.'):]) > 1 # url是否存在文件名

                # print(f'self.Path={self.Path} firstPath={firstPath} lastPath={lastPath} isFileRoute={isFileRoute}')

                if isFileRoute: # 如果当前url存在文件名
                    self.staticFile = lastPath
                    self.staticDir += firstPath
                else: # 当前url不存在文件名 默认index
                    self.staticFile = ''
                    self.staticDir += self.url_path

            # print(f'路由检查2 bindPath={self.bindPath} Path={self.Path} staticDir={self.staticDir} staticFile={self.staticFile}')



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
        if not self.onMessage and not self.staticDir:
            return False
        if self.Protocol == 'HTTP':
            self.parse_form_data()
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

        return True


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
        self.__initLog__()
        self.logger.info(f'初始化中')
        self.__Host = host
        self.__Port = port
        self.__TCP_listenNum = listenNum
        self.__TCP_ReuseAddr = reuseAddr
        self.__Exit = False
        self.__TCP_SendQueueCommon = queue.Queue()

        # 初始化父级路由


    def __initLog__(self):

        # 创建一个格式化器，用于自定义日志的输出格式
        formatter = logger_color_format('[%(asctime)s] [%(name)s - %(levelname)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

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
            self.logger.info(f'绑定WS服务 ws://{self.__Host}:{self.__Port}{path} isZip={isZip}')
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

    def __response_http(self, client_socket=None, CtSocket: Csocket = None):
        """
        响应 HTTP请求 包含HTTPS
        :param client_socket:
        :param ReqParse:
        :param CtSocket:
        :return:
        """
        headers = {}
        for key, value in CtSocket.SetHeader.items():
            headers[key] = value

        def get_header():
            hds = []
            for key, value in headers.items():
                hds.append(f"{key}: {value}")
            return "\r\n".join(hds)

        def set_header(key, value):
            headers[key] = value

        if CtSocket.requestObject.staticDir:  # 静态资源文件请求
            if CtSocket.requestObject.staticFile:
                staticFiles = [CtSocket.requestObject.staticFile]
            else:
                staticFiles = ['index.html', 'index.htm', 'default.htm', 'default.html']

            for value in staticFiles:
                resource_file = os.path.join(CtSocket.requestObject.staticDir, value)
                # 根据静态目录地址和文件组合需要返回的文件路径

                if os.path.isfile(resource_file):
                    with open(resource_file, 'rb') as file:
                        file_content = file.read()
                        set_header('Content-Length', len(file_content))
                        response = f"HTTP/1.1 200 OK\r\n{get_header()}\r\n\r\n"
                        CtSocket.send(response.encode('utf-8') + file_content)
                        CtSocket.close()
                        return

        if CtSocket.requestObject.bindPath and CtSocket.Method in ['GET', 'POST', 'PUT', 'PATCH', 'DELETE']:
            set_header('Content-Type', 'text/html; charset=utf-8')
            replyMessage = CtSocket.onMessage(msg=CtSocket.requestObject.Body)
            if replyMessage is not None:

                if isinstance(replyMessage, dict) or isinstance(replyMessage, list):
                    replyMessage = json.dumps(replyMessage, ensure_ascii=False)
                    set_header('Content-Type', 'application/json; charset=utf-8')

                response = f"HTTP/1.1 200 OK\r\n{get_header()}; charset=utf-8\r\n\r\n".encode('utf-8')

                if isinstance(replyMessage, bytes):
                    response += replyMessage
                else:
                    response += replyMessage.encode('utf-8')
                CtSocket.send(response)
                CtSocket.close()
                return

        CtSocket.send(b"HTTP/1.1 404 NotFound\r\n")
        CtSocket.close()

    def __response_WebSocket(self, client_socket=None, CtSocket: Csocket = None):
        """
        响应 WebSocket 请求
        :param client_socket:
        :param CtSocket:
        :return:
        """
        # 设置为非阻塞模式
        client_socket.setblocking(False)
        self.__WebSocket_ClientListMap[CtSocket.clientID] = client_socket
        self.logger.debug(f'WebSocket 连接 {CtSocket.clientID}')
        WsSocket.send_Protocols(client_socket, CtSocket.request)
        CtSocket.onConnect()
        # 循环处理 WebSocket 数据
        while not self.__Exit and not CtSocket.Exit:
            try:
                data = client_socket.recv(self.__TCP_bufferSize)
                if data == b'' or data[0] == 0x88:
                    self.logger.debug(f'WebSocket 断开 {CtSocket.clientID}')
                    CtSocket.onClose()
                    break
                if data is not None or data != b'':
                    message = WsSocket.decode(data)
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

    def __response_TCP(self, client_socket=None, CtSocket: Csocket = None):
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
                    CtSocket.onMessage(data)

            except socket.error as e:
                if e.errno not in (socket.EWOULDBLOCK, 10035):
                    self.logger.debug(f'TCP客户端 断开 IP={CtSocket.ip}:{CtSocket.port} socket.error={e.errno}')
                    # 关闭客户端连接
                    CtSocket.close()
                    try:
                        self.__TCP_onClose(CtSocket.clientID)
                    except Exception as e:
                        pass
            time.sleep(0.001)

    def __thread_handle(self, client_socket, addr):
        request = None
        try:
            request = client_socket.recv(1024)
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
            checkRes = CtSocket._RouteParse(self.__ROUTE_HTTP, self.__ROUTE_WebSocket)
            if not checkRes:
                self.logger.error(f'错误的请求 {addr[0]}:{addr[1]} Protocol={CtSocket.Protocol} / {CtSocket.Method} Path={CtSocket.Path}')
                # print('request', request)
                client_socket.close()
                return

            # self.logger.debug(f"新客户端请求 {addr[0]}:{addr[1]} 协议={CtSocket.Protocol}")

            if CtSocket.Protocol == 'HTTP':
                self.__response_http(client_socket=client_socket, CtSocket=CtSocket)

            elif CtSocket.Protocol == 'WebSocket':
                self.__response_WebSocket(client_socket=client_socket, CtSocket=CtSocket)
            else:
                client_socket.close()

        if Protocol == 'KSASocket':
            client_socket.sendall(b"\t\fKsaSocket\f\t")
            CtSocket._setCallbackEvent(onConnect=self.__TCP_onConnect, onMessage=self.__TCP_onMessage, onClose=self.__TCP_onClose)
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
            if len(self.__ROUTE_HTTP):
                self.logger.info(f'HTTP服务 http://{self.__Host}:{self.__Port}')


            self.logger.info(f'启动成功：host={self.__Host}:{self.__Port} 端口复用={self.__TCP_ReuseAddr} 客户端容量={self.__TCP_listenNum}')
        except socket.error as e:
            self.logger.error(f'服务启动失败 host={self.__Host}:{self.__Port} e.errno={e.errno} 端口被占用了吗？')
            self.close()
        except Exception as e:
            pass

    def _Thread_TCP_SendQueue(self):
        self.logger.debug('TCP 全局消息线程 启动')

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
                    for socket in self.__TCP_ClientListMap.values():
                        res = socket.send(msg=data, bufferHead=self.__TCP_bufferHead, bufferFooter=self.__TCP_bufferFooter, iszip=self.__TCP_ZIP)
                        if not res:
                            try:
                                del self.__TCP_ClientListMap[socket.clientID]
                            except Exception as e:
                                pass

            except Exception as e:
                print('TCP 全局消息线程报错：', e)
                pass

            try:
                for clientID in del_clients:
                    del self.__TCP_ClientListMap[clientID]
            except Exception as e:
                pass

            time.sleep(0.001)
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

    def sendAll(self, data=None):
        """
        发送消息给所有TCP客户端
        :param data:
        :return:
        """
        # print('KsaSocket 发送消息给所有TCP客户端', data)
        self.__TCP_SendQueueCommon.put(data)

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