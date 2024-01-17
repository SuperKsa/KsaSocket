# cython: language_level=3

import json
import zlib


from .KsaCoder import KsaCoder

cdef class Csocket:
    cdef:
        object KSA
        object socket
        str request
        str _UrlQuery
        dict _GET
        dict _POST
        dict _HEADER
        str _BODY
        bint Exit  # 客户端是否退出
        str _ip  # 客户端 IP
        int _port  # 客户端 端口
        str _clientID  # 客户端ID IP:端口
        str _Protocol  # 协议类型
        str _Path  # HTTP 请求路径
        str _Method
        object _onConnect
        object _onMessage
        object _onClose
        dict SetHeader
        double _onMessage_Recv_time # TCP原始数据读取时的时间戳
        bint _isZip  # 是否需要压缩数据
        bytes _bufferHead
        bytes _bufferFooter

    def __init__(self, KSA:object=None, socket:object=None, request: bytes = b'', addr:object=None):
        """
        客户端对象 回调到外部的socket对象
        :param socket:
        :param request:
        :param addr:
        """

        self._GET = {}
        self._POST = {}
        self._HEADER = {}
        self._BODY = None
        self.Exit = False  # 客户端是否退出
        self._Protocol = 'TCP'  # 协议类型
        self._Path = ''  # HTTP 请求路径
        self._Method = ''
        self._onConnect = None
        self._onMessage = None
        self._onClose = None
        self.SetHeader = {}
        self._onMessage_Recv_time = 0  # TCP原始数据读取时的时间戳

        self.KSA = KSA
        self.socket = socket
        if request is not None:
            self.request = request.decode('utf-8')

        self._ip = addr[0]
        self._port = addr[1]
        self._clientID = f'{addr[0]}:{addr[1]}'
        self._isZip = False

    def set_RouteParse(self, Protocol, Path, UrlQuery, method, Header, Body, GET, POST):
        """
        写入请求解析数据
        :param Protocol:
        :param Path:
        :param UrlQuery:
        :param method:
        :param Header:
        :param Body:
        :return:
        """
        # print('Csocket 写入请求解析数据', Protocol, Path, UrlQuery, method, Header, Body, GET, POST)
        self._HEADER = Header
        self._BODY = Body
        self._GET = GET
        self._POST = POST
        self._UrlQuery = UrlQuery
        self._Protocol = Protocol
        self._Path = Path
        self._Method = method



    def setMsgConfig(self, bint isZip=False, str bufferHead='', str bufferFooter=''):
        self._isZip = isZip

        if bufferHead:
            self._bufferHead = bufferHead.encode('utf-8')

        if bufferFooter:
            self._bufferFooter = bufferFooter.encode('utf-8')

    def _setCallbackEvent(self, onConnect:object=None, onMessage:object=None, onClose:object=None):
        self._onConnect = onConnect
        self._onMessage = onMessage
        self._onClose = onClose

    def send(self, object msg=None):
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
                    if self._Protocol == 'WebSocket':
                        message = KsaCoder.encode(message)

                    if self._isZip:
                        message = zlib.decompress(message)

                    # 包头包尾组合
                    sendMessage = b""
                    if self._bufferHead:
                        sendMessage += self._bufferHead
                    sendMessage += message
                    if self._bufferFooter:
                        sendMessage += self._bufferFooter
                    message = None

                    self.socket.sendall(sendMessage)
                    return True
            except Exception as e:
                return False

    def set_header(self, key:str='', value:str=''):
        """
        响应header 写入
        :param key:
        :param value:
        :return:
        """
        self.SetHeader[key] = value

    def get_header(self):
        """
        响应header 读取所有
        :return:
        """
        hds = {}
        for key, value in self.SetHeader.items():
            hds[key] = value
        return hds


    def close(self):
        """
        主动断开客户端
        :return:
        """

        status = None
        try:
            status = self.socket.close()
        except Exception as e:
            pass
        self.onClose()
        self.Exit = True
        return status

    def recv(self, buffersize:int=0, flags=None):
        return self.socket.recv(buffersize)

    def Protocol(self):
        return self._Protocol

    def path(self):
        return self._Path

    def method(self):
        return self._Method

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

    def Header(self):
        """
        返回客户端的header
        :return:
        """
        return self._HEADER


    def onMessage(self, msg=None, double recv_time=0.):
        self._onMessage_Recv_time = recv_time
        if self._onMessage is not None:
            try:
                return self._onMessage(self._clientID, self, msg)
            except Exception as e:
                pass

    def onMessageRecv_time(self):
        return self._onMessage_Recv_time

    def onConnect(self):
        if self._onConnect is not None:
            try:
                return self._onConnect(self._clientID, self, 'Connect')
            except Exception as e:
                pass

    def onClose(self):
        # 清理KSA TCP 客户端

        self.KSA._clientMapRemove(self._clientID)

        closeRes = None
        if self._onClose is not None:
            # 触发回调函数
            try:
                closeRes = self._onClose(self._clientID, self, 'Close')
            except Exception as e:
                pass

        return closeRes

    def clientID(self):
        """
        返回客户端ID
        :return:
        """
        return self._clientID

    def ip(self):
        """
        返回客户端IP
        :return:
        """
        return self._ip

    def port(self):
        """
        返回客户端IP端口
        :return:
        """
        return self._port

    def connectEd(self):
        """
        返回客户端是否连接
        :return:
        """
        return not self.Exit