# cython: language_level=3

import base64
import hashlib
import struct


class KsaCoder:
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
    def send_Protocols(client_socket, WebSocketKey):
        """
        向客户端发送wss升级协议
        :param client_socket:
        :param client_request:
        :return:
        """
        # 提取 WebSocket key
        # key = client_request.split('Sec-WebSocket-Key: ')[1].split('\r\n')[0]

        response_key = base64.b64encode(hashlib.sha1((WebSocketKey + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode('utf-8')).digest()).decode('utf-8')

        # 发送 WebSocket 握手响应
        response = "HTTP/1.1 101 Switching Protocols\r\n"
        response += "Upgrade: websocket\r\n"
        response += "Connection: Upgrade\r\n"
        response += f"Sec-WebSocket-Accept: {response_key}\r\n\r\n"

        client_socket.send(response.encode('utf-8'))
