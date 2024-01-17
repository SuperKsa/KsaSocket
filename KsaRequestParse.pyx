# cython: language_level=3

import re
from urllib.parse import urlparse

from .KsaCoder import KsaCoder

HTTP_MIME = {
    'html': 'text/html; charset=utf-8',
    'htm': 'text/html; charset=utf-8',
    'css': 'text/css; charset=utf-8',
    'js': 'application/javascript',
    'json': 'application/json; charset=utf-8',
    'xml': 'application/xml; charset=utf-8',
    'pdf': 'application/pdf',
    'doc': 'application/msword',
    'docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'xls': 'application/vnd.ms-excel',
    'xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    'png': 'image/png',
    'jpg': 'image/jpeg',
    'jpeg': 'image/jpeg',
    'gif': 'image/gif',
    'bmp': 'image/bmp',
    'ico': 'image/x-icon',
    'txt': 'text/plain; charset=utf-8',
    'csv': 'text/csv; charset=utf-8',
    'zip': 'application/zip',
    'rar': 'application/x-rar-compressed',
}

def KsaRequestParse_HTTP_MIME(str fileName = ''):
    ext = fileName[fileName.rfind('.') + 1:].lower()
    mime = HTTP_MIME.get(ext)
    if not mime:
        mime = 'application/octet-stream'
    return mime


class KsaRequestParse:
    Protocol = 'TCP'  # 请求协议类型 TCP、HTTP、HTTPS、WSS、WS等
    IsSSL = False
    IsZIP = False
    method = None
    Path = None  # URL路径 头始终带/
    UrlQuery = None # URL get查询条件部分 ?之后
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

    MIME = None


    def __init__(self, bytes req=None):
        """
        解析socket请求头
        :param req:
        """
        self.request = req.decode('utf-8')
        self.http_mime_types = {
            'html': 'text/html; charset=utf-8',
            'htm': 'text/html; charset=utf-8',
            'css': 'text/css; charset=utf-8',
            'js': 'application/javascript',
            'json': 'application/json; charset=utf-8',
            'xml': 'application/xml; charset=utf-8',
            'pdf': 'application/pdf',
            'doc': 'application/msword',
            'docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            'xls': 'application/vnd.ms-excel',
            'xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            'png': 'image/png',
            'jpg': 'image/jpeg',
            'jpeg': 'image/jpeg',
            'gif': 'image/gif',
            'bmp': 'image/bmp',
            'ico': 'image/x-icon',
            'txt': 'text/plain; charset=utf-8',
            'csv': 'text/csv; charset=utf-8',
            'zip': 'application/zip',
            'rar': 'application/x-rar-compressed',
        }

    def get_mime(self, fileName:str=''):
        ext = fileName[fileName.rfind('.')+1:].lower()
        mime = self.http_mime_types.get(ext)
        if not mime:
            mime = 'application/octet-stream'
        return mime

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
        if self.method != 'POST':
            return

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
                for routePath in KsaCoder.parseCheckPath(self.Path, inverted=True):
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
                    if self.url_path != '/':
                        self.staticDir += self.url_path

            # print(f'路由检查2 bindPath={self.bindPath} Path={self.Path} staticDir={self.staticDir} staticFile={self.staticFile}')

            # 路由检查不通过
            if not self.onMessage and not self.staticDir:
                return False

        elif self.Protocol == 'WebSocket' and WSMap is not None:
            self.method = method
            routeObj = WSMap.get(self.Path)
            if routeObj is not None:
                self.onMessage = routeObj.get('onMessage')
                self.onConnect = routeObj.get('onConnect')
                self.onClose = routeObj.get('onClose')
                self.IsZIP = routeObj.get('isZip')

            # 路由检查不通过
            if not self.onMessage and not self.onConnect and not self.onClose:
                return False
        else:
            return False


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

        if self.Protocol == 'HTTP':
            self.UrlQuery = parsed_url.query
            self.parse_form_data()
            self.GET = {}
            get_query = self.parse_qs(parsed_url.query)
            if get_query is not None:
                self.GET = get_query

            self.Body = None

            # 解析消息体
            if '' in lines:
                body_start = lines.index('') + 1
                self.Body = '\r\n'.join(lines[body_start:])

        return True
