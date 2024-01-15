import signal
import time

from KsaSocket import KsaSocket


def httpcall(clientID='', con=None, msg=None):
    print('main_Callback http请求回调')
    return ['hi 欢迎']


def wss_onConnect(clientID='', con=None, msg=None):
    print(f'main_Callback wss 连接 ip={con.ip}, port={con.port}')
    return 'Pong'


def wss_onMessage(clientID='', con=None, msg=None):
    # print('wss连接回调')
    return 'Pong'


def wss_onClose(clientID='', con=None, msg=None):
    print(f'main_Callback wss 关闭 ip={con.ip}, port={con.port}')
    return 'Pong'


def tcp_onConnect(clientID='', con=None, msg=None):
    print(f'main_Callback wss 连接 ip={con.ip}, port={con.port}')
    return 'Pong'


def tcp_onMessage(clientID='', con=None, msg=None):
    # print('wss连接回调')
    return 'Pong'


def tcp_onClose(clientID='', con=None, msg=None):
    print(f'main_Callback wss 关闭 ip={con.ip}, port={con.port}')
    return 'Pong'


kss = KsaSocket(host='0.0.0.0', port=8765)
kss.http('/index', method='GET', onMessage=httpcall)
kss.http('/hhh', dirs='./www')
kss.ws('/wss', onConnect=wss_onConnect, onMessage=wss_onMessage, onClose=wss_onClose)
kss.tcp(bufferSize=1024, bufferHead='\t', bufferFooter='\f', onConnect=tcp_onConnect, onMessage=tcp_onMessage, onClose=tcp_onClose)
kss.start()

IsMainExit = False


def signal_handler(signal, frame):
    global IsMainExit
    IsMainExit = True
    print("收到 Ctrl+C 信号，程序即将退出。")
    # 在这里添加一些清理操作，然后退出程序


# 注册信号处理程序
signal.signal(signal.SIGINT, signal_handler)

while not IsMainExit and kss.running():
    time.sleep(0.1)

kss.close()

print("程序退出")