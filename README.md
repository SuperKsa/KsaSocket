# KsaSocket (Python)

### 非阻塞多线程一个端口同时启用HTTP、WebSocket、TCP服务端的基础框架，高性能！高性能！高性能！


#### 骚技能(Niu.B KungFu)：
- 以socket原生作为载体通过一个端口同时启用HTTP、WebSocket、TCP服务端。
- (En↑:Rocking native sockets to host HTTP, WebSocket, and TCP services on a single port like it's a piece of cake.)
- 语法干净，不骚！基本无视Python版本迭代影响
- (En↑:Syntax so clean it makes angels jealous! Python version changes? Pff, practically invisible.)
- 采用非阻塞多线程，启动服务后还能继续干别的事儿。
- (En↑:Riding the non-blocking multithreading wave – start the service and still have time to conquer other realms.)
- 高性能粘包分包，TCP消息不漏！
- (En↑:Juggling packets with high-performance finesse, no TCP messages playing hide and seek!)
- 纯底层坚实底层框架，其他骚操作自行在框架上实现。
- (En↑:A hardcore, rock-solid framework at the bottom. Go ahead, add your own swag on top!)



### 如何使用？
```
python >= 3.7
原生即可
```

```angular2html
# 初始化
kss = KsaSocket(host='0.0.0.0', port=8765)
# 绑定http路由
kss.http('/index', method='GET', onMessage=回调函数)
# 绑定静态文件目录
kss.http('/html', dirs='./www')
# 绑定wss服务
kss.ws('/wss', onConnect=wss_onConnect, onMessage=wss_onMessage, onClose=wss_onClose)
# 监听TCP消息
kss.tcp(bufferSize=1024, bufferHead='\t', bufferFooter='\f', onConnect=tcp_onConnect, onMessage=tcp_onMessage, onClose=tcp_onClose)
# 启动服务
kss.start()

# 这里还能继续干别的事情
while kss.running():
    time.sleep(0.1)

# 主动关闭
kss.close()

print("程序退出")
```