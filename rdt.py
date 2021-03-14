import asyncio
import struct
from enum import Enum
from queue import Queue

from USocket import UnreliableSocket
import threading
import time

start_time = 0

# 校验和检测
def checkSUM(packet):
    checksum = 0
    for i in range(int(len(packet) / 2)):
        checksum += int.from_bytes(packet[2 * i:2 * i + 2], "big", signed=False)
        if checksum > 0xFFFF:
            checksum &= 0xFFFF  # 强制截断
            checksum += 1
    if len(packet) % 2 == 1:
        checksum += packet[-1] << 8
        if checksum > 0xFFFF:
            checksum &= 0xFFFF  # 强制截断
            checksum += 1
    if checksum & 0xffff == 0xffff:
        return True
    else:
        return False

# 产生校验和
def produce_checkSUM(packet):
    checksum = 0
    for i in range(int(len(packet) / 2)):
        checksum += int.from_bytes(packet[2 * i:2 * i + 2], "big", signed=False)
        if checksum > 0xFFFF:
            checksum &= 0xFFFF  # 强制截断
            checksum += 1
    if len(packet) % 2 == 1:
        checksum += packet[-1] << 8
        if checksum > 0xFFFF:
            checksum &= 0xFFFF  # 强制截断
            checksum += 1
    return ~checksum

# 解包
def unpack(packet):
    if checkSUM(packet):
        CHECKSUM, flags_length, SEQ, SEQ_ACK = struct.unpack(">HHHH", packet[:8])
        flags = flags_length
        return udp_header(flags, SEQ, SEQ_ACK=SEQ_ACK, CHECKSUM=CHECKSUM, data=packet[8:])
    else:
        return None


class udp_header:
    # 报文头
    def __init__(self, flags=0, SEQ=0, SEQ_ACK=0, CHECKSUM=0, data=b''):
        self.ACK = (flags & 0x4) >> 2
        self.SYN = (flags & 0x2) >> 1
        self.FIN = flags & 0x1
        self.RES = flags >> 3  # 回复的是哪个包
        self.SEQ = SEQ
        self.SEQ_ACK = SEQ_ACK
        self.CHECKSUM = CHECKSUM
        self.data = data

    # 包装
    def pack(self):
        self.CHECKSUM = 0
        temp = str.format(">HHHH{}s", len(self.data))
        packet = struct.pack(temp, self.CHECKSUM, (self.ACK << 2 | self.SYN << 1 | self.FIN | self.RES << 3), self.SEQ,
                             self.SEQ_ACK, self.data)
        self.CHECKSUM = produce_checkSUM(packet)
        return struct.pack(temp, self.CHECKSUM & 0xFFFF, (self.ACK << 2 | self.SYN << 1 | self.FIN | self.RES << 3),
                           self.SEQ,
                           self.SEQ_ACK, self.data)


class SendWindow:
    def __init__(self, send_base, rwnd):
        self.window = []
        self.send_base = send_base
        self.nextseqnum = send_base
        self.max = 9999999
        self.rwnd = rwnd
        self.ackTime = 0

    def isFull(self):
        return self.max == len(self.window)

    def isEmpty(self):
        return len(self.window) == 0

    def append(self, content):
        if self.isFull():
            return
        # print(content)
        self.window.append(content)

    # 得到下一个未发送的包
    def getItemToSend(self):
        if self.nextseqnum < self.send_base + self.rwnd and self.nextseqnum - self.send_base < len(self.window):
            item = self.window[self.nextseqnum - self.send_base]
            self.nextseqnum += 1
            # print("getItem:", self.nextseqnum, self.send_base, ": ", item)
            return (item, self.nextseqnum - 1)
        return None

    def getContentBySeqnum(self, seqnum):
        if self.send_base <= seqnum < self.send_base + len(self.window):
            if seqnum == self.nextseqnum:
                self.nextseqnum += 1
            # print("gerContent", seqnum, ": ", self.window[seqnum - self.send_base])
            return self.window[seqnum - self.send_base]
        return None

    def update(self, seqnum):
        if seqnum == self.send_base:
            self.ackTime += 1
        else:
            n = seqnum - self.send_base
            self.ackTime = 0
            for i in range(n):
                self.window.pop(0)
                self.send_base += 1

    # 得到多个未发送的包
    def getSendList(self, cwnd):
        cwnd = min(cwnd, self.rwnd, len(self.window))
        List = []
        while cwnd + self.send_base > self.nextseqnum:
            List.append(self.getItemToSend())
        return List


class ReciveWindow:
    def __init__(self, recv_base, rwnd=1000):
        self.window = []
        self.recv_base = recv_base
        self.rwnd = rwnd
        self.buffer = []
        self.lock = threading.Lock()
        for i in range(rwnd):
            self.window.append(None)

    # recv窗口插入数据
    def insert(self, seqnum, content):
        self.lock.acquire()
        if self.window[seqnum - self.recv_base] is None:
            self.window[seqnum - self.recv_base] = content
            if seqnum == self.recv_base:
                self.update()
        self.lock.release()

    # 更新recv窗口
    def update(self):
        while self.window[0] is not None:
            self.buffer += self.window.pop(0)
            self.recv_base += 1
            self.window.append(None)


# 服务器状态
class State(Enum):
    CLOSED = 0
    LISTEN = 1
    SYN_RCVN = 2
    ESTABLISHED = 3
    CLOSN_WAIT = 4
    LAST_ACK = 5
    SYN_SEND = 6
    FIN_SEND = 7
    FIN_WAIT1 = 8
    FIN_WAIT2 = 9
    TIME_WAIT = 10
    FIN_server = 11

# 传输状态
class Trans_state(Enum):
    slow_start = 1
    Congestion_avoidance = 2
    Fast_recovery = 3


class RDTSocket(UnreliableSocket):
    """
    The functions with which you are to build your RDT.
    -   recvfrom(bufsize)->bytes, addr
    -   sendto(bytes, address)
    -   bind(address)

    You can set the mode of the socket.
    -   settimeout(timeout)
    -   setblocking(flag)
    By default, a socket is created in the blocking mode.
    https://docs.python.org/3/library/socket.html#socket-timeouts

    """

    def __init__(self, rate=None, debug=True, mode=0, parentsocker=None):
        super().__init__(rate=rate)
        self.tran_state = Trans_state.slow_start
        self._rate = rate
        self._send_to = None
        self._recv_from = None
        self.debug = debug
        self.send_window = None
        self.recv_window = None
        self.timeOut = 0.02

        if parentsocker is None:
            self.true_socker = self
        else:
            self.true_socker = parentsocker
        self.timer = None
        self.TimeoutInterval = 0.05  # ttl
        self.send_lock = threading.Lock()

        self.cwnd = 1
        self.ssthresh = 8

        # send_list
        self.recv_ACK = None
        # client
        self.send_method_lock = threading.Lock()    # 发送窗口的线程锁
        self.server_isn = 0  # 记录建立连接客户端的SEQ
        self.client_isn = 0
        self.state = State.CLOSED
        self.bufferSize = 1024
        self.close_timer = None

        self.recv_lock = threading.Lock()

        # Serve
        self.ACK_Queue = Queue()  # ack信息队列
        self.model = mode  # 0代表主服务器，1代表次服务器， 2代表客户端

        self.rwnd = 1000
        self.wait_socket_dict = {}  # 等待建立
        self.build_socket_dict = {}  # 连接建立成功
        self.time_dict = {}         # 标记发送时间
        self.read_socket_dict = Queue()  # 等待accept读取连接列表
        self.Time_Wait_Timer = None
        self.State_lock = threading.Lock()

        threading.Thread(target=self.run).start()

    def accept(self):
        """
        Accept a connection. The socket must be bound to an address and listening for
        connections. The return value is a pair (conn, address) where conn is a new
        socket object usable to send and receive data on the connection, and address
        is the address bound to the socket on the other end of the connection.

        This function should be blocking.
        """
        #############################################################################
        # TODO: YOUR CODE HERE                                                      #
        #############################################################################
        while self.read_socket_dict.empty():
            continue
        addr = self.read_socket_dict.get()
        conn = self.build_socket_dict[addr]
        #############################################################################
        #                             END OF YOUR CODE                              #
        #############################################################################
        return conn, addr

    def connect(self, address: (str, int)):
        """
        Connect to a remote socket at address.
        Corresponds to the process of establishing a connection on the client side.
        """
        #############################################################################
        # TODO: YOUR CODE HERE                                                      #
        #############################################################################
        self.model = 2
        self.State_lock.acquire()
        if self.state == State.CLOSED:
            message = udp_header(flags=0x2, SEQ=self.client_isn).pack()
            self.true_socker.sendto(message, address)
            self.state = State.SYN_SEND
            self._send_to = address
            self._recv_from = address
            threading.Timer(2*self.TimeoutInterval, self.resend, [self.state, message]).start()
            threading.Thread(target=self.Client_receivemessage).start()
        self.State_lock.release()
        while self.state != State.ESTABLISHED:
            pass
        #############################################################################
        #                             END OF YOUR CODE                              #
        #############################################################################

    def recv(self, bufsize: int) -> bytes:
        """
        Receive data from the socket.
        The return value is a bytes object representing the data received.
        The maximum amount of data to be received at once is specified by bufsize.

        Note that ONLY data send by the peer should be accepted.
        In other words, if someone else sends data to you from another address,
        it MUST NOT affect the data returned by this function.
        """
        data = None
        assert self._recv_from, "Connection not established yet. Use recvfrom instead."
        #############################################################################
        # TODO: YOUR CODE HERE                                                      #
        #############################################################################
        while True:
            # 检测接受到的数据
            if len(self.recv_window.buffer) == 0:
                data = None
            elif len(self.recv_window.buffer) < bufsize:
                data = self.recv_window.buffer[:]
                self.recv_window.buffer = []
            else:
                data = self.recv_window.buffer[:bufsize]
                del self.recv_window.buffer[:bufsize]
            if data is not None:
                data = bytes(data)
                break
            elif self.state != State.ESTABLISHED and self.state != State.FIN_WAIT2 and self.state != State.FIN_WAIT1:
                break
        #############################################################################
        #                             END OF YOUR CODE                              #
        #############################################################################
        return data

    def send(self, byte_s: bytes):
        """
        Send data to the socket.
        The socket must be connected to a remote socket, i.e. self._send_to must not be none.
        """
        assert self._send_to, "Connection not established yet. Use sendto instead."
        #############################################################################
        # TODO: YOUR CODE HERE                                                      #
        #############################################################################
        global start_time
        start_time = time.time()
        self.State_lock.acquire()
        if self.state == State.ESTABLISHED:
            self.asy_send(byte_s)   # 发送窗口填充数据
        self.State_lock.release()
        #############################################################################
        #                             END OF YOUR CODE                              #
        #############################################################################

    def close(self):
        """
        Finish the connection and release resources. For simplicity, assume that
        after a socket is closed, neither futher sends nor receives are allowed.
        """
        #############################################################################
        # TODO: YOUR CODE HERE                                                      #
        #############################################################################
        # 监听的服务器关闭连接，依次关闭建立的连接
        if self.model == 0:
            for item in self.build_socket_dict.values():
                item.close()
            while len(self.build_socket_dict) != 0:
                pass
            self.State_lock.acquire()
            self.state = State.FIN_server
            self.State_lock.release()
        else:
            # 其他模式，照常发起4次回收
            self.State_lock.acquire()
            if self.state == State.ESTABLISHED:
                while self.state != State.CLOSED:
                    if self.send_window.isEmpty():
                        break
                message = udp_header(flags=0x1, SEQ=self.send_window.send_base, SEQ_ACK=self.recv_window.recv_base)
                message = message.pack()
                self.true_socker.sendto(message, self._send_to)
                self.state = State.FIN_WAIT1
                threading.Timer(2*self.TimeoutInterval, function=self.resend, args=(self.state, message,)).start()
            self.State_lock.release()
            while self.state != State.CLOSED:
                # print(self.state)
                pass
        #############################################################################
        #                             END OF YOUR CODE                              #
        #############################################################################
        super().close()

    # 判断挥手和握手的数据是否需要重发
    def resend(self, state, message):
        self.State_lock.acquire()
        if self.state == state:
            self.true_socker.sendto(message, self._send_to)
            # print("resend", self.state)
            threading.Timer(2*self.TimeoutInterval, function=self.resend, args=(state, message, )).start()
        self.State_lock.release()

    # 装填数据
    def asy_send(self, byte: bytes):
        begin = 0
        while begin < len(byte):
            if self.send_window.isFull():  # 窗口已经满了
                print('send window full')
                continue
            if len(byte) - begin >= self.bufferSize:
                content = byte[begin: begin + self.bufferSize]  # 每次读出来的文件内容
                self.send_lock.acquire()
                self.send_window.append(content)
                # print(self.send_window)
                # print(len(byte) - begin, '----------', self.bufferSize)
                self.send_lock.release()
                begin += self.bufferSize
            else:
                content = byte[begin:]  # 最后一次读出来的文件内容
                self.send_lock.acquire()
                self.send_window.append(content)
                self.send_lock.release()
                break

    # 服务器监听
    def run(self):
        while self.model == 0:
            if self.state == State.CLOSED:
                try:
                    message_addr = self.recvfrom(2000)
                except OSError:
                    continue
                if message_addr is None:
                    continue
                else:
                    message, addr = message_addr[0], message_addr[1]
                udp_message = unpack(message)
                if udp_message is not None:
                    # 判断发来的地址是否已经建立连接
                    if addr in self.wait_socket_dict and udp_message.SYN == 0 and udp_message.ACK == 1 \
                            and udp_message.SEQ == self.wait_socket_dict[addr][2] + 1 and udp_message.SEQ_ACK == \
                            self.wait_socket_dict[addr][1] + 1:
                        del self.wait_socket_dict[addr]
                        t_socket = RDTSocket(rate=self._rate, mode=1, parentsocker=self)
                        t_socket.send_window = SendWindow(udp_message.SEQ_ACK, self.rwnd)
                        t_socket.recv_window = ReciveWindow(udp_message.SEQ + 1, self.rwnd)
                        t_socket._send_to = addr
                        t_socket._recv_from = addr
                        t_socket.state = State.ESTABLISHED
                        t_socket.recv_ACK = threading.Thread(target=t_socket.recvACK)
                        t_socket.recv_ACK.start()
                        self.build_socket_dict[addr] = t_socket
                        self.read_socket_dict.put(addr)
                    # 如果是窗口转发
                    elif addr in self.build_socket_dict:
                        self.build_socket_dict[addr].Server_receivemessage(udp_message)
                    else:
                        # 如果是建立连接的消息，开始记录
                        if udp_message.SYN == 1 and udp_message.ACK == 0 and udp_message.FIN == 0:
                            if addr not in self.wait_socket_dict:
                                self.wait_socket_dict[addr] = [State.SYN_RCVN, udp_message.SEQ, 0]
                            temp = self.wait_socket_dict[addr]
                            respond = udp_header(flags=0x6, SEQ=temp[2], SEQ_ACK=temp[1] + 1)
                            self.true_socker.sendto(respond.pack(), addr)
                            threading.Timer(2*self.TimeoutInterval, self.SYNReceive, args=(addr, temp,)).start()

    # 第3次握手信息没有收到，重发第二次握手
    def SYNReceive(self, addr, temp):
        if addr not in self.build_socket_dict:
            respond = udp_header(flags=0x6, SEQ=temp[2], SEQ_ACK=temp[1] + 1)
            self.true_socker.sendto(respond.pack(), addr)
            threading.Timer(2*self.TimeoutInterval, self.SYNReceive, args=(addr, temp,)).start()

    # 传输cwnd值的包
    def transmit(self):
        List = self.send_window.getSendList(self.cwnd)
        for item in List:
            message = udp_header(flags=0x0, SEQ_ACK=self.recv_window.recv_base, SEQ=item[1],
                                 data=item[0])
            self.true_socker.sendto(message.pack(), self._send_to)
            self.send_list[self.send_window.send_base] = time.time()
        # 重新设置超时定时器
        self.timer.cancel()
        self.timer = threading.Timer(2 * self.TimeoutInterval, self.TimeOutAndReSend)
        self.timer.start()

    # 快速重传
    def fast_transmit(self, acknum):
        r_content = self.send_window.getContentBySeqnum(acknum)
        r_message = udp_header(flags=0x0, SEQ_ACK=self.recv_window.recv_base, SEQ=acknum, data=r_content)
        self.true_socker.sendto(r_message.pack(), self._send_to)
        self.send_list[self.send_window.send_base] = time.time()
        # 重新设置超时定时器
        self.timer.cancel()
        self.timer = threading.Timer(2 * self.TimeoutInterval, self.TimeOutAndReSend)
        self.timer.start()

    # 服务器接收信号
    def Server_receivemessage(self, message: udp_header):
        seqnum = message.SEQ
        Seqnum_ACK = message.SEQ_ACK
        RES = message.RES
        content = message.data
        self.State_lock.acquire()
        # 根据连接状态接受报文
        if self.state == State.SYN_SEND:
            if message.ACK == 1 and message.SYN == 1 and message.SEQ_ACK == self.client_isn + 1:
                self.server_isn = message.SEQ
                respond = udp_header(flags=0x4, SEQ=self.client_isn + 1, SEQ_ACK=self.server_isn + 1)
                self.true_socker.sendto(respond.pack(), self._send_to)
                self.send_window = SendWindow(self.client_isn + 2, self.rwnd)
                self.recv_window = ReciveWindow(self.server_isn + 1, self.rwnd)
                self.state = State.ESTABLISHED
                self.recv_ACK = threading.Thread(target=self.recvACK)
                self.recv_ACK.start()
        elif self.state == State.ESTABLISHED:
            if message.ACK == 1 and message.SYN == 1 and message.SEQ_ACK == self.client_isn + 1 and message.SEQ == self.server_isn:
                respond = udp_header(flags=0x4, SEQ=self.client_isn + 1, SEQ_ACK=self.server_isn + 1)
                self.true_socker.sendto(respond.pack(), self._send_to)
            elif message.ACK == 0 and message.SYN == 0 and message.FIN == 0:
                self.recv_window.insert(seqnum, content)
                # print(message.SEQ,": ", message.data)
                respond = udp_header(flags=(0x4 | ((seqnum << 3) & 0xFFFF)), SEQ=self.send_window.send_base,
                                     SEQ_ACK=self.recv_window.recv_base)
                self.true_socker.sendto(respond.pack(), self._send_to)
            elif message.ACK == 1 and message.SYN == 0 and message.FIN == 0:
                if RES in self.send_list:
                    self.TimeoutInterval = 0.875 * self.TimeoutInterval + 0.125 * (time.time() - self.send_list[RES]) # 计算rtt
                self.ACK_Queue.put(Seqnum_ACK)
            elif message.ACK == 0 and message.SYN == 0 and message.FIN == 1:
                self.recv_window.insert(seqnum, content)
                respond = udp_header(flags=0x4, SEQ=self.send_window.send_base, SEQ_ACK=self.recv_window.recv_base)
                self.true_socker.sendto(respond.pack(), self._send_to)
                self.state = State.CLOSN_WAIT
        elif self.state == State.FIN_WAIT1:
            if message.ACK == 0 and message.SYN == 0 and message.FIN == 0:
                self.recv_window.insert(seqnum, content)
                respond = udp_header(flags=(0x4 | ((seqnum << 3) & 0xFFFF)), SEQ=self.send_window.send_base,
                                     SEQ_ACK=self.recv_window.recv_base)
                self.true_socker.sendto(respond.pack(), self._send_to)
            elif message.ACK == 1 and message.SYN == 0 and message.FIN == 0:
                if self.send_window.send_base < message.SEQ_ACK:
                    self.send_window.send_base = message.SEQ_ACK
                self.state = State.FIN_WAIT2
            elif message.ACK == 1 and message.SYN == 1 and message.SEQ_ACK == self.client_isn + 1 and message.SEQ == self.server_isn:
                respond = udp_header(flags=0x4, SEQ=self.client_isn + 1, SEQ_ACK=self.server_isn + 1)
                self.true_socker.sendto(respond.pack(), self._send_to)
        elif self.state == State.FIN_WAIT2:
            if message.ACK == 0 and message.SYN == 0 and message.FIN == 0:
                self.recv_window.insert(seqnum, content)
                respond = udp_header(flags=(0x4 | ((seqnum << 3) & 0xFFFF)), SEQ=self.send_window.send_base,
                                     SEQ_ACK=self.recv_window.recv_base)
                self.true_socker.sendto(respond.pack(), self._send_to)
            elif message.ACK == 1 and message.SYN == 0 and message.FIN == 1:
                self.state = State.TIME_WAIT
                self.recv_window.insert(seqnum, content)
                respond = udp_header(flags=(0x4 | ((seqnum << 3) & 0xFFFF)), SEQ=self.send_window.send_base,
                                     SEQ_ACK=self.recv_window.recv_base)
                self.true_socker.sendto(respond.pack(), self._send_to)
                if self.send_window.send_base < message.SEQ_ACK:
                    self.send_window.send_base = message.SEQ_ACK
                self.Time_Wait_Timer = threading.Timer(8*self.TimeoutInterval, function=self.ChangeState, args=(State.CLOSED,))
                self.Time_Wait_Timer.start()
        elif self.state == State.TIME_WAIT:
            if message.ACK == 1 and message.SYN == 0 and message.FIN == 1:
                self.recv_window.insert(seqnum, content)
                respond = udp_header(flags=(0x4 | ((seqnum << 3) & 0xFFFF)), SEQ=self.send_window.send_base,
                                     SEQ_ACK=self.recv_window.recv_base)
                self.true_socker.sendto(respond.pack(), self._send_to)
                self.send_window.send_base = message.SEQ_ACK
                self.Time_Wait_Timer.cancel()
                self.Time_Wait_Timer = threading.Timer(8*self.TimeoutInterval, function=self.ChangeState, args=(State.CLOSED,))
                if self.send_window.send_base < message.SEQ_ACK:
                    self.send_window.send_base = message.SEQ_ACK
                self.Time_Wait_Timer.start()
        elif self.state == State.CLOSN_WAIT:
            if message.ACK == 1 and message.SYN == 0 and message.FIN == 0:
                if RES in self.send_list:
                    self.TimeoutInterval = 0.875 * self.TimeoutInterval + 0.125 * (time.time() - self.send_list[RES])
                self.ACK_Queue.put(Seqnum_ACK)
            elif message.ACK == 0 and message.SYN == 0 and message.FIN == 1:
                self.recv_window.insert(seqnum, content)
                respond = udp_header(flags=0x4, SEQ=self.send_window.send_base, SEQ_ACK=self.recv_window.recv_base)
                self.true_socker.sendto(respond.pack(), self._send_to)
        elif self.state == State.LAST_ACK:
            if message.ACK == 1 and message.SYN == 0 and message.FIN == 0:
                self.recv_window.insert(seqnum, content)
                respond = udp_header(flags=0x4, SEQ=message.SEQ_ACK, SEQ_ACK=self.recv_window.recv_base)
                self.true_socker.sendto(respond.pack(), self._send_to)
                self.state = State.CLOSED
            elif message.ACK == 0 and message.SYN == 0 and message.FIN == 1:
                self.recv_window.insert(seqnum, content)
                respond = udp_header(flags=0x4, SEQ=self.send_window.send_base, SEQ_ACK=self.recv_window.recv_base)
                self.true_socker.sendto(respond.pack(), self._send_to)
        self.State_lock.release()


    def ChangeState(self, state):
        self.State_lock.acquire()
        self.state = state
        self.State_lock.release()

    # 关闭连接的状态
    def ChangeClosed(self):
        self.State_lock.acquire()
        self.state = State.CLOSED
        if self.model == 1:
            del self.true_socker.build_socket_dict[self._send_to]
        self._send_to = None
        self._recv_from = None

    # 客户端接受信息确认
    def Client_receivemessage(self):
        while self.state != State.CLOSED:
            try:
                message_addr = self.recvfrom(2048)
            except Exception:
                break
            if message_addr is None:
                continue
            else:
                message, addr = message_addr[0], message_addr[1]
            if addr != self._recv_from:
                continue
            message = unpack(message)
            if message is None:
                continue
            self.Server_receivemessage(message)

    # 接受ACK消息， 并发送数据
    def recvACK(self):
        self.cwnd = 1
        while True:
            self.send_lock.acquire()
            if self.send_window.isEmpty() is False:
                item = self.send_window.getItemToSend()
                if item is not None:
                    self.send_lock.release()
                    break
            self.send_lock.release()
            self.State_lock.acquire()
            if self.state == State.CLOSN_WAIT:
                message = udp_header(flags=0x5, SEQ_ACK=self.recv_window.recv_base, SEQ=self.send_window.send_base).pack()
                self.true_socker.sendto(message, self._send_to)
                self.state = State.LAST_ACK
                self.Time_Wait_Timer = threading.Timer(10 * self.TimeoutInterval, function=self.ChangeState,
                                                       args=(State.LAST_ACK,))
                threading.Timer(2 * self.TimeoutInterval, function=self.resend, args=(self.state, message,)).start()
                return
            self.State_lock.release()
        first_message = udp_header(flags=0x0, SEQ_ACK=self.recv_window.recv_base, SEQ=item[1],
                                   data=item[0])
        self.send_list[self.send_window.send_base] = time.time()
        self.true_socker.sendto(first_message.pack(), self._send_to)
        # 设置超时定时器
        self.timer = threading.Timer(2 * self.TimeoutInterval, self.TimeOutAndReSend)
        self.timer.start()

        while True:
            # 接收信息
            while self.ACK_Queue.empty():
                if self.state == State.LAST_ACK:
                    return
                else:
                    continue
            acknum = self.ACK_Queue.get()
            self.send_lock.acquire()
            # 更新rwnd
            self.send_window.update(acknum)
            if self.send_window.isEmpty():
                self.send_lock.release()
                continue
            dupack = self.send_window.ackTime
            # 如果当前在慢启动状态
            if self.tran_state == Trans_state.slow_start:
                # 3次重复ack
                if dupack == 4:
                    self.ssthresh = self.cwnd / 2
                    self.cwnd = self.cwnd / 2 + 3
                    self.fast_transmit(acknum)
                    self.tran_state = Trans_state.Fast_recovery
                # 新的ack
                else:
                    if self.cwnd < self.ssthresh:
                        self.cwnd += 1
                    else:
                        self.cwnd += 1 / int(self.cwnd)
                        self.tran_state = Trans_state.Congestion_avoidance
                    self.transmit()
            elif self.tran_state == Trans_state.Fast_recovery:
                # 首次接收到，send_base改变
                if dupack == 1:
                    self.cwnd = self.ssthresh
                    self.tran_state = Trans_state.Congestion_avoidance
                else:
                    self.cwnd += 1
                    self.transmit()
            elif self.tran_state == Trans_state.Congestion_avoidance:
                if dupack == 4:
                    self.ssthresh = self.cwnd / 2
                    self.cwnd = self.cwnd / 2 + 3
                    self.fast_transmit(acknum)
                    self.tran_state = Trans_state.Fast_recovery
                else:
                    self.cwnd += 1 / self.cwnd
                    self.transmit()
            self.send_lock.release()

    # 超时重传
    def TimeOutAndReSend(self):
        self.send_lock.acquire()
        self.ssthresh = self.cwnd / 2
        self.cwnd = 1
        seqnum = self.send_window.send_base
        content = self.send_window.getContentBySeqnum(seqnum)
        self.send_lock.release()
        self.tran_state = Trans_state.slow_start
        if content is not None:
            # print("超时重传：", seqnum)
            message = udp_header(flags=0x0, SEQ_ACK=self.recv_window.recv_base, SEQ=seqnum, data=content)
            self.true_socker.sendto(message.pack(), self._send_to)
            self.send_list[self.send_window.send_base] = time.time()
        else:
            self.State_lock.acquire()
            if self.state == State.CLOSN_WAIT:
                message = udp_header(flags=0x5, SEQ_ACK=self.recv_window.recv_base, SEQ=seqnum).pack()
                self.true_socker.sendto(message, self._send_to)
                self.state = State.LAST_ACK
                threading.Timer(2*self.TimeoutInterval, function=self.resend, args=(self.state, message,)).start()
                self.State_lock.release()
                return
            self.State_lock.release()
        self.timer.cancel()
        self.timer = threading.Timer(2 * self.TimeoutInterval, self.TimeOutAndReSend)
        self.timer.start()
