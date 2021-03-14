import threading

from rdt import RDTSocket
from socket import socket, AF_INET, SOCK_DGRAM, SOCK_STREAM
import time

R1_END = False
R2_END = False


def receiveData(conn):
    global R1_END
    while True:
        data = conn.recv(2048)
        if data:
            conn.send(data)
        else:
            R1_END = True
            break


def receiveData2(conn):
    global R2_END
    while True:
        data = conn.recv(2048)
        if data:
            conn.send(data)
        else:
            R2_END = True
            break


if __name__ == '__main__':
    server = RDTSocket()
    # server = socket(AF_INET, SOCK_STREAM) # check what python socket does
    server.bind(('127.0.0.1', 9999))
    # server.listen(0) # check what python socket does
    server2 = RDTSocket()
    server2.bind(('127.0.0.1', 9998))
    pre_data = None
    while True:
        conn, client_addr = server.accept()
        conn2, client_addr2 = server2.accept()
        start = time.perf_counter()
        threading.Thread(target=receiveData, args=(conn, )).start()
        threading.Thread(target=receiveData2, args=(conn2, )).start()
        while True:
            if R1_END and R2_END:
                break

        '''
        make sure the following is reachable
        '''
        print("close")
        conn.close()
        conn2.close()
        # conn.send(data)

        print(f'connection finished in {time.perf_counter() - start}s')
        # server.get_connection()
