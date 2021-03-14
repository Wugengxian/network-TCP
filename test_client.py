from rdt import RDTSocket
from socket import socket, AF_INET, SOCK_STREAM
import time
from difflib import Differ

if __name__ == '__main__':
    client = RDTSocket()
    # client = socket(AF_INET, SOCK_STREAM) # check what python socket does
    client.connect(('127.0.0.1', 9999))
    client2 = RDTSocket()
    # client = socket(AF_INET, SOCK_STREAM) # check what python socket does
    client2.connect(('127.0.0.1', 9998))

    print('连接状态： ', client.state)

    echo = b''
    echo2 = b''
    count = 5
    slice_size = 2048
    blocking_send = False

    with open('alice.txt', 'r') as f:
        data = f.read()
        encoded = data.encode()
        assert len(data) == len(encoded)

    '''
    check if your rdt pass either of the two
    mode A may be significantly slower when slice size is small
    '''
    # start = time.perf_counter()
    if blocking_send:
        print('transmit in mode A, send & recv in slices')
        slices = [encoded[i * slice_size:i * slice_size + slice_size] for i in range(len(encoded) // slice_size + 1)]
        assert sum([len(slice) for slice in slices]) == len(encoded)

        start = time.perf_counter()
        for i in range(count):  # send 'alice.txt' for count times
            for slice in slices:
                client.send(slice)
                reply = client.recv(slice_size)

                echo += reply
                if slice != reply:
                    print('error')
                    print('error: ', reply)
                    print('error: ', slice)

    else:
        print('transmit in mode B')
        start = time.perf_counter()
        for i in range(count):
            client.send(encoded)
            client2.send(encoded)
            while len(echo) < len(encoded) * (i + 1):
                reply = client.recv(slice_size)
                echo += reply
            # client.close()
            while len(echo2) < len(encoded) * (i + 1):
                reply2 = client2.recv(slice_size)
                echo2 += reply2
            # client2.close()

    print('数据传输完毕，关闭连接')
    client.close()
    client2.close()

    '''
    make sure the following is reachable
    '''

    print(f'transmitted {len(encoded) * count}bytes in {time.perf_counter() - start}s')
    client.send(b'0000')
    diff = Differ().compare((data * count).splitlines(keepends=True), echo.decode().splitlines(keepends=True))
    for line in diff:
        if not line.startswith('  '):  # check if data is correctly echoed
            print(line)

    diff = Differ().compare((data * count).splitlines(keepends=True), echo2.decode().splitlines(keepends=True))
    for line in diff:
        if not line.startswith('  '):  # check if data is correctly echoed
            print(line)
