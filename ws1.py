#!/usr/bin/env python3
# encoding: utf-8
import socket
import threading
import select
import sys
import time
from os import system

system("clear")

IP = '127.0.0.1'
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 10015
PASS = b''
BUFLEN = 8196 * 8
TIMEOUT = 10
DEFAULT_HOST = '127.0.0.1:109'
RESPONSE = 'HTTP/1.1 101 MakhlukTunnel\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: foo\r\n\r\n'


class Server(threading.Thread):
    def __init__(self, host, port):
        super().__init__()
        self.running = False
        self.host = host
        self.port = port
        self.threads = []
        self.threadsLock = threading.Lock()
        self.logLock = threading.Lock()

    def run(self):
        self.soc = socket.socket(socket.AF_INET)
        self.soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.soc.settimeout(2)
        self.soc.bind((self.host, self.port))
        self.soc.listen(0)
        self.running = True

        try:
            while self.running:
                try:
                    c, addr = self.soc.accept()
                    c.setblocking(1)
                    conn = ConnectionHandler(c, self, addr)
                    conn.start()
                    self.addConn(conn)
                except socket.timeout:
                    continue
        finally:
            self.running = False
            self.soc.close()

    def printLog(self, log):
        with self.logLock:
            print(log)

    def addConn(self, conn):
        with self.threadsLock:
            if self.running:
                self.threads.append(conn)

    def removeConn(self, conn):
        with self.threadsLock:
            self.threads.remove(conn)

    def close(self):
        self.running = False
        with self.threadsLock:
            for c in list(self.threads):
                c.close()


class ConnectionHandler(threading.Thread):
    def __init__(self, socClient, server, addr):
        super().__init__()
        self.clientClosed = False
        self.targetClosed = True
        self.client = socClient
        self.client_buffer = ''
        self.server = server
        self.log = 'Connection: ' + str(addr)

    def close(self):
        if not self.clientClosed:
            try:
                self.client.shutdown(socket.SHUT_RDWR)
                self.client.close()
            except:
                pass
            finally:
                self.clientClosed = True

        if not self.targetClosed:
            try:
                self.target.shutdown(socket.SHUT_RDWR)
                self.target.close()
            except:
                pass
            finally:
                self.targetClosed = True

    def run(self):
        try:
            self.client_buffer = self.client.recv(BUFLEN)

            hostPort = self.findHeader(self.client_buffer, 'X-Real-Host')
            hostPort = hostPort if hostPort else DEFAULT_HOST

            split = self.findHeader(self.client_buffer, 'X-Split')
            if split:
                self.client.recv(BUFLEN)

            passwd = self.findHeader(self.client_buffer, 'X-Pass')
            if len(PASS) != 0 and passwd != PASS:
                self.client.send(b'HTTP/1.1 400 WrongPass!\r\n\r\n')
            elif hostPort.startswith(IP):
                self.method_CONNECT(hostPort)
            else:
                self.client.send(b'HTTP/1.1 403 Forbidden!\r\n\r\n')
        except Exception as e:
            self.log += ' - error: ' + str(e)
            self.server.printLog(self.log)
        finally:
            self.close()
            self.server.removeConn(self)

    def findHeader(self, head, header):
        start = head.find((header + ': ').encode())
        if start == -1:
            return ''

        start = head.find(':'.encode(), start) + 2
        end = head.find(b'\r\n', start)
        return head[start:end].decode() if end != -1 else ''

    def connect_target(self, host):
        i = host.find(':')
        port = int(host[i+1:]) if i != -1 else 443
        host = host[:i] if i != -1 else host

        soc_family, soc_type, proto, _, address = socket.getaddrinfo(host, port)[0]
        self.target = socket.socket(soc_family, soc_type, proto)
        self.targetClosed = False
        self.target.connect(address)

    def method_CONNECT(self, path):
        self.log += ' - CONNECT ' + path
        self.connect_target(path)
        self.client.sendall(RESPONSE.encode())
        self.doCONNECT()

    def doCONNECT(self):
        socs = [self.client, self.target]
        count = 0
        while True:
            count += 1
            recv, _, err = select.select(socs, [], socs, 3)
            if err:
                break

            if recv:
                for in_ in recv:
                    try:
                        data = in_.recv(BUFLEN)
                        if not data:
                            return
                        if in_ is self.target:
                            self.client.send(data)
                        else:
                            self.target.sendall(data)
                        count = 0
                    except:
                        return
            if count == TIMEOUT:
                break


def main():
    print("━" * 8, "PROXY SOCKS", "━" * 8, "\n")
    print("IP:", IP)
    print("PORT:", PORT, "\n")
    print("━" * 10, "SSHPLUS", "━" * 11, "\n")
    server = Server(IP, PORT)
    server.start()
    try:
        while True:
            time.sleep(2)
    except KeyboardInterrupt:
        print('\nStopping...')
        server.close()


if __name__ == '__main__':
    main()
