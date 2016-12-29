#!/usr/bin/env python

OPCSERVER_HOST = 'localhost'
OPCSERVER_PORT = 7891
LISTEN_PORT = 7890
NUM_STRINGS = 2
LEDS_PER_STRING = 682

import numpy
import select
import socket
import time

tcp_listen = None
clients = []
opc_sock = None
led_buf = numpy.zeros((NUM_STRINGS, LEDS_PER_STRING * 3), dtype = numpy.uint8)
sockbuf = {}
last_update = [0] * NUM_STRINGS

def open_opc_sock():
    global opc_sock
    if opc_sock != None:
        return
    opc_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        opc_sock.connect((OPCSERVER_HOST, OPCSERVER_PORT))
    except:
        opc_sock = None
        return
    opc_sock.setblocking(0)
    print('Connected to OPC server')

def main():
    global tcp_listen, clients, opc_sock, led_buf, sockbuf, last_update
    open_opc_sock()

    tcp_listen = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_listen.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tcp_listen.bind(('', LISTEN_PORT))

    tcp_listen.listen(5)
    tcp_listen.setblocking(0)
    while True:
        newdata = False
        now = time.time()
        socklist = clients + [tcp_listen]
        r, w, x = select.select(socklist, [], [], 1)
        for s in r:
            if s == tcp_listen:
                cl, addrinfo = s.accept()
                cl.setblocking(0)
                print('New connection from %s:%d' % (addrinfo[0], addrinfo[1]))
                sockbuf[cl] = ''
                clients.append(cl)
                continue

            tmp = s.recv(4096)
            if len(tmp) == 0:
                print('Client disconnected')
                clients.remove(s)
                sockbuf.pop(s)
                s.close()
                continue
            sockbuf[s] = sockbuf[s] + tmp
            if len(sockbuf[s]) < 5:
                continue
            chan = ord(sockbuf[s][0])
            command = ord(sockbuf[s][1])
            plen = ord(sockbuf[s][2]) << 8 | ord(sockbuf[s][3])
            if len(sockbuf[s]) - 4 < plen:
                continue
            data = sockbuf[s][4:plen + 4]
            sockbuf[s] = sockbuf[s][plen + 4:]
            if command != 0:
                print('Unknown command %d' % (command))
                continue
            if chan < 0 or chan > NUM_STRINGS:
                print('Channel %d out of range' % (chan))
                continue
            last_update[chan] = now
            led_buf[chan][0:plen] = numpy.fromstring(data, dtype = numpy.uint8)
            led_buf[chan][plen:] = 0
            newdata = True
        # Check for idle channels
        for i in range(len(last_update)):
            if last_update[i] < now - 5:
                led_buf[i] = 0
                last_update[i] = now
                newdata = True
                print('Clearing channel %d' % (i))
        # Need to send update?
        if not newdata:
            continue
        sz = NUM_STRINGS * LEDS_PER_STRING * 3
        try:
            r = opc_sock.send('\x00\x00%c%c' % (sz >> 8, sz & 0xff) + led_buf.tostring())
            if r != sz + 4:
                print('Short write, got %d, expected %d' % (r, sz + 4))
        except:
            opc_sock = None
            open_opc_sock()
if __name__ == '__main__':
    main()

