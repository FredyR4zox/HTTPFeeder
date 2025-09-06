#!/usr/bin/env python3

import selectors
import socket
import sys
import traceback

import libclient
import time

sel = selectors.DefaultSelector()


def create_request(action, value):
    if action == "search":
        return dict(
            type="text/json",
            encoding="utf-8",
            content=dict(action=action, value=value),
        )
    else:
        return dict(
            type="binary/custom-client-binary-type",
            encoding="binary",
            content=bytes(action + value, encoding="utf-8"),
        )


def start_connection(host, port):
    addr = (host, port)
    print(f"Starting connection to {addr}")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setblocking(True)
    sock.connect_ex(addr)
    events = selectors.EVENT_READ | selectors.EVENT_WRITE
    # message = libclient.Message(sel, sock, addr, request)
    # sel.register(sock, events, data=message)

    # time.sleep(10)

    with open("output.txt") as f:
        for message in f:
            print(f"Sending {message!r} to {addr}")
            try:
                # Should be ready to write
                sent = sock.sendall(message.encode())
            except Exception as e:
                # Resource temporarily unavailable (errno EWOULDBLOCK)
                print(f"EXCEPTION OCCURED!!!")
                print(e)
                break

            if sent != None:
                print(f"Error sending message!!!")
                break

    sock.close()


if len(sys.argv) != 3:
    print(f"Usage: {sys.argv[0]} <host> <port>")
    sys.exit(1)

host, port = sys.argv[1], int(sys.argv[2])
start_connection(host, port)

try:
    while True:
        events = sel.select(timeout=1)
        for key, mask in events:
            message = key.data
            try:
                message.process_events(mask)
            except Exception:
                print(
                    f"Main: Error: Exception for {message.addr}:\n"
                    f"{traceback.format_exc()}"
                )
                message.close()
        # Check for a socket being monitored to continue.
        if not sel.get_map():
            break
except KeyboardInterrupt:
    print("Caught keyboard interrupt, exiting")
finally:
    sel.close()
