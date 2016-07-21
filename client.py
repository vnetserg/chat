#!/usr/bin/python3.5
# -*- coding: utf-8 -*-

import argparse, socket, json, random, sys, time

from subprocess import Popen, CREATE_NEW_CONSOLE

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--ip", help="ip address",
        metavar="IP", default="127.0.0.1")
    parser.add_argument("-p", "--port", help="tcp port",
        metavar="PORT", default=1993, type=int)
    args = parser.parse_args()

    
    username = input("Enter username: ").strip()
    socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socket.connect((args.ip, args.port))

    cookie = "".join([chr(random.randrange(ord('a'), ord('z')+1)) for i in range(32)])
    socket.send(json.dumps({"username": username, "cookie": cookie}))

    reply = json.loads(socket.recv().decode("utf-8"))
    if not reply["ok"]:
        sys.exit(0)

    
    Popen([sys.executable, "client_monitor.py", "-i", args.ip,
            "-p", args.port, cookie], creationflags=CREATE_NEW_CONSOLE)
    time.sleep(10000)

    while True:
        socket.send(input("> ").encode("utf-8"))

if __name__ == "__main__":
    main()