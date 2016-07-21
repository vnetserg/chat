#!/usr/bin/python3.5
# -*- coding: utf-8 -*-

import argparse, socket, json, random, sys, time, os

from subprocess import Popen, PIPE, CREATE_NEW_CONSOLE

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--ip", help="ip address",
        metavar="IP", default="127.0.0.1")
    parser.add_argument("-p", "--port", help="tcp port",
        metavar="PORT", default=1993, type=int)
    args = parser.parse_args()

    username = input("Enter username: ").strip()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((args.ip, args.port))

    cookie = "".join([chr(random.randrange(ord('a'), ord('z')+1)) for i in range(32)])
    sock.send(json.dumps({"username": username, "cookie": cookie}).encode("utf-8"))

    reply = json.loads(sock.recv(1024).decode("utf-8"))
    if not reply["ok"]:
        sys.exit(0)
    
    dir = os.path.dirname(os.path.abspath(__file__))
    file = os.path.join(dir, "client_monitor.py")
    
    proc = Popen(["cmd.exe", "/c", "start", sys.executable, file, "-i", args.ip,
            "-p", str(args.port), "-c", cookie])
    
    while True:
        sock.send(input("> ").encode("utf-8"))

if __name__ == "__main__":
    main()