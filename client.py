#!/usr/bin/python3.5
# -*- coding: utf-8 -*-

import argparse, socket, json, random, sys, os, threading
from subprocess import Popen

def start_connection_daemon(sock):
    thread = threading.Thread(target=lambda: monitor(sock))
    thread.daemon = True
    thread.start()
    return thread

def monitor(sock):
    try:
        data = sock.recv(1024)
    except socket.error:
        pass
    print("\nConnection terminated.")
    os._exit(0)

def any_key():
    input("Press enter to quit.")
    
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--ip", help="ip address",
        metavar="IP", default="127.0.0.1")
    parser.add_argument("-p", "--port", help="tcp port",
        metavar="PORT", default=1993, type=int)
    args = parser.parse_args()

    username = input("Enter username: ").strip()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    try:
        sock.connect((args.ip, args.port))
    except socket.error:
        print("Unable to establish connection.")
        any_key()
        sys.exit(1)

    cookie = "".join([chr(random.randrange(ord('a'), ord('z')+1)) for i in range(32)])
    sock.send(json.dumps({"username": username, "cookie": cookie}).encode("utf-8"))

    try:
        reply = json.loads(sock.recv(1024).decode("utf-8"))
    except (socket.error, ValueError):
        print("Server rejected authorization.")
        any_key()
        sys.exit(1)
    
    if not reply["ok"]:
        print("Server rejected authorization. Reason:", reply["why"])
        any_key()
        sys.exit(1)
    
    dir = os.path.dirname(os.path.abspath(__file__))
    file = os.path.join(dir, "client_monitor.py")
    
    proc = Popen(["cmd.exe", "/c", "start", sys.executable, file, "-i", args.ip,
            "-p", str(args.port), "-c", cookie])
    
    print("You may now type messages here.")
    thread = start_connection_daemon(sock)
    while True:
        try:
            sock.send(input("> ").encode("utf-8"))
        except (socket.error, KeyboardInterrupt):
            print("Connection terminated.")

if __name__ == "__main__":
    main()