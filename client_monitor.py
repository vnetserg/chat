#!/usr/bin/python3.5
# -*- coding: utf-8 -*-

import argparse, socket, json, sys

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--ip", help="ip address",
        metavar="IP", default="127.0.0.1")
    parser.add_argument("-p", "--port", help="tcp port",
        metavar="PORT", default=1993, type=int)
    parser.add_argument("-c", "--cookie", help="cookie value")
    args = parser.parse_args()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((args.ip, args.port))
    except socket.error:
        print("Enable to establish connection")
        sys.exit(1)
    
    sock.send(json.dumps({"cookie": args.cookie}).encode("utf-8"))
    
    while True:
        try:
            data = sock.recv(1024).decode("utf-8")
        except (socket.error, UnicodeDecodeError):
            break
        if not data: break
        print(data, end="")
   
if __name__ == "__main__":
    main()