#!/usr/bin/python3.5
# -*- coding: utf-8 -*-

import argparse, socket, time

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--ip", help="ip address",
        metavar="IP", default="127.0.0.1")
    parser.add_argument("-p", "--port", help="tcp port",
        metavar="PORT", default=1993, type=int)
    parser.add_argument("cookie", help="cookie value")
    args = parser.parse_args()

    print(args.ip, args.port, args.cookie)
    time.sleep(10000)