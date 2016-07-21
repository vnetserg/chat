#!/usr/bin/python3.5
# -*- coding: utf-8 -*-

import argparse, threading, sys, time, datetime, json
import socket
from select import select

class CommandLine:
    greeting = "Hello, root! IP: {ip}, PORT: {port}"
    commands = ["who", "halt"]

    def __init__(self, chat):
        self._chat = chat

    def run(self):
        print(self.greeting.format(ip=self._chat.ip,
            port=self._chat.port))
        while True:
            words = input(">> ").split()
            if words[0] in self.commands:
                getattr(self, words[0])(words[1:])
            else:
                print("Unknown command: {}".format(words[0]))

    def who(self, args):
        users = self._chat.getUsersInfo()
        print("Users online:")
        for user in users:
            print(" * <{}> from [{}:{}]".format(user["name"],
                user["ip"], user["port"]))

    def halt(self, args):
        print("Goodbye!")
        sys.exit(0)

class ChatServer:
    greeting = "Hello, {username}!"
    connected = "User <{username}> connected"
    disconnected = "User <{username}> disconnected"
    commands = ["who", "quit"]

    @staticmethod
    def time():
        time = datetime.datetime.now().time()
        return "[{:02}:{:02}] ".format(time.hour, time.minute)

    def __init__(self, ip, port):
        self.ip = ip
        self.port = port
        self._manager = UserManager(ip, port)
        self._users = set()
        self._lock = threading.Lock()

    def run(self):
        for event in self._manager.eventLoop():
            user = event["user"]
            if event["type"] == "new_user":
                self._addUser(user)
                self._send(user, self.greeting.format(username=user.name))
                self.broadcast(self.time() + self.connected.format(username=user.name),
                    except_=[user])
            elif event["type"] == "new_message":
                msg = event["message"]
                words = msg.split()
                if words[0][0] == "@":
                    cmd = words[0][1:]
                    if cmd in self.commands:
                        getattr(self, "_"+cmd)(user, words[1:])
                    else:
                        self._send(user, "Unknown command: {}".format(words[0]))
                else:
                    self.broadcast(self.time() + "<{}> {}".format(user.name, msg))
            elif event["type"] == "user_dropped":
                self._removeUser(user)
                self.broadcast(self.time() + self.disconnected.format(username=user.name))

    def _send(self, user, msg):
        self._lock.acquire()
        user.sendline(msg)
        self._lock.release()

    def broadcast(self, msg, except_=[]):
        self._lock.acquire()
        for user in self._users:
            if user not in except_:
                user.sendline(msg)
        self._lock.release()

    def _addUser(self, user):
        self._lock.acquire()
        self._users.add(user)
        self._lock.release()

    def _removeUser(self, user):
        self._lock.acquire()
        self._users.remove(user)
        self._lock.release()

    def _who(self, user, args):
        msg = "Users online:\n"
        for user in sorted(self._users, key = lambda u: u.name):
            msg += " * {}\n".format(user.name)
        self._send(user, msg)

    def _quit(self, user, args):
        self._send(user, "Goodbye!")
        user.disconnect()

    def getUsersInfo(self):
        self._lock.acquire()
        info = [{"name": user.name, "ip": user.ip, "port": user.port}
            for user in sorted(self._users, key = lambda u: u.name)]
        self._lock.release()
        return info

class UserManager:
    def __init__(self, ip, port):
        self._manager = SocketManager(ip, port)
        self._cookies = {}
        self._socket_user = {}
        self._banlist = set()

    def eventLoop(self):
        for event in self._manager.eventLoop():
            #print(event)
            socket = event["socket"]
            if event["type"] == "new_socket":
                pass
            elif event["type"] == "new_data":
                try:
                    data = event["data"].decode("utf-8")
                except:
                    self._manager.dropSocket(socket)
                    continue

                user = self._socket_user.get(socket, None)
                if user:
                    yield {"type": "new_message", "user": user, "message": data}
                else:
                    #print(repr(data))
                    try:
                        msg = json.loads(data)
                        assert type(msg) is dict
                        assert "cookie" in msg
                    except:
                        self._manager.dropSocket(socket)
                    else:
                        if "username" in msg:
                            if msg["username"] in self._banlist:
                                self._manager.dropSocket(socket)
                            else:
                                self._cookies[msg["cookie"]] = (msg["username"], socket)
                            socket.send(json.dumps({"ok": True}).encode("utf-8"))
                        elif msg["cookie"] in self._cookies:
                            username, pair_socket = self._cookies[msg["cookie"]]
                            user = User(username, socket, pair_socket, self._manager)
                            self._socket_user[socket] = user
                            self._socket_user[pair_socket] = user
                            del self._cookies[msg["cookie"]]
                            yield {"type": "new_user", "user": user}
                        else:
                            self._manager.dropSocket(socket)

            elif event["type"] == "socket_dropped":
                if socket in self._socket_user:
                    user = self._socket_user[socket]
                    yield {"type": "user_dropped", "user": user}
                    if socket is user._read_socket:
                        self._manager.dropSocket(user._write_socket)
                    else:
                        self._manager.dropSocket(user._read_socket)
                    del self._socket_user[user._read_socket]
                    del self._socket_user[user._write_socket]

class User:
    def __init__(self, name, write_socket, read_socket, socket_manager):
        self.name = name
        self.ip = read_socket.getpeername()[0]
        self.port = read_socket.getpeername()[1]
        self._read_socket = read_socket
        self._write_socket = write_socket
        self._manager = socket_manager

    def sendline(self, line):
        if line[-1] != '\n':
            line += '\n'
        self._write_socket.send(line.encode("utf-8"))

    def disconnect(self):
        self._manager.dropSocket(self._read_socket)
        self._manager.dropSocket(self._write_socket)

class SocketManager:
    def __init__(self, ip, port):
        self._server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server.setblocking(0)
        self._server.bind((ip, port))
        self._server.listen(5)

        self._banlist = set()
        self._client_sockets = set()
        self._sockets_to_drop = []

    def eventLoop(self):
        while True:
            for sock in self._sockets_to_drop:
                if sock in self._client_sockets:
                    sock.close()
                    yield {"type": "socket_dropped", "socket": sock}
                    self._client_sockets.remove(sock)
            self._sockets_to_drop = []

            readable, _, _ = select(list(self._client_sockets) + [self._server], [], [])
            for sock in readable:
                if sock is self._server:
                    client_sock, client_address = sock.accept()
                    client_sock.setblocking(0)
                    if client_address[0] in self._banlist:
                        client_sock.close()
                    else:
                        self._client_sockets.add(client_sock)
                        yield {"type": "new_socket", "socket": client_sock}
                else:
                    data = sock.recv(1024)
                    if data:
                        yield {"type": "new_data", "socket": sock, "data": data}
                    else:
                        sock.close()
                        yield {"type": "socket_dropped", "socket": sock}

    def dropSocket(self, socket):
        self._sockets_to_drop.append(socket)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--ip", help="ip address",
        metavar="IP", default="127.0.0.1")
    parser.add_argument("-p", "--port", help="tcp port",
        metavar="PORT", default=1993, type=int)
    args = parser.parse_args()

    chat = ChatServer(args.ip, args.port)
    #chat.run()
    cmd = CommandLine(chat)

    thread = threading.Thread(target=chat.run)
    thread.daemon = True
    thread.start()

    cmd.run()

if __name__ == "__main__":
    main()