#!/usr/bin/env python3

import selectors

import socket

import sys

import types

import rsa

from cryptography.fernet import Fernet

sel = selectors.DefaultSelector()


def start_connections(host, port, num_conns):

    server_addr = (host, port)

    # 👤 USERNAME

    username = input("Inserisci username: ")

    for i in range(num_conns):

        connid = i + 1

        print(f"Starting connection {connid} to {server_addr}")

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        sock.connect(server_addr)

        # =========================

        # 🔐 HANDSHAKE

        # =========================

        # 1. Ricevi RSA pubblica

        rsa_pub_data = sock.recv(2048)

        rsa_pub = rsa.PublicKey.load_pkcs1(rsa_pub_data)

        print("📥 RSA pub ricevuta dal server")

        # 2. Genera chiave sessione

        my_session_key = Fernet.generate_key()

        my_cipher = Fernet(my_session_key)

        # 3. Invia chiave cifrata

        sock.sendall(rsa.encrypt(my_session_key, rsa_pub))

        print("📤 Inviata mia chiave sessione")

        sock.setblocking(False)

        data = types.SimpleNamespace(

            connid=connid,

            cipher=my_cipher,

            outb=b"",

            username=username

        )

        events = selectors.EVENT_READ | selectors.EVENT_WRITE

        sel.register(sock, events, data=data)


def service_connection(key, mask):

    sock = key.fileobj

    data = key.data

    # =========================

    # 📤 INVIO MESSAGGI

    # =========================

    if mask & selectors.EVENT_WRITE:

        try:

            testo = input("> ")

            messaggio = f"{data.username}: {testo}"

            token = data.cipher.encrypt(messaggio.encode())

            sock.sendall(token)

        except:

            pass

    # =========================

    # 📥 RICEZIONE MESSAGGI

    # =========================

    if mask & selectors.EVENT_READ:

        try:

            recv_data = sock.recv(1024)

            if recv_data:

                plaintext = data.cipher.decrypt(recv_data).decode()

                print("<<", plaintext)

        except Exception as e:

            print("❌ Errore:", e)

            sel.unregister(sock)

            sock.close()

# =========================

# ARGOMENTI

# =========================

if len(sys.argv) != 4:

    print(f"Usage: {sys.argv[0]} <host> <port> <num_connections>")

    sys.exit(1)

host, port, num_conns = sys.argv[1:4]

start_connections(host, int(port), int(num_conns))

try:

    while True:

        events = sel.select(timeout=1)

        for key, mask in events:

            service_connection(key, mask)

except KeyboardInterrupt:

    print("Client stopped")

finally:

    sel.close()
 