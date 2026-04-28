import selectors
import socket
import types
import rsa
from cryptography.fernet import Fernet
from datetime import datetime  # ← NUOVO

sel = selectors.DefaultSelector()
connected_clients = []

# 🔑 RSA UNA VOLTA SOLA
rsa_pub, rsa_priv = rsa.newkeys(1024)
print("🔑 Server RSA pub generata:", rsa_pub)


def accept_wrapper(sock):
    conn, addr = sock.accept()
    print(f"🔌 Nuova connessione da {addr}")

    conn.setblocking(False)

    data = types.SimpleNamespace(
        addr=addr,
        outb=b"",
        cipher=None,
        session_key=None
    )

    sel.register(conn, selectors.EVENT_READ | selectors.EVENT_WRITE, data=data)
    connected_clients.append((conn, data))


def service_connection(key, mask):
    sock = key.fileobj
    data = key.data

    # =========================
    # 🔐 HANDSHAKE
    # =========================
    if data.cipher is None:
        try:
            sock.sendall(rsa_pub.save_pkcs1())
            print("📤 Inviata RSA pub al client")

            # FIX socket non bloccante
            sock.setblocking(True)
            key_cifrata = sock.recv(2048)
            sock.setblocking(False)

            session_key = rsa.decrypt(key_cifrata, rsa_priv)

            data.session_key = session_key
            data.cipher = Fernet(session_key)

            print("✅ Ricevuta chiave sessione:", session_key)

        except Exception as e:
            print("❌ Errore handshake:", e)
            sel.unregister(sock)
            sock.close()
            return

        return

    # =========================
    # 📥 LETTURA
    # =========================
    if mask & selectors.EVENT_READ:
        try:
            recv_data = sock.recv(1024)
        except:
            return

        if recv_data:
            try:
                plaintext = data.cipher.decrypt(recv_data).decode()

                # 🕒 ORA E DATA
                ora = datetime.now().strftime("%d/%m/%Y %H:%M:%S")

                print(f"📨 [{ora}] [{data.addr}] {plaintext}")

            except Exception as e:
                print("❌ Errore decrypt:", e)
                return

            # 🔁 BROADCAST (con ora inclusa)
            messaggio = f"[{ora}] {plaintext}"

            for s, d in connected_clients:
                if s != sock and d.cipher is not None:
                    try:
                        encrypted = d.cipher.encrypt(messaggio.encode())
                        d.outb += encrypted
                    except:
                        pass
        else:
            print(f"❌ Connessione chiusa da {data.addr}")
            sel.unregister(sock)
            sock.close()
            connected_clients.remove((sock, data))

    # =========================
    # 📤 SCRITTURA
    # =========================
    if mask & selectors.EVENT_WRITE:
        if data.outb:
            try:
                sent = sock.send(data.outb)
                data.outb = data.outb[sent:]
            except:
                pass


def main():
    host = "0.0.0.0"
    port = 65432

    lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lsock.bind((host, port))
    lsock.listen()

    print(f"🟢 Server in ascolto su {(host, port)}")

    lsock.setblocking(False)
    sel.register(lsock, selectors.EVENT_READ, data=None)

    try:
        while True:
            events = sel.select(timeout=None)
            for key, mask in events:
                if key.data is None:
                    accept_wrapper(key.fileobj)
                else:
                    service_connection(key, mask)
    except KeyboardInterrupt:
        print("🛑 Server interrotto")
    finally:
        sel.close()


if __name__ == "__main__":
    main()