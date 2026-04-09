# server.py
# ============================================================
# RFTP Multi-Client UDP Server (FIXED VERSION)
# ============================================================

import socket
import threading
import os
import time
import json
from colorama import Fore, Style, init

import protocol as P
import crypto_utils as C

init(autoreset=True)

SERVER_HOST = "0.0.0.0"
STORE_DIR = "server_files"
os.makedirs(STORE_DIR, exist_ok=True)


# ---------------- STATE ---------------- #
class TransferState:
    def __init__(self, filename, total_chunks):
        self.filename = filename
        self.total_chunks = total_chunks
        self.received = {}
        self.completed = False
        self.last_active = time.time()

    def is_done(self):
        return len(self.received) == self.total_chunks


transfers = {}
state_lock = threading.Lock()


def log(tag, msg, color=Fore.CYAN):
    ts = time.strftime("%H:%M:%S")
    print(f"{color}[{ts}][{tag}]{Style.RESET_ALL} {msg}")


# ---------------- SAVE ---------------- #
def assemble_and_save(state):
    path = os.path.join(STORE_DIR, state.filename)
    with open(path, "wb") as f:
        for i in range(state.total_chunks):
            f.write(state.received[i])
    log("SAVE", f"File saved -> {path}", Fore.GREEN)


# ---------------- ACK/NACK ---------------- #
def send_ack(sock, addr, seq, filename):
    pkt = P.build_packet(seq, 0, 0, filename, b"", P.FLAG_ACK)
    sock.sendto(pkt, addr)


def send_nack(sock, addr, seq, filename):
    pkt = P.build_packet(seq, 0, 0, filename, b"", P.FLAG_NACK)
    sock.sendto(pkt, addr)


# ---------------- UPLOAD ---------------- #
def handle_upload(sock, addr, parsed):
    seq, total, _, filename, checksum, _, payload = parsed

    try:
        decrypted = C.decrypt(payload)
    except Exception:
        send_nack(sock, addr, seq, filename)
        return

    if not P.verify_checksum(payload, checksum):
        send_nack(sock, addr, seq, filename)
        return

    key = (addr, filename)

    with state_lock:
        if key not in transfers:
            transfers[key] = TransferState(filename, total)
            log("UPLOAD", f"New transfer: '{filename}' from {addr}", Fore.YELLOW)

        state = transfers[key]

        if seq not in state.received:
            state.received[seq] = decrypted

        send_ack(sock, addr, seq, filename)

        if state.is_done() and not state.completed:
            state.completed = True
            assemble_and_save(state)

            fin = P.build_control(P.FLAG_FIN, filename, {"status": "ok"})
            sock.sendto(fin, addr)

            log("DONE", f"Upload complete '{filename}' from {addr}", Fore.GREEN)


# ---------------- DOWNLOAD ---------------- #
def send_file_to_client(sock, addr, filepath, filename):
    chunks = [data for _, _, data in P.file_to_chunks(filepath)]
    total = len(chunks)

    acked = set()
    base = 0

    def send_chunk(i):
        data = chunks[i]
        enc = C.encrypt(data)
        pkt = P.build_packet(i, total, len(enc), filename, enc, P.FLAG_DATA)
        sock.sendto(pkt, addr)

    sock.settimeout(P.TIMEOUT)

    while base < total:
        for i in range(base, total):
            if i not in acked:
                send_chunk(i)

        try:
            raw, _ = sock.recvfrom(P.BUFFER_SIZE)
            parsed = P.parse_packet(raw)
            if not parsed:
                continue

            seq, _, _, fname, _, flag, _ = parsed

            if fname != filename:
                continue

            if flag & P.FLAG_ACK:
                acked.add(seq)
                while base in acked:
                    base += 1

            elif flag & P.FLAG_NACK:
                send_chunk(seq)

        except socket.timeout:
            continue

    fin = P.build_control(P.FLAG_FIN, filename, {"status": "ok"})
    sock.sendto(fin, addr)

    log("DONE", f"Download complete '{filename}' -> {addr}", Fore.GREEN)


# ---------------- SYN HANDLER ---------------- #
def handle_syn(sock, addr, parsed):
    _, _, _, filename, _, _, payload = parsed
    meta = P.parse_control_payload(payload)
    action = meta.get("action", "upload")

    if action == "download":
        path = os.path.join(STORE_DIR, filename)

        if not os.path.exists(path):
            err = P.build_control(P.FLAG_ERROR, filename, {"error": "Not found"})
            sock.sendto(err, addr)
            return

        log("DOWNLOAD", f"Sending '{filename}' to {addr}", Fore.YELLOW)

        threading.Thread(
            target=send_file_to_client,
            args=(sock, addr, path, filename),
            daemon=True
        ).start()

    elif action == "list":
        files = os.listdir(STORE_DIR)
        pkt = P.build_control(P.FLAG_LIST, "", {"files": files})
        sock.sendto(pkt, addr)
        log("LIST", f"Sent file list to {addr}", Fore.BLUE)

    else:
        ack = P.build_control(P.FLAG_ACK, filename, {"status": "ready"})
        sock.sendto(ack, addr)


# ---------------- SERVER LOOP ---------------- #
def server_loop():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((SERVER_HOST, P.SERVER_PORT))

    log("SERVER", f"Listening on {SERVER_HOST}:{P.SERVER_PORT}", Fore.GREEN)

    while True:
        try:
            raw, addr = sock.recvfrom(P.BUFFER_SIZE)
            parsed = P.parse_packet(raw)

            if not parsed:
                continue

            _, _, _, _, _, flag, _ = parsed

            if flag & P.FLAG_SYN:
                threading.Thread(target=handle_syn, args=(sock, addr, parsed), daemon=True).start()

            elif flag & P.FLAG_DATA:
                threading.Thread(target=handle_upload, args=(sock, addr, parsed), daemon=True).start()

        except socket.timeout:
            continue

        except KeyboardInterrupt:
            log("SERVER", "Stopped", Fore.RED)
            break

        except Exception as e:
            log("ERROR", str(e), Fore.RED)

    sock.close()


# ---------------- MAIN ---------------- #
if __name__ == "__main__":
    server_loop()