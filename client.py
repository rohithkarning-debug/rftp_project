# client.py
# ============================================================
# FINAL RFTP CLIENT (FULLY FIXED)
# ============================================================

import socket
import os
import time
from tqdm import tqdm
from colorama import Fore, Style, init

import protocol as P
import crypto_utils as C

init(autoreset=True)

STORE_DIR = "client_files"
os.makedirs(STORE_DIR, exist_ok=True)


def log(tag, msg, color=Fore.CYAN):
    ts = time.strftime("%H:%M:%S")
    print(f"{color}[{ts}][{tag}]{Style.RESET_ALL} {msg}")


class RFTPClient:
    def __init__(self, server_ip="192.168.80.139", port=P.SERVER_PORT):
        self.server = (server_ip, port)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(P.TIMEOUT)

    # ================= UPLOAD ================= #
    def upload(self, filepath):
        if not os.path.exists(filepath):
            log("ERROR", f"File not found: {filepath}", Fore.RED)
            return

        filename = os.path.basename(filepath)
        chunks = [data for _, _, data in P.file_to_chunks(filepath)]
        total = len(chunks)

        log("UPLOAD", f"{filename} | {total} chunks", Fore.YELLOW)

        syn = P.build_control(P.FLAG_SYN, filename, {"action": "upload"})
        self.sock.sendto(syn, self.server)

        try:
            self.sock.recvfrom(P.BUFFER_SIZE)
        except socket.timeout:
            log("ERROR", "Server not responding", Fore.RED)
            return

        acked = set()
        pbar = tqdm(total=total, desc=f"Uploading {filename}")

        def send_chunk(i):
            data = chunks[i]
            enc = C.encrypt(data)
            pkt = P.build_packet(i, total, len(enc), filename, enc, P.FLAG_DATA)
            self.sock.sendto(pkt, self.server)

        while len(acked) < total:
            for i in range(total):
                if i not in acked:
                    send_chunk(i)

            try:
                raw, _ = self.sock.recvfrom(P.BUFFER_SIZE)
                parsed = P.parse_packet(raw)
                if not parsed:
                    continue

                seq, _, _, fname, _, flag, _ = parsed

                if fname != filename:
                    continue

                if flag & P.FLAG_ACK:
                    if seq not in acked:
                        acked.add(seq)
                        pbar.update(1)

                elif flag & P.FLAG_NACK:
                    send_chunk(seq)

                elif flag & P.FLAG_FIN:
                    break

            except socket.timeout:
                continue

        pbar.close()
        log("UPLOAD", "Completed", Fore.GREEN)

    # ================= DOWNLOAD ================= #
    def download(self, filename):
        log("DOWNLOAD", f"Requesting '{filename}'", Fore.YELLOW)

        syn = P.build_control(P.FLAG_SYN, filename, {"action": "download"})
        self.sock.sendto(syn, self.server)

        received = {}
        total = None
        pbar = None

        while True:
            try:
                raw, _ = self.sock.recvfrom(P.BUFFER_SIZE)
                parsed = P.parse_packet(raw)
                if not parsed:
                    continue

                seq, tot, _, fname, checksum, flag, payload = parsed

                if fname != filename:
                    continue

                if flag & P.FLAG_ERROR:
                    log("ERROR", "File not found on server", Fore.RED)
                    return

                if flag & P.FLAG_DATA:
                    if total is None:
                        total = tot
                        pbar = tqdm(total=total, desc=f"Downloading {filename}")

                    # verify encrypted checksum
                    if not P.verify_checksum(payload, checksum):
                        nack = P.build_packet(seq, 0, 0, filename, b"", P.FLAG_NACK)
                        self.sock.sendto(nack, self.server)
                        continue

                    data = C.decrypt(payload)

                    if seq not in received:
                        received[seq] = data
                        pbar.update(1)

                    ack = P.build_packet(seq, 0, 0, filename, b"", P.FLAG_ACK)
                    self.sock.sendto(ack, self.server)

                elif flag & P.FLAG_FIN:
                    log("DONE", "Download complete", Fore.GREEN)
                    break

            except socket.timeout:
                log("ERROR", "Download timeout", Fore.RED)
                break

        if pbar:
            pbar.close()

        if total and len(received) == total:
            path = os.path.join(STORE_DIR, filename)
            with open(path, "wb") as f:
                for i in range(total):
                    f.write(received[i])
            log("SAVED", f"{path}", Fore.GREEN)
        else:
            log("ERROR", "Incomplete download!", Fore.RED)

    # ================= LIST ================= #
    def list_files(self):
        log("LIST", "Requesting files", Fore.YELLOW)

        syn = P.build_control(P.FLAG_SYN, "", {"action": "list"})
        self.sock.sendto(syn, self.server)

        try:
            raw, _ = self.sock.recvfrom(P.BUFFER_SIZE)
            parsed = P.parse_packet(raw)

            if parsed:
                _, _, _, _, _, flag, payload = parsed

                if flag & P.FLAG_LIST:
                    files = P.parse_control_payload(payload).get("files", [])

                    print("\n===== SERVER FILES =====")
                    if not files:
                        print("(No files found)")
                    else:
                        for f in files:
                            print(f)
                    print("========================\n")

        except socket.timeout:
            log("ERROR", "List timeout", Fore.RED)

    def close(self):
        self.sock.close()


# ================= MAIN ================= #
def main():
    client = RFTPClient()
    log("CONNECT", "Connected to server", Fore.GREEN)

    while True:
        print("\n1.Upload  2.Download  3.List  4.Exit")
        ch = input("Choice: ").strip()

        if ch == "1":
            path = input("File path: ")
            client.upload(path)

        elif ch == "2":
            name = input("Filename: ")
            client.download(name)

        elif ch == "3":
            client.list_files()

        elif ch == "4":
            client.close()
            break


if __name__ == "__main__":
    main()