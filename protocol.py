# protocol.py
# ============================================================
# RFTP Protocol - Packet structure, constants, utilities
# ============================================================

import struct
import hashlib
import json
import time

# ---- Protocol Constants ----
CHUNK_SIZE       = 8192          # bytes per chunk
HEADER_FORMAT    = "!I I I 256s 64s B"   # big-endian
HEADER_SIZE      = struct.calcsize(HEADER_FORMAT)
MAX_RETRIES      = 10
TIMEOUT          = 2.0           # seconds
WINDOW_SIZE      = 16            # sliding window
SERVER_PORT      = 9000
BUFFER_SIZE      = CHUNK_SIZE + HEADER_SIZE + 512

# ---- Packet Flags ----
FLAG_DATA    = 0x01
FLAG_ACK     = 0x02
FLAG_NACK    = 0x04
FLAG_SYN     = 0x08
FLAG_FIN     = 0x10
FLAG_RESUME  = 0x20
FLAG_LIST    = 0x40
FLAG_ERROR   = 0x80


def compute_checksum(data: bytes) -> bytes:
    """SHA-256 checksum of data, returns 64-byte hex string encoded as bytes."""
    return hashlib.sha256(data).hexdigest().encode("utf-8")


def verify_checksum(data: bytes, checksum: bytes) -> bool:
    expected = compute_checksum(data)
    return expected == checksum.rstrip(b"\x00")


def build_packet(
    seq_num: int,
    total_chunks: int,
    chunk_size: int,
    filename: str,
    payload: bytes,
    flag: int,
) -> bytes:
    """Pack a UDP datagram with header + payload."""
    checksum = compute_checksum(payload) if payload else b"\x00" * 64
    fname_bytes = filename.encode("utf-8")[:256].ljust(256, b"\x00")
    checksum    = checksum[:64].ljust(64, b"\x00")
    header = struct.pack(
        HEADER_FORMAT,
        seq_num,
        total_chunks,
        chunk_size,
        fname_bytes,
        checksum,
        flag,
    )
    return header + payload


def parse_packet(raw: bytes):
    """
    Returns (seq_num, total_chunks, chunk_size, filename, checksum, flag, payload)
    or None on malformed packet.
    """
    if len(raw) < HEADER_SIZE:
        return None
    header  = raw[:HEADER_SIZE]
    payload = raw[HEADER_SIZE:]
    seq_num, total_chunks, chunk_size, fname_b, checksum_b, flag = struct.unpack(
        HEADER_FORMAT, header
    )
    filename = fname_b.rstrip(b"\x00").decode("utf-8", errors="replace")
    checksum = checksum_b.rstrip(b"\x00")
    return seq_num, total_chunks, chunk_size, filename, checksum, flag, payload


def file_to_chunks(filepath: str, chunk_size: int = CHUNK_SIZE):
    """Generator: yields (chunk_index, total_chunks, data) for every chunk."""
    import os
    filesize   = os.path.getsize(filepath)
    total      = (filesize + chunk_size - 1) // chunk_size
    with open(filepath, "rb") as f:
        idx = 0
        while True:
            data = f.read(chunk_size)
            if not data:
                break
            yield idx, total, data
            idx += 1


def build_control(flag: int, filename: str = "", payload_dict: dict = None) -> bytes:
    """Build a control packet (SYN, ACK, FIN, etc.) with optional JSON payload."""
    raw = json.dumps(payload_dict or {}).encode("utf-8")
    return build_packet(0, 0, 0, filename, raw, flag)


def parse_control_payload(payload: bytes) -> dict:
    try:
        return json.loads(payload.decode("utf-8"))
    except Exception:
        return {}