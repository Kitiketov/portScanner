import socket
import time

from .helpers import build_dns_query, make_address, recv_all


def probe_http_tcp(ip: str, port: int, timeout: float, family: socket.AddressFamily) -> str | None:
    addr = make_address(ip, port, family)
    try:
        with socket.socket(family, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect(addr)
            request = f"HEAD / HTTP/1.0\r\nHost: {ip}\r\n\r\n".encode()
            sock.sendall(request)
            data = sock.recv(512)
            if data.startswith(b"HTTP/"):
                return "HTTP"
    except OSError:
        return None
    return None


def probe_dns_tcp(ip: str, port: int, timeout: float, family: socket.AddressFamily) -> str | None:
    tx_id, payload = build_dns_query()
    addr = make_address(ip, port, family)
    try:
        with socket.socket(family, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect(addr)
            message = len(payload).to_bytes(2, byteorder="big") + payload
            sock.sendall(message)
            length_bytes = recv_all(sock, 2)
            if len(length_bytes) != 2:
                return None
            expected_len = int.from_bytes(length_bytes, "big")
            response = recv_all(sock, expected_len)
            if len(response) < 2:
                return None
            resp_id = int.from_bytes(response[:2], "big")
            if resp_id == tx_id:
                return "DNS"
    except OSError:
        return None
    return None


def probe_echo_tcp(ip: str, port: int, timeout: float, family: socket.AddressFamily) -> str | None:
    addr = make_address(ip, port, family)
    payload = b"echo-test"
    try:
        with socket.socket(family, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect(addr)
            sock.sendall(payload)
            data = recv_all(sock, len(payload))
            if data == payload:
                return "ECHO"
    except OSError:
        return None
    return None


def guess_tcp_protocol(ip: str, port: int, timeout: float, family: socket.AddressFamily) -> str | None:
    for probe in (probe_http_tcp, probe_dns_tcp, probe_echo_tcp):
        proto = probe(ip, port, timeout, family)
        if proto:
            return proto
    return None


def probe_dns_udp(ip: str, port: int, timeout: float, family: socket.AddressFamily) -> tuple[str | None, float | None]:
    tx_id, payload = build_dns_query()
    addr = make_address(ip, port, family)
    start = time.perf_counter()
    try:
        with socket.socket(family, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(payload, addr)
            data, _ = sock.recvfrom(512)
            elapsed = (time.perf_counter() - start) * 1000.0
            if len(data) >= 2 and int.from_bytes(data[:2], "big") == tx_id:
                return "DNS", elapsed
    except ConnectionRefusedError:
        return None, None
    except (socket.timeout, OSError):
        return None, None
    return None, None


def probe_echo_udp(ip: str, port: int, timeout: float, family: socket.AddressFamily) -> tuple[str | None, float | None]:
    addr = make_address(ip, port, family)
    payload = b"echo-test"
    start = time.perf_counter()
    try:
        with socket.socket(family, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(payload, addr)
            data, _ = sock.recvfrom(len(payload) + 256)
            elapsed = (time.perf_counter() - start) * 1000.0
            if data.startswith(payload):
                return "ECHO", elapsed
    except ConnectionRefusedError:
        return None, None
    except (socket.timeout, OSError):
        return None, None
    return None, None


def guess_udp_protocol(ip: str, port: int, timeout: float, family: socket.AddressFamily) -> tuple[str | None, float | None]:
    for probe in (probe_dns_udp, probe_echo_udp):
        proto, elapsed = probe(ip, port, timeout, family)
        if proto:
            return proto, elapsed
    return None, None
