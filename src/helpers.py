import socket
import struct
import ipaddress


def make_address(ip: str, port: int, family: socket.AddressFamily) -> tuple:
    if family == socket.AF_INET6:
        return ip, port, 0, 0
    return ip, port


def recv_all(sock: socket.socket, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        try:
            chunk = sock.recv(size - len(data))
        except socket.timeout:
            break
        if not chunk:
            break
        data.extend(chunk)
    return bytes(data)


def build_dns_query() -> tuple[int, bytes]:
    tx_id = 0x1234
    header = struct.pack("!HHHHHH", tx_id, 0x0100, 1, 0, 0, 0)
    question = b"\x07example\x03com\x00\x00\x01\x00\x01"
    return tx_id, header + question


def resolve_target(target: str) -> str:
    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(target, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValueError(f"cannot resolve host '{target}': {exc}") from exc
    for family, _, _, _, sockaddr in infos:
        if family == socket.AF_INET:
            return sockaddr[0]
    if infos:
        return infos[0][4][0]
    raise ValueError(f"cannot resolve host '{target}'")
