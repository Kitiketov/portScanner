import ipaddress
import socket
import time

from ..helpers import make_address
from ..models import ScanResult
from ..protocol_guess import guess_udp_protocol


class UDPScanner:
    def __init__(self, ip: str, timeout: float, guess_proto: bool) -> None:
        self.ip = ip
        self.timeout = timeout
        self.guess_proto = guess_proto
        self.ip_obj = ipaddress.ip_address(ip)
        self.family = socket.AF_INET6 if self.ip_obj.version == 6 else socket.AF_INET

    def scan(self, port: int) -> ScanResult | None:
        proto_name = None
        elapsed = None
        proto_name, elapsed = guess_udp_protocol(self.ip, port, self.timeout, self.family)
        if proto_name:
            return ScanResult("UDP", port, elapsed or 0.0, proto_name if self.guess_proto else None)
        addr = make_address(self.ip, port, self.family)
        start = time.perf_counter()
        try:
            with socket.socket(self.family, socket.SOCK_DGRAM) as sock:
                sock.settimeout(self.timeout)
                sock.sendto(b"", addr)
                data, _ = sock.recvfrom(512)
                elapsed = (time.perf_counter() - start) * 1000.0
                proto_name = None
                if self.guess_proto and data and data.startswith(b"HTTP/"):
                    proto_name = "HTTP"
                return ScanResult("UDP", port, elapsed, proto_name)
        except ConnectionRefusedError:
            return None
        except (socket.timeout, OSError):
            return None
        return None
