import ipaddress
import socket
import threading
import time

from scapy.all import IP, IPv6, TCP, RandShort, send, sr1

from ..models import ScanResult
from ..protocol_guess import guess_tcp_protocol

SCAPY_LOCK = threading.Lock()


class TCPSYNScanner:
    def __init__(self, ip: str, timeout: float, guess_proto: bool) -> None:
        self.ip = ip
        self.timeout = timeout
        self.guess_proto = guess_proto
        self.ip_obj = ipaddress.ip_address(ip)
        self.is_ipv6 = self.ip_obj.version == 6
        self.family = socket.AF_INET6 if self.is_ipv6 else socket.AF_INET

    def scan(self, port: int) -> ScanResult | None:
        ip_layer_cls = IPv6 if self.is_ipv6 else IP
        sport = RandShort()
        syn_packet = ip_layer_cls(dst=self.ip) / TCP(sport=sport, dport=port, flags="S", seq=100)
        start = time.perf_counter()
        try:
            with SCAPY_LOCK:
                resp = sr1(syn_packet, timeout=self.timeout, verbose=0)
        except OSError:
            return None
        elapsed = (time.perf_counter() - start) * 1000.0
        if not self._is_syn_ack(resp):
            return None
        tcp_layer = resp.getlayer(TCP)
        ack_num = int(tcp_layer.seq or 0) + 1
        seq_num = int(tcp_layer.ack or 0)
        result = self._finalize_port(ip_layer_cls, sport, port, seq_num, ack_num, elapsed)
        return result

    def _is_syn_ack(self, packet) -> bool:
        if packet is None or not packet.haslayer(TCP):
            return False
        flags = int(packet.getlayer(TCP).flags)
        return flags & 0x12 == 0x12

    def _finalize_port(self, ip_layer_cls, sport: int, dport: int, seq_num: int, ack_num: int, elapsed: float) -> ScanResult | None:
        rst_packet = ip_layer_cls(dst=self.ip) / TCP(
            sport=sport,
            dport=dport,
            flags="R",
            seq=seq_num,
            ack=ack_num,
        )
        with SCAPY_LOCK:
            send(rst_packet, verbose=0)
        proto_name = guess_tcp_protocol(self.ip, dport, self.timeout, self.family) if self.guess_proto else None
        return ScanResult("TCP", dport, elapsed, proto_name)
