from concurrent.futures import ThreadPoolExecutor, as_completed

from .models import ScanResult
from .scanners import TCPSYNScanner, UDPScanner


class PortScanner:
    def __init__(self, ip: str, timeout: float, threads: int, guess_proto: bool) -> None:
        self.tcp_scanner = TCPSYNScanner(ip, timeout, guess_proto)
        self.udp_scanner = UDPScanner(ip, timeout, guess_proto)
        self.threads = threads

    def scan(self, tcp_ports: set[int], udp_ports: set[int]) -> list[ScanResult]:
        results = []
        futures = {}
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            for port in sorted(tcp_ports):
                futures[executor.submit(self.tcp_scanner.scan, port)] = port
            for port in sorted(udp_ports):
                futures[executor.submit(self.udp_scanner.scan, port)] = port
            try:
                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        results.append(result)
            except KeyboardInterrupt:
                for fut in futures:
                    fut.cancel()
        return results
