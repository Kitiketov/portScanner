class ScanResult:
    def __init__(self, proto: str, port: int, elapsed_ms: float, app_proto: str | None = None) -> None:
        self.proto = proto
        self.port = port
        self.elapsed_ms = elapsed_ms
        self.app_proto = app_proto
