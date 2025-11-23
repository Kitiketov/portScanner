from .config import MAX_PORT


def parse_port_piece(piece: str) -> range:
    if "-" in piece:
        start_s, end_s = piece.split("-", 1)
        start, end = int(start_s), int(end_s)
    else:
        start = end = int(piece)
    if start < 1 or end < 1 or start > MAX_PORT or end > MAX_PORT or start > end:
        raise ValueError(f"invalid port range: {piece}")
    return range(start, end + 1)


def parse_ports(part: str) -> set[int]:
    if part == "":
        return set(range(1, MAX_PORT + 1))
    ports = set()
    for piece in part.split(","):
        piece = piece.strip()
        if not piece:
            raise ValueError("empty port token")
        ports.update(parse_port_piece(piece))
    return ports


def parse_targets(raw_targets: list[str]) -> tuple[set[int], set[int]]:
    tcp_ports = set()
    udp_ports = set()
    for token in raw_targets:
        proto_part, sep, port_part = token.partition("/")
        proto = proto_part.lower()
        if proto not in {"tcp", "udp"}:
            raise ValueError(f"unknown protocol in token '{token}'")
        try:
            ports = parse_ports(port_part)
        except ValueError as exc:
            raise ValueError(f"{exc} in token '{token}'") from exc
        if proto == "tcp":
            tcp_ports.update(ports)
        else:
            udp_ports.update(ports)
    return tcp_ports, udp_ports
