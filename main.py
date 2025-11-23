from src.args import parse_args
from src.helpers import resolve_target
from src.output import render_table
from src.ports import parse_targets
from src.scanner import PortScanner


def main() -> None:
    args = parse_args()
    try:
        target_ip = resolve_target(args.ip)
    except ValueError as exc:
        print(f"Error: {exc}")
        raise SystemExit(1)
    try:
        tcp_ports, udp_ports = parse_targets(args.targets)
    except ValueError as exc:
        print(f"Error: {exc}")
        raise SystemExit(1)

    scanner = PortScanner(target_ip, args.timeout, args.num_threads, args.guess)
    results = scanner.scan(tcp_ports, udp_ports)
    results.sort(key=lambda r: (r.proto, r.port))
    render_table(results, args.verbose, args.guess)


if __name__ == "__main__":
    main()
