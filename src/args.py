import argparse

from .config import DEFAULT_THREADS, DEFAULT_TIMEOUT


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Simple TCP/UDP port scanner")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help="response timeout in seconds (default: 2)")
    parser.add_argument("-j", "--num-threads", type=int, default=DEFAULT_THREADS, help="number of worker threads")
    parser.add_argument("-v", "--verbose", action="store_true", help="print response time column")
    parser.add_argument("-g", "--guess", action="store_true", help="guess application protocol")
    parser.add_argument("ip", help="target IP address")
    parser.add_argument("targets", nargs="*", help="protocol/port specifications like tcp/80, udp/53, tcp/1-1024")
    args = parser.parse_args()

    if args.timeout <= 0:
        parser.error("timeout must be positive")
    if args.num_threads is None or args.num_threads <= 0:
        parser.error("number of threads must be positive")
    if not args.targets:
        parser.error("provide at least one protocol/port specification")
    return args
