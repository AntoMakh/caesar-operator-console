#!/usr/bin/env python3

from typing import List, Optional
import argparse
import concurrent.futures
import re
import socket
import sys
import threading

print_lock = threading.Lock()

GREEN = "\033[32m"
YELLOW = "\033[33m"
RED = "\033[31m"
BLUE = "\033[36m"
RESET = "\033[0m"
MAX_TIMEOUT_SECONDS = 300


def parse_arguments():
    """parse command line arguments for kongming."""
    parser = argparse.ArgumentParser(description="Kongming TCP Port Scanner")
    parser.add_argument("TARGET", help="Target host or IP address")
    parser.add_argument(
        "--ports",
        dest="PORTS",
        default="21,22,23,25,53,80,110,143,443,445,3306,3389,8080",
        help="Ports to scan, e.g. 1-1024 or 22,80,443 or 20-25,80",
    )
    parser.add_argument("--threads", dest="THREADS", default="50", help="Number of worker threads")
    parser.add_argument(
        "--timeout",
        dest="TIMEOUT",
        default="1.0",
        help=f"Connection timeout in seconds (greater than 0, up to {MAX_TIMEOUT_SECONDS})",
    )
    parser.add_argument(
        "--quiet",
        dest="QUIET",
        action="store_true",
        help="Output only open port numbers for pipelining",
    )
    return parser.parse_args()


def clean_target(target: str) -> str:
    """strip any scheme and path, leaving a bare host or IP."""
    target = target.strip()
    target = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", target)
    target = target.split("/")[0]
    return target


def parse_ports(spec: str) -> List[int]:
    """turn a port specification into a sorted list of unique valid ports.

    Accepts comma-separated single ports and inclusive ranges, for example
    "22,80,443" or "1-1024" or "20-25,8080". Raises ValueError on malformed
    input or ports outside 1-65535.
    """
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start_text, end_text = part.split("-", 1)
            try:
                start, end = int(start_text), int(end_text)
            except ValueError:
                raise ValueError(f"invalid port range '{part}'") from None
            if start > end:
                start, end = end, start
            if not 1 <= start <= end <= 65535:
                raise ValueError(f"port range '{part}' is out of range 1-65535")
            for port in range(start, end + 1):
                ports.add(port)
        else:
            try:
                ports.add(int(part))
            except ValueError:
                raise ValueError(f"invalid port '{part}'") from None

    if not ports:
        raise ValueError("no ports to scan")

    out_of_range = [port for port in ports if not 1 <= port <= 65535]
    if out_of_range:
        raise ValueError(f"ports out of range 1-65535: {sorted(out_of_range)}")

    return sorted(ports)


def scan_port(host: str, port: int, timeout: float = 1.0, quiet: bool = False) -> Optional[int]:
    """attempt a TCP connection to one port; return the port if it is open."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            with print_lock:
                if quiet:
                    print(port)
                else:
                    print(f"{GREEN}[+]{RESET} Open: {port}")
            return port
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None


def main():
    args = parse_arguments()
    host = clean_target(args.TARGET)

    try:
        ports = parse_ports(args.PORTS)
    except ValueError as error:
        print(f"{RED}[!] Invalid --ports value: {error}{RESET}", file=sys.stderr)
        sys.exit(1)

    try:
        max_threads = int(args.THREADS)
    except ValueError:
        max_threads = 50
    max_threads = max(1, min(max_threads, len(ports)))

    try:
        timeout = float(args.TIMEOUT)
        if not 0 < timeout <= MAX_TIMEOUT_SECONDS:
            raise ValueError
    except ValueError:
        print(
            f"{RED}[!] Invalid --timeout value: enter a number greater than 0 "
            f"and no more than {MAX_TIMEOUT_SECONDS} seconds.{RESET}",
            file=sys.stderr,
        )
        sys.exit(1)

    try:
        resolved = socket.gethostbyname(host)
    except socket.gaierror:
        print(f"{RED}[!] Could not resolve target: {host}{RESET}", file=sys.stderr)
        sys.exit(1)

    if not args.QUIET:
        print(f"[*] Scanning {host} ({resolved}) across {len(ports)} ports | Threads: {max_threads}")
        print("-" * 60)

    open_ports = []
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=max_threads)
    futures = [
        executor.submit(scan_port, resolved, port, timeout, args.QUIET) for port in ports
    ]
    try:
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result is not None:
                open_ports.append(result)
    except KeyboardInterrupt:
        executor.shutdown(wait=False, cancel_futures=True)
        print(f"\n{RED}[!] Scan interrupted by user.{RESET}", file=sys.stderr)
        sys.exit(130)

    executor.shutdown(wait=True)

    if not args.QUIET:
        print("-" * 60)
        print(f"{GREEN}[+] Scan complete.{RESET}")
        print(f"[*] Open ports: {len(open_ports)} / {len(ports)}")


if __name__ == "__main__":
    main()
