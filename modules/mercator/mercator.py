#!/usr/bin/env python3

import argparse
import sys

import requests

# adopting new approach of making more functions when coding

def parse_arguments():
    parser = argparse.ArgumentParser(description="Mercator crt.sh subdomain enumeration tool")
    parser.add_argument("TARGET", help="The target domain as it exists on the internet")
    parser.add_argument(
        "--quiet",
        dest="QUIET",
        action="store_true",
        help="Output only discovered subdomains for pipelining",
    )
    return parser.parse_args()


def validate_target(target):
    if not target or "." not in target:
        print("[!] Error: TARGET must be a valid domain name", file=sys.stderr)
        sys.exit(1)


def build_query_url(target):
    return f"https://crt.sh/?q={target}&output=json"


def fetch_certificate_data(target):
    url = build_query_url(target)

    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as error:
        print(f"[!] Error retrieving crt.sh data: {error}", file=sys.stderr)
        sys.exit(1)
    except ValueError:
        print("[!] Error: crt.sh did not return valid JSON", file=sys.stderr)
        sys.exit(1)


def extract_subdomains(certificates):
    subdomains = set()
    for cert in certificates:
        name_value = cert.get("name_value", "")
        if not name_value:
            continue

        entries = name_value.split("\n")

        for entry in entries:
            entry = entry.strip()
            if not entry:
                continue

            if entry.startswith("CN="):
                continue
            subdomains.add(entry)
    return subdomains


def print_subdomains(subdomains, quiet=False):
    if not quiet:
        print(f"[*] Discovered {len(subdomains)} unique names from crt.sh")
    for subdomain in sorted(subdomains):
        print(subdomain if quiet else f"[+] {subdomain}")


def main():
    args = parse_arguments()
    validate_target(args.TARGET)

    certificates = fetch_certificate_data(args.TARGET)
    subdomains = extract_subdomains(certificates)
    print_subdomains(subdomains, args.QUIET)

if __name__ == "__main__":
    main()
