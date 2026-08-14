#!/usr/bin/env python3

from logging import exception
import argparse
import os
import requests
import sys
import threading
import concurrent.futures
import socket

print_lock = threading.Lock()

GREEN = "\033[32m"
YELLOW = "\033[33m"
RED = "\033[31m"
BLUE = "\033[36m"
RESET = "\033[0m"

def parse_arguments():
    parser = argparse.ArgumentParser(description="Magellan DNS Subdomain Enumeration")
    parser.add_argument("DOMAIN", help="Target root domain (e.g. example.com)")
    parser.add_argument("WORDLIST", help="Path to subdomain wordlist")
    parser.add_argument("--threads", dest="THREADS", default="10", help="Number of worker threads")
    return parser.parse_args()

def clean_domain(domain):
    # need to strip scheme and trailing slashes
    domain = domain.replace("http://", "").replace("https://", "").strip("/")
    return domain

def validate_wordlist(path):
    if not os.path.isfile(path):
        print(f"{RED}[!] Error: wordlist not found at {path}{RESET}")
        sys.exit(1)

def resolve_subdomain(subdomain, domain):
    domain_name = f"{subdomain}.{domain}"

    try:
        ip = socket.gethostbyname(domain_name)

        with print_lock:
            print(f"{GREEN}[+]{RESET} Discovered: {domain_name:<35} -> {ip}")

        return (domain_name, ip)
    except socket.gaierror:
        return None
    except Exception as e:
        return None

def main():
    args = parse_arguments()
    target_domain = clean_domain(args.DOMAIN)
    validate_wordlist(args.WORDLIST)

    try:
        max_threads = int(args.THREADS)
    except ValueError:
        max_threads = 10

    with open(args.WORDLIST, "r", encoding="utf-8", errors="ignore") as f:
        subdomain_words = [line.strip() for line in f if line.strip()]

    total = len(subdomain_words)
    discovered = []
    print(f"[*] Starting DNS enumeration on {target_domain} using {args.WORDLIST}")
    print(f"[*] Total words to check: {total} | Threads running: {max_threads}\n")
    print("-" * 60)
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = [
            executor.submit(resolve_subdomain, word, target_domain) for word in subdomain_words
        ]
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result is not None:
                discovered.append(result)
        
    print("-" * 60)
    print(f"{GREEN}[+] DNS enumeration completed.{RESET}")
    print(f"[*] Discovered subdomains: {len(discovered)} / {total}")

if __name__ == "__main__":
    main()