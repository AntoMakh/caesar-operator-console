#!/usr/bin/env python3

import argparse
import os
import requests
import sys
import threading
import concurrent.futures

print_lock = threading.Lock()

GREEN = "\033[32m"
YELLOW = "\033[33m"
RED = "\033[31m"
BLUE = "\033[36m"
RESET = "\033[0m"

STATUS_WIDTH = 6

MARK_SUCCESS = f"{GREEN}[+]{RESET}"
MARK_REDIRECT = f"{YELLOW}[~]{RESET}"
MARK_FORBIDDEN = f"{BLUE}[!]{RESET}"
MARK_OTHER = f"{RED}[-]{RESET}"

MAX_THREADS = 20



def parse_arguments():
    parser = argparse.ArgumentParser(description="SunTzu directory enumeration tool")
    parser.add_argument("TARGET", help="The target URL or IP address")
    parser.add_argument("PORT", help="The target port")
    parser.add_argument("WORDLIST", help="Path to the wordlist file")
    parser.add_argument("STATUS_CODES_EXCLUDED", nargs='?', default="", help="Status codes to exclude from results separated by commas (e.g., 404,403)")
    return parser.parse_args()

def validate_wordlist(path):
    if not os.path.isfile(path):
        print("Error: wordlist not found")
        sys.exit(1)

def validate_target(target):
    if not target.startswith("http://") and not target.startswith("https://"):
        print("Error: TARGET must start with http:// or https://")
        sys.exit(1)

def validate_port(port):
    if not port.isdigit() or not (1 <= int(port) <= 65535):
        print("Error: invalid port number")
        sys.exit(1)

def validate_status_codes(codes):
    for code in codes:
        if not code.isdigit() or not (100 <= int(code) <= 599):
            print(f"Error: invalid status code '{code}' in STATUS_CODES_EXCLUDED")
            sys.exit(1)

thread_local = threading.local()

def get_session() :
    if not hasattr(thread_local, "session"):
        session = requests.Session()
        session.headers.update({"User-Agent": "Mozilla/5.0"})
        thread_local.session = session
    return thread_local.session



def scan_directory(base_url, directory, status_codes, STATUS_WIDTH, markers):
    url = f"{base_url}/{directory}"

    session = get_session()

    MARK_SUCCESS, MARK_REDIRECT, MARK_FORBIDDEN, MARK_OTHER = markers

    try:
        response = session.get(url, timeout = 3, allow_redirects = False)

        if response.status_code in status_codes:
            return
    
        if response.status_code == 200:
            marker = MARK_SUCCESS
        elif 300 <= response.status_code < 400:
            marker = MARK_REDIRECT
        elif response.status_code == 403:
            marker = MARK_FORBIDDEN
        else:
            marker = MARK_OTHER

        location = response.headers.get("Location", "")
        with print_lock:
            if location:
                print(f"{marker} {response.status_code:<{STATUS_WIDTH}}{directory} -> {location}")
            else:
                print(f"{marker} {response.status_code:<{STATUS_WIDTH}}{directory}")

    except requests.exceptions.Timeout:
        with print_lock:
            print(f"{MARK_OTHER} {'TIMEOUT':<{STATUS_WIDTH}}{directory}")

    except requests.exceptions.RequestException:
        with print_lock:
            print(f"{MARK_OTHER} {'ERROR':<{STATUS_WIDTH}}{directory}")


def main():
    args = parse_arguments()
    validate_wordlist(args.WORDLIST)
    validate_target(args.TARGET)
    validate_port(args.PORT)
    # transform comma-separated string into list of status codes to exclude
    status_codes = args.STATUS_CODES_EXCLUDED.split(",") if args.STATUS_CODES_EXCLUDED else []
    validate_status_codes(status_codes)
    status_codes = [int(code) for code in status_codes]

    counter = 0
    progress_interval = 50

    base_url = f"{args.TARGET.rstrip('/')}:{args.PORT}"
    
    print(f"Starting directory enumeration on {args.TARGET}:{args.PORT} using wordlist {args.WORDLIST}")
    print(f"{'':3} {'CODE':<{STATUS_WIDTH}}DIRECTORY")
    
    with open(args.WORDLIST, 'r') as wordlist:
        # remove empty lines and strip whitespces
        lines = []
        for line in wordlist:
            stripped_line = line.strip()
            if stripped_line:
                lines.append(stripped_line)
        total = len(lines)

    markers = (MARK_SUCCESS, MARK_REDIRECT, MARK_FORBIDDEN, MARK_OTHER)

    try:
        requests.get(f"{base_url}", timeout=3, allow_redirects=False)
    except requests.exceptions.RequestException:
        print(f"Error: {base_url} seems to be down or is blocking requests.")
        sys.exit(1)


    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = [
            executor.submit(scan_directory, base_url, directory, status_codes, STATUS_WIDTH, markers) for directory in lines
        ]
        for _ in concurrent.futures.as_completed(futures):
            counter += 1

            if counter % progress_interval == 0:
                with print_lock:
                    print(f"Progress: {counter}/{total}")

    print("Directory enumeration completed.")
    print(f"Progress: {counter}/{total}")

if __name__ == "__main__":
    main()
