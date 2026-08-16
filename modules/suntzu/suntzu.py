#!/usr/bin/env python3

import time
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

STATUS_WIDTH = 8

MARK_SUCCESS = f"{GREEN}[+]{RESET}"
MARK_REDIRECT = f"{YELLOW}[~]{RESET}"
MARK_FORBIDDEN = f"{BLUE}[!]{RESET}"
MARK_OTHER = f"{RED}[-]{RESET}"

SUMMARY_LABELS = {
    "success": "200 responses",
    "redirect": "Redirects",
    "forbidden": "403 responses",
    "other": "Other responses",
    "filtered": "Filtered responses",
    "timeout": "Timeouts",
    "error": "Errors"
}



def parse_arguments():
    parser = argparse.ArgumentParser(description="SunTzu directory enumeration tool")
    parser.add_argument("TARGET", help="The target URL or IP address")
    parser.add_argument("PORT", help="The target port")
    parser.add_argument("WORDLIST", help="Path to the wordlist file")
    parser.add_argument("--exclude-codes", dest="EXCLUDED_STATUS_CODES", default="", help="Status codes to exclude from results separated by commas (e.g., 404,403)")
    parser.add_argument("--extensions", dest="EXTENSIONS", default="", help="File extensions to append to each word (e.g., .php,html,js,.txt)")
    parser.add_argument("--threads", dest="THREADS", type=int, default=10, help="Number of concurrent worker threads")
    parser.add_argument("--delay", dest="DELAY", type=float, default=0.0, help="Delay in seconds between requests per threads")
    parser.add_argument("--quiet", dest="QUIET", action="store_true", help="Turn on quiet mode for pipelining")
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
            print(f"Error: invalid status code '{code}' in EXCLUDED_STATUS_CODES")
            sys.exit(1)

def validate_extensions(exts):
    for ext in exts:
        if ext.strip() == "":
            print("Error: empty file extension in EXTENSIONS")
            sys.exit(1)

        clean_ext = ext.lstrip(".")

        if clean_ext == "":
            print(f"Error: file extension '{ext}' cannot be just a dot in EXTENSIONS")
            sys.exit(1)

        if not clean_ext.isalnum():
            print(f"Error: invalid file extension '{ext}' in EXTENSIONS")
            sys.exit(1)


thread_local = threading.local()

def get_session() :
    if not hasattr(thread_local, "session"):
        session = requests.Session()
        session.headers.update({"User-Agent": "Mozilla/5.0"})
        thread_local.session = session
    return thread_local.session


def add_scan_target(scan_targets, seen_targets, candidate):
    if candidate not in seen_targets:
        seen_targets.add(candidate)
        scan_targets.append(candidate)


def has_file_extension(path):
    last_segment = path.rsplit("/", 1)[-1]
    return "." in last_segment



def scan_directory(base_url, directory, status_codes, STATUS_WIDTH, markers, delay=0.0, quiet=False):
    if delay > 0:
        time.sleep(delay)

    url = f"{base_url}/{directory}"

    session = get_session()

    MARK_SUCCESS, MARK_REDIRECT, MARK_FORBIDDEN, MARK_OTHER = markers

    try:
        response = session.get(url, timeout = 3, allow_redirects = False)

        if response.status_code in status_codes:
            return "filtered"
    
        if response.status_code == 200:
            marker = MARK_SUCCESS
            result = "success"
        elif 300 <= response.status_code < 400:
            marker = MARK_REDIRECT
            result = "redirect"
        elif response.status_code == 403:
            marker = MARK_FORBIDDEN
            result = "forbidden"
        else:
            marker = MARK_OTHER
            result = "other"

        location = response.headers.get("Location", "")
        with print_lock:
            if quiet:
                if result == "success":
                    print(directory)
            else:
                if location:
                    print(f"{marker} {response.status_code:<{STATUS_WIDTH}}{directory} -> {location}")
                else:
                    print(f"{marker} {response.status_code:<{STATUS_WIDTH}}{directory}")
        return result

    except requests.exceptions.Timeout:
        with print_lock:
            print(f"{MARK_OTHER} {'TIMEOUT':<{STATUS_WIDTH}}{directory}")
        return "timeout"

    except requests.exceptions.RequestException:
        with print_lock:
            print(f"{MARK_OTHER} {'ERROR':<{STATUS_WIDTH}}{directory}")
        return "error"


def main():
    args = parse_arguments()
    validate_wordlist(args.WORDLIST)
    validate_target(args.TARGET)
    validate_port(args.PORT)
    # transform comma-separated string into list of status codes to exclude
    status_codes = args.EXCLUDED_STATUS_CODES.split(",") if args.EXCLUDED_STATUS_CODES else []
    validate_status_codes(status_codes)
    status_codes = [int(code) for code in status_codes]
    # transform comma-separated string into list of extensions
    extensions = args.EXTENSIONS.split(",") if args.EXTENSIONS else []
    validate_extensions(extensions)

    counter = 0
    progress_interval = 50
    summary_counts = {
        "success": 0,
        "redirect": 0,
        "forbidden": 0,
        "other": 0,
        "filtered": 0,
        "timeout": 0,
        "error": 0
    }

    base_url = f"{args.TARGET.rstrip('/')}:{args.PORT}"
    
    if not args.QUIET:
        print(f"Starting directory enumeration on {args.TARGET}:{args.PORT} using wordlist {args.WORDLIST}")
        print(f"{'':3} {'CODE':<{STATUS_WIDTH}}DIRECTORY")
    
    with open(args.WORDLIST, 'r') as wordlist:
        # remove empty lines and strip whitespces
        lines = []
        seen_targets = set()
        for line in wordlist:
            stripped_line = line.strip()
            if stripped_line:
                add_scan_target(lines, seen_targets, stripped_line)
                if not has_file_extension(stripped_line):
                    for ext in extensions:
                        clean_ext = ext.lstrip(".")
                        add_scan_target(lines, seen_targets, f"{stripped_line}.{clean_ext}")
        total = len(lines)

    markers = (MARK_SUCCESS, MARK_REDIRECT, MARK_FORBIDDEN, MARK_OTHER)

    try:
        requests.get(f"{base_url}", timeout=3, allow_redirects=False)
    except requests.exceptions.RequestException:
        print(f"Error: {base_url} seems to be down or is blocking requests.")
        sys.exit(1)

    executor = concurrent.futures.ThreadPoolExecutor(max_workers=args.THREADS)
    futures = [
        executor.submit(scan_directory, base_url, directory, status_codes, STATUS_WIDTH, markers, args.DELAY, args.QUIET) for directory in lines
    ]
    try:
        for future in concurrent.futures.as_completed(futures):
            counter += 1
            result = future.result()
            summary_counts[result] += 1

            if counter % progress_interval == 0 and not args.QUIET:
                with print_lock:
                    print(f"Progress: {counter}/{total}")
    except KeyboardInterrupt:
        executor.shutdown(wait=False, cancel_futures=True)
        print(f"\n{RED}[!] Directory enumeration interrupted by user.{RESET}")
        sys.exit(130)

    if not args.QUIET:
        print("Directory enumeration completed.")
        print("Summary:")
        print(f"{'Total requests':<20}{counter}")
        for result_name, label in SUMMARY_LABELS.items():
            print(f"{label:<20}{summary_counts[result_name]}")
        print(f"Progress: {counter}/{total}")

if __name__ == "__main__":
    main()
