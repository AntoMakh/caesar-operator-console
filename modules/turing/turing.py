import requests
import argparse
import sys
import json
import os
import re

def parse_arguments():
    parser = argparse.ArgumentParser(description="Turing Web App Fingerprinting tool")
    parser.add_argument("TARGET", help="The target URL or IP address")
    parser.add_argument("PORT", help="The target port")
    return parser.parse_args()

def validate_target(target):
    if not target.startswith("http://") and not target.startswith("https://"):
        print("Error: TARGET must start with http:// or https://")
        sys.exit(1)

def validate_port(port):
    if not port.isdigit() or not (1 <= int(port) <= 65535):
        print("Error: invalid port number")
        sys.exit(1)

def parse_header_products(header_value):
    products = []
    product_pattern = re.findall(r'([A-Za-z][A-Za-z0-9_-]*)/([^\s()]+)', header_value)
    for name, version in product_pattern:
        products.append({"name": name, "version": version})
    return products

def load_signatures():
    signature_database_path = os.path.join(os.path.dirname(__file__), "signature.json")
    if not os.path.isfile(signature_database_path):
        print("[ERROR] No signature database file. Cannot run.")
        sys.exit(1)

    with open(signature_database_path, "r") as f:
        return json.load(f)

def match_evidence(source_name, evidence, signatures):
    matches = []
    for header_name, possible_header_values in signatures.get("headers", {}).items():
        if header_name in evidence.get("headers", {}):
            found_header_value = evidence["headers"][header_name]
            for possible_header_value in possible_header_values:
                if possible_header_value.lower() in found_header_value.lower():
                    matches.append({
                        "matched_source": source_name,
                        "matched_header": header_name,
                        "matched_value": possible_header_value
                    })

    for keyword in signatures.get("body_contains", []):
        if keyword.lower() in evidence.get("body", "").lower():
            matches.append({
                "matched_source": source_name,
                "matched_header": None,
                "matched_value": keyword
            })

    return matches if matches else None

def detect_technologies(evidence, path_evidence, signatures):
    findings = []

    for technology, rules in signatures.items():
        main_match = match_evidence("main_page", evidence, rules)
        if main_match:
            for match in main_match:
                findings.append({
                        "technology": technology,
                        "matched_source": match["matched_source"],
                        "matched_header": match["matched_header"],
                        "matched_value": match["matched_value"]
                    })

        for path, path_info in path_evidence.items():
            if path_info is None:
                continue

            if path in rules.get("paths", []) and path_info.get("status_code") == 200:
                findings.append({
                    "technology": technology,
                    "matched_source": f"path: {path}",
                    "matched_header": None,
                    "matched_value": path
                })

            path_match = match_evidence(f"path: {path}", path_info, signatures)
            if path_match:
                findings.append({
                    "technology": main_match["matched_value"],
                    "matched_source": path_match["matched_source"],
                    "matched_header": path_match["matched_header"],
                    "matched_value": path_match["matched_value"]
                })

    return findings

def detect_technology_version(findings, evidence):
    results = []

    for finding in findings:
        version = "unknown"
        matched_header = finding["matched_header"]
        matched_value = finding["matched_value"]

        if matched_header:
            header_value = evidence["headers"].get(matched_header, "")
            parsed_products = parse_header_products(header_value)
            for product in parsed_products:
                if product["name"].lower() == matched_value.lower():
                    version = product["version"]
                    break

        results.append({
            "technology": finding["technology"],
            "matched_header": matched_header,
            "matched_value": matched_value,
            "version": version
        })
    return results

def collect_path_evidence(base_url, paths):
    path_evidence = {}

    for path in paths:
        try:
            response = requests.get(f"{base_url}/{path}", timeout=3)
            path_evidence[path] = {
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "body": response.text
            }
        except requests.RequestException:
            path_evidence[path] = {
                "status_code": None,
                "headers": {},
                "body": ""
            }

    return path_evidence

def collect_evidence(response):
    return {
        "status_code": response.status_code,
        "headers": dict(response.headers),
        "body": response.text
    }

def main():
    args = parse_arguments()
    validate_target(args.TARGET)
    validate_port(args.PORT)
    
    base_url = f"{args.TARGET}:{args.PORT}"
    try:
        response = requests.get(base_url, timeout=3)
        evidence = collect_evidence(response)
        signatures = load_signatures()

        all_paths = []
        for rules in signatures.values():
            all_paths.extend(rules.get("paths", []))
        all_paths = list(set(all_paths))
        
        path_evidence = collect_path_evidence(base_url, all_paths)

        print(json.dumps(evidence["headers"], indent=4))
        findings = detect_technologies(evidence, path_evidence, signatures)
        findings_with_versions = detect_technology_version(findings, evidence)
        print("\n[+] Detected Technologies:")
        for finding in findings_with_versions:
            if finding["version"] != "unknown":
                print(f" - {finding['technology']} {finding['version']} (matched: {finding['matched_value']})")
            else:
                print(f" - {finding['technology']} (matched: {finding['matched_value']})")
    except requests.RequestException as e:
        print(f"Error connecting to {base_url}: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
