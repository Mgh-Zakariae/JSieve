import argparse
import json
import os
import pathlib
import shutil
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

# Make imports work from any installation path.
for folder in ["recon", "collector", "analyzer", "reporting"]:
    sys.path.insert(0, str(BASE_DIR / folder))

from get_LiveHosts import get_subdomain
from crawler import get_js
from js_downloader import install_js
from sourcemap_checker import build_sourcemap_candidates, map_downloader
from sensitive_analyzer import analyzer
from endpoint_extractor import endpointExtractor


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="JSieve: collect public JavaScript files and analyze them for endpoints and exposed secrets."
    )

    group = parser.add_mutually_exclusive_group(required=True)

    group.add_argument(
        "-d",
        "--domain",
        help="Target a single domain or URL, example: example.com or https://app.example.com",
    )

    group.add_argument(
        "-l",
        "--list",
        type=pathlib.Path,
        help="Path to a text file containing domains/URLs, one per line",
    )

    parser.add_argument(
        "--no-subdomains",
        action="store_true",
        help="Disable subdomain enumeration and scan only the provided target(s)",
    )

    parser.add_argument(
        "-gr",
        "--generate-report",
        action="store_true",
        help="Generate an HTML report from findings.json and endpoints.json",
    )

    parser.add_argument(
        "-t",
        "--threads",
        type=int,
        default=15,
        help="Number of worker threads for downloading/analyzing files (default: 15)",
    )

    parser.add_argument(
        "-o",
        "--output",
        default="output",
        help="Base output directory (default: output)",
    )

    return parser.parse_args()


def safe_scan_name(value):
    value = value.strip().replace("https://", "").replace("http://", "")
    value = value.strip("/")

    safe = []
    for char in value:
        if char.isalnum() or char in ".-_":
            safe.append(char)
        else:
            safe.append("_")

    result = "".join(safe).strip("_")
    return result or "scan"


def load_targets(args):
    if args.domain:
        return [args.domain.strip()]

    if not args.list.exists():
        print(f"[!] Error: file '{args.list}' does not exist.")
        sys.exit(1)

    with open(args.list, "r", encoding="utf-8") as file:
        targets = [
            line.strip()
            for line in file
            if line.strip() and not line.strip().startswith("#")
        ]

    return targets


def normalize_exact_targets(targets):
    hosts = []

    for target in targets:
        target = target.strip().rstrip("/")

        if target.startswith(("http://", "https://")):
            hosts.append(target)
        else:
            hosts.append("https://" + target)

    return list(dict.fromkeys(hosts))


def check_required_tools(args):
    missing = []

    if shutil.which("katana") is None:
        missing.append("katana")

    if not args.no_subdomains and not args.list:
        if shutil.which("subfinder") is None:
            missing.append("subfinder")

        if shutil.which("httpx-toolkit") is None and shutil.which("httpx") is None:
            missing.append("httpx-toolkit or httpx")

    if missing:
        print("[!] Missing external tool(s): " + ", ".join(missing))
        print("[!] Install ProjectDiscovery tools, then make sure they are in your PATH.")
        print("[!] See README.md for installation commands.")
        sys.exit(1)


def write_lines(path, lines):
    with open(path, "w", encoding="utf-8") as file:
        for line in lines:
            file.write(str(line) + "\n")


def write_json(path, data):
    with open(path, "w", encoding="utf-8") as file:
        json.dump(data, file, indent=4)


def main():
    args = parse_arguments()
    check_required_tools(args)

    targets = load_targets(args)

    if not targets:
        print("[!] No valid target provided.")
        sys.exit(1)

    scan_name = safe_scan_name(targets[0])
    if args.list:
        scan_name = "list_" + scan_name

    output_dir = Path(args.output) / scan_name
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"[*] Output directory: {output_dir}")

    # Step 1: host preparation
    if not args.no_subdomains and not args.list:
        print("[*] Enumerating subdomains...")
        hosts = get_subdomain(targets[0])
    else:
        print("[*] Subdomain enumeration disabled.")
        hosts = normalize_exact_targets(targets)

    hosts = list(dict.fromkeys(hosts))
    write_lines(output_dir / "hosts.txt", hosts)

    print(f"[+] Hosts saved: {output_dir / 'hosts.txt'}")
    print(f"[+] Total hosts: {len(hosts)}")

    # Step 2: JavaScript URL enumeration
    print("\n[*] Enumerating JS files...")
    js_urls = get_js(hosts)
    js_urls = list(dict.fromkeys(js_urls))
    write_lines(output_dir / "js_urls.txt", js_urls)

    print(f"[+] JS URLs saved: {output_dir / 'js_urls.txt'}")
    print(f"[+] Total JS URLs: {len(js_urls)}")

    # Step 3: JavaScript download
    print("\n[*] Downloading JS files...")
    js_files = install_js(js_urls, scan_name, threads=args.threads)
    write_json(output_dir / "downloaded_js_files.json", js_files)

    print(f"[+] Downloaded JS metadata saved: {output_dir / 'downloaded_js_files.json'}")
    print(f"[+] Total downloaded JS files: {len(js_files)}")

    # Step 4: source maps
    print("\n[*] Finding and downloading sourcemaps...")
    all_files = js_files.copy()
    all_maps = []

    for js_file in js_files:
        candidates = build_sourcemap_candidates(js_file)
        maps = map_downloader(candidates, scan_name, threads=args.threads)
        if maps:
            all_maps.extend(maps)

    all_maps = list({item.get("url", ""): item for item in all_maps}.values())
    all_files.extend(all_maps)
    write_json(output_dir / "sourcemaps.json", all_maps)

    print(f"[+] Source maps saved: {output_dir / 'sourcemaps.json'}")
    print(f"[+] Total source maps: {len(all_maps)}")

    # Step 5: sensitive data analysis
    print("\n[*] Analyzing JS files and sourcemaps...")
    findings = analyzer(all_files, threads=args.threads) if all_files else []
    write_json(output_dir / "findings.json", findings)

    print(f"[+] Findings saved: {output_dir / 'findings.json'}")
    print(f"[+] Total findings: {len(findings)}")

    # Step 6: endpoint extraction
    print("\n[*] Extracting endpoints from JS files...")
    endpoints = endpointExtractor(all_files, threads=args.threads) if all_files else []
    write_json(output_dir / "endpoints.json", endpoints)
    write_lines(output_dir / "endpoints.txt", [item.get("endpoint", "") for item in endpoints])

    print(f"[+] Endpoints saved: {output_dir / 'endpoints.json'}")
    print(f"[+] Endpoints TXT saved: {output_dir / 'endpoints.txt'}")
    print(f"[+] Total endpoints: {len(endpoints)}")

    # Step 7: optional report
    if args.generate_report:
        print("\n[*] Generating HTML report...")
        try:
            from json_to_html import json_to_html

            report_path = json_to_html(str(output_dir))
            print(f"[+] HTML report saved: {report_path}")
        except ModuleNotFoundError as error:
            print(f"[!] Report generation failed: missing module {error.name}")
            print("[!] Install Python dependencies with: pip install -r requirements.txt")
        except Exception as error:
            print(f"[!] Report generation failed: {error}")

    print("\n[+] Scan completed!")


if __name__ == "__main__":
    main()
