#!/usr/bin/env python3

import requests
import re
import argparse
import random
import json
import sys
from termcolor import colored
from concurrent.futures import ThreadPoolExecutor, as_completed
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Disable insecure request warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Define colors for output
colors = ["red", "green", "yellow", "blue", "magenta", "cyan", "white"]

# Load patterns from JSON file
try:
    with open("patterns.json", "r") as f:
        patterns = json.load(f)
except FileNotFoundError:
    print("Error: patterns.json file not found.")
    sys.exit(1)
except json.JSONDecodeError as e:
    print(f"Error parsing patterns.json: {e}")
    sys.exit(1)

# Convert patterns to list of tuples
patterns = list(patterns.items())

already_found = set()

# Set up argument parser
ap = argparse.ArgumentParser(description='Secret Finder Tool')
ap.add_argument("--list", required=True, help="File containing list of URLs")
ap.add_argument("--threads", required=False, type=int, default=10, help="Number of threads (default: 10)")
ap.add_argument("--colorless", required=False, action='store_true', help="Disable colored output")
ap.add_argument("--output", required=False, help="Output file to write results")
args = ap.parse_args()

# Create thread pool
thread_pool = ThreadPoolExecutor(max_workers=args.threads)

def print_banner():
    banner = """
                                                     /$$             
                                                    | $$             
  /$$$$$$$  /$$$$$$   /$$$$$$$  /$$$$$$   /$$$$$$  /$$$$$$  /$$   /$$
 /$$_____/ /$$__  $$ /$$_____/ /$$__  $$ /$$__  $$|_  $$_/ |  $$ /$$/
|  $$$$$$ | $$$$$$$$| $$      | $$  \__/| $$$$$$$$  | $$    \  $$$$/ 
 \____  $$| $$_____/| $$      | $$      | $$_____/  | $$ /$$ >$$  $$ 
 /$$$$$$$/|  $$$$$$$|  $$$$$$$| $$      |  $$$$$$$  |  $$$$//$$/\  $$
|_______/  \_______/ \_______/|__/       \_______/   \___/ |__/  \__/ 

    """
    print(banner)

def print_result(name, key, url):
    if key not in already_found:
        message = f"[+] Name: {name}, Key: {key}, URL: {url}"
        if args.colorless:
            print(message)
        else:
            color = random.choice(colors)
            print(colored(message, color))

        # Write to output file if specified
        if args.output:
            with open(args.output, "a") as outfile:
                outfile.write(f"Name: {name}, Key: {key}, URL: {url}\n")

        already_found.add(key)

def extract_secrets(url):
    req_headers = {
        "User-Agent": (
            "Mozilla/5.0 (compatible; SecretFinder/1.0; +https://github.com/xyele)"
        )
    }
    try:
        response = requests.get(
            url.strip(),
            verify=False,
            allow_redirects=True,
            headers=req_headers,
            timeout=10
        )

        if response.status_code in [200, 301, 302, 307, 308]:
            for name, pattern in patterns:
                try:
                    regex_pattern = re.compile(pattern)
                    matches = regex_pattern.findall(response.text)
                    for match in matches:
                        if isinstance(match, tuple):
                            key_value = match[0]
                        else:
                            key_value = match
                        print_result(name, key_value, url)
                except re.error as e:
                    print(f"Invalid regex pattern '{pattern}' for '{name}': {e}")
    except requests.exceptions.RequestException as e:
        print(f"[!] Error fetching {url}: {e}")

def main():
    print_banner()
    try:
        with open(args.list, "r") as f:
            url_list = [line.strip() for line in f if line.strip()]
        if not url_list:
            print("No URLs found in the list.")
            sys.exit(1)

        futures = {thread_pool.submit(extract_secrets, url): url for url in url_list}

        for future in as_completed(futures):
            _ = future.result()  # We don't need the result here
    except KeyboardInterrupt:
        print("\n[!] Keyboard interrupt received. Shutting down...")
        thread_pool.shutdown(wait=False)
        sys.exit(0)
    except Exception as e:
        print(f"[!] An error occurred: {e}")
        sys.exit(1)
    finally:
        thread_pool.shutdown(wait=False)

if __name__ == "__main__":
    main()
