#!/usr/bin/python3
import requests
import argparse
import os
from colorama import Fore, Style, init
init(autoreset=True)
def get_severity_color(cvss_score):
    if cvss_score is None:
        cvss_score = 0
    if cvss_score >= 9.0:
        return f"{Fore.RED}[CRITICAL]{Style.RESET_ALL}"
    elif cvss_score >= 7.0:
        return f"{Fore.RED}[HIGH]{Style.RESET_ALL}"
    elif cvss_score >= 4.0:
        return f"{Fore.YELLOW}[MEDIUM]{Style.RESET_ALL}"
    else:
        return f"{Fore.GREEN}[LOW]{Style.RESET_ALL}"
def fetch_cve_details(cve_id):
    url = f"https://cvedb.shodan.io/cve/{cve_id}"
    response = requests.get(url)
    if response.status_code == 200:
        return response.json()
    return {}
def log_cves(ip, data):
    if data.get("vulns"):
        for cve in data["vulns"]:
            cve_info = fetch_cve_details(cve)
            severity = get_severity_color(cve_info.get("cvss_v3", 0))
            cve_description = cve_info.get("summary", "No description available.")[:80]  # Short description
            print(f"{Fore.BLUE}[{ip}]{Style.RESET_ALL} [{Fore.GREEN}{cve}{Style.RESET_ALL}] {severity} [{Fore.GREEN}{cve_description}{Style.RESET_ALL}]")
    else:
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} No CVEs found for {ip}")
def process_ip(ip):
    url = f"https://internetdb.shodan.io/{ip}"
    response = requests.get(url)
    if response.status_code == 200:
        data = response.json()
        log_cves(ip, data)
    else:
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Failed to fetch data for {ip}")
class CustomHelpFormatter(argparse.HelpFormatter):
    def add_usage(self, usage, actions, groups, prefix=None):
        pass
def main():
    os.system("cls" if os.name == "nt" else "clear")
    print(fr'''                      _          _    
   ___  ___ ____ ___ (_)  _____ (_)__ 
  / _ \/ _ `(_-<(_-</ / |/ / -_) / _ \
 / .__/\_,_/___/___/_/|___/\__/_/ .__/
/_/                            /_/    v1.1.0
                @rootharpy

{Fore.CYAN}[INFO]{Style.RESET_ALL} Passive IP recon tool using Shodan API to gather metadata, vulnerabilities, 
 and CVE information for analysis
    ''')

    script_name = os.path.basename(__file__)
    parser = argparse.ArgumentParser(
        formatter_class=CustomHelpFormatter
    )
    parser.add_argument("-f", "--file", help="File containing a list of IPs.")
    parser.epilog = f"Usage:\n  python {script_name} -f <file>"
    try:
        args = parser.parse_args()
        if not args.file:
            print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} The '-f/--file' argument is required.")
            exit(1)
        with open(args.file, "r") as file:
            ips = file.read().splitlines()
            for ip in ips:
                process_ip(ip)
        print(f"\n{Fore.YELLOW}[INFO]{Style.RESET_ALL} Scan Completed")
    except FileNotFoundError:
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} The file '{args.file}' was not found.")
        exit(1)
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[INFO]{Style.RESET_ALL} Process interrupted by user. Exiting...")
        exit(0)
    except argparse.ArgumentError:
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} The '-f/--file' argument is required.")
        exit(1)
if __name__ == "__main__":
    main()
