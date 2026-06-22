import argparse
import requests
import json
import subprocess
import os
from concurrent.futures import ThreadPoolExecutor, as_completed

requests.packages.urllib3.disable_warnings()

class CTFEnumerator:
    def __init__(self, target_url, wordlist_path=None, threads=10):
        self.target = target_url.rstrip('/')
        self.wordlist_path = wordlist_path
        self.threads = threads
        self.headers = {'User-Agent': 'CTF-Exploration-Bot/1.0'}
        self.session = requests.Session()
        self.session.headers.update(self.headers)

    def run_all(self):
        self.check_headers()
        self.parse_hidden_files()
        if self.wordlist_path:
            self.brute_directories()
        else:
            print("\n[-] Skipping Directory Fuzzing: No wordlist provided (-w).")

    def check_headers(self):
        print(f"\n[*] Starting scan against: {self.target}")
        print("[+] --- Checking Headers & Server Info ---")
        
        try:
            response = self.session.get(self.target, verify=False, timeout=5)
            server = response.headers.get('Server')
            powered_by = response.headers.get('X-Powered-By')
            
            if server:
                print(f"    [!] Server Banner Found: {server}")
                self.lookup_vuln(server)
            else:
                print("    [-] No 'Server' header exposed.")
                
            if powered_by:
                print(f"    [!] Technology Clue:    {powered_by}")
                self.lookup_vuln(powered_by)
                
            for header, value in response.headers.items():
                if any(keyword in header.lower() for keyword in ['flag', 'admin', 'debug', 'secret']):
                    print(f"    [!!!] High-value CTF Header Detected -> {header}: {value}")
                    
        except requests.RequestException as e:
            print(f"    [-] Connection Error: Could not connect to {self.target}")
            print(f"        Details: {e}")
            
    def lookup_vuln(self, software_string):
        print(f"    [*] Querying local Searchsploit for '{software_string}'...")
        
        search_term = software_string.split('(')[0].replace('/', ' ').strip()
        
        try:
            result = subprocess.run(
                ['searchsploit', '--json', search_term],
                capture_output=True,
                text=True,
                check=True
            )
            
            data = json.loads(result.stdout)
            results = data.get('RESULTS_EXPLOIT', [])
            
            if results:
                print(f"    [!!!] Found {len(results)} potential exploits! Top matches:")
                for exploit in results[:3]:
                    title = exploit.get('Title', 'No Title')
                    path = exploit.get('Path', 'No Path')
                    print(f"        [-] {title}")
                    print(f"            Path: {path}")
            else:
                print("        [-] No immediate searchsploit matches found.")
                
        except FileNotFoundError:
            print("        [-] Error: 'searchsploit' utility not found on your system PATH.")
            print("            Make sure exploitdb is installed (e.g., sudo apt install exploitdb).")
        except subprocess.CalledProcessError:
            print("        [-] Searchsploit encountered an error executing.")
        except json.JSONDecodeError:
            print("        [-] Failed to parse Searchsploit's output data.")

    def parse_hidden_files(self):
        print("\n[+] --- Checking Hidden Files ---")
        paths = ['/robots.txt', '/sitemap.xml']
        
        for path in paths:
            url = self.target + path
            try:
                res = self.session.get(url, verify=False, timeout=5)
                if res.status_code == 200:
                    print(f"    [!!!] Found {path}! Content:")
                    indented_content = "\n".join([f"        {line}" for line in res.text.strip().split('\n')])
                    print(indented_content)
                else:
                    print(f"    [-] {path} not found (Status: {res.status_code})")
            except requests.RequestException:
                print(f"    [-] Error checking {path}")

    def test_single_dir(self, word, baseline_status=None):
        url = f"{self.target}/{word}"
        try:
            res = self.session.head(url, verify=False, timeout=5, allow_redirects=False)
            
            if baseline_status and res.status_code == baseline_status:
                return None
                
            if res.status_code in [200, 204, 301, 302, 403]:
                return (url, res.status_code)
        except requests.RequestException:
            pass
        return None

    def brute_directories(self):
        print(f"\n[+] --- Launching Directory Brute Forcer ({self.threads} Threads) ---")
        
        if not os.path.exists(self.wordlist_path):
            print(f"    [-] Error: The wordlist file '{self.wordlist_path}' does not exist.")
            return

        print("    [*] Calibrating fuzzer baseline against wildcard redirects...")
        baseline_status = None
        try:
            calibration_res = self.session.head(
                f"{self.target}/calibrated_filter_test_xyz987", 
                verify=False, timeout=5, allow_redirects=False
            )
            if calibration_res.status_code != 404:
                baseline_status = calibration_res.status_code
                print(f"    [!] Wildcard detected! Server returns status {baseline_status} for missing pages.")
                print(f"        Filtering out all future status {baseline_status} responses to prevent spam.")
            else:
                print("    [+] No wildcard detected. Server handles missing pages correctly (404).")
        except requests.RequestException:
            print("    [-] Calibration failed. Proceeding without filtering.")

        with open(self.wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
            words = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            
        print(f"    [*] Successfully loaded {len(words)} directory permutations. Fuzzing...")

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(self.test_single_dir, word, baseline_status) for word in words]
            
            found_any = False
            for future in as_completed(futures):
                result = future.result()
                if result:
                    url, status = result
                    print(f"    [!!!] Found: {url} (Status: {status})")
                    found_any = True
            
            if not found_any:
                print("    [-] Fuzzing complete. No legitimate directories discovered.")

def main():
    parser = argparse.ArgumentParser(
        description="CTF-Recon: An automated web enumeration tool built specifically for CTFs."
    )
    
    parser.add_argument(
        "-u", "--url", 
        required=True, 
        help="Target URL to scan (e.g., http://10.10.10.15 or http://example.com)"
    )
    
    parser.add_argument(
        "-w", "--wordlist", 
        required=False, 
        help="Path to the directory wordlist file (e.g., common.txt)"
    )
    
    parser.add_argument(
        "-t", "--threads", 
        type=int, 
        default=10, 
        help="Number of concurrent threads for brute forcing (Default: 10)"
    )

    args = parser.parse_args()

    scanner = CTFEnumerator(args.url, wordlist_path=args.wordlist, threads=args.threads)
    scanner.run_all()

if __name__ == "__main__":
    main()
