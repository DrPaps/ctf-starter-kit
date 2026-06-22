import argparse
import requests
import json
import subprocess

requests.packages.urllib3.disable_warnings()

class CTFEnumerator:
    def __init__(self, target_url):
        self.target = target_url.rstrip('/')
        self.headers = {'User-Agent': 'CTF-Exploration-Bot/1.0'}
        self.session = requests.Session()
        self.session.headers.update(self.headers)

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

    scanner = CTFEnumerator(args.url)
    scanner.check_headers()

if __name__ == "__main__":
    main()
