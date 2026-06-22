import argparse
import requests

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
            else:
                print("    [-] No 'Server' header exposed.")
                
            if powered_by:
                print(f"    [!] Technology Clue:    {powered_by}")
                
            for header, value in response.headers.items():
                if any(keyword in header.lower() for keyword in ['flag', 'admin', 'debug', 'secret']):
                    print(f"    [!!!] High-value CTF Header Detected -> {header}: {value}")
                    
        except requests.RequestException as e:
            print(f"    [-] Connection Error: Could not connect to {self.target}")
            print(f"        Details: {e}")

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
