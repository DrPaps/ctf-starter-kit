import argparse

def main():
    parser = argparse.ArgumentParser(
        description="CTF-Recon: An automated web enumeration and vulnerability scanner for CTF challenges."
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

    # for testing
    print("[*] Configuration Loaded Successfully:")
    print(f"    [+] Target URL: {args.url}")
    print(f"    [+] Wordlist:   {args.wordlist}")
    print(f"    [+] Threads:    {args.threads}")

if __name__ == "__main__":
    main()
