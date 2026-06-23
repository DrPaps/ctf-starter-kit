# CTF-WebApp-Starterkit

An object-oriented Python command-line utility engineered for automated web security reconnaissance and CTF (Capture The Flag) enumeration. This tool automates infrastructure banner grabbing, cross-references findings with local vulnerability databases, identifies hidden architectural files, and conducts fast, multi-threaded directory fuzzing equipped with dynamic wildcard calibration.

## Features

*   **Infrastructure Analysis:** Extracts HTTP headers, target technologies, and server infrastructure details.
*   **Automated Searchsploit Mapping:** Integrates via `subprocess` with local `searchsploit` installations to immediately pull relevant CVEs and Exploit-DB scripts matching server banners.
*   **Hidden file Analysis:** Automatically checks for `/robots.txt` and `/sitemap.xml` presence and HTTP availability.
*   **Directory Fuzzing:** Implements multi-threaded directory discovery utilizing Python's `ThreadPoolExecutor`.
*   **False-Positive Filtering:** Features an automated pre-scan calibration routine to detect wildcard server redirects, dynamically filtering out spam status codes.


## Installation & Setup

### 1. Clone the Repository
```bash
git clone git@github.com:DrPaps/ctf-starter-kit.git
cd ctf-starter-kit
```

### 2. (Optional) Create and activate a Virtual Environment
```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install Required Dependencies
```bash
pip install requests
```


## Usage

### Basic Scan (Infrastructure & Hidden Files)
```bash
python3 ctf_recon.py -u [https://example.com](https://example.com)
```

### Advanced Scan (Multi-Threaded Fuzzing with Custom Wordlist)
```bash
python3 ctf_recon.py -u [https://example.com](https://example.com) -w your_wordlist.txt -t 15
```


