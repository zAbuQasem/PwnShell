#!/usr/bin/env python3
#coding=utf-8
import netifaces
import base64
import requests
import os
import argparse
import nclib
from threading import Thread
import urllib.parse
import ipaddress

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
	link()
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
	url = domain.replace('PWNME','127.0.0.1') #payload will be the revshells
	headers=''
	cookies=''
	data=''
	r=requests.post(url)

def req_get():
	url = domain.replace('PWNME','127.0.0.1') #payload will be the revshells
	headers=''
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
