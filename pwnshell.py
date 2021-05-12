#!/usr/bin/env python3
import netifaces
import base64
import requests
import os
import argparse
import nclib
from threading import Thread

def main():
	global args , default_ip , nc , port
	ip_address = netifaces.ifaddresses('eth0')[2] #change interface
	default_ip = ip_address[0]['addr'] 
	parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
	parser.add_argument('-H','--host' ,help='LOCAL IP ADDRESS',default=default_ip)
	parser.add_argument('-p','--port' ,help='LOCAL PORT NUMBER',type=int,default=9001)
	parser.add_argument("-t","--type",help='Payload Type [windows/linux]',type=str,default='linux')
	parser.add_argument("-u","--url",help='Target url [http://localhost:8888/h.php?meow=PWN]')
	#parser.add_argument("-c","--cookie",help='Provide a Cookie')
	#parser.add_argument("-l","--header",help='Provide a header')
	#parser.add_argument("-m","--method",help='Request Method')
	#parser.add_argument("-d","--data",help='Post data')
	args = parser.parse_args()
	ip=default_ip
	ip=args.host
	port=args.port


	if args.type == "linux" or args.type == "l":
		shell_linux()
	elif args.type == "windows" or args.type == "w":
		shell_windows()
	else:
		print("[!]Invalid Value -> "+ args.type)



def shell_linux():
	print("listening on port: "+ f"{port}" + "\n" + "Default ip for payloads: "+ f"{default_ip}")
	print ("---> Waiting For a connection ")
	aa()
	nc.close()


def aa():
	global nc
	nc = nclib.Netcat(listen=('', port))
	nc.interact()


if __name__ == '__main__':
		exit(main())


#TODO
#add payloads to a list or a dict for iteration
