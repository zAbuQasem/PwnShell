#!/usr/bin/env python3
import base64
import requests
import sys
import argparse

def main():
	parser = argparse.ArgumentParser()
	parser.add_argument('-H','--host' ,help='LOCAL IP ADDRESS',required=True)
	parser.add_argument('-p','--port' ,help='LOCAL PORT NUMBER',type=int,required=True)
	parser.add_argument("-t","--type",help='Payload Type [windows/linux]',type=str,required=True)
	args = parser.parse_args()

	if args.type == "linux" or args.type == "l":
		shell_linux()
	elif args.type == "windows" or args.type == "w":
		shell_windows()
	else:
		print("[!]Invalid Value -> "+args.type)

def shell_linux():
	print ("jello")

def shell_windows():
	print("hello")

if __name__ == '__main__':
		exit(main())