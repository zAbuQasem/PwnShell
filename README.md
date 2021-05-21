

# PwnShell

PwnShell is a python script that automate the remote code execution process

![Product Name Screen Shot][product-screenshot]


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
###Recommended method 👇
```sh
   ./pwnshell.py -H [HOST IP] -f [REQUEST FILE]
   ```
### OR

```sh
   ./pwnshell.py -H [HOST IP] -u [TARGET URL] -m [REQUEST METHOD] -c [COOKIE (optional)] -k [HEADERS (optional)]
   ```
#### Note: Cookie and headers must be in JSON format (if provided).
### For NodeJs Payloads
```shell
  ./pwnshell.py -H [HOST IP] -n   
```
##### To use only NodeJs payload -> require('child_process').exec('PWNME')
### Use Help for full usage details
```sh
   ./pwnshell.py -h
   ```



## License

Distributed under the MIT License. See `LICENSE` for more information.



<!-- CONTACT -->
## Contact

Zeyad AbuQasem - [LinkedIn](https://www.linkedin.com/in/zeyad-yahya-0985971b5/)

Omar Albalouli - [LinkedIn](https://www.linkedin.com/in/omar-albalouli/)

Project Link: [https://github.com/zAbuQasem/PwnShell](https://github.com/zAbuQasem/PwnShell)



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
