#!/bin/bash
. "$(dirname $0)/wcs-lib.sh"

f_check_pcregrep
f_check_root

#         1      1   2              23 4      43 5  5
PCRE_URL='([a-z]+)://([a-z0-9.-]+)(:([0-9]+))?(.*)'

rproto=$(echo "$1" | pcregrep -o1 -i "$PCRE_URL")
rhost=$(echo "$1" | pcregrep -o2 -i "$PCRE_URL")
rport=$(echo "$1" | pcregrep -o4 -i "$PCRE_URL")
rpath=$(echo "$1" | pcregrep -o5 -i "$PCRE_URL")

# Пути по умолчанию
[[ -z "$rpath" ]] && rpath='/'

if [[ "$rproto" =~ https? ]]; then
	scripts='http-title,http-auth,http-brute,http-form-brute'
	scripts_args="http-auth.path='$rpath',http-form-brute.path='$rpath',http-brute.path='$rpath'"
elif [[ "$rproto" =~ ftp ]]; then
	scripts='ftp-brute'
	scripts_args='ftp-brute.timeout=10h'
else
	echo "Протокол '$rproto' не поддерживается."
	exit 1
fi
scripts_args="$scripts_args,brute.timeout=10h,brute.retries=1000000,unpwdb.timelimit=10h"

# Порты по-умолчанию
if [[ -z "$rport" ]]; then
	if [[ "$rproto" =~ http ]]; then
		rport=80
	elif [[ "$rproto" =~ https ]]; then
		rport=443
	elif [[ "$rproto" =~ ftp ]]; then 
		rport=21
	fi
fi

echo "Запуск сканирования [$rproto]://[$rhost]:[$rport][$rpath]..."
nmap -vvv --privileged -T4 -n -PN -sS -p "$rport" --reason \
	--script-args "$scripts_args" --script "$scripts" --host-timeout 10h "$rhost"
