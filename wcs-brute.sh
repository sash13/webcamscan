#!/bin/bash
#
[[ $EUID -ne 0 ]] && echo "Скрипт должен работать от root." && exit 1
nmap -vvv --privileged -T4 -n -PN -sS -p "T:$2" --reason \
	--script-args "unpwdb.timelimit=10h,brute.retries=1000000,http-auth.path='$3',http-form-brute.path='$3',http-brute.path='$3'" \
	--script http-title,http-auth,http-brute,http-form-brute --host-timeout 10h "$1"