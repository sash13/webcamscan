#!/bin/bash

. "$(dirname $0)/wcs-lib.sh"

f_check_nmap
f_check_root
f_check_file "$1"

echo "Поиск..."
f_iterate_file "$1" f_scan - | sort -R - | uniq > "$2"
f_fix_own "$2"

f_clean "$t1"
f_cleanup

echo "Готово!"
exit 0
