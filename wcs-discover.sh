#!/bin/bash
. "$(dirname "$0")/wcs-lib.sh"

wcs_check_nmap
wcs_check_root
wcs_check_file "$1"

echo "Поиск..."
wcs_iterate_file "$1" wcs_scan - | sort -R - | uniq > "$2"
wcs_fix_own "$2"

wcs_clean "$t1"
wcs_cleanup

echo "Готово!"
exit 0
