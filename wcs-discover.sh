#!/bin/bash
. "$(dirname "$0")/wcs-lib.sh"

wcs_check_nmap
wcs_check_root
wcs_check_file "$1"

echo "Поиск..."
wcs_discover "$1" "$2"

wcs_cleanup

echo "Готово!"
exit 0
