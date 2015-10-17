#!/bin/bash
. "$(dirname $0)/wcs-lib.sh"

f_check_nmap
f_check_root
f_check_file "$1"

echo "Расширенное сканирование..."
f_iterate_file "$1" f_deep_scan_host
