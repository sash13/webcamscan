#!/bin/bash
. "$(dirname "$0")/wcs-lib.sh"

wcs_check_bash
wcs_check_nmap
wcs_check_root
wcs_check_file "$1"

wcs_println "Расширенное сканирование..."
wcs_deep_scan "$1" "$2"

wcs_println "Готово!"
exit 0
