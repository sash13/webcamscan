#!/bin/bash
. "$(dirname "$0")/wcs-lib.sh"

wcs_check_bash
wcs_check_nmap
wcs_check_root
wcs_check_file "$1"

wcs_println "Расширенное сканирование..."
wcs_iterate_file "$1" wcs_deep_scan_host

wcs_println "Готово!"
exit 0
