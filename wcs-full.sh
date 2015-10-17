#!/bin/bash
. "$(dirname "$0")/wcs-lib.sh"

wcs_check_nmap
wcs_check_root
wcs_check_file "$1"

DISCOVERED2="$TMP/discovered.2.tmp"
rm -rf "$DISCOVERED2"

wcs_println "Первый этап: Поиск..."
wcs_iterate_file "$1" wcs_scan - | sort -R - | uniq > "$DISCOVERED2"
wcs_write_all_hosts "$DISCOVERED2"
wcs_println "Найдено $(wc -l < "$DISCOVERED2") потенциальных камер."

wcs_println "Второй этап: Расширенное сканирование..."
wcs_iterate_file "$DISCOVERED2" wcs_deep_scan_host 

wcs_cleanup

wcs_println "Готово!"
exit 0
