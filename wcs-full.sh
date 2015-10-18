#!/bin/bash
. "$(dirname "$0")/wcs-lib.sh"

wcs_check_nmap
wcs_check_root
wcs_check_file "$1"

DISCOVERED2=$(wcs_alloc_temp)

wcs_println "Первый этап: Поиск..."
wcs_discover "$1" - | sort -R - | uniq > "$DISCOVERED2"
wcs_write_all_hosts "$DISCOVERED2"
wcs_println "Найдено $(wc -l < "$DISCOVERED2") потенциальных камер."

wcs_println "Второй этап: Расширенное сканирование..."
wcs_deep_scan "$DISCOVERED2" "$2"

wcs_clean "$DISCOVERED2"

wcs_cleanup

wcs_println "Готово!"
exit 0
