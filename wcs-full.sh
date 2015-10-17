#!/bin/bash
. "$(dirname $0)/wcs-lib.sh"

wcs_check_nmap
wcs_check_root
wcs_check_file "$1"

DISCOVERED2="$TMP/discovered.2.tmp"
rm -rf "$DISCOVERED2"

echo "Первый этап: Поиск..."
wcs_iterate_file "$1" wcs_scan - | sort -R - | uniq > "$DISCOVERED2"
wcs_write_all_hosts "$DISCOVERED2"
echo "Найдено $(wc -l < "$DISCOVERED2") потенциальных камер."

echo "Второй этап: Расширенное сканирование..."
wcs_iterate_file "$DISCOVERED2" wcs_deep_scan_host 

wcs_cleanup

echo "Готово!"
exit 0
