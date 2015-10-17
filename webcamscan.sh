#!/bin/bash
. "$(dirname $0)/wcs-lib.sh"

f_check_nmap
f_check_root
f_check_file "$1"

DISCOVERED2="$TMP/discovered.2.tmp"
rm -rf "$DISCOVERED2"

echo "Первый этап: Поиск..."
f_iterate_file "$1" f_scan - | sort -R - | uniq > "$DISCOVERED2"
f_write_all_hosts "$DISCOVERED2"
echo "Найдено $(wc -l < "$DISCOVERED2") потенциальных камер."

echo "Второй этап: Расширенное сканирование..."
f_iterate_file "$DISCOVERED2" f_deep_scan_host 

f_cleanup

echo "Готово!"
exit 0
