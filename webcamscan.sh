#!/bin/bash
#
# Базовые проверки
[[ $EUID -ne 0 ]] && echo "Скрипт должен работать от root." && exit 1
[[ ! -f "$1" ]] && echo "Файл '$1' не найден!" && exit 1
#
# Загружаем настройки
. "$(dirname $0)/config.sh"
NMAPDIR="${NMAPDIR:-.}"
WRITE_ALL_HOSTS="${WRITE_ALL_HOSTS:-true}"
HOST_TIMELIMIT="${HOST_TIMELIMIT:-5m}"
RTSP_URLS="${RTSP_URLS:-./rtsp-urls.txt}"
FIND_AUTH="${FIND_AUTH:-true}"
BRUTEFORCE="${BRUTEFORCE:-true}"
BRUTEFORCE_TIMELIMIT="${BRUTEFORCE_TIMELIMIT:-2m}"
LIBAV_LIMIT="${LIBAV_LIMIT:-4}"
LIBAV_SCREENSHOT="${LIBAV_SCREENSHOT:-true}"
SAVE_NO_FLAGS="${SAVE_NO_FLAGS:-false}"
CLEANUP="${CLEANUP:-true}"
#
# 'Константные' регексы
REGEX_IP='[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}'
REGEX_URL_RSTP='rtsp://[0-9.]+/\S*'
#
# Рабочие переменные окружения
OUT="${OUT:-$1-webcam}"
OUT_ALL="${OUT}/all.txt"
mkdir -p "$OUT"
TMP="${TMP:-$OUT/tmp}"
mkdir -p "$TMP"
DISCOVERED1="$TMP/discovered.1.tmp"
DISCOVERED2="$TMP/discovered.2.tmp"
STAGE3="$TMP/stage.3.tmp"
STAGE4="$TMP/stage.4.tmp"
#
SCRIPTS='rtsp-methods,rtsp-url-brute,http-title'
[[ "$FIND_AUTH" = 'true' ]] && SCRIPTS="$SCRIPTS,http-auth,http-auth-finder"
[[ "$BRUTEFORCE" = 'true' ]] && SCRIPTS="$SCRIPTS,http-brute,http-form-brute"
SCRIPTS_ARGS="unpwdb.timelimit='$BRUTEFORCE_TIMELIMIT'"
SCRIPTS_ARGS="$SCRIPTS_ARGS,rtsp-url-brute.urlfile='$RTSP_URLS',brute.retries=10240"
SCRIPTS_ARGS="$SCRIPTS_ARGS,http-auth.path='/',http-form-brute.path='/',http-brute.path='/'"
#
# $1 - позиция, $2 - максимум.
function f_echo_progress () { echo -n " $(bc -l <<< "scale=1; 100.0*($1-0.5)/$2")%" ; }
function f_echo_subprogress () { echo -n '.' ; }
#
# Исправляет владельца файла из-за выполенния от root'а: $1 - файл
function f_fix_own () {
	# Не уверен, что это правильно.
	local u=$(who am i | awk '{print $1}')
	chown -R "$u:$u" "$1"
	return 0
}
#
# Обход по файлу с прогрессом: $1 - файл, $2... - коллбек
function f_iterate_file () {
	local file=$1
	shift
	local n=$(( $(wc -l < "$file") + 1 ))
	local i=1
	while IFS=$'\n' read -r item || [[ -n "$item" ]] ; do
		f_echo_progress "$(( i++ ))" "$n"
		$@ "$item" #INVOKE CALLBACK
	done < "$file"
	echo # NL после прогресса
	return 0
}
#
# Первичное сканирование целей: $1 - куда сохранять, $2 - цели 
function f_scan () {
	#echo "$2"
	nmap --privileged -n -sS -sU -p T:554,U:554 --open --max-retries 3 --host-timeout 10s \
		--randomize-hosts --min-parallelism=4 --min-hostgroup=4096 --max-hostgroup=65536 \
		-oG - $(printf "%q" "$2" ) 2>&1 | grep 'open/' | grep -Eo "$REGEX_IP" | uniq >> "$1"
		#     ^ этот костыль нужен, потому что nmap не принимает список хостов
		#       как один аргумент, но переменные нужно как-то экранировать.
	return 0
}
#
# Записывает найденые хосты в выход: $1 - файл с хостами
function f_write_all_hosts () {
	local file="${OUT}/all_hosts.txt"
	cat "$1" >> "$file"
	f_fix_own "$file"
	return 0
}
#
# Сохраняет скриншот: $1 - трансляция, $2 - файл.
function f_libav_probe () {
	timeout -k 5 15 avprobe -v info "$item3" && echo "Неудаётся сделать avprobe '$1'!"
	return 0
}
#
# Сохраняет скриншот: $1 - трансляция, $2 - файл.
function f_libav_screenshot () {
	timeout -k 5 15 avconv -v quiet -i "$1" -ss 3 -qscale 0 -t 1 -r 1 "$2"
	[[ -f "$2" ]] && f_fix_own "$2" \
		&& echo "Скриншот '$1' сохранен в '$2'." || echo "Неудаётся сделать скриншот '$1'!"
	return 0
}
#
# Глубокое сканирование хоста: $1 - хост
function f_deep_scan_host () {
	rm -f "$STAGE3" "$STAGE4"
	# 81,8008,8081 - Beward MJPG
	nmap -vvv --privileged -T4 -n -PN -sS -sU -p T:80,T:81,T:8008,T:8080,T:8081,T:554,U:554 --reason \
		--script "$SCRIPTS" --script-args "$SCRIPTS_ARGS" \
		--host-timeout "$HOST_TIMELIMIT" "$1" > "$STAGE3" 2>&1
	local f=''
	grep -q 'Skipping host [0-9.]+ due to host timeout' "$STAGE3" && f="${f}_timeout" # Флаг: Ошибка
	grep -qE '[0-9]+/tcp\s+open\s+https?' "$STAGE3" && f="${f}_http" # Флаг: Есть рабочая HTTP-служба
	grep -q 'Valid credentials' "$STAGE3" && f="${f}_creds" # Флаг: Найден логин-пароль
	grep -q 'No valid accounts found' "$STAGE3" && f="${f}_nocreds" # Флаг: Не найден логин-пароль
	grep -qz 'rtsp-methods:.*DESCRIBE' "$STAGE3" && f="${f}_rtsp" # Флаг: Есть рабочая  RTSP-служба
	grep -q 'An error occured while testing the following URLs' "$STAGE3" && f="${f}_error" # Флаг: Ошибка
	if grep -q 'Discovered URLs' "$STAGE3" ; then
		f="${f}_found" # Флаг: Есть рабочие стримы
		echo >> "$STAGE4"
		local m=0
		for item3 in `grep -Eo "$REGEX_URL_RSTP" "$STAGE3"` ; do
			if [ "$(( M++ ))" -ge "$LIBAV_LIMIT" ] ; then
				echo "Достигнут LIBAV_LIMIT ($LIBAV_LIMIT)!" >> "$STAGE4"
				break
			fi
			f_echo_subprogress
			f_libav_probe >> "$STAGE4" 2>&1
			[[ "$LIBAV_SCREENSHOT" = 'true' ]] \
				&& f_libav_screenshot "$item3" "${OUT}/${1}_${M}.jpg" >> "$STAGE4" 2>&1
		done
		grep -q 'Stream #[.0-9]*: Video' "$STAGE4" && f="${f}_video" # Флаг: Есть видео
		grep -q 'Stream #[.0-9]*: Audio' "$STAGE4" && f="${f}_audio" # Флаг: Есть звук
		grep -q 'Interleaved RTP mode is not supported yet' "$STAGE4" && f="${f}_il" # Флаг: TCP
		cat "$STAGE4" >> "$STAGE3"
	fi
	if [[ -n "$f" ]] || [[ "$SAVE_NO_FLAGS" = 'true' ]] ; then
		cat "$STAGE3" >> "$OUT_ALL" # ! Дозапись
		local infofile="${OUT}/${1}${f}_.txt"
		cat "$STAGE3" >> "$infofile" # ! Дозапись
		f_fix_own "$infofile"
	else
		echo >> "$OUT_ALL" # ! Дозапись
		echo "Пропуск '$1': Нет тегов." >> "$OUT_ALL" # ! Дозапись
	fi
}
#
# ОСНОВНОЙ КОД
#
echo "Первый этап: Поиск..."
rm -f "$DISCOVERED1"
f_iterate_file "$1" f_scan "$DISCOVERED1"
cat "$DISCOVERED1" | sort -R - | uniq > "$DISCOVERED2"
[[ "$WRITE_ALL_HOSTS" = 'true' ]] && f_write_all_hosts "$DISCOVERED2"
echo "Найдено $(wc -l < "$DISCOVERED2") потенциальных камер."
#
echo "Второй этап: Расширенное сканирование..."
f_iterate_file "$DISCOVERED2" f_deep_scan_host 
#
[[ "$CLEANUP" = 'true' ]] && rm -rf "$TMP"
f_fix_own "$OUT"
#
echo "Готово!"
exit 0
