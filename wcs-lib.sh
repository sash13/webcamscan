#!/bin/bash

# Загружаем настройки
. "$(dirname "$0")/config.sh"
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

# 'Константные' регексы
REGEX_IP='([0-9]{1,3}\.){3}[0-9]{1,3}'
REGEX_URL_RSTP='rtsp://[0-9.]+/\S*'

# Рабочие переменные окружения
OUT="${OUT:-$1-webcam}"
OUT_ALL="${OUT}/all.txt"
mkdir -p "$OUT"
TMP="${TMP:-$OUT/tmp}"
mkdir -p "$TMP"

SCRIPTS='rtsp-methods,rtsp-url-brute,http-title'
[[ "$FIND_AUTH" = 'true' ]] && SCRIPTS="$SCRIPTS,http-auth,http-auth-finder"
[[ "$BRUTEFORCE" = 'true' ]] && SCRIPTS="$SCRIPTS,http-brute,http-form-brute"
SCRIPTS_ARGS="unpwdb.timelimit='$BRUTEFORCE_TIMELIMIT'"
SCRIPTS_ARGS="$SCRIPTS_ARGS,rtsp-url-brute.urlfile='$RTSP_URLS',brute.retries=10240"
SCRIPTS_ARGS="$SCRIPTS_ARGS,http-auth.path='/',http-form-brute.path='/',http-brute.path='/'"


function wcs_print () {
	printf '%s' "$@" 1>&2
	return 0
}

function wcs_println () {
	printf '%s\n' "$@" 1>&2
	return 0
}

function wcs_printb () {
	printf '%b' "$@" 1>&2
	return 0
}

function wcs_error () {
	printf '%b' "$@" 1>&2
	exit 1
}


# Прогресс: $1 - позиция, $2 - максимум.
function wcs_echo_progress () {
	wcs_print " $(bc -l <<< "scale=1; 100.0*($1-0.5)/$2")%"
}

function wcs_echo_subprogress () {
	wcs_print '.'
}


function wcs_check_bash () {
	(( ${BASH_VERSION%%[^0-9]*} < 4 )) \
		&& wcs_error "Вы используете устревший ($BASH_VERSION) bash, не обходима версия не ниже 4."
}

function wcs_check_root () {
	[[ $EUID -ne 0 ]] \
		&& wcs_error "Скрипт должен работать от root."
}

function wcs_check_pcregrep () {
	pcregrep --version &> /dev/null \
		|| wcs_error "pcregrep не обнаружен."
}

function wcs_check_nmap () {
	nmap --version &> /dev/null \
		|| wcs_error "nmap не обнаружен."
}

function wcs_check_file () {
	[[ ! -f "$1" ]] \
		&& wcs_error "Файл '$1' не найден!"
}


function wcs_alloc_temp () {
	mktemp --tmpdir="${TMP}/"
}


# Исправляет владельца файла из-за выполенния от root'а: $1 - файл
function wcs_fix_own () {
	# Не уверен, что это правильно.
	local u=$(who am i | awk '{print $1}')
	chown -R "$u:$u" "$1"
	return 0
}


# Обход по файлу с прогрессом: $1 - файл, $2... - коллбек
function wcs_iterate_file () {
	local file="$1"
	shift
	local n=$(( $(wc -l < "$file") + 1 ))
	local i=1
	while IFS=$'\n' read -r item || [[ -n "$item" ]]
	do
		wcs_echo_progress "$(( i++ ))" "$n"
		$@ "$item" #INVOKE CALLBACK
	done < "$file"
	wcs_println # NL после прогресса
	return 0
}


# Первичное сканирование целей: $1 - куда сохранять, $2 - цели 
function wcs_scan () {
	local out="$1"
	[[ -z "$out" || "$out" == '-' ]] && out='/dev/stdout'
	nmap --privileged -n -sS -sU -p T:554,U:554 --open --max-retries 3 --host-timeout 10s \
		--randomize-hosts --min-parallelism=4 --min-hostgroup=4096 --max-hostgroup=65536 \
		-oG - $(printf "%q" "$2" ) 2>&1 | grep 'open/' | grep -Eo "$REGEX_IP" | uniq >> "$out"
		#     ^ этот костыль нужен, потому что nmap не принимает список хостов
		#       как один аргумент, но переменные нужно как-то экранировать.
	return 0
}


# Записывает найденые хосты в выходную папку: $1 - файл с хостами
function wcs_write_all_hosts () {
	if [[ "$WRITE_ALL_HOSTS" = 'true' ]]
	then
		local file="${OUT}/all_hosts.txt"
		cat "$1" >> "$file"
		wcs_fix_own "$file"
	fi
	return 0
}


# Сохраняет скриншот: $1 - трансляция, $2 - файл.
function wcs_libav_probe () {
	timeout -k 5 25 avprobe -v info "$1" && wcs_println "Не удаётся сделать avprobe '$1'!"
	return 0
}


# Сохраняет скриншот: $1 - трансляция, $2 - файл.
function wcs_libav_screenshot () {
	timeout -k 5 25 avconv -v quiet -i "$1" -ss 3 -qscale 0 -t 1 -r 1 "$2"
	[[ -f "$2" ]] && wcs_fix_own "$2" \
		&& wcs_println "Скриншот '$1' сохранен в '$2'." || wcs_println "Не удаётся сделать скриншот '$1'!"
	return 0
}


# Глубокое сканирование хоста: $1 - хост
function wcs_deep_scan_host () {

	local nmap_tmp=$(wcs_alloc_temp)
	local f=''

	# 81,8008,8081 - Beward MJPG
	nmap -vvv --privileged -T4 -n -PN -sS -sU -p T:80,T:81,T:8008,T:8080,T:8081,T:554,U:554 --reason \
		--script "$SCRIPTS" --script-args "$SCRIPTS_ARGS" \
		--host-timeout "$HOST_TIMELIMIT" "$1" &> "$nmap_tmp"

	# Флаг: Ошибка
	grep -q 'Skipping host [0-9.]+ due to host timeout' "$nmap_tmp" \
		&& f="${f}_timeout"

	# Флаг: Есть рабочая HTTP-служба
	grep -qE '[0-9]+/tcp\s+open\s+https?' "$nmap_tmp" \
		&& f="${f}_http" 

	# Флаг: Найден логин-пароль
	grep -q 'Valid credentials' "$nmap_tmp" \
		&& f="${f}_creds" 

	 # Флаг: Не найден логин-пароль
	grep -q 'No valid accounts found' "$nmap_tmp" \
		&& f="${f}_nocreds"

	# Флаг: Есть рабочая  RTSP-служба
	grep -qz 'rtsp-methods:.*DESCRIBE' "$nmap_tmp" \
		&& f="${f}_rtsp" 

	# Флаг: Ошибка
	grep -q 'An error occured while testing the following URLs' "$nmap_tmp" \
		&& f="${f}_error" # Флаг: Ошибка

	# Флаг: Есть рабочие стримы
	if grep -q 'Discovered URLs' "$nmap_tmp"
	then
		f="${f}_found" 

		local libav_tmp=$(wcs_alloc_temp)

		local i=0
		grep -Eo "$REGEX_URL_RSTP" "$nmap_tmp" | \
		while IFS=$'\n' read -r item3 || [[ -n "$item3" ]]
		do
			if [ "$(( i++ ))" -ge "$LIBAV_LIMIT" ]
			then
				wcs_println "Достигнут LIBAV_LIMIT ($LIBAV_LIMIT)!" >> "$libav_tmp"
				break
			fi

			wcs_echo_subprogress
			wcs_libav_probe "$item3" &>> "$libav_tmp"
			[[ "$LIBAV_SCREENSHOT" = 'true' ]] \
				&& wcs_libav_screenshot "$item3" "${OUT}/${1}_${i}.jpg" &>> "$libav_tmp"

		done

		# Флаг: Есть видео
		grep -q 'Stream #[.0-9]*: Video' "$libav_tmp" \
			&& f="${f}_video"

		# Флаг: Есть звук
		grep -q 'Stream #[.0-9]*: Audio' "$libav_tmp" \
			&& f="${f}_audio"

		# Флаг: TCP
		grep -q 'Interleaved RTP mode is not supported yet' "$libav_tmp" \
			&& f="${f}_il"

		wcs_println >> "$nmap_tmp" # Разделительная пустая строка.
		cat "$libav_tmp" >> "$nmap_tmp"

		wcs_clean "$libav_tmp"
	fi

	if [[ -n "$f" || "$SAVE_NO_FLAGS" = 'true' ]]
	then
		cat "$nmap_tmp" >> "$OUT_ALL" # ! Дозапись
		local infofile="${OUT}/${1}${f}_.txt"
		cat "$nmap_tmp" >> "$infofile" # ! Дозапись
		wcs_fix_own "$infofile"
	else
		wcs_printb "\nПропуск '$1': Нет тегов.\n\n" >> "$OUT_ALL" # ! Дозапись
	fi

	wcs_clean "$nmap_tmp"
}


function wcs_clean () {
	[[ "$CLEANUP" = 'true' && -e "$1" ]] && rm -rf "$1"
}


function wcs_cleanup () {
	wcs_clean "$TMP"
	[[ -n "$OUT" ]] && wcs_fix_own "$OUT"
}
